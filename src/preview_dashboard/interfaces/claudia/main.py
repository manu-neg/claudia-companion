"""Claudia host process entry point (ADR 0031, units M4b + M5b; C46, C49-C53, C55, C58-C60).

Start-up refuses (exit 2) with any API credential variable set (C49), an
unsafe/incomplete host settings file or a settings source that switches
the hooks off (C50, C59), an unsafe MCP config (C51, C53), an unsafe
`claudia` token file (C12/C45), an untrusted admin socket (C30), an unsafe
hook socket directory (C59), an unusable knowledge base or (with
`--require-run-cgroups`) no delegated cgroup for per-run cgroups (C58). A KB
halt persisted in the state dir is read at start (the host starts halted). `build_host`
wires the screen pipeline (C48), the hook gate + control socket (C59/C60),
the approval flow (C46/C55), KB commits (C53) and voice replies (C56).
Then two threads: the **poller** long-polls the inbox, claims each message
(handled CAS: processed once) and runs `/stop` `/status` `/voice` at once
(so `/stop` works while a run is busy); the **worker** runs everything
else in order (`ClaudiaHost`) and closes idle windows between messages.
Errors are logged by type name only.
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import signal
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from preview_dashboard.adapters.claude_cli import (
    HOOK_PEER_LOOKUP_TIMEOUT,
    ApiCredentialError,
    ClaudeAgentsDirectory,
    ClaudeCliConfig,
    CliClaudeRunner,
    RunCgroups,
    UuidWindowIds,
    delegated_cgroup_root,
    refuse_api_credentials,
)
from preview_dashboard.adapters.claudia_admin_client import ClaudiaAdminClient, ReplyAlerts
from preview_dashboard.adapters.claudia_audit_log import JsonlAuditLog
from preview_dashboard.adapters.claudia_halt_flag import FileHaltFlag
from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.haiku_screen import HaikuScreenRunner
from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.piper_tts import PiperTextToSpeech
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.adapters.transcripts import JsonlTranscripts
from preview_dashboard.application.claudia.approval_flow import ApprovalFlow, DenialRecorder
from preview_dashboard.application.claudia.audit import PeerAudit
from preview_dashboard.application.claudia.hook_gate import HookGate
from preview_dashboard.application.claudia.kb import KbService
from preview_dashboard.application.claudia.runs import ClaudiaHost
from preview_dashboard.application.claudia.screening import ScreenPipeline
from preview_dashboard.application.claudia.voice import VoiceComposer
from preview_dashboard.application.claudia.windows import (
    HostCommand,
    WindowTracker,
    parse_host_command,
)
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.owner_messages import OwnerMessage
from preview_dashboard.interfaces.claudia.control_socket import (
    ControlSocketError,
    ControlSocketServer,
)
from preview_dashboard.interfaces.claudia.hook import DEFAULT_SOCKET_PATH
from preview_dashboard.interfaces.claudia.mcp_config import (
    McpConfigPreflight,
    load_mcp_config,
    pin_file,
    write_recap_config,
)
from preview_dashboard.interfaces.claudia.settings import (
    HOOK_COMMAND,
    HOST_SETTINGS_PATH,
    HostSettings,
    HostSettingsError,
    SettingsPreflight,
    check_hook_command,
    check_settings_sources,
    load_host_settings,
    settings_sources,
)
from preview_dashboard.interfaces.mcp.admin_socket import AdminSocketTrustError, verify_admin_socket
from preview_dashboard.interfaces.notifier.runner import Backoff
from preview_dashboard.interfaces.token_file import (
    TokenFileError,
    TokenGroupPolicy,
    TokenKind,
    TokenLoader,
)
from preview_dashboard.ports.claudia_host import HostAdmin, RunPreflight
from preview_dashboard.ports.claudia_screen import Screen, ScreenHealth

POLL_WAIT_SECONDS: Final = 50
TICK_SECONDS: Final = 60.0
# Commands that must work while a run is busy (C58); `/new` waits its turn.
IMMEDIATE_COMMANDS: Final = frozenset({HostCommand.STOP, HostCommand.STATUS, HostCommand.VOICE})
EXIT_REFUSED: Final = 2
VOICES_DIR_NAME: Final = "voices"  # Piper models, root 0700 (install.sh --voice-models)
KB_HALT_FILE: Final = "kb-halted"  # the persisted KB halt (C53, newcode-1)

_log = logging.getLogger("preview_dashboard.claudia")


@dataclass(frozen=True, slots=True, kw_only=True)
class HostConfig:
    """The host's fixed paths (root-owned deploy config, never from messages)."""

    admin_socket: Path
    token_file: Path
    settings_file: Path
    mcp_config: Path
    workdir: Path
    state_dir: Path
    claude_bin: Path
    home: Path
    hook_socket: Path = DEFAULT_SOCKET_PATH
    # host-flow-5: refuse to start unless every run can get its own cgroup (the unit sets it).
    require_run_cgroups: bool = False

    @property
    def projects_dir(self) -> Path:
        """Where Claude Code writes the runs' transcripts (C52)."""
        return self.home / ".claude" / "projects"

    @property
    def voices_dir(self) -> Path:
        """Piper voice models (voice replies are off when it is missing)."""
        return self.state_dir / VOICES_DIR_NAME


def parse_args(argv: Sequence[str] | None = None) -> HostConfig:
    """Parse the host's command line (all paths absolute).

    Raises:
        SystemExit: bad arguments (argparse).
    """
    parser = argparse.ArgumentParser(prog="claudia-host", description=__doc__)
    parser.add_argument(
        "--admin-socket", type=Path, default=Path("/run/preview-dashboard/admin.sock")
    )
    parser.add_argument(
        "--token-file", type=Path, default=Path("/etc/preview-dashboard/claudia.token")
    )
    parser.add_argument("--settings", type=Path, default=HOST_SETTINGS_PATH)
    parser.add_argument(
        "--mcp-config", type=Path, default=Path("/etc/preview-dashboard/claudia-mcp.json")
    )
    parser.add_argument("--workdir", type=Path, default=Path("/var/lib/claudia-host/work"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/claudia-host"))
    parser.add_argument("--claude-bin", type=Path, default=Path("/root/.local/bin/claude"))
    parser.add_argument("--home", type=Path, default=Path("/root"))
    # Fixed in the hook command too: only tests point it elsewhere.
    parser.add_argument("--hook-socket", type=Path, default=DEFAULT_SOCKET_PATH)
    parser.add_argument(
        "--require-run-cgroups",
        action="store_true",
        help="refuse to start without a delegated cgroup for per-run cgroups (ADR 0039)",
    )
    ns = parser.parse_args(argv)
    paths = {
        "admin_socket": ns.admin_socket,
        "token_file": ns.token_file,
        "settings_file": ns.settings,
        "mcp_config": ns.mcp_config,
        "workdir": ns.workdir,
        "state_dir": ns.state_dir,
        "claude_bin": ns.claude_bin,
        "home": ns.home,
        "hook_socket": ns.hook_socket,
    }
    for name, value in paths.items():
        if not value.is_absolute():
            parser.error(f"--{name.replace('_', '-')} must be an absolute path")
    return HostConfig(**paths, require_run_cgroups=ns.require_run_cgroups)


def startup_checks(
    config: HostConfig,
    environ: Mapping[str, str],
    *,
    trusted_uids: Sequence[int] = (0,),
    hook_command: Path = Path(HOOK_COMMAND),
) -> HostSettings:
    """C49 + C50/C59 start checks, in that order; returns the verified host settings.

    Raises:
        ApiCredentialError: an API credential variable is set.
        HostSettingsError: the host settings or another settings source is
            unsafe, or the hook command / its interpreter is (hook-5).
    """
    refuse_api_credentials(environ)
    verified = load_host_settings(config.settings_file, trusted_uids=trusted_uids)
    check_settings_sources(settings_sources(config.home, config.workdir))
    # hook-5: a broken hook would let every call run unchecked; refuse at start, not first run.
    check_hook_command(hook_command, trusted_uids=trusted_uids)
    return verified


@dataclass(frozen=True, slots=True)
class _Work:
    message: OwnerMessage
    command: HostCommand | None
    generation: int


class HostLoop:
    """The poller + worker threads around `ClaudiaHost`.

    Args:
        admin: admin API client.
        host: the host service.
        screen: for health reports (`POST /v1/claudia/health`).
        poll_wait: inbox long-poll seconds.
        tick_seconds: how often the idle worker checks for a due window.
    """

    def __init__(
        self,
        admin: HostAdmin,
        host: ClaudiaHost,
        screen: Screen,
        *,
        poll_wait: float = POLL_WAIT_SECONDS,
        tick_seconds: float = TICK_SECONDS,
    ) -> None:
        self._admin = admin
        self._host = host
        self._screen = screen
        self._poll_wait = poll_wait
        self._tick = tick_seconds
        self._queue: queue.Queue[_Work] = queue.Queue()
        self._stop = threading.Event()
        self._reported: ScreenHealth | None = None

    def stop(self) -> None:
        """Ask both threads to finish (thread- and signal-safe)."""
        self._stop.set()

    def poll_once(self) -> int:
        """One inbox round: claim each message, run immediate commands, queue the rest."""
        self._report_health()
        claimed = 0
        for message in self._admin.unhandled(self._poll_wait):
            if not self._admin.mark_handled(message.id):
                continue  # someone else claimed it: processed once (C58)
            claimed += 1
            command = parse_host_command(message.text)
            if command is not None and command in IMMEDIATE_COMMANDS:
                self._host.command(command, message.id)
            else:
                self._queue.put(_Work(message, command, self._host.generation))
        return claimed

    def work_once(self) -> bool:
        """Run one queued item, or check for a due window when idle; True if one ran."""
        try:
            work = self._queue.get(timeout=self._tick)
        except queue.Empty:
            self._host.tick()
            return False
        if work.command is not None:
            if work.generation == self._host.generation:
                self._host.command(work.command, work.message.id)
        else:
            self._host.handle_message(work.message, generation=work.generation)
        return True

    def _report_health(self) -> None:
        try:
            health = self._screen.health()
            if health is not self._reported:
                self._admin.report_health(str(health))
                self._reported = health
        except Exception as exc:
            _log.warning("health report failed (%s)", type(exc).__name__)

    def _loop(self, name: str, round_fn: Callable[[], object]) -> None:
        backoff = Backoff()
        while not self._stop.is_set():
            try:
                round_fn()
            except Exception as exc:
                # Type name only: exception text may hold content (C29).
                delay = backoff.next_delay()
                _log.warning(
                    "%s round failed (%s); retrying in %.0f s", name, type(exc).__name__, delay
                )
                self._stop.wait(delay)
                continue
            backoff.reset()

    def run(self) -> bool:
        """Run both threads until `stop()`; False if one died (systemd restarts the host)."""
        threads = [
            threading.Thread(target=self._loop, args=(n, f), name=f"claudia-{n}", daemon=True)
            for n, f in (("poller", self.poll_once), ("worker", self.work_once))
        ]
        for thread in threads:
            thread.start()
        healthy = True
        while not self._stop.wait(0.5):
            if not all(t.is_alive() for t in threads):
                _log.error("a host thread died; stopping")
                healthy = False
                self.stop()
        self._host.stop()  # kill runs on shutdown too
        return healthy


def build_host(
    config: HostConfig,
    environ: Mapping[str, str],
    verified: HostSettings,
    *,
    screen: Screen | None = None,
) -> HostParts:
    """Load the `claudia` token, trust the admin socket, then `wire_host` (after `startup_checks`).

    Raises:
        TokenFileError: the `claudia` token file is unsafe (C12/C45).
        AdminSocketTrustError: the admin socket can't be trusted (C30).
        HostSettingsError, StorageUnavailableError, ValueError, OSError: see `wire_host`.
    """
    token = TokenLoader(TokenGroupPolicy(own=TokenKind.CLAUDIA)).load(
        TokenKind.CLAUDIA, config.token_file
    )
    verify_admin_socket(config.admin_socket)
    admin = ClaudiaAdminClient(config.admin_socket, token)
    try:
        return wire_host(config, environ, verified, admin, screen=screen)
    except BaseException:
        admin.close()
        raise


@dataclass(frozen=True, slots=True)
class HostParts:
    """What `main` runs and closes: the loop, the admin client, the hook control socket."""

    loop: HostLoop
    admin: ClaudiaAdminClient
    control: ControlSocketServer
    host: ClaudiaHost


class PreflightChain:
    """`RunPreflight` running each check in order; the first refusal wins.

    Raises (`check`):
        RunRefusedError: from the first failing check.
    """

    def __init__(self, *checks: RunPreflight) -> None:
        self._checks = checks

    def check(self) -> None:
        """Run every check (see the class docstring)."""
        for check in self._checks:
            check.check()


def voice_composer(voices_dir: Path) -> VoiceComposer | None:
    """Piper voice replies if the models dir exists (install.sh `--voice-models`), else None."""
    if not voices_dir.is_dir():
        _log.info("voice replies off: no voice models installed")
        return None
    # Piper and its models load lazily: a missing extra only fails the first note (text fallback).
    return VoiceComposer(tts=PiperTextToSpeech(voices_dir), scanner=RegexSecretScanner())


class RunCgroupError(RuntimeError):
    """Per-run cgroups are required but the host has no delegated cgroup (host-flow-5)."""


def run_containment(config: HostConfig, find_root: Callable[[], Path | None]) -> RunCgroups | None:
    """Per-run cgroups under the unit's delegated cgroup; None = process-group fallback.

    Raises:
        RunCgroupError: `config.require_run_cgroups` and no delegated cgroup.
    """
    root = find_root()
    if root is not None:
        return RunCgroups(root)
    if config.require_run_cgroups:
        # Fail closed: /stop could miss detached background jobs (C58).
        raise RunCgroupError(
            "no delegated cgroup for per-run cgroups (unit needs Delegate=yes, "
            "DelegateSubgroup=host)"
        )
    _log.warning("per-run cgroups unavailable: /stop falls back to process groups")
    return None


def wire_host(
    config: HostConfig,
    environ: Mapping[str, str],
    verified: HostSettings,
    admin: ClaudiaAdminClient,
    *,
    screen: Screen | None = None,
    trusted_uids: Sequence[int] = (0,),
    find_cgroup_root: Callable[[], Path | None] = delegated_cgroup_root,
) -> HostParts:
    """Wire every adapter into `ClaudiaHost` (composition root of the host process).

    Raises:
        HostSettingsError: the MCP config is unsafe or not the expected shape (C51, C53).
        StorageUnavailableError: the knowledge base root or git is unusable (C53).
        RunCgroupError: `require_run_cgroups` is set but no delegated cgroup exists.
        ValueError, OSError: bad paths or an unusable state directory.
    """
    clock = SystemClock()
    mcp = load_mcp_config(config.mcp_config, trusted_uids=trusted_uids)
    recap_config = write_recap_config(mcp, config.state_dir)
    # host-flow-1: both configs are pinned now and re-checked before every run.
    mcp_pins = McpConfigPreflight(
        (
            pin_file(config.mcp_config, trusted_uids=trusted_uids),
            pin_file(recap_config, trusted_uids=trusted_uids),
        ),
        trusted_uids=trusted_uids,
    )
    runner = CliClaudeRunner(
        ClaudeCliConfig(
            claude_bin=config.claude_bin,
            mcp_config=config.mcp_config,
            settings=config.settings_file,
            workdir=config.workdir,
            recap_mcp_config=recap_config,
        ),
        environ,
        containment=run_containment(config, find_cgroup_root),
    )
    audit_log = JsonlAuditLog(config.state_dir / "audit", clock)
    audit = PeerAudit(
        JsonlTranscripts(config.projects_dir, config.workdir),
        ClaudeAgentsDirectory(config.claude_bin, environ, config.workdir),
        audit_log,
        clock,
    )
    # The gate's denies pass the recorder, so an approval names the classifier's action (C59).
    denials = DenialRecorder(audit_log)
    gate = HookGate(
        ClaudeAgentsDirectory(
            config.claude_bin, environ, config.workdir, timeout=HOOK_PEER_LOOKUP_TIMEOUT
        ),
        denials,
        clock,
        realpath=os.path.realpath,
    )
    control = ControlSocketServer(gate, config.hook_socket, trusted_uids=trusted_uids)
    alerts = ReplyAlerts(admin)
    screen = screen or ScreenPipeline(
        runner=HaikuScreenRunner(claude_bin=str(config.claude_bin), environ=environ),
        alerts=alerts,
    )
    flow = ApprovalFlow(
        admin=admin, denials=denials, alerts=alerts, clock=clock, record=audit.record_approval
    )
    # The gardener's restore (`*.md` only) also undoes a failed host post-run commit (F-C2c).
    kb = KbService(
        FsKbStore(mcp.kb_root, group_id=mcp.kb_gid),
        RegexSecretScanner(),
        worktree=GitKbHistory(mcp.kb_root),
    )
    host = ClaudiaHost(
        admin=admin,
        screen=screen,
        runner=runner,
        # newcode-1: a KB halt survives restarts; read here, so a halted host restarts halted.
        windows=WindowTracker(
            clock, UuidWindowIds(), kb_halt=FileHaltFlag(config.state_dir / KB_HALT_FILE)
        ),
        audit=audit,
        preflight=PreflightChain(
            SettingsPreflight(
                verified, settings_sources(config.home, config.workdir), trusted_uids=trusted_uids
            ),
            mcp_pins,
        ),
        alerts=alerts,
        clock=clock,
        gate=gate,
        flow=flow,
        kb=kb,
        voice=voice_composer(config.voices_dir),
        voice_admin=admin,
    )
    return HostParts(loop=HostLoop(admin, host, screen), admin=admin, control=control, host=host)


_REFUSALS: Final = (
    ApiCredentialError,
    HostSettingsError,
    TokenFileError,
    AdminSocketTrustError,
    ControlSocketError,
    StorageUnavailableError,
    RunCgroupError,
)


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Run the host; returns the process exit code (2 = refused to start)."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    env = dict(os.environ if environ is None else environ)
    config = parse_args(argv)
    try:
        verified = startup_checks(config, env)
        parts = build_host(config, env, verified)
    except _REFUSALS as exc:
        # These name a variable, file or rule only, never a value (C49, C12).
        _log.error("refusing to start: %s", exc)
        return EXIT_REFUSED
    try:
        # C59: no socket, no runs (every hooked call would be denied anyway).
        parts.control.start()
    except (ControlSocketError, OSError) as exc:
        _log.error("refusing to start: hook control socket (%s)", type(exc).__name__)
        parts.admin.close()
        return EXIT_REFUSED
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _signum, _frame: parts.loop.stop())
    try:
        return 0 if parts.loop.run() else 1
    finally:
        parts.control.close()
        parts.admin.close()


if __name__ == "__main__":
    sys.exit(main())
