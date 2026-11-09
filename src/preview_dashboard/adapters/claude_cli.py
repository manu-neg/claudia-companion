"""Claude Code CLI adapter for the Claudia host: env allowlist, argv template, runner, peers.

`refuse_api_credentials` makes the host refuse to start with any API
credential variable set (subscription only, D15/C49); every `claude` child
gets `child_env` (allowlist, never the inherited environment, plus the fixed
variables that keep the owner's CLAUDE.md and auto memory out, F-CL1). Run argv
comes from one fixed template (C51): `-p --permission-mode auto
--strict-mcp-config --mcp-config <host> --settings <host> --tools <exact
built-ins>` plus the host's tool set and window id (a recap run swaps in the
host's recap MCP config) and one `--append-system-prompt`: the host rules,
then the run's checked persona (F-CL2); the prompt goes to stdin (never
argv, so owner text can't become a flag). Each run gets its own process group and, under
the host unit's delegated cgroup, its own cgroup, so `/stop` kills it and
everything it left behind, detached jobs included (C58, host-flow-5);
spawn and `/stop` share one lock and a stop epoch, so a run queued before
a `/stop` never starts.
"""

from __future__ import annotations

import contextlib
import itertools
import json
import logging
import os
import re
import signal
import subprocess  # nosec B404 - fixed argv list, no shell (C51)
import tempfile
import threading
import time
import uuid
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final, Protocol

from preview_dashboard.domain.approvals import WindowId, parse_window_id
from preview_dashboard.ports.claudia_host import RUN_NONCE_ENV, PeerInfo, RunOutcome, RunRequest

_log = logging.getLogger(__name__)

# D15/C49: any of these means API billing or another provider; refuse to start.
FORBIDDEN_ENV: Final = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
)
# The only variables a child may see (C49). HOME finds the subscription
# login; XDG_RUNTIME_DIR the session sockets `SendMessage` uses (V5).
ALLOWED_ENV: Final = ("HOME", "PATH", "LANG", "LC_ALL", "TERM", "TZ", "USER", "LOGNAME")
_OPTIONAL_ENV: Final = ("XDG_RUNTIME_DIR",)
DEFAULT_PATH: Final = "/usr/local/bin:/usr/bin:/bin"
# F-CL1: runs share root's login with the owner's coding sessions; these keep the
# owner's CLAUDE.md files (user, project) and auto memory out of every run. Set
# explicitly, never inherited. Not `--bare` (it skips the OAuth login) and not
# CLAUDE_CONFIG_DIR (the credentials live there).
ISOLATION_ENV: Final[Mapping[str, str]] = {
    "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
}

DEFAULT_RUN_TIMEOUT: Final = 30 * 60.0
MAX_OUTPUT_BYTES: Final = 4 * 1024 * 1024
KILL_GRACE_SECONDS: Final = 5.0
# Bounded reap after SIGKILL: a stuck leader (D state) must not hang the host's worker.
LEADER_REAP_SECONDS: Final = 10.0
PEER_LOOKUP_TIMEOUT: Final = 10.0
# Fail closed: only these `claude agents` kinds count as headless (verify on upgrades, V5).
HEADLESS_KINDS: Final = frozenset({"background", "headless", "bg"})
# Flag spellings that must never appear in a run argv (C51).
FORBIDDEN_FLAGS: Final = (
    "--dangerously-skip-permissions",
    "--allow-dangerously-skip-permissions",
    "bypassPermissions",
    "--channels",
    "--development",
)
_TOOL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,127}")
PROC_ROOT: Final = Path("/proc")
# Bound on the /stop descendant sweep (pid_max default is 4M; real hosts have far fewer).
MAX_PROC_ENTRIES: Final = 65536
CGROUP_FS: Final = Path("/sys/fs/cgroup")
PROC_SELF_CGROUP: Final = Path("/proc/self/cgroup")
# `DelegateSubgroup=` in claudia-host.service: the host's own leaf; runs are its siblings.
HOST_SUBGROUP: Final = "host"
_CGROUP_SEG_RE = re.compile(r"[A-Za-z0-9_.@:\\-]{1,255}")


class ApiCredentialError(RuntimeError):
    """An API credential variable is set; the message names the variable, never its value."""


def refuse_api_credentials(environ: Mapping[str, str]) -> None:
    """Refuse to start if any `FORBIDDEN_ENV` variable is present, even empty (C49).

    Raises:
        ApiCredentialError: naming the first variable found.
    """
    for name in FORBIDDEN_ENV:
        if name in environ:
            raise ApiCredentialError(
                f"{name} is set: the Claudia host runs on the subscription only (D15)"
            )


class RunIsolationError(RuntimeError):
    """A `claude` child env would load the owner's CLAUDE.md / auto memory (F-CL1)."""


def child_env(environ: Mapping[str, str]) -> dict[str, str]:
    """The environment of every `claude` child: allowlisted names plus `ISOLATION_ENV` (C49).

    PATH falls back to a fixed default; nothing else is ever inherited, so no
    key, token or token-file path reaches a run. The isolation variables are
    always set to their fixed values (F-CL1).
    """
    env = {name: environ[name] for name in (*ALLOWED_ENV, *_OPTIONAL_ENV) if name in environ}
    env.setdefault("PATH", DEFAULT_PATH)
    env.update(ISOLATION_ENV)
    return env


_RUN_NONCE_RE = re.compile(r"[0-9a-f]{16,64}")


def run_env(base: Mapping[str, str], run_nonce: str) -> dict[str, str]:
    """`base` (the allowlisted child env) plus this run's `RUN_NONCE_ENV`, if it has a nonce.

    The MCP servers Claude Code starts for the run inherit it; the
    `request_approval` tool presents it to the host (F-CL3b, C46). It is
    set per run, so the pinned MCP config stays unchanged (C51).

    Raises:
        ValueError: a non-empty nonce that is not 16-64 lowercase hex chars.
    """
    env = dict(base)
    if run_nonce:
        if not _RUN_NONCE_RE.fullmatch(run_nonce):
            raise ValueError("invalid run nonce")
        env[RUN_NONCE_ENV] = run_nonce
    return env


def check_run_isolation(env: Mapping[str, str]) -> None:
    """Refuse an env that would let a run load CLAUDE.md files or auto memory (F-CL1).

    Raises:
        RunIsolationError: naming the first variable missing or not at its fixed value.
    """
    for name, value in ISOLATION_ENV.items():
        if env.get(name) != value:
            raise RunIsolationError(f"{name} is not {value} in the run environment (F-CL1)")


@dataclass(frozen=True, slots=True, kw_only=True)
class ClaudeCliConfig:
    """Fixed paths of the run template.

    Raises (constructor):
        ValueError: a path is not absolute or a limit is not positive.
    """

    claude_bin: Path
    mcp_config: Path
    settings: Path
    workdir: Path
    run_timeout: float = DEFAULT_RUN_TIMEOUT
    max_output_bytes: int = MAX_OUTPUT_BYTES
    # Same servers, `claudia-kb --caller recap` (written by the host at start, M5b).
    recap_mcp_config: Path | None = None
    # The host's fixed rules (F-CL1), passed as `--append-system-prompt`; "" = none.
    system_append: str = ""

    def __post_init__(self) -> None:
        for name in ("claude_bin", "mcp_config", "settings", "workdir"):
            if not getattr(self, name).is_absolute():
                raise ValueError(f"{name} must be an absolute path")
        if self.recap_mcp_config is not None and not self.recap_mcp_config.is_absolute():
            raise ValueError("recap_mcp_config must be an absolute path")
        if self.run_timeout <= 0 or self.max_output_bytes <= 0:
            raise ValueError("run_timeout and max_output_bytes must be positive")


def _tool_list(tools: Sequence[str]) -> str:
    for tool in tools:
        # One name per entry: a comma or space would smuggle extra entries.
        if not _TOOL_RE.fullmatch(tool):
            raise ValueError("invalid tool name in a tool set")
    return ",".join(tools)


def system_append_text(host_rules: str, persona: str) -> str:
    """The `--append-system-prompt` text: host rules first, then the persona (F-CL2).

    The persona is tone only and always comes after the rules it must never
    override. A persona naming a forbidden flag spelling is dropped (logged)
    rather than failing the run on the argv check below.
    """
    if persona and any(flag in persona for flag in FORBIDDEN_FLAGS):
        _log.warning("persona not used (forbidden_flag)")
        persona = ""
    return "\n\n".join(part for part in (host_rules, persona) if part)


def build_run_argv(config: ClaudeCliConfig, request: RunRequest) -> list[str]:
    """The argv of one run, from the fixed template (C51). The prompt is not in it.

    `--tools` is a strict allow-list of built-ins (host-flow-3): a built-in it
    doesn't name does not exist in the run, so a new CLI tool can't slip past
    the tool sets or the hook matcher.

    Raises:
        ValidationError: the window id is not a canonical UUID.
        ValueError: a tool name is malformed, the set is empty, or a built-in
            is not also in the allowed list (or is an MCP tool).
    """
    window = parse_window_id(request.window_id)
    if not request.allowed_tools:
        raise ValueError("a run needs an allowed tool set")
    for tool in request.builtin_tools:
        if tool.startswith("mcp__") or tool not in request.allowed_tools:
            raise ValueError("a built-in tool must be in the allowed tool set")
    mcp_config = config.mcp_config
    if request.recap and config.recap_mcp_config is not None:
        mcp_config = config.recap_mcp_config
    argv = [
        str(config.claude_bin),
        "-p",
        "--output-format",
        "json",
        "--permission-mode",
        "auto",
        # Never the user's MCP config (C51): only the host file's servers.
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        "--settings",
        str(config.settings),
        # `=` form: a variadic option must not swallow the next argument.
        # An empty `--tools=` means no built-ins at all (fail closed).
        f"--tools={_tool_list(request.builtin_tools)}",
        f"--allowedTools={_tool_list(request.allowed_tools)}",
        f"--disallowedTools={_tool_list(request.disallowed_tools)}",
        "--resume" if request.resume else "--session-id",
        window,
    ]
    append = system_append_text(config.system_append, request.persona)
    if append:
        # `=` form: a fixed host text, never read as another option.
        argv.append(f"--append-system-prompt={append}")
    if any(flag in arg for arg in argv for flag in FORBIDDEN_FLAGS):
        raise ValueError("forbidden flag in run argv")  # unreachable by construction
    return argv


def parse_run_output(raw: bytes, exit_code: int | None) -> RunOutcome:
    """Parse `--output-format json` output; anything unexpected is an error outcome."""
    try:
        data = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError, RecursionError):
        data = None
    if not isinstance(data, dict):
        return RunOutcome(exit_code=exit_code, is_error=True)
    result = data.get("result")
    denials = data.get("permission_denials")
    expires = data.get("credential_expires_at")
    return RunOutcome(
        exit_code=exit_code,
        result_text=result if isinstance(result, str) else None,
        is_error=data.get("is_error") is not False or exit_code != 0,
        permission_denials=len(denials) if isinstance(denials, list) else 0,
        credential_expires_at=expires if isinstance(expires, str) and len(expires) <= 64 else None,
    )


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(pgid: int, sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, sig)


def _unreaped(pidfd: int) -> bool:
    """True while our child behind `pidfd` is running or a zombie (its pid is still taken)."""
    try:
        os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except OSError:  # ChildProcessError: already reaped; its pgid may be reused
        return False
    return True


def _bounded_wait(proc: subprocess.Popen[bytes]) -> None:
    """Reap a killed child, but never block the caller for good (newcode-4)."""
    try:
        proc.wait(timeout=LEADER_REAP_SECONDS)
    except subprocess.TimeoutExpired:
        _log.error("run leader did not exit after SIGKILL: pid=%d", proc.pid)


def _proc_stat(proc_root: Path, name: str) -> tuple[int, int, int] | None:
    """`(pid, ppid, pgid)` from `/proc/<pid>/stat`; None if gone or unparsable."""
    try:
        raw = (proc_root / name / "stat").read_bytes()
    except OSError:
        return None
    # Field 2 (comm) may hold spaces and ')': the fixed fields follow the last ')'.
    _comm, sep, rest = raw.rpartition(b")")
    fields = rest.split()
    if not sep or len(fields) < 3:
        return None
    try:
        return int(name), int(fields[1]), int(fields[2])
    except ValueError:
        return None


def detached_descendant_groups(
    groups: Collection[int], *, proc_root: Path = PROC_ROOT
) -> tuple[int, ...]:
    """Process groups of live descendants of `groups`' members that sit in another group.

    Catches work a run detached with `setsid` (host-flow-5) while its parent
    chain is still alive. Best effort: a process whose parent already exited
    was re-parented away and can't be linked to the run any more (documented;
    verified at deploy). Never returns the caller's own group or groups <= 1.
    """
    tracked = set(groups)
    if not tracked:
        return ()
    try:
        names = os.listdir(proc_root)
    except OSError:
        return ()
    table = [
        entry
        for name in names[:MAX_PROC_ENTRIES]
        if name.isdigit() and (entry := _proc_stat(proc_root, name)) is not None
    ]
    children: dict[int, list[tuple[int, int]]] = {}
    for pid, ppid, pgid in table:
        children.setdefault(ppid, []).append((pid, pgid))
    frontier = [pid for pid, _ppid, pgid in table if pgid in tracked]
    seen = set(frontier)
    own = os.getpgrp()
    found: list[int] = []
    while frontier:
        for child, pgid in children.get(frontier.pop(), ()):
            if child in seen:
                continue
            seen.add(child)
            frontier.append(child)
            if pgid not in tracked and pgid > 1 and pgid != own and pgid not in found:
                found.append(pgid)
    return tuple(found)


# --- per-run cgroups (host-flow-5, ADR 0039) ----------------------------------------------


def delegated_cgroup_root(
    *, proc_self_cgroup: Path = PROC_SELF_CGROUP, cgroup_fs: Path = CGROUP_FS
) -> Path | None:
    """The host unit's delegated cgroup v2 directory, or None if runs can't get their own.

    Only when this process sits in the unit's `host` leaf (`Delegate=yes` +
    `DelegateSubgroup=host`) and the parent supports `cgroup.kill` and is
    writable: run cgroups are then siblings of the host, inside the unit
    (its limits and `KillMode=control-group` still cover them).
    """
    try:
        text = proc_self_cgroup.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    rel = next((line[3:] for line in text.splitlines() if line.startswith("0::")), None)
    if rel is None or not rel.startswith("/"):
        return None
    parts = rel.strip("/").split("/")
    # Kernel text, still checked: no traversal, no odd segments, never the cgroup root.
    if len(parts) < 2 or parts[-1] != HOST_SUBGROUP:
        return None
    if any(p in (".", "..") or not _CGROUP_SEG_RE.fullmatch(p) for p in parts):
        return None
    root = cgroup_fs.joinpath(*parts[:-1])
    if not (root / "cgroup.kill").is_file() or not os.access(root, os.W_OK):
        return None
    return root


class RunContainment(Protocol):
    """Puts each run in its own cgroup and kills everything in it (`/stop`, C58)."""

    def create(self, pid: int) -> Path:
        """Make the empty cgroup of the run whose first process is `pid`.

        Raises:
            OSError: it exists already or can't be made.
        """
        ...

    def join(self, cgroup: Path, pid: int) -> None:
        """Move `pid` into `cgroup` (its later children follow it there).

        Raises:
            OSError: the move failed.
        """
        ...

    def populated(self, cgroup: Path) -> bool:
        """True while any process (at any depth) is still in `cgroup`."""
        ...

    def kill(self, cgroup: Path) -> None:
        """SIGKILL every process in `cgroup`, however it detached; never raises."""
        ...

    def signal_all(self, cgroup: Path, sig: signal.Signals) -> None:
        """Send `sig` to every process now in `cgroup` (the graceful step); never raises."""
        ...

    def remove(self, cgroup: Path) -> bool:
        """Remove an empty `cgroup`; False if it is still populated or already gone."""
        ...


class RunCgroups:
    """`RunContainment` over cgroup v2 leaves `run-<pid>` under the delegated `root`.

    A `setsid` or double-forked job can't leave its cgroup by itself (only a
    write to another `cgroup.procs` moves it), so `cgroup.kill` reaches every
    background job a run started, even after its parent exited (host-flow-5).
    """

    def __init__(self, root: Path) -> None:
        self._root = root
        self._seq = itertools.count(1)

    def create(self, pid: int) -> Path:
        """See `RunContainment.create`."""
        # A sequence number too: a reused pid never meets a leftover cgroup.
        cgroup = self._root / f"run-{next(self._seq)}-{pid}"
        cgroup.mkdir(mode=0o755)  # FileExistsError: never reuse a leftover cgroup
        return cgroup

    def join(self, cgroup: Path, pid: int) -> None:
        """See `RunContainment.join`."""
        _write_control(cgroup / "cgroup.procs", f"{pid}\n")

    def populated(self, cgroup: Path) -> bool:
        """See `RunContainment.populated`."""
        try:
            events = (cgroup / "cgroup.events").read_text(encoding="ascii", errors="replace")
        except OSError:
            return False  # gone: nothing left in it
        return "populated 1" in events.splitlines()

    def kill(self, cgroup: Path) -> None:
        """See `RunContainment.kill`."""
        try:
            _write_control(cgroup / "cgroup.kill", "1\n")
        except OSError as exc:
            _log.error("cgroup kill failed (%s)", type(exc).__name__)

    def signal_all(self, cgroup: Path, sig: signal.Signals) -> None:
        """See `RunContainment.signal_all`."""
        try:
            listed = (cgroup / "cgroup.procs").read_text(encoding="ascii", errors="replace")
        except OSError:
            return
        # Only pids the kernel lists as members: never a pgid that may have been reused.
        for line in listed.split()[:MAX_PROC_ENTRIES]:
            if line.isdigit() and int(line) > 1:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(int(line), sig)

    def remove(self, cgroup: Path) -> bool:
        """See `RunContainment.remove`."""
        try:
            cgroup.rmdir()
        except OSError:
            return False
        return True


def _write_control(path: Path, value: str) -> None:
    # No O_CREAT: a cgroup control file always exists; a missing one is an error.
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.write(fd, value.encode("ascii"))
    finally:
        os.close(fd)


class CliClaudeRunner:
    """`ClaudeRunner` over `claude -p` child processes (one process group per run).

    Args:
        config: the template's fixed paths and limits.
        environ: source environment, filtered through `child_env` once here.
        containment: per-run cgroups (host-flow-5). With it a run that can't
            be placed in its own cgroup is refused, and `/stop`/`busy()` go by
            the cgroup; None (no delegated cgroup, tests) = process groups
            plus the `/proc` descendant sweep.

    Raises (constructor):
        RunIsolationError: the child env lacks the F-CL1 isolation variables.
    """

    def __init__(
        self,
        config: ClaudeCliConfig,
        environ: Mapping[str, str],
        *,
        containment: RunContainment | None = None,
    ) -> None:
        self._config = config
        self._env = child_env(environ)
        check_run_isolation(self._env)  # never a run that loads the owner's CLAUDE.md
        self._containment = containment
        self._lock = threading.Lock()
        # pgid -> True while its run is in progress; finished runs whose group
        # (or cgroup) still has members (dispatched work) stay until they die or /stop.
        self._groups: dict[int, bool] = {}
        self._cgroups: dict[int, Path] = {}  # pgid -> its run's cgroup
        # pgid -> pidfd of its leader while the run is in progress: signals the exact
        # process even if it left its cgroup, never a reused pid (newcode-4).
        self._pidfds: dict[int, int] = {}
        self._killed: set[int] = set()
        self._epoch = 0  # newest /stop generation seen (kill_all)

    def run(self, request: RunRequest) -> RunOutcome:
        """Run one turn (blocking); a spawn failure becomes an error outcome.

        Raises:
            ValidationError, ValueError: a malformed request (see `build_run_argv`).
        """
        argv = build_run_argv(self._config, request)
        env = run_env(self._env, request.run_nonce)
        with tempfile.TemporaryFile() as out:
            # Epoch check, spawn and pid registration under one lock shared with
            # kill_all (host-flow-2): a /stop either sees this group or this run
            # sees the stop and never starts.
            with self._lock:
                if request.generation < self._epoch:
                    _log.warning("run refused: a /stop happened after it was queued")
                    return RunOutcome(exit_code=None, killed=True)
                try:
                    proc = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, no shell
                        argv,
                        stdin=subprocess.PIPE,
                        stdout=out,
                        stderr=subprocess.DEVNULL,  # may echo content: never captured or logged
                        cwd=self._config.workdir,
                        env=env,
                        start_new_session=True,  # own process group for /stop (C58)
                        close_fds=True,
                    )
                except OSError as exc:
                    _log.error("claude could not start (%s)", type(exc).__name__)
                    return RunOutcome(exit_code=None, is_error=True)
                contained = self._contain(proc.pid)
                if contained:
                    self._groups[proc.pid] = True
                    self._track_leader(proc.pid)
            if not contained:
                self._abort(proc)
                return RunOutcome(exit_code=None, is_error=True)
            timed_out = self._feed_and_wait(proc, request.prompt)
            with self._lock:
                self._groups[proc.pid] = False
                self._untrack_leader(proc.pid)
                killed = proc.pid in self._killed
                self._killed.discard(proc.pid)
                self._forget_if_dead(proc.pid)
            out.seek(0)
            raw = out.read(self._config.max_output_bytes + 1)
        if killed or timed_out:
            return RunOutcome(exit_code=proc.returncode, killed=killed, timed_out=timed_out)
        if len(raw) > self._config.max_output_bytes:
            return RunOutcome(exit_code=proc.returncode, is_error=True)
        return parse_run_output(raw, proc.returncode)

    def _contain(self, pid: int) -> bool:
        """Put a fresh child in its own cgroup (caller holds the lock); False = refuse the run.

        Runs before the prompt is written: `claude -p` reads all of stdin
        before its first tool call, so nothing it starts can predate the move.
        """
        if self._containment is None:
            return True
        cgroup: Path | None = None
        try:
            cgroup = self._containment.create(pid)
            self._containment.join(cgroup, pid)
        except OSError as exc:
            # Fail closed: a run /stop could not fully reach must not start (C58).
            _log.error("run refused: no cgroup of its own (%s)", type(exc).__name__)
            if cgroup is not None:
                self._containment.kill(cgroup)
                self._containment.remove(cgroup)
            return False
        self._cgroups[pid] = cgroup
        return True

    def _track_leader(self, pid: int) -> None:
        """Open a pidfd on a fresh, unreaped child (caller holds the lock)."""
        try:
            self._pidfds[pid] = os.pidfd_open(pid)
        except OSError as exc:
            # Old kernel / seccomp: the cgroup and the pgid still reach it.
            _log.warning("no pidfd for a run leader (%s)", type(exc).__name__)

    def _untrack_leader(self, pid: int) -> None:
        """Close the leader's pidfd once its run is over (caller holds the lock)."""
        fd = self._pidfds.pop(pid, None)
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)

    def _kill_leader(self, pgid: int) -> None:
        """SIGKILL a run's leader and, while it is unreaped, its pgid (newcode-4).

        Covers a leader that moved out of its cgroup or a cgroup whose files
        can't be read. Under the lock, so the pidfd can't be closed meanwhile;
        the pgid can't be reused while the leader is unreaped (`waitid` WNOWAIT).
        """
        with self._lock:
            fd = self._pidfds.get(pgid)
            if fd is None:
                return
            with contextlib.suppress(OSError):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            if _unreaped(fd):
                _signal_group(pgid, signal.SIGKILL)

    @staticmethod
    def _abort(proc: subprocess.Popen[bytes]) -> None:
        """Kill a child that must not run (it never got its prompt)."""
        if proc.stdin is not None:
            with contextlib.suppress(OSError):
                proc.stdin.close()
        _signal_group(proc.pid, signal.SIGKILL)
        _bounded_wait(proc)

    def _alive(self, pgid: int) -> bool:
        """A run's work is alive: its cgroup is populated, or (no cgroup) its group has members."""
        cgroup = self._cgroups.get(pgid)
        if cgroup is not None and self._containment is not None:
            return self._containment.populated(cgroup)
        return _group_alive(pgid)

    def _forget_if_dead(self, pgid: int) -> None:
        """Drop a finished run whose work is gone (caller holds the lock); remove its cgroup."""
        if self._groups.get(pgid, False) or self._alive(pgid):
            return
        cgroup = self._cgroups.get(pgid)
        if cgroup is not None and self._containment is not None:
            if not self._containment.remove(cgroup):
                return  # still there: retried by busy() / kill_all
            del self._cgroups[pgid]
        self._groups.pop(pgid, None)

    def _feed_and_wait(self, proc: subprocess.Popen[bytes], prompt: str) -> bool:
        stdin: IO[bytes] | None = proc.stdin
        try:
            if stdin is not None:
                stdin.write(prompt.encode("utf-8", "replace"))
                stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            proc.wait(timeout=self._config.run_timeout)
        except subprocess.TimeoutExpired:
            _log.error("run exceeded %.0f s; killing its process group", self._config.run_timeout)
            with self._lock:
                cgroup = self._cgroups.get(proc.pid)
            if cgroup is None:
                self._terminate(proc.pid)
            else:
                self._terminate_cgroup(cgroup)  # its background jobs go with it
            self._kill_leader(proc.pid)  # even if it left its cgroup (newcode-4)
            _bounded_wait(proc)  # never hang the worker on an unkillable leader
            return True
        return False

    def kill_all(self, *, epoch: int | None = None) -> int:
        """Kill every tracked run (SIGTERM, then SIGKILL after 5 s); return the count.

        A run with a cgroup: every member gets SIGTERM and the grace period,
        then `cgroup.kill` takes everything left, detached background jobs
        included (host-flow-5). Without one: its process group and the groups of
        live descendants that left a run's group (`setsid`), as far as
        `/proc` still links them to it. A run still in progress is killed even
        if its cgroup reads as empty, and its leader gets SIGKILL through its
        pidfd plus its pgid (newcode-4). `epoch` (the new `/stop` generation)
        makes later spawns of older requests refuse.
        """
        with self._lock:
            if epoch is not None:
                self._epoch = max(self._epoch, epoch)
            # newcode-4: a run in progress is always killed, whatever its cgroup
            # says (an unreadable cgroup.events reads as "not populated").
            groups = [g for g, running in self._groups.items() if running or self._alive(g)]
            running = [g for g in groups if self._groups[g]]
            self._killed.update(running)
            cgroups = [self._cgroups[g] for g in groups if g in self._cgroups]
            # A plain group only while it has members: an empty pgid may be reused.
            plain = [g for g in groups if g not in self._cgroups and _group_alive(g)]
            strays = detached_descendant_groups(plain)
        for cgroup in cgroups:
            # Not killpg: once the leader's group is empty its pgid may be reused.
            self._terminate_cgroup(cgroup)
        for pgid in (*plain, *strays):
            self._terminate(pgid)
        for pgid in running:
            self._kill_leader(pgid)  # a leader that left its cgroup goes too
        with self._lock:
            for pgid in groups:
                self._forget_if_dead(pgid)
        return len(groups) + len(strays)

    def busy(self) -> bool:
        """True while a run is in progress or a finished run's (c)group still has members."""
        with self._lock:
            # Forget dead runs first: a pgid could later be reused by an unrelated process.
            for pgid in [g for g, running in self._groups.items() if not running]:
                self._forget_if_dead(pgid)
            return any(running or self._alive(g) for g, running in self._groups.items())

    def _terminate_cgroup(self, cgroup: Path) -> None:
        containment = self._containment
        if containment is None:
            return
        containment.signal_all(cgroup, signal.SIGTERM)
        deadline = time.monotonic() + KILL_GRACE_SECONDS
        while time.monotonic() < deadline and containment.populated(cgroup):
            time.sleep(0.05)
        # Always: a process forked during the grace period got no SIGTERM.
        containment.kill(cgroup)

    @staticmethod
    def _terminate(pgid: int) -> None:
        _signal_group(pgid, signal.SIGTERM)
        deadline = time.monotonic() + KILL_GRACE_SECONDS
        while time.monotonic() < deadline and _group_alive(pgid):
            time.sleep(0.05)
        if _group_alive(pgid):
            _signal_group(pgid, signal.SIGKILL)


class UuidWindowIds:
    """`WindowIds` from `uuid4` (canonical lowercase UUID, C51)."""

    def new_window_id(self) -> WindowId:
        """A fresh random window id."""
        return parse_window_id(str(uuid.uuid4()))


class ClaudeAgentsDirectory:
    """`PeerDirectory` over `claude agents --json` (V5); any failure -> None (interactive).

    Args:
        claude_bin: absolute path of the CLI.
        environ: source environment (filtered by `child_env`).
        workdir: cwd of the lookup.
        headless_kinds: `kind` values that mean "not owner-attached".
        timeout: seconds before a lookup gives up (then unknown -> interactive).

    Raises (constructor):
        ValueError: a non-positive timeout.
    """

    def __init__(
        self,
        claude_bin: Path,
        environ: Mapping[str, str],
        workdir: Path,
        *,
        headless_kinds: frozenset[str] = HEADLESS_KINDS,
        timeout: float = PEER_LOOKUP_TIMEOUT,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._argv = [str(claude_bin), "agents", "--json"]
        self._env = child_env(environ)
        self._workdir = workdir
        self._headless = headless_kinds
        self._timeout = timeout

    def lookup(self, target: str) -> PeerInfo | None:
        """The one live session named `target` (name, id or session id), else None."""
        try:
            done = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell
                self._argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                cwd=self._workdir,
                env=self._env,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            _log.warning("peer lookup failed (%s)", type(exc).__name__)
            return None
        if done.returncode != 0 or len(done.stdout) > MAX_OUTPUT_BYTES:
            return None
        return parse_agents(done.stdout, target, self._headless)


def parse_agents(raw: bytes, target: str, headless_kinds: frozenset[str]) -> PeerInfo | None:
    """Resolve `target` in `claude agents --json` output; ambiguous or malformed -> None."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if isinstance(data, dict):
        data = data.get("agents")
    if not isinstance(data, list):
        return None
    matches = [
        entry
        for entry in data
        if isinstance(entry, dict)
        and target in (entry.get("name"), entry.get("id"), entry.get("sessionId"))
    ]
    if len(matches) != 1:
        return None
    session, kind = matches[0].get("sessionId"), matches[0].get("kind")
    if not isinstance(session, str) or not session:
        return None
    return PeerInfo(session_id=session, interactive=kind not in headless_kinds)
