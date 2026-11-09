"""Test support for the Claudia host (units M4b, M5b): in-memory fakes of its ports and builders.

Fakes record calls so tests can assert what the host did (runs, replies,
cancels, alerts) without a real `claude` or admin API. `write_fake_claude`
writes a stand-in CLI script for runner tests: it records argv, env and
stdin and prints a fixed JSON result (never the real `claude`).
"""

from __future__ import annotations

import json
import stat
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia.approval_flow import ApprovalFlow, DenialRecorder
from preview_dashboard.application.claudia.audit import PeerAudit
from preview_dashboard.application.claudia.persona import PersonaLoader
from preview_dashboard.application.claudia.pings import ProgressPings
from preview_dashboard.application.claudia.runs import ClaudiaHost
from preview_dashboard.application.claudia.voice import VoiceComposer
from preview_dashboard.application.claudia.windows import WindowTracker
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    flagged_message_text,
    parse_window_id,
)
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.owner_messages import OwnerMessage, OwnerMessageId
from preview_dashboard.ports.claudia_host import (
    AuditValue,
    PeerInfo,
    RunOutcome,
    RunRefusedError,
    RunRequest,
    SendMessageCall,
    TranscriptSlice,
)
from preview_dashboard.ports.claudia_kb import KbBusyError
from preview_dashboard.ports.claudia_screen import ScreenHealth, ScreenResult, ScreenVerdict
from tests.fakes import FixedClock
from tests.owner_updates_support import ogg_opus

WINDOW_A = parse_window_id("11111111-1111-4111-8111-111111111111")
WINDOW_B = parse_window_id("22222222-2222-4222-8222-222222222222")


def message(text: str = "hola Claudia", n: int = 1, *, forwarded: bool = False) -> OwnerMessage:
    """An inbox message with a deterministic ULID id."""
    clock = FixedClock()
    return OwnerMessage(
        id=OwnerMessageId(f"{n:026d}"),
        update_id=n,
        telegram_message_id=n,
        text=text,
        received_at=clock.now(),
        is_forwarded=forwarded,
    )


class SeqWindowIds:
    """Hands out WINDOW_A, WINDOW_B, then fails (tests never need more)."""

    def __init__(self) -> None:
        self._ids = [WINDOW_A, WINDOW_B]

    def new_window_id(self) -> WindowId:
        return self._ids.pop(0)


@dataclass
class FakeAdmin:
    """`HostAdmin` recording every call; `refuse_replies` makes replies come back False."""

    inbox: list[OwnerMessage] = field(default_factory=list)
    handled: list[str] = field(default_factory=list)
    already_handled: set[str] = field(default_factory=set)
    replies: list[tuple[str, str | None]] = field(default_factory=list)
    cancelled_windows: list[str] = field(default_factory=list)
    health: list[str] = field(default_factory=list)
    refuse_replies: bool = False
    cancel_fails: bool = False

    def unhandled(self, wait: float) -> Sequence[OwnerMessage]:
        out, self.inbox = self.inbox, []
        return out

    def mark_handled(self, message_id: OwnerMessageId) -> bool:
        if message_id in self.already_handled:
            return False
        self.already_handled.add(message_id)
        self.handled.append(message_id)
        return True

    def send_reply(self, text: str, *, message_id: OwnerMessageId | None) -> bool:
        self.replies.append((text, message_id))
        return not self.refuse_replies

    def cancel_open_approvals(self, window_id: WindowId) -> list[str]:
        if self.cancel_fails:
            raise RuntimeError("admin down")
        self.cancelled_windows.append(window_id)
        return []

    def report_health(self, screen: str) -> None:
        self.health.append(screen)


@dataclass
class FakeScreen:
    """`Screen` returning a fixed verdict."""

    result: ScreenResult = field(default_factory=lambda: ScreenResult(verdict=ScreenVerdict.OK))
    state: ScreenHealth = ScreenHealth.OK
    seen: list[str] = field(default_factory=list)
    on_screen: object = None  # optional callable() run while screening (e.g. a /stop)

    def screen(self, message: OwnerMessage) -> ScreenResult:
        self.seen.append(message.id)
        if callable(self.on_screen):
            self.on_screen()
        return self.result

    def health(self) -> ScreenHealth:
        return self.state


@dataclass
class FakeRunner:
    """`ClaudeRunner` recording requests; `outcome` is returned for every run."""

    outcome: RunOutcome = field(
        default_factory=lambda: RunOutcome(exit_code=0, result_text="¡Hola! Claro que sí.")
    )
    requests: list[RunRequest] = field(default_factory=list)
    kills: int = 0
    epochs: list[int | None] = field(default_factory=list)
    is_busy: bool = False
    on_run: object = None  # optional callable(request) run during `run`

    def run(self, request: RunRequest) -> RunOutcome:
        self.requests.append(request)
        if callable(self.on_run):
            self.on_run(request)
        return self.outcome

    def kill_all(self, *, epoch: int | None = None) -> int:
        self.kills += 1
        self.epochs.append(epoch)
        return 1

    def busy(self) -> bool:
        return self.is_busy


@dataclass
class FakeTranscripts:
    """`TranscriptReader` serving prepared calls once per window."""

    calls: dict[str, list[SendMessageCall]] = field(default_factory=dict)
    complete: bool = True
    sizes: dict[str, int] = field(default_factory=dict)

    def offset(self, window_id: WindowId) -> int:
        return self.sizes.get(window_id, 0)

    def send_messages(self, window_id: WindowId, since: int) -> TranscriptSlice:
        calls = tuple(self.calls.pop(window_id, []))
        return TranscriptSlice(calls=calls, end_offset=since, complete=self.complete)


@dataclass
class FakePeers:
    """`PeerDirectory` over a dict (missing target -> None)."""

    peers: dict[str, PeerInfo] = field(default_factory=dict)

    def lookup(self, target: str) -> PeerInfo | None:
        return self.peers.get(target)


@dataclass
class FakeAuditLog:
    entries: list[dict[str, AuditValue]] = field(default_factory=list)

    def record(self, entry: Mapping[str, AuditValue]) -> None:
        self.entries.append(dict(entry))


@dataclass
class FakeAlerts:
    titles: list[str] = field(default_factory=list)

    def failed(self, title: str) -> None:
        self.titles.append(title)


@dataclass
class FakePreflight:
    refuse: bool = False
    checks: int = 0
    on_check: object = None  # optional callable() run inside the check (e.g. a /stop)

    def check(self) -> None:
        self.checks += 1
        if callable(self.on_check):
            self.on_check()
        if self.refuse:
            raise RunRefusedError("settings source sets disableAllHooks")


@dataclass
class FakeGate:
    """`RunGate` recording each run's window and covers; `active` while a run is open."""

    runs: list[tuple[str, tuple[ApprovalRequest, ...]]] = field(default_factory=list)
    ended: int = 0
    active: bool = False

    def begin_run(self, window_id: WindowId, covers: Iterable[ApprovalRequest] = ()) -> None:
        self.runs.append((window_id, tuple(covers)))
        self.active = True

    def end_run(self) -> None:
        self.ended += 1
        self.active = False


@dataclass
class FakeKb:
    """`KbCommits`: `busy` makes commits raise `KbBusyError` (a gardener holds the KB)."""

    commits: list[str] = field(default_factory=list)
    fail: bool = False
    busy: bool = False
    restore_fails: bool = False
    restores: int = 0
    clean: bool = True
    clean_checks: int = 0

    def commit_run(self, message: str) -> str | None:
        if self.busy:
            raise KbBusyError("knowledge base is busy")
        if self.fail:
            raise OSError("git broke")
        self.commits.append(message)
        return "abc123"

    def restore_worktree(self) -> None:
        self.restores += 1
        if self.restore_fails:
            raise StorageUnavailableError("git checkout failed")

    def worktree_clean(self) -> bool:
        self.clean_checks += 1
        return self.clean


@dataclass
class MemoryHaltFlag:
    """`HaltFlag` in memory; `broken` makes set/clear fail like an unwritable state dir."""

    on: bool = False
    broken: bool = False

    def is_set(self) -> bool:
        return self.on

    def set(self) -> None:
        if self.broken:
            raise StorageUnavailableError("could not persist the KB halt")
        self.on = True

    def clear(self) -> None:
        if self.broken:
            raise StorageUnavailableError("could not clear the KB halt")
        self.on = False


@dataclass
class FakeVoiceAdmin:
    sent: list[tuple[str, bytes, str | None]] = field(default_factory=list)
    refuse: bool = False

    def send_voice(self, text: str, audio: bytes, *, message_id: OwnerMessageId | None) -> bool:
        self.sent.append((text, audio, message_id))
        return not self.refuse


@dataclass
class FakeApprovalAdmin:
    """`ApprovalAdmin` over one in-memory request at a time.

    `decisions` are the states successive `get_approval` calls move the
    request to (TAPPED, APPROVED, DENIED, EXPIRED, CANCELLED);
    `consume_result` overrides a successful consume.
    """

    clock: FixedClock
    decisions: list[ApprovalState] = field(default_factory=list)
    consume_result: str = "consumed"
    create_error: Exception | None = None
    get_error: Exception | None = None
    created: list[ApprovalRequest] = field(default_factory=list)
    consumed: list[str] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)
    polls: int = 0
    on_poll: object = None  # optional callable() run inside every get_approval
    current: ApprovalRequest | None = None

    def request_approval(
        self,
        *,
        window_id: WindowId,
        kind: ApprovalKind,
        action_text: str | None,
        action_kind: ActionKind | None,
        action_target: str | None,
        message_id: OwnerMessageId | None,
    ) -> ApprovalRequest:
        if self.create_error is not None:
            raise self.create_error
        if kind is ApprovalKind.FLAGGED_MESSAGE:
            assert action_text is None and message_id is not None
            action_text = flagged_message_text(message_id, "do the thing")
        assert action_text is not None
        request = ApprovalRequest.new(
            id=ApprovalId(f"{len(self.created) + 1:026d}"),
            window_id=window_id,
            kind=kind,
            action_text=action_text,
            now=self.clock.now(),
            action_kind=action_kind,
            action_target=action_target,
            message_id=message_id,
        )
        self.created.append(request)
        self.current = request
        return request

    def get_approval(self, approval_id: ApprovalId, wait: float = 0) -> ApprovalRequest:
        self.polls += 1
        if callable(self.on_poll):
            self.on_poll()
        if self.get_error is not None:
            raise self.get_error
        assert self.current is not None and self.current.id == approval_id
        if self.decisions:
            self.current = _step(self.current, self.decisions.pop(0), self.clock.now())
        else:
            # Nobody decided: the long-poll ran its full length.
            self.clock.advance(timedelta(seconds=wait))
        return self.current

    def consume_approval(self, approval_id: ApprovalId) -> tuple[str, ApprovalRequest | None]:
        assert self.current is not None
        self.consumed.append(approval_id)
        if self.consume_result != "consumed":
            return self.consume_result, self.current
        self.current = self.current.consumed(max(self.clock.now(), self.current.updated_at))
        return "consumed", self.current

    def cancel_approval(self, approval_id: ApprovalId) -> str:
        self.cancelled.append(approval_id)
        return "cancelled"


def _step(request: ApprovalRequest, state: ApprovalState, now: datetime) -> ApprovalRequest:
    now = max(now, request.updated_at)  # the fixed clock may not have moved since the last step
    if state is ApprovalState.TAPPED:
        return request.tapped(now)
    if state is ApprovalState.APPROVED:
        tapped = request if request.state is ApprovalState.TAPPED else request.tapped(now)
        return tapped.approved(max(now, tapped.updated_at))
    if state is ApprovalState.DENIED:
        return request.denied(now)
    if state is ApprovalState.EXPIRED:
        return request.expired(request.expires_at)
    if state is ApprovalState.CANCELLED:
        return request.cancelled(now)
    raise AssertionError(f"unsupported step {state}")


@dataclass
class HostRig:
    """A `ClaudiaHost` with all fakes exposed."""

    host: ClaudiaHost
    admin: FakeAdmin
    screen: FakeScreen
    runner: FakeRunner
    windows: WindowTracker
    transcripts: FakeTranscripts
    peers: FakePeers
    log: FakeAuditLog
    alerts: FakeAlerts
    preflight: FakePreflight
    clock: FixedClock
    gate: FakeGate
    kb: FakeKb
    approvals: FakeApprovalAdmin
    denials: DenialRecorder
    flow: ApprovalFlow
    voice_admin: FakeVoiceAdmin


def host_rig(
    *,
    voice: VoiceComposer | None = None,
    persona: PersonaLoader | None = None,
    pings: ProgressPings | None = None,
    **overrides: object,
) -> HostRig:
    """Build a host over fakes; keyword overrides replace a fake (same names as fields)."""
    clock = overrides.pop("clock", None) or FixedClock()
    assert isinstance(clock, FixedClock)
    parts: dict[str, object] = {
        "admin": FakeAdmin(),
        "screen": FakeScreen(),
        "runner": FakeRunner(),
        "transcripts": FakeTranscripts(),
        "peers": FakePeers(),
        "log": FakeAuditLog(),
        "alerts": FakeAlerts(),
        "preflight": FakePreflight(),
        "gate": FakeGate(),
        "kb": FakeKb(),
        "approvals": FakeApprovalAdmin(clock),
        "voice_admin": FakeVoiceAdmin(),
    }
    halt_flag = overrides.pop("halt_flag", None)
    parts.update(overrides)
    windows = WindowTracker(clock, SeqWindowIds(), kb_halt=halt_flag)  # type: ignore[arg-type]
    audit = PeerAudit(parts["transcripts"], parts["peers"], parts["log"], clock)  # type: ignore[arg-type]
    denials = DenialRecorder(parts["log"])  # type: ignore[arg-type]
    flow = ApprovalFlow(
        admin=parts["approvals"],  # type: ignore[arg-type]
        denials=denials,
        alerts=parts["alerts"],  # type: ignore[arg-type]
        clock=clock,
        record=audit.record_approval,
        pause=lambda _seconds: None,
    )
    host = ClaudiaHost(
        admin=parts["admin"],  # type: ignore[arg-type]
        screen=parts["screen"],  # type: ignore[arg-type]
        runner=parts["runner"],  # type: ignore[arg-type]
        windows=windows,
        audit=audit,
        preflight=parts["preflight"],  # type: ignore[arg-type]
        alerts=parts["alerts"],  # type: ignore[arg-type]
        clock=clock,
        nonce=lambda: "n0nce",
        gate=parts["gate"],  # type: ignore[arg-type]
        flow=flow,
        kb=parts["kb"],  # type: ignore[arg-type]
        voice=voice,
        voice_admin=parts["voice_admin"],  # type: ignore[arg-type]
        persona=persona,
        pings=pings,
    )
    return HostRig(
        host=host,
        windows=windows,
        clock=clock,
        denials=denials,
        flow=flow,
        **parts,  # type: ignore[arg-type]
    )


@dataclass
class FakeTts:
    """`TextToSpeech` returning a small valid Ogg/Opus note; records what it spoke."""

    spoken: list[tuple[str, str]] = field(default_factory=list)
    fail: bool = False

    def synthesize(self, text: str, language: str) -> bytes:
        if self.fail:
            raise StorageUnavailableError("speech synthesis failed")
        self.spoken.append((text, language))
        return ogg_opus(2.0)


def fake_voice(tts: FakeTts | None = None) -> VoiceComposer:
    """A real `VoiceComposer` (real secret scanner) over `FakeTts`."""
    return VoiceComposer(tts=tts or FakeTts(), scanner=RegexSecretScanner())


def hook_deny(window_id: str, kind: str, target: str | None) -> dict[str, AuditValue]:
    """The audit entry `HookGate` writes for a deny (kind + target only)."""
    return {
        "event": "hook_deny",
        "at": "2026-11-09T00:00:00+00:00",
        "window": window_id,
        "action_kind": kind,
        "action_target": target,
    }


# --- fake CLI for runner tests ------------------------------------------------------------

FAKE_RESULT = {
    "type": "result",
    "subtype": "success",
    "is_error": False,
    "result": "hecho",
    "session_id": "x",
    "permission_denials": [],
}


def write_fake_claude(
    directory: Path, *, sleep: float = 0.0, spawn_child: bool = False, detach_child: bool = False
) -> Path:
    """A stand-in `claude`: records argv/env/stdin to `<cwd>/record.json`, prints a result.

    `sleep` keeps it running (kill tests); `spawn_child` leaves a child in its
    process group (dispatched-work tests); `detach_child` starts a child in
    its own session (`setsid`, host-flow-5) and writes its pid to `<cwd>/child.pid`.
    """
    script = directory / "fake-claude"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, subprocess, sys, time\n"
        "data = sys.stdin.read() if '-p' in sys.argv else ''\n"
        "with open('record.json', 'w') as fh:\n"
        "    json.dump({'argv': sys.argv, 'env': dict(os.environ), 'stdin': data,\n"
        "               'pgid': os.getpgid(0), 'pid': os.getpid()}, fh)\n"
        f"if {spawn_child!r}:\n"
        f"    subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"if {detach_child!r}:\n"
        "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],\n"
        "                             start_new_session=True)\n"
        "    with open('child.pid.tmp', 'w') as fh:\n"
        "        fh.write(str(child.pid))\n"
        "    os.rename('child.pid.tmp', 'child.pid')\n"
        f"time.sleep({sleep!r})\n"
        f"print(json.dumps({FAKE_RESULT!r}))\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def read_record(workdir: Path) -> dict[str, object]:
    """What the fake CLI recorded."""
    data = json.loads((workdir / "record.json").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data
