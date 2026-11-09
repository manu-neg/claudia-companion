"""S-C3 fixes (unit F-C3-2): KB locks, the persisted KB halt, run kills, approval budgets.

- fixcheck-a-1: the gardener's run group gets SIGTERM, a ≤ 5 s grace, then
  SIGKILL; a stale `.git/index.lock` is removed only under the exclusive run
  lock + `.lock`.
- fixcheck-a-2 / newcode-2: the host restore runs under the KB locks; a
  "busy" commit is retried later, never restored alongside the holder.
- fixcheck-a-3: the note/size cap check runs under the same lock as the write.
- newcode-1: the KB halt is persisted, read at start, and `/new` lifts it
  only after a restore that leaves `*.md` clean.
- newcode-4: `/stop` kills a run in progress even when its cgroup can't be
  read, through the leader's pidfd; the final wait is bounded.
- newcode-7: refused approval attempts never use the created budget; per-window
  budgets; `/stop` (cancel-open of a window) resets that window's budgets.
"""

from __future__ import annotations

import fcntl
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.adapters import claude_cli
from preview_dashboard.adapters.claude_cli import ClaudeCliConfig, CliClaudeRunner
from preview_dashboard.adapters.claudia_halt_flag import FileHaltFlag
from preview_dashboard.adapters.gardener_runner import ClaudeGardenModel
from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.approvals import (
    APPROVAL_CREATE_BUDGET,
    APPROVAL_REFUSED_BUDGET,
    APPROVAL_WINDOW_CREATE_BUDGET,
    APPROVAL_WINDOW_REFUSED_BUDGET,
    ApprovalCreateCommand,
    ApprovalService,
    SlidingBudget,
)
from preview_dashboard.application.claudia.kb import MAX_NOTES, KbRefusedError, KbService
from preview_dashboard.application.claudia.runs import (
    KB_COMMIT_FAILED_ALERT,
    KB_HALTED_TEXT,
    KB_STILL_HALTED_TEXT,
    NEW_WINDOW_TEXT,
    TOOL_SETS,
    ToolSetName,
)
from preview_dashboard.application.claudia.windows import HostCommand, WindowTracker
from preview_dashboard.domain.approvals import ApprovalRequest
from preview_dashboard.domain.errors import (
    ConflictError,
    RateLimitedError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.ports.claudia_host import RunOutcome, RunRequest
from preview_dashboard.ports.claudia_kb import KbBusyError, KbStats
from tests.claudia_admin_support import approval_body
from tests.claudia_host_support import (
    WINDOW_A,
    FakeKb,
    MemoryHaltFlag,
    SeqWindowIds,
    host_rig,
    message,
    write_fake_claude,
)
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryApprovalStore,
    InMemoryOwnerMessageStore,
    SequentialIdGenerator,
)

pytestmark = pytest.mark.security

NOTE = "---\ntags: [x]\nupdated: 2026-11-09\nsources: [dashboard:abc@rev1]\n---\n{body}\n"
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture
def kb(tmp_path: Path) -> Path:
    root = tmp_path / "kb"
    root.mkdir(mode=0o750)
    return root


def _seeded(root: Path) -> FsKbStore:
    store = FsKbStore(root)
    store.write("now.md", b"Now.\n")
    store.write("topics/c/a.md", NOTE.format(body="A.").encode())
    store.commit("seed")
    return store


def _flock_free(root: Path, name: str) -> bool:
    fd = os.open(root / name, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


def _exe(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(stat.S_IRWXU)
    return path


# --- fixcheck-a-1: gardener kill order and the stale index.lock -----------------------------

# A stand-in `claude` whose child holds `.git/index.lock` like git mid-commit.
# `cleanup`: the child removes it on SIGTERM (what git does); else it ignores SIGTERM.
_CHILD = """\
import os, signal, sys, time
lock = os.path.join(sys.argv[1], '.git', 'index.lock')
open(lock, 'w').close()
def term(_s, _f):
    os.unlink(lock)
    open(sys.argv[2], 'w').close()
    sys.exit(0)
signal.signal(signal.SIGTERM, term if sys.argv[3] == '1' else signal.SIG_IGN)
open(sys.argv[2] + '.ready', 'w').close()
time.sleep(60)
"""


def _gardener_claude(tmp_path: Path, kb_root: Path, *, cleanup: bool) -> tuple[Path, Path]:
    child = tmp_path / "child.py"
    child.write_text(_CHILD, encoding="utf-8")
    marker = tmp_path / "terminated"
    script = _exe(
        tmp_path / "claude",
        f"#!{sys.executable}\n"
        "import os, subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, {str(child)!r}, {str(kb_root)!r}, "
        f"{str(marker)!r}, {'1' if cleanup else '0'!r}])\n"
        f"while not os.path.exists({str(marker) + '.ready'!r}):\n"
        "    time.sleep(0.01)\n"
        'print(\'{"type":"result","is_error":false,"result":"ok"}\')\n',
    )
    return script, marker


@needs_git
def test_fixcheck_a1_gardener_sigterms_the_group_so_a_commit_can_clean_up(
    tmp_path: Path, kb: Path
) -> None:
    _seeded(kb)
    script, marker = _gardener_claude(tmp_path, kb, cleanup=True)
    model = ClaudeGardenModel(script, kb, "SYS", {"PATH": "/usr/bin:/bin"}, timeout_s=20)
    assert model.run("prompt").ok
    assert marker.exists()  # the child got SIGTERM, not an instant SIGKILL
    assert not (kb / ".git" / "index.lock").exists()


@needs_git
def test_fixcheck_a1_kill_during_commit_leaves_no_lasting_index_lock(
    tmp_path: Path, kb: Path
) -> None:
    """A child that ignores SIGTERM mid-commit is SIGKILLed; the next locked step clears it."""
    store = _seeded(kb)
    gardener_store = FsKbStore(kb, exempt_run_lock=True)
    script, marker = _gardener_claude(tmp_path, kb, cleanup=False)
    model = ClaudeGardenModel(
        script, kb, "SYS", {"PATH": "/usr/bin:/bin"}, timeout_s=20, kill_grace_s=0.5
    )
    with gardener_store.exclusive_run():
        started = time.monotonic()
        assert model.run("prompt").ok
        assert time.monotonic() - started < 5  # bounded grace, then SIGKILL
        assert not marker.exists()  # it never ran its cleanup
        assert (kb / ".git" / "index.lock").exists()  # stale: its owner is dead
        (kb / "now.md").write_text("Now, later.\n")
        # Holding the exclusive run lock + `.lock`: the stale lock goes, the commit works.
        assert gardener_store.commit("gardener: run") is not None
    assert not (kb / ".git" / "index.lock").exists()
    assert store.read("now.md") == b"Now, later.\n"


@needs_git
def test_fixcheck_a1_index_lock_is_kept_without_the_exclusive_run_lock(kb: Path) -> None:
    store = _seeded(kb)
    (kb / ".git" / "index.lock").write_text("")
    (kb / "now.md").write_text("Changed.\n")
    with pytest.raises(StorageUnavailableError):
        store.commit("claudia: run")  # a live git may own it: never removed here
    assert (kb / ".git" / "index.lock").exists()


def test_fixcheck_a1_grace_is_bounded(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="kill_grace_s"):
        ClaudeGardenModel(tmp_path / "c", tmp_path, "S", {}, kill_grace_s=6)


# --- fixcheck-a-2 / newcode-2: restore under the locks; busy = retry -------------------------


@needs_git
def test_fixcheck_a2_restore_waits_for_a_gardener_and_never_wipes_its_work(kb: Path) -> None:
    _seeded(kb)
    gardener_store = FsKbStore(kb, exempt_run_lock=True)
    host = KbService(
        FsKbStore(kb, lock_wait_s=0.2),
        RegexSecretScanner(),
        worktree=GitKbHistory(kb),
        restore_wait_s=0.2,
    )
    with gardener_store.exclusive_run():
        (kb / "topics/c/a.md").write_text(NOTE.format(body="Gardener edit."))
        with pytest.raises(KbBusyError):
            host.restore_worktree()
        with pytest.raises(KbBusyError):
            host.worktree_clean()
    assert (kb / "topics/c/a.md").read_text() == NOTE.format(body="Gardener edit.")
    host.restore_worktree()  # the lock is free again: now it runs
    assert (kb / "topics/c/a.md").read_text() == NOTE.format(body="A.")
    assert host.worktree_clean()


@needs_git
def test_fixcheck_a2_restore_holds_the_kb_lock(kb: Path) -> None:
    store = _seeded(kb)
    seen: list[bool] = []
    store.run_locked(lambda: seen.append(_flock_free(kb, ".lock")))
    assert seen == [False]


def test_newcode2_busy_commit_is_retried_not_restored() -> None:
    rig = host_rig(kb=FakeKb(busy=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.kb.restores == 0 and rig.alerts.titles == []
    assert not rig.windows.kb_halted
    rig.host.tick()  # still busy: nothing happens
    assert rig.kb.commits == [] and rig.kb.restores == 0
    rig.kb.busy = False
    rig.host.tick()
    assert rig.kb.commits == [f"claudia: window {WINDOW_A}"]
    rig.host.tick()
    assert len(rig.kb.commits) == 1  # done once


def test_newcode2_pending_commit_is_retried_before_the_next_run() -> None:
    rig = host_rig(kb=FakeKb(busy=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    rig.kb.busy = False
    rig.host.handle_message(message("again", 2), generation=0)
    # The first run's commit, then the second run's own one.
    assert rig.kb.commits == [f"claudia: window {WINDOW_A}"] * 2


def test_newcode2_failed_locked_restore_halts() -> None:
    rig = host_rig(kb=FakeKb(fail=True, restore_fails=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.windows.kb_halted


# --- fixcheck-a-3: cap check and write under one lock hold -----------------------------------


def test_fixcheck_a3_cap_check_runs_under_the_write_lock(kb: Path) -> None:
    store = FsKbStore(kb)
    held: list[bool] = []

    def admit(size: int | None, stats: KbStats) -> None:
        held.append(not _flock_free(kb, ".lock"))

    store.write_admitted("now.md", b"x\n", admit)
    assert held == [True]
    assert store.read("now.md") == b"x\n"


def test_fixcheck_a3_refused_admit_writes_nothing(kb: Path) -> None:
    store = FsKbStore(kb)

    def refuse(size: int | None, stats: KbStats) -> None:
        raise KbRefusedError("full")

    with pytest.raises(KbRefusedError):
        store.write_admitted("now.md", b"x\n", refuse)
    assert store.read("now.md") is None


def test_fixcheck_a3_service_note_cap_is_enforced_inside_the_store(kb: Path) -> None:
    class Full(FsKbStore):
        def stats(self) -> KbStats:
            return KbStats(MAX_NOTES, 0)

    svc = KbService(Full(kb), RegexSecretScanner())
    with pytest.raises(KbRefusedError, match="full"):
        svc.write("topics/c/new.md", NOTE.format(body="New."), caller="claudia")


# --- newcode-1: persisted halt, /new only on a clean tree -------------------------------------


def test_newcode1_halt_is_persisted_across_a_restart(tmp_path: Path) -> None:
    flag = FileHaltFlag(tmp_path / "kb-halted")
    rig = host_rig(kb=FakeKb(fail=True, restore_fails=True), halt_flag=flag)
    rig.host.handle_message(message("hola", 1), generation=0)
    assert (tmp_path / "kb-halted").exists()
    # A restarted host reads the flag: it starts halted, and messages get the fixed reply.
    restarted = host_rig(kb=FakeKb(), halt_flag=FileHaltFlag(tmp_path / "kb-halted"))
    assert restarted.windows.kb_halted
    restarted.host.handle_message(message("hola", 2), generation=0)
    assert restarted.admin.replies == [(KB_HALTED_TEXT, message("hola", 2).id)]
    assert restarted.runner.requests == []


def test_newcode1_new_keeps_the_halt_while_the_tree_is_dirty(tmp_path: Path) -> None:
    flag = FileHaltFlag(tmp_path / "kb-halted")
    flag.set()
    rig = host_rig(kb=FakeKb(clean=False), halt_flag=flag)
    rig.host.command(HostCommand.NEW, message("/new", 1).id)
    assert rig.kb.restores == 1 and rig.kb.clean_checks == 1
    assert rig.windows.kb_halted and flag.is_set()
    assert rig.admin.replies[-1][0] == KB_STILL_HALTED_TEXT
    rig.kb.clean = True
    rig.host.command(HostCommand.NEW, message("/new", 2).id)
    assert not rig.windows.kb_halted and not flag.is_set()
    assert rig.admin.replies[-1][0] == NEW_WINDOW_TEXT


def test_newcode1_flag_that_cannot_be_cleared_keeps_the_halt() -> None:
    flag = MemoryHaltFlag(on=True, broken=True)
    rig = host_rig(kb=FakeKb(), halt_flag=flag)
    rig.host.command(HostCommand.NEW, message("/new", 1).id)
    assert rig.windows.kb_halted
    assert rig.admin.replies[-1][0] == KB_STILL_HALTED_TEXT


def test_newcode1_unreadable_flag_counts_as_halted(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("")
    flag = FileHaltFlag(tmp_path / "file" / "kb-halted")  # ENOTDIR: state unknown
    assert flag.is_set()
    assert WindowTracker(FixedClock(), SeqWindowIds(), kb_halt=flag).kb_halted


def test_newcode1_halted_reply_does_not_say_send_new_first() -> None:
    assert KB_HALTED_TEXT.index("fixed") < KB_HALTED_TEXT.index("/new")


@needs_git
def test_newcode1_new_restores_the_real_tree_then_lifts_the_halt(tmp_path: Path, kb: Path) -> None:
    _seeded(kb)
    svc = KbService(FsKbStore(kb), RegexSecretScanner(), worktree=GitKbHistory(kb))
    (kb / "topics/c/planted.md").write_text(NOTE.format(body="Unverified."))
    flag = FileHaltFlag(tmp_path / "kb-halted")
    flag.set()
    rig = host_rig(kb=svc, halt_flag=flag)
    rig.host.command(HostCommand.NEW, message("/new", 1).id)
    assert not (kb / "topics/c/planted.md").exists()
    assert not rig.windows.kb_halted and not flag.is_set()


def test_newcode1_commit_failure_with_working_restore_does_not_halt() -> None:
    rig = host_rig(kb=FakeKb(fail=True), halt_flag=MemoryHaltFlag())
    rig.host.handle_message(message("hola", 1), generation=0)
    assert not rig.windows.kb_halted
    assert rig.alerts.titles == [KB_COMMIT_FAILED_ALERT]


# --- newcode-4: /stop and the timeout with an unreadable cgroup ------------------------------


@dataclass
class BrokenContainment:
    """A cgroup whose files can't be read or written: reads as empty, kills do nothing."""

    root: Path
    killed: list[Path] = field(default_factory=list)

    def create(self, pid: int) -> Path:
        path = self.root / f"run-{pid}"
        path.mkdir()
        return path

    def join(self, cgroup: Path, pid: int) -> None:
        del cgroup, pid

    def populated(self, cgroup: Path) -> bool:
        return False  # what an OSError on cgroup.events reads as

    def kill(self, cgroup: Path) -> None:
        self.killed.append(cgroup)  # the write "failed": nothing is killed

    def signal_all(self, cgroup: Path, sig: signal.Signals) -> None:
        del cgroup, sig

    def remove(self, cgroup: Path) -> bool:
        return False


def _broken_runner(tmp_path: Path, *, timeout: float = 60) -> tuple[CliClaudeRunner, Path]:
    workdir = tmp_path / "work"
    workdir.mkdir()
    cg = tmp_path / "cg"
    cg.mkdir()
    config = ClaudeCliConfig(
        claude_bin=write_fake_claude(tmp_path, sleep=60.0),
        mcp_config=tmp_path / "mcp.json",
        settings=tmp_path / "s.json",
        workdir=workdir,
        run_timeout=timeout,
    )
    runner = CliClaudeRunner(config, {"PATH": "/usr/bin:/bin"}, containment=BrokenContainment(cg))
    return runner, workdir


def _request() -> RunRequest:
    tools = TOOL_SETS[ToolSetName.FULL]
    return RunRequest(
        window_id=WINDOW_A,
        resume=False,
        prompt="hola",
        allowed_tools=tools.allowed,
        disallowed_tools=tools.disallowed,
        builtin_tools=tools.builtins,
    )


def test_newcode4_stop_kills_a_running_run_whose_cgroup_read_fails(tmp_path: Path) -> None:
    runner, workdir = _broken_runner(tmp_path)
    outcomes: list[RunOutcome] = []
    worker = threading.Thread(target=lambda: outcomes.append(runner.run(_request())))
    worker.start()
    deadline = time.monotonic() + 10
    while not (workdir / "record.json").exists():
        assert time.monotonic() < deadline and worker.is_alive()
        time.sleep(0.02)
    assert runner.kill_all(epoch=1) == 1  # counted although its cgroup "is empty"
    worker.join(15)
    assert not worker.is_alive()
    assert outcomes[0].killed  # the leader got SIGKILL through its pidfd


def test_newcode4_timeout_kills_the_leader_when_the_cgroup_kill_fails(tmp_path: Path) -> None:
    runner, _ = _broken_runner(tmp_path, timeout=0.5)
    started = time.monotonic()
    assert runner.run(_request()).timed_out
    assert time.monotonic() - started < 15


def test_newcode4_final_wait_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(claude_cli, "LEADER_REAP_SECONDS", 0.1)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        started = time.monotonic()
        claude_cli._bounded_wait(proc)  # a leader that would not die: give up, don't hang
        assert time.monotonic() - started < 5
    finally:
        proc.kill()
        proc.wait()


# --- newcode-7: approval budgets -------------------------------------------------------------


class _Prompts:
    def prompt(self, request: ApprovalRequest) -> None:
        del request


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _service(monotonic: _Clock | None = None) -> ApprovalService:
    return ApprovalService(
        store=InMemoryApprovalStore(),
        messages=InMemoryOwnerMessageStore(),
        clock=FixedClock(),
        ids=SequentialIdGenerator(),
        scanner=FakeContentScanner(),
        prompts=_Prompts(),
        monotonic=monotonic or _Clock(),
    )


def _window(n: int) -> str:
    return f"{n:08d}-e89b-42d3-a456-426614174000"


def _command(window: str, **overrides: str) -> ApprovalCreateCommand:
    body = approval_body(window_id=window, **overrides)
    return ApprovalCreateCommand(
        window_id=body["window_id"],
        kind=body["kind"],
        action_text=body["action_text"],
        action_kind=body["action_kind"],
        action_target=body["action_target"],
    )


def _create_and_close(service: ApprovalService, window: str) -> None:
    request = service.create(_command(window))
    service.cancel(request.id)


def test_newcode7_budget_not_consumed_by_refusals() -> None:
    service = _service()
    window = _window(1)
    for _ in range(APPROVAL_WINDOW_REFUSED_BUDGET):
        with pytest.raises(ValidationError):
            service.create(_command(window, kind="bogus"))
    # Busy window refusals (one open request) don't count against it either.
    service.create(_command(window))
    with pytest.raises(RateLimitedError):
        service.create(_command(window))  # refused budget spent: no reason given
    service.cancel_open(window)
    for _ in range(APPROVAL_WINDOW_CREATE_BUDGET):
        _create_and_close(service, window)  # the full created budget is still there


def test_newcode7_refusals_past_their_budget_answer_rate_limited() -> None:
    service = _service()
    for n in range(APPROVAL_REFUSED_BUDGET):
        with pytest.raises(ValidationError):
            service.create(_command(_window(n % 9 + 10), kind="bogus"))
    with pytest.raises(RateLimitedError):
        service.create(_command(_window(99), kind="bogus"))
    _create_and_close(service, _window(99))  # a real request is not locked out


def test_newcode7_per_window_created_budget() -> None:
    service = _service()
    for _ in range(APPROVAL_WINDOW_CREATE_BUDGET):
        _create_and_close(service, _window(1))
    with pytest.raises(RateLimitedError):
        service.create(_command(_window(1)))
    _create_and_close(service, _window(2))  # another window still has its share


def test_newcode7_stop_resets_the_windows_budget_not_the_global_one() -> None:
    service = _service()
    for _ in range(APPROVAL_WINDOW_CREATE_BUDGET):
        _create_and_close(service, _window(1))
    service.cancel_open(_window(1))  # /stop
    for _ in range(APPROVAL_CREATE_BUDGET - APPROVAL_WINDOW_CREATE_BUDGET):
        _create_and_close(service, _window(1))
    service.cancel_open(_window(1))
    with pytest.raises(RateLimitedError):
        service.create(_command(_window(1)))  # the global hourly bound still holds


def test_newcode7_budget_frees_up_after_the_hour() -> None:
    clock = _Clock()
    service = _service(clock)
    for n in range(APPROVAL_CREATE_BUDGET):
        _create_and_close(service, _window(n % 2 + 1))
    with pytest.raises(RateLimitedError):
        service.create(_command(_window(3)))
    clock.now += timedelta(hours=1).total_seconds() + 1
    _create_and_close(service, _window(3))


def test_newcode7_open_cap_refusal_uses_the_refused_budget() -> None:
    service = _service()
    for n in range(3):
        service.create(_command(_window(n + 1)))
    with pytest.raises(ConflictError):
        service.create(_command(_window(4)))
    for n in range(3):
        service.cancel_open(_window(n + 1))
    for _ in range(APPROVAL_WINDOW_CREATE_BUDGET):
        _create_and_close(service, _window(4))


def test_newcode7_sliding_budget_room_and_charge_are_separate() -> None:
    clock = _Clock()
    budget = SlidingBudget(limit=1, window=timedelta(seconds=10), monotonic=clock)
    assert budget.has_room() and budget.has_room()  # checking costs nothing
    budget.charge()
    assert not budget.has_room()
    budget.reset()
    assert budget.has_room()
    with pytest.raises(ValueError):
        SlidingBudget(limit=0, window=timedelta(seconds=1))
