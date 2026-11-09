"""C58: `/stop` kill switch, exact-match commands, each inbox message processed once.

`/stop` kills every run's process group (real child processes here,
started by a stand-in CLI, never the real `claude`), cancels the window's
open approvals over A1's cancel route, drops queued messages and sends no
reply for the killed run; commands work while a run is busy and only on
an exact whole-message match; a message already claimed is never run.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters.claude_cli import (
    ClaudeCliConfig,
    CliClaudeRunner,
    detached_descendant_groups,
)
from preview_dashboard.adapters.claudia_admin_client import (
    ALERT_PREFIX,
    ClaudiaAdminClient,
    ClaudiaAdminError,
    ReplyAlerts,
)
from preview_dashboard.application.claudia.runs import STOPPED_TEXT, TOOL_SETS, ToolSetName
from preview_dashboard.application.claudia.windows import HostCommand
from preview_dashboard.domain.owner_messages import OwnerMessageId
from preview_dashboard.interfaces.claudia.main import HostLoop
from preview_dashboard.ports.claudia_host import RunOutcome, RunRequest
from tests.claudia_host_support import (
    WINDOW_A,
    FakePreflight,
    FakeRunner,
    FakeScreen,
    HostRig,
    host_rig,
    message,
    read_record,
    write_fake_claude,
)

pytestmark = pytest.mark.security

TOKEN = b"claudia-token-" + b"abcdefghijklmnopqrstuvwxyz0123456789"


def test_c58_stop_kills_runs_and_cancels_approvals() -> None:
    rig = host_rig()
    rig.host.handle_message(message("hola", 1), generation=0)
    rig.host.command(HostCommand.STOP, message("/stop", 2).id)
    assert rig.runner.kills == 1
    assert rig.admin.cancelled_windows == [WINDOW_A]
    assert rig.windows.halted
    assert rig.admin.replies[-1] == (STOPPED_TEXT, message("/stop", 2).id)


def test_c58_stop_during_a_run_sends_no_reply() -> None:
    runner = FakeRunner(outcome=RunOutcome(exit_code=-15, killed=True))
    rig = host_rig(runner=runner)
    runner.on_run = lambda _request: rig.host.stop()
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.admin.replies == []


def test_c58_stop_mid_run_drops_the_reply_even_if_the_run_finished() -> None:
    rig = host_rig()
    rig.runner.on_run = lambda _request: rig.host.stop()
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.admin.replies == []


def test_c58_messages_queued_before_stop_are_dropped() -> None:
    rig = host_rig()
    generation = rig.host.generation
    rig.host.stop()
    rig.host.handle_message(message("queued earlier", 1), generation=generation)
    assert rig.runner.requests == []
    assert rig.screen.seen == []


def test_c58_next_message_after_stop_runs() -> None:
    rig = host_rig()
    rig.host.stop()
    rig.host.handle_message(message("hola", 2), generation=rig.host.generation)
    assert len(rig.runner.requests) == 1 and not rig.windows.halted


def test_c58_stop_during_screen_starts_no_run() -> None:
    """host-flow-2: a /stop while the message is screened drops it before any run."""
    screen = FakeScreen()
    rig = host_rig(screen=screen)
    screen.on_screen = rig.host.stop
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.screen.seen == [message("hola", 1).id]
    assert rig.runner.requests == []
    assert rig.preflight.checks == 0
    assert rig.windows.halted  # the stale message did not clear the halt
    assert rig.admin.replies == []


def test_c58_stop_during_preflight_starts_no_run() -> None:
    """host-flow-2: a /stop while the settings/MCP preflight runs refuses the spawn."""
    preflight = FakePreflight()
    rig = host_rig(preflight=preflight)
    preflight.on_check = rig.host.stop
    rig.host.handle_message(message("hola", 1), generation=0)
    assert preflight.checks == 1
    assert rig.runner.requests == []
    assert rig.gate.runs == []  # the gate never opened a run either
    assert rig.admin.replies == []


def test_c58_stop_during_resume_preflight_starts_no_resume_turn() -> None:
    rig = host_rig()
    rig.host.handle_message(message("hola", 1), generation=0)
    assert len(rig.runner.requests) == 1
    rig.preflight.on_check = rig.host.stop
    outcome = rig.host.run_resume_turn(
        "approved: go on",
        full=True,
        covers=(),
        approved_sessions=(),
        message_id=message("hola", 1).id,
        generation=0,
        chain=0,
    )
    assert outcome is None
    assert len(rig.runner.requests) == 1


def test_c58_stop_passes_its_epoch_and_runs_carry_their_generation() -> None:
    rig = host_rig()
    rig.host.stop()
    rig.host.stop()
    assert rig.runner.epochs == [1, 2]
    rig.host.handle_message(message("hola", 1), generation=2)
    assert rig.runner.requests[0].generation == 2


def test_c58_recap_after_a_stop_is_refused() -> None:
    rig = host_rig()
    rig.host.handle_message(message("hola", 1), generation=0)
    rig.preflight.on_check = rig.host.stop  # the stop lands during the recap's preflight
    rig.host.command(HostCommand.NEW, message("/new", 2).id)
    assert len(rig.runner.requests) == 1  # no recap run


def test_c58_cancel_failure_still_stops_and_alerts() -> None:
    rig = host_rig()
    rig.host.handle_message(message("hola", 1), generation=0)
    rig.admin.cancel_fails = True
    rig.host.stop()
    assert rig.runner.kills == 1 and rig.windows.halted
    assert len(rig.alerts.titles) == 1


class TestLoop:
    def rig_loop(self) -> tuple[HostLoop, HostRig]:
        rig = host_rig()
        return HostLoop(rig.admin, rig.host, rig.screen, poll_wait=0, tick_seconds=0.01), rig

    def test_c58_stop_is_immediate_and_drops_earlier_queued_work(self) -> None:
        loop, rig = self.rig_loop()
        rig.admin.inbox = [message("do the work", 1), message("/stop", 2)]
        assert loop.poll_once() == 2
        assert rig.runner.kills == 1
        assert loop.work_once()  # the queued message is dropped, not run
        assert rig.runner.requests == []

    def test_c58_commands_exact_match_only(self) -> None:
        loop, rig = self.rig_loop()
        rig.admin.inbox = [message(" /stop", 1), message("/stop please", 2)]
        loop.poll_once()
        assert rig.runner.kills == 0
        loop.work_once()
        loop.work_once()
        assert len(rig.screen.seen) == 2  # screened like any text
        assert len(rig.runner.requests) == 2

    def test_c58_commands_skip_the_screen(self) -> None:
        loop, rig = self.rig_loop()
        rig.admin.inbox = [message("/status", 1), message("/voice", 2), message("/new", 3)]
        loop.poll_once()
        loop.work_once()
        assert rig.screen.seen == []
        assert rig.runner.requests == []
        assert len(rig.admin.replies) == 3

    def test_c58_processed_once(self) -> None:
        loop, rig = self.rig_loop()
        first = message("hola", 1)
        rig.admin.already_handled.add(first.id)
        rig.admin.inbox = [first, message("otra", 2)]
        assert loop.poll_once() == 1
        loop.work_once()
        assert rig.screen.seen == [message("otra", 2).id]

    def test_c58_idle_worker_ticks(self) -> None:
        loop, _ = self.rig_loop()
        assert loop.work_once() is False

    def test_health_reported_on_change_only(self) -> None:
        loop, rig = self.rig_loop()
        loop.poll_once()
        loop.poll_once()
        assert rig.admin.health == ["ok"]

    def test_c58_one_failing_message_never_stops_the_loop(self) -> None:
        class Exploding(FakeScreen):
            def screen(self, message):
                raise RuntimeError("boom")

        rig = host_rig(screen=Exploding())
        rig.runner.on_run = lambda _r: (_ for _ in ()).throw(RuntimeError("run broke"))
        loop = HostLoop(rig.admin, rig.host, rig.screen, poll_wait=0, tick_seconds=0.01)
        rig.admin.inbox = [message("a", 1), message("b", 2)]
        loop.poll_once()
        assert loop.work_once() and loop.work_once()
        assert len(rig.runner.requests) == 2


# --- real process groups (stand-in CLI) ---------------------------------------------------


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _runner(tmp_path: Path, **fake: object) -> tuple[CliClaudeRunner, Path]:
    workdir = tmp_path / "work"
    workdir.mkdir()
    script = write_fake_claude(tmp_path, **fake)  # type: ignore[arg-type]
    config = ClaudeCliConfig(
        claude_bin=script,
        mcp_config=tmp_path / "mcp.json",
        settings=tmp_path / "s.json",
        workdir=workdir,
        run_timeout=60,
    )
    return CliClaudeRunner(config, {"PATH": "/usr/bin:/bin"}), workdir


def _request(generation: int = 0) -> RunRequest:
    tools = TOOL_SETS[ToolSetName.FULL]
    return RunRequest(
        window_id=WINDOW_A,
        resume=False,
        prompt="hola",
        allowed_tools=tools.allowed,
        disallowed_tools=tools.disallowed,
        builtin_tools=tools.builtins,
        generation=generation,
    )


def _wait_for(path: Path) -> None:
    deadline = time.monotonic() + 10
    while not path.exists():
        assert time.monotonic() < deadline, "fake CLI never started"
        time.sleep(0.02)
    time.sleep(0.1)  # let the JSON write finish


def test_c58_kill_all_kills_a_running_process_group(tmp_path: Path) -> None:
    runner, workdir = _runner(tmp_path, sleep=60.0)
    outcomes: list[RunOutcome] = []
    worker = threading.Thread(target=lambda: outcomes.append(runner.run(_request())))
    worker.start()
    _wait_for(workdir / "record.json")
    assert runner.busy()
    assert runner.kill_all() == 1
    worker.join(15)
    assert not worker.is_alive()
    assert outcomes[0].killed
    assert not runner.busy()


def test_c58_dispatched_work_keeps_the_runner_busy_until_stop(tmp_path: Path) -> None:
    runner, workdir = _runner(tmp_path, spawn_child=True)
    outcome = runner.run(_request())
    assert outcome.exit_code == 0 and not outcome.killed
    record = read_record(workdir)
    pgid = record["pgid"]
    assert isinstance(pgid, int) and pgid == record["pid"]  # its own group (start_new_session)
    assert runner.busy()  # the child it left behind is still running
    assert runner.kill_all() == 1
    deadline = time.monotonic() + 10
    while runner.busy():
        assert time.monotonic() < deadline
        time.sleep(0.05)


def test_c58_runner_refuses_a_request_queued_before_the_stop(tmp_path: Path) -> None:
    """host-flow-2: the epoch check sits with the spawn under the runner lock."""
    runner, workdir = _runner(tmp_path)
    assert runner.kill_all(epoch=1) == 0
    outcome = runner.run(_request(generation=0))
    assert outcome.killed and outcome.exit_code is None
    assert not (workdir / "record.json").exists()  # never spawned
    assert not runner.busy()
    assert runner.run(_request(generation=1)).exit_code == 0


def test_c58_runner_epoch_never_goes_back(tmp_path: Path) -> None:
    runner, workdir = _runner(tmp_path)
    runner.kill_all(epoch=3)
    runner.kill_all(epoch=1)
    runner.kill_all()
    assert runner.run(_request(generation=2)).killed
    assert not (workdir / "record.json").exists()


def test_c58_stop_kills_a_detached_child_of_a_live_run(tmp_path: Path) -> None:
    """host-flow-5: work moved to its own session is still found through /proc and killed."""
    runner, workdir = _runner(tmp_path, sleep=60.0, detach_child=True)
    outcomes: list[RunOutcome] = []
    worker = threading.Thread(target=lambda: outcomes.append(runner.run(_request())))
    worker.start()
    _wait_for(workdir / "child.pid")
    child = int((workdir / "child.pid").read_text())
    assert os.getpgid(child) == child  # its own group: killpg of the run would miss it
    assert runner.kill_all() == 2
    worker.join(15)
    assert outcomes[0].killed
    deadline = time.monotonic() + 10
    while _alive(child) and not _zombie(child):
        assert time.monotonic() < deadline, "detached child survived /stop"
        time.sleep(0.05)


def _zombie(pid: int) -> bool:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True
    return stat.rpartition(")")[2].split()[0] == "Z"


def test_c58_descendant_sweep_never_returns_unrelated_or_own_groups(tmp_path: Path) -> None:
    proc = tmp_path / "proc"
    for pid, ppid, pgid in ((100, 1, 100), (101, 100, 101), (102, 101, 102), (200, 1, 200)):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "stat").write_text(f"{pid} (odd ) name) S {ppid} {pgid} {pgid} 0\n")
    (proc / "self").mkdir()
    (proc / "999").mkdir()  # vanished: no stat file
    assert detached_descendant_groups([100], proc_root=proc) == (101, 102)
    assert detached_descendant_groups([], proc_root=proc) == ()
    assert detached_descendant_groups([100], proc_root=tmp_path / "missing") == ()


def test_c58_run_timeout_kills_the_group(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path, sleep=60.0)
    runner._config = ClaudeCliConfig(
        claude_bin=runner._config.claude_bin,
        mcp_config=runner._config.mcp_config,
        settings=runner._config.settings,
        workdir=runner._config.workdir,
        run_timeout=0.5,
    )
    outcome = runner.run(_request())
    assert outcome.timed_out and not runner.busy()


# --- admin client: A1 cancel routes, CAS claim, reply refusal -----------------------------


class Recorder:
    def __init__(self, status: int = 200, body: object | None = None) -> None:
        self.status = status
        self.body = {} if body is None else body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, json=self.body)


def client(recorder: Recorder) -> ClaudiaAdminClient:
    return ClaudiaAdminClient(
        Path("/nonexistent.sock"), TOKEN, transport=httpx.MockTransport(recorder)
    )


def test_c58_cancel_open_uses_the_a1_route() -> None:
    approval = "01" + "0" * 24
    recorder = Recorder(body={"cancelled": [approval]})
    assert client(recorder).cancel_open_approvals(WINDOW_A) == [approval]
    sent = recorder.requests[0]
    assert (sent.method, sent.url.path) == ("POST", "/v1/claudia/approvals/cancel-open")
    # Always the window: `{}` would cancel every window's requests (A1 body).
    assert json.loads(sent.content) == {"window_id": WINDOW_A}
    assert sent.headers["authorization"] == "Bearer " + TOKEN.decode()


def test_c58_cancel_open_malformed_result_is_an_error() -> None:
    with pytest.raises(ClaudiaAdminError, match="malformed"):
        client(Recorder(body={"cancelled": ["not-a-ulid"]})).cancel_open_approvals(WINDOW_A)


def test_c58_cancel_one_uses_the_a1_route_and_ignores_already_resolved() -> None:
    approval = "01" + "0" * 24
    recorder = Recorder(status=409, body={"error": "conflict"})
    assert client(recorder).cancel_approval(approval) == "already_resolved"  # type: ignore[arg-type]
    assert recorder.requests[0].url.path == f"/v1/claudia/approvals/{approval}/cancel"


@pytest.mark.parametrize("result", ["cancelled", "already_resolved", "unknown"])
def test_c58_cancel_one_returns_the_a1_result_code(result: str) -> None:
    approval = "01" + "0" * 24
    recorder = Recorder(body={"result": result, "approval": None})
    assert client(recorder).cancel_approval(approval) == result  # type: ignore[arg-type]
    assert len(recorder.requests) == 1


def test_c58_cancel_one_retries_busy() -> None:
    approval = "01" + "0" * 24
    recorder = Recorder(body={"result": "busy", "approval": None})
    assert client(recorder).cancel_approval(approval) == "busy"  # type: ignore[arg-type]
    assert len(recorder.requests) == 3


def test_c58_cancel_route_errors_surface() -> None:
    with pytest.raises(ClaudiaAdminError, match="500"):
        client(Recorder(status=500)).cancel_open_approvals(WINDOW_A)


def test_c58_handled_claim_is_a_cas() -> None:
    message_id = OwnerMessageId("0" * 26)
    assert client(Recorder(status=200)).mark_handled(message_id) is True
    assert (
        client(Recorder(status=409, body={"error": "conflict"})).mark_handled(message_id) is False
    )


def test_reply_refusal_is_false_not_an_error() -> None:
    assert (
        client(Recorder(status=400, body={"error": "validation"})).send_reply("x", message_id=None)
        is False
    )
    assert client(Recorder(status=201, body={"id": "1"})).send_reply("x", message_id=None)


def test_alerts_are_fixed_replies() -> None:
    recorder = Recorder(status=201, body={"id": "1"})
    ReplyAlerts(client(recorder)).failed("Claudia stopped")
    body = json.loads(recorder.requests[0].content)
    assert body == {"text": ALERT_PREFIX + "Claudia stopped", "message_id": None, "item_id": None}


def test_token_never_in_repr_or_errors() -> None:
    admin = client(Recorder(status=503, body={"error": "storage_unavailable"}))
    assert TOKEN.decode() not in repr(admin)
    with pytest.raises(ClaudiaAdminError) as caught:
        admin.report_health("ok")
    assert TOKEN.decode() not in str(caught.value)
