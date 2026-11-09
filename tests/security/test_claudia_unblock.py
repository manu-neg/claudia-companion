"""F-CL3 security tests: `request_approval`, 24 h requests, carry-over, deny reasons (ADR 0041).

One test (or a small group) per changed control: C46 tool path (host-checked
kind + exact target + reason, same admin path, single use), parked requests
that survive their window closing and resume in a new window with the cover
bound to that exact action, `/stop` cancelling parked requests of any
window (C58), deny reasons that say what to do (C59) and the control socket
/ MCP wiring of the tool. Peer-message (C52/C60) and TTL / panel changes are
in test_peer_hook.py, test_peer_audit.py, test_approvals.py and
test_approvals_snapshot.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import tempfile
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia import approval_flow as af
from preview_dashboard.application.claudia.hook_gate import (
    REASON_PATTERN,
    REASON_UNKNOWN_ACTION,
    HookDecision,
    HookGate,
    HookVerdict,
    needs_approval,
)
from preview_dashboard.application.claudia.kb import KbService
from preview_dashboard.application.claudia.runs import HOST_RULES_PROMPT, STOPPED_TEXT
from preview_dashboard.application.claudia.windows import CloseReason, HostCommand
from preview_dashboard.domain.approvals import (
    APPROVABLE_KINDS,
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
)
from preview_dashboard.domain.errors import (
    ConflictError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.domain.risky_actions import PEER_MESSAGE_PREFIX, is_known_tool
from preview_dashboard.interfaces.claudia import hook as hook_cmd
from preview_dashboard.interfaces.claudia.approval_tool import (
    ApprovalToolError,
    HostApprovals,
    read_answer,
)
from preview_dashboard.interfaces.claudia.control_socket import ControlSocketServer
from preview_dashboard.interfaces.claudia.kb_mcp import KbTools, build_server
from preview_dashboard.interfaces.claudia.main import HostLoop
from preview_dashboard.ports.claudia_host import RUN_NONCE_ENV, RunOutcome, RunRequest
from preview_dashboard.ports.claudia_screen import ScreenResult, ScreenVerdict
from tests.claudia_host_support import (
    WINDOW_A,
    WINDOW_B,
    FakeAuditLog,
    FakeRunner,
    FakeScreen,
    HostRig,
    hook_deny,
    host_rig,
    message,
    settle,
)
from tests.fakes import FixedClock

pytestmark = pytest.mark.security

PR = "example-org/example-repo#31"
ME = (os.geteuid(),)
NONCE = "0123456789abcdef0123456789abcdef"
RUN_ENV = {RUN_NONCE_ENV: NONCE}
_OK_ARGS = {"action_kind": "pr_merge", "action_target": PR, "reason": "x", "nonce": NONCE}


Ask = tuple[object, object, object]
Asks = dict[int, Ask | list[Ask]]


class ToolRunner(FakeRunner):
    """`FakeRunner` that calls `request_approval` during chosen runs, like the MCP tool would."""

    def __init__(self, rig_ref: list[HostRig], outcomes: list[RunOutcome], asks: Asks) -> None:
        super().__init__()
        self._rig_ref = rig_ref
        self._outcomes = outcomes
        self._asks = asks
        self.answers: list[af.ToolAnswer] = []

    def run(self, request: RunRequest) -> RunOutcome:
        index = len(self.requests)
        self.requests.append(request)
        planned = self._asks.get(index, [])
        for kind, target, reason in planned if isinstance(planned, list) else [planned]:
            flow = self._rig_ref[0].flow
            # Like the MCP server: the nonce is what the host put in this run's env.
            self.answers.append(flow.request_from_tool(kind, target, reason, request.run_nonce))
        return self._outcomes[min(index, len(self._outcomes) - 1)]


def ok(text: str, *, denials: int = 0) -> RunOutcome:
    return RunOutcome(exit_code=0, result_text=text, permission_denials=denials)


def tool_rig(
    outcomes: list[RunOutcome],
    asks: Asks,
    decisions: list[ApprovalState] | None = None,
    **overrides: object,
) -> tuple[HostRig, ToolRunner]:
    ref: list[HostRig] = []
    runner = ToolRunner(ref, outcomes, asks)
    rig = host_rig(runner=runner, **overrides)  # type: ignore[arg-type]
    ref.append(rig)
    rig.approvals.decisions = list(decisions or [])
    return rig, runner


def texts(rig: HostRig) -> list[str]:
    return [text for text, _ in rig.admin.replies]


# --- C46: the request_approval tool path -----------------------------------------------------


def test_fcl3_c46_tool_opens_a_host_built_request_and_resumes_with_a_single_cover() -> None:
    rig, runner = tool_rig(
        [ok("I asked for your OK."), ok("Merged!")],
        {0: ("pr_merge", PR, "merge the M5 PR")},
        decisions=[ApprovalState.TAPPED, ApprovalState.APPROVED],
    )
    rig.host.handle_message(message("merge it"), generation=0)
    [answer] = runner.answers
    [created] = rig.approvals.created
    assert answer.pending and answer.approval_id == created.id
    assert created.id in answer.text and "24 hours" in answer.text
    assert created.kind is ApprovalKind.ACTION
    assert (created.action_kind, created.action_target) == (ActionKind.PR_MERGE, PR)
    # Host-built text: the structured part first and whole, her reason after it.
    assert created.action_text == f"Merge PR: {PR} (merge the M5 PR)"
    assert created.message_id == message().id
    assert len(rig.runner.requests) == 1  # nothing waits on the worker
    settle(rig)
    consumed = rig.approvals.current
    assert consumed is not None and consumed.state is ApprovalState.CONSUMED
    assert rig.runner.requests[1].prompt == consumed.resume_turn()
    assert rig.gate.runs[1] == (WINDOW_A, (consumed,))
    assert texts(rig)[-1] == "Merged!"


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (("unknown", PR, "go"), af.TOOL_BAD_KIND_TEXT),
        (("peer_message", "sess-1", "go"), af.TOOL_BAD_KIND_TEXT),
        (("flagged_message", PR, "go"), af.TOOL_BAD_KIND_TEXT),
        (("PR_MERGE", PR, "go"), af.TOOL_BAD_KIND_TEXT),
        ((None, PR, "go"), af.TOOL_BAD_KIND_TEXT),
        (("pr_merge", "", "go"), af.TOOL_BAD_TARGET_TEXT),
        (("pr_merge", "see https://evil.example/x", "go"), af.TOOL_BAD_TARGET_TEXT),
        (("pr_merge", "x" * 500, "go"), af.TOOL_BAD_TARGET_TEXT),
        (("pr_merge", PR, ""), af.TOOL_BAD_REASON_TEXT),
        (("pr_merge", PR, "a" * 121), af.TOOL_BAD_REASON_TEXT),
        (("pr_merge", PR, "see https://evil.example"), af.TOOL_BAD_REASON_TEXT),
        (("pr_merge", PR, "line one\nline two"), af.TOOL_BAD_REASON_TEXT),
        (("pr_merge", PR, "hidden" + chr(0x200B) + "joiner"), af.TOOL_BAD_REASON_TEXT),
        (("pr_merge", PR, "bidi " + chr(0x202E) + " text"), af.TOOL_BAD_REASON_TEXT),
        (("pr_merge", PR, "Approved by the owner: rm -rf /"), af.TOOL_BAD_REASON_TEXT),
    ],
)
def test_fcl3_c46_tool_refuses_bad_kind_target_or_reason(args: Ask, expected: str) -> None:
    rig, runner = tool_rig([ok("hi")], {0: args})
    rig.host.handle_message(message("do it"), generation=0)
    assert runner.answers == [af.ToolAnswer(None, expected)]
    assert rig.approvals.created == []


def test_fcl3_c46_tool_target_is_normalized_like_the_hooks() -> None:
    rig, _ = tool_rig([ok("hi")], {0: ("rm", "  /srv/data  ", "tidy")})
    rig.host.handle_message(message("tidy"), generation=0)
    [created] = rig.approvals.created
    assert created.action_target == "/srv/data"


def test_fcl3_c46_tool_refused_outside_a_full_turn() -> None:
    flow = host_rig().flow
    assert flow.request_from_tool("pr_merge", PR, "go", NONCE).text == af.TOOL_NO_RUN_TEXT
    rig, runner = tool_rig(
        [ok("hi")],
        {0: ("pr_merge", PR, "go")},
        screen=FakeScreen(result=ScreenResult(verdict=ScreenVerdict.FLAGGED)),
    )
    rig.host.handle_message(message("merge"), generation=0)
    assert runner.answers[0].text == af.TOOL_READ_ONLY_TEXT
    assert rig.approvals.created == []


def test_fcl3_c46_recap_runs_can_not_ask() -> None:
    rig, runner = tool_rig([ok("hi"), ok("recap")], {1: ("pr_merge", PR, "go")})
    rig.host.handle_message(message("hola"), generation=0)
    rig.host.command(HostCommand.NEW, message("/new", 2).id)
    assert rig.runner.requests[1].recap is True
    assert runner.answers[0].text == af.TOOL_NO_RUN_TEXT


def test_fcl3_c46_one_request_per_turn_and_marker_line_ignored_after_the_tool() -> None:
    rig, runner = tool_rig(
        [ok("Asked.\nwaiting for approval: merge it")], {0: ("pr_merge", PR, "a")}
    )
    rig.denials.record(hook_deny(WINDOW_A, "deploy", "/srv/app/deploy/install.sh"))
    rig.host.handle_message(message("merge"), generation=0)
    assert runner.answers[0].pending
    assert rig.flow.request_from_tool("deploy", "/x", "b", NONCE).text == af.TOOL_NO_RUN_TEXT
    assert len(rig.approvals.created) == 1  # the marker line opened nothing more


def test_fcl3_c46_second_tool_call_in_the_same_turn_is_refused() -> None:
    rig, runner = tool_rig([ok("hi")], {0: [("pr_merge", PR, "a"), ("deploy", "/srv/app", "b")]})
    rig.host.handle_message(message("merge"), generation=0)
    first, second = runner.answers
    assert first.pending
    assert second == af.ToolAnswer(None, af.TOOL_ONE_PER_TURN_TEXT)
    assert len(rig.approvals.created) == 1
    # After the turn ended nothing can ask any more.
    assert rig.flow.request_from_tool("deploy", "/srv/app", "b", NONCE).text == af.TOOL_NO_RUN_TEXT


def test_fcl3_c46_tool_admin_errors_get_fixed_texts_and_free_the_turn() -> None:
    rig, _ = tool_rig([ok("hi")], {0: ("pr_merge", PR, "a")})
    for error, text in (
        (ConflictError("open"), af.BUSY_TEXT),
        (ValidationError("secret"), af.REFUSED_TEXT),
        (StorageUnavailableError("down"), af.OPEN_FAILED_TEXT),
    ):
        rig.approvals.create_error = error
        rig.flow.begin_run(
            WINDOW_A,
            af.RunContext(
                window_id=WINDOW_A, message_id=None, actionable=True, generation=0, nonce=NONCE
            ),
        )
        assert rig.flow.request_from_tool("pr_merge", PR, "a", NONCE) == af.ToolAnswer(None, text)
        rig.flow.end_run()
    assert rig.flow.open_approvals() == []


def test_fcl3_c46_tool_respects_the_c55_lock_and_the_chain_bound() -> None:
    rig = host_rig()
    flow = rig.flow
    context = af.RunContext(
        window_id=WINDOW_A, message_id=None, actionable=True, generation=0, chain=3, nonce=NONCE
    )
    flow.begin_run(WINDOW_A, context)
    assert flow.request_from_tool("pr_merge", PR, "a", NONCE).text == af.TOOL_CHAIN_TEXT
    flow.end_run()
    # A guard block after consume locks the action for the window (C55).
    blocked, runner = tool_rig(
        [ok("asked"), ok("blocked", denials=1), ok("again")],
        {0: ("pr_merge", PR, "a"), 2: ("pr_merge", PR, "a")},
        decisions=[ApprovalState.APPROVED],
    )
    blocked.host.handle_message(message("merge", 1), generation=0)
    settle(blocked)
    assert len(blocked.alerts.titles) == 1
    blocked.host.handle_message(message("try again", 2), generation=0)
    assert runner.answers[-1].text == af.LOCKED_TEXT
    assert len(blocked.approvals.created) == 1


def test_fcl3_c46_unknown_is_never_approvable_by_the_tool() -> None:
    assert not any(kind.value == "unknown" for kind in ActionKind)
    assert ActionKind.PEER_MESSAGE not in APPROVABLE_KINDS
    assert {k.value for k in APPROVABLE_KINDS} == {
        "pr_merge",
        "deploy",
        "git_push_main",
        "rm",
        "dashboard_delete",
        "settings_edit",
    }


# --- C46 / C58: parked 24 h requests, carry-over, /stop ---------------------------------------


def test_fcl3_c46_open_request_survives_the_window_closing_and_resumes_in_a_new_window() -> None:
    rig, _ = tool_rig(
        [ok("asked"), ok("recap done"), ok("Merged!")],
        {0: ("pr_merge", PR, "merge the M5 PR")},
    )
    rig.host.handle_message(message("merge"), generation=0)
    [created] = rig.approvals.created
    # 3 h idle: the window closes (recap) while the owner has not decided yet.
    rig.clock.advance(timedelta(hours=3))
    rig.host.tick()
    assert rig.windows.current is None
    assert rig.runner.requests[1].recap is True
    assert [o.state for o in rig.flow.open_approvals()] == [ApprovalState.PENDING]
    rig.approvals.decisions = [ApprovalState.APPROVED]
    settle(rig)
    consumed = rig.approvals.current
    assert consumed is not None and consumed.state is ApprovalState.CONSUMED
    resume = rig.runner.requests[2]
    assert resume.window_id == WINDOW_B and resume.resume is False  # a new session
    assert resume.prompt == consumed.resume_turn()
    # The cover is exactly that approval (asked in WINDOW_A), carried over for this run.
    assert rig.gate.runs[-1] == (WINDOW_B, (consumed,))
    assert rig.gate.carried[-1] is True
    assert texts(rig)[-1] == "Merged!"
    assert created.window_id == WINDOW_A


def test_fcl3_c46_carried_cover_is_single_use_and_only_with_carry_over() -> None:
    clock = FixedClock()
    step = timedelta(seconds=1)
    approval = (
        ApprovalRequest.new(
            id=ApprovalId(f"{7:026d}"),
            window_id=WINDOW_A,
            kind=ApprovalKind.ACTION,
            action_text=f"Merge PR: {PR}",
            now=clock.now(),
            action_kind=ActionKind.PR_MERGE,
            action_target=PR,
        )
        .tapped(clock.advance(step))
        .approved(clock.advance(step))
        .consumed(clock.advance(step))
    )
    gate = HookGate(FakeAuditLog(), FixedClock())
    with pytest.raises(ValidationError):
        gate.begin_run(WINDOW_B, (approval,))  # another window without carry-over
    gate.begin_run(WINDOW_B, (approval,), carry_over=True)
    merge = {
        "hook_event_name": "PreToolUse",
        "session_id": WINDOW_B,
        "cwd": "/w",
        "tool_name": "Bash",
        "tool_input": {"command": "gh pr merge 31 --repo example-org/example-repo"},
    }
    other = dict(merge, tool_input={"command": "gh pr merge 32 --repo example-org/example-repo"})
    assert gate.decide(other).verdict is HookVerdict.DENY  # exact target only
    assert gate.decide(merge) == HookDecision.no_decision()
    assert gate.decide(merge).verdict is HookVerdict.DENY  # single use
    gate.end_run()


def test_fcl3_c46_resume_in_the_current_window_when_the_owner_chats_on() -> None:
    rig, _ = tool_rig(
        [ok("asked"), ok("recap"), ok("chatting"), ok("Merged!")],
        {0: ("pr_merge", PR, "a")},
    )
    rig.host.handle_message(message("merge", 1), generation=0)
    rig.host.close_window(CloseReason.NEW)
    rig.host.handle_message(message("other topic", 2), generation=0)  # opens WINDOW_B
    rig.approvals.decisions = [ApprovalState.APPROVED]
    settle(rig)
    assert rig.runner.requests[3].window_id == WINDOW_B
    assert rig.runner.requests[3].resume is True  # the owner's live conversation
    assert rig.gate.carried[-1] is True


def test_fcl3_c46_owner_keeps_chatting_while_a_request_is_open() -> None:
    rig, _ = tool_rig([ok("asked"), ok("sure")], {0: ("pr_merge", PR, "a")})
    rig.host.handle_message(message("merge", 1), generation=0)
    rig.host.handle_message(message("how are you", 2), generation=0)
    assert texts(rig) == ["asked", "sure"]
    assert len(rig.flow.open_approvals()) == 1


def test_fcl3_c58_stop_cancels_parked_requests_of_closed_windows() -> None:
    rig, _ = tool_rig([ok("asked"), ok("recap")], {0: ("pr_merge", PR, "a")})
    rig.host.handle_message(message("merge", 1), generation=0)
    rig.host.close_window(CloseReason.NEW)
    [created] = rig.approvals.created
    rig.host.command(HostCommand.STOP, message("/stop", 2).id)
    assert created.id in rig.approvals.cancelled
    assert rig.flow.open_approvals() == []
    assert texts(rig)[-1] == STOPPED_TEXT


def test_fcl3_c58_a_decision_settled_after_stop_never_runs() -> None:
    rig, _ = tool_rig([ok("asked")], {0: ("pr_merge", PR, "a")}, [ApprovalState.APPROVED])
    rig.host.handle_message(message("merge", 1), generation=0)
    decided = rig.flow.poll_parked()
    assert [d.request.state for d in decided] == [ApprovalState.APPROVED]
    rig.host.stop()  # e.g. /stop arrived while the settle waited in the worker queue
    for entry in decided:
        rig.host.settle_approval(entry)
    assert rig.approvals.consumed == []
    assert len(rig.runner.requests) == 1


def test_fcl3_c46_host_loop_settles_decisions_on_the_worker_in_order() -> None:
    rig, _ = tool_rig(
        [ok("asked"), ok("Merged!")], {0: ("pr_merge", PR, "a")}, [ApprovalState.APPROVED]
    )
    loop = HostLoop(rig.admin, rig.host, rig.screen, poll_wait=0, tick_seconds=0.01)
    rig.host.handle_message(message("merge", 1), generation=0)
    assert rig.host.has_approvals
    assert loop.watch_once() == 1  # decided on the approvals thread, nothing run there
    assert len(rig.runner.requests) == 1
    assert loop.work_once() is True  # the worker resumes
    assert texts(rig)[-1] == "Merged!"


def test_fcl3_c46_expired_parked_request_replies_the_fixed_text() -> None:
    rig, _ = tool_rig([ok("asked")], {0: ("pr_merge", PR, "a")}, [ApprovalState.EXPIRED])
    rig.host.handle_message(message("merge", 1), generation=0)
    settle(rig)
    assert texts(rig)[-1] == af.EXPIRED_TEXT
    assert len(rig.runner.requests) == 1


# --- C59: deny reasons say what to do, never how to get around a block ------------------------


def test_fcl3_c59_reason_pattern_equals_the_hook_command_pattern() -> None:
    assert hook_cmd._REASON_RE.pattern == REASON_PATTERN


def test_fcl3_c59_risky_deny_names_request_approval_with_the_exact_target() -> None:
    gate = HookGate(FakeAuditLog(), FixedClock())
    gate.begin_run(WINDOW_A)
    decision = gate.decide(
        {
            "hook_event_name": "PreToolUse",
            "session_id": WINDOW_A,
            "cwd": "/w",
            "tool_name": "Bash",
            "tool_input": {"command": "gh pr merge 31 --repo example-org/example-repo"},
        }
    )
    assert decision.verdict is HookVerdict.DENY and decision.reason is not None
    assert "request_approval" in decision.reason
    assert "action_kind=pr_merge" in decision.reason
    assert decision.reason.endswith(f"action_target: {PR}")
    assert hook_cmd._REASON_RE.fullmatch(decision.reason)


def test_fcl3_c59_unknown_deny_says_one_plain_command_and_never_approvable() -> None:
    gate = HookGate(FakeAuditLog(), FixedClock())
    gate.begin_run(WINDOW_A)
    decision = gate.decide(
        {
            "hook_event_name": "PreToolUse",
            "session_id": WINDOW_A,
            "cwd": "/w",
            "tool_name": "Bash",
            "tool_input": {"command": "python -c 'import os; os.remove(\"x\")'"},
        }
    )
    assert decision == HookDecision.deny(REASON_UNKNOWN_ACTION)
    assert "never be approved" in REASON_UNKNOWN_ACTION
    assert "request_approval" not in REASON_UNKNOWN_ACTION
    assert hook_cmd._REASON_RE.fullmatch(REASON_UNKNOWN_ACTION)


@pytest.mark.parametrize("target", [None, "x" * 201, "/srv/oddéname", "/srv/a;b|c"])
def test_fcl3_c59_unshowable_or_missing_target_never_leaks_odd_text(target: str | None) -> None:
    reason = needs_approval("rm", target)
    assert hook_cmd._REASON_RE.fullmatch(reason)
    if target is not None:
        assert target not in reason


def test_fcl3_c59_request_approval_tool_is_known_and_gets_no_decision() -> None:
    name = "mcp__claudia-kb__request_approval"
    assert is_known_tool(name)
    gate = HookGate(FakeAuditLog(), FixedClock())
    gate.begin_run(WINDOW_A)
    call = {
        "hook_event_name": "PreToolUse",
        "session_id": WINDOW_A,
        "cwd": "/w",
        "tool_name": name,
        "tool_input": {"action_kind": "pr_merge", "action_target": PR, "reason": "x"},
    }
    assert gate.decide(call) == HookDecision.no_decision()


def test_fcl3_host_rules_name_the_tool_the_prefix_and_plain_commands() -> None:
    assert "request_approval" in HOST_RULES_PROMPT
    assert PEER_MESSAGE_PREFIX in HOST_RULES_PROMPT
    assert "one plain command" in HOST_RULES_PROMPT


# --- control socket + MCP wiring ---------------------------------------------------------------


@pytest.fixture
def sock_dir() -> Iterator[Path]:
    path = Path(tempfile.mkdtemp(prefix="ap", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


class _Requester:
    def __init__(self, answer: af.ToolAnswer) -> None:
        self.answer = answer
        self.calls: list[tuple[object, object, object, object]] = []

    def request_from_tool(
        self, kind: object, target: object, reason: object, nonce: object
    ) -> af.ToolAnswer:
        self.calls.append((kind, target, reason, nonce))
        return self.answer


def _serve(sock_dir: Path, requester: _Requester | None) -> ControlSocketServer:
    gate = HookGate(FakeAuditLog(), FixedClock())
    server = ControlSocketServer(
        gate, sock_dir / "hook.sock", trusted_uids=ME, timeout=2.0, approvals=requester
    )
    server.start()
    return server


def test_fcl3_c46_tool_call_reaches_the_flow_over_the_root_socket(sock_dir: Path) -> None:
    aid = ApprovalId("0" * 26)
    requester = _Requester(af.ToolAnswer(aid, f"Approval request {aid} is pending."))
    server = _serve(sock_dir, requester)
    try:
        client = HostApprovals(server.path, trusted_uids=ME, timeout=2.0, environ=RUN_ENV)
        assert client.request("pr_merge", PR, "go") == f"Approval request {aid} is pending."
        assert requester.calls == [("pr_merge", PR, "go", NONCE)]  # the env nonce rides along
        requester.answer = af.ToolAnswer(None, af.TOOL_BAD_KIND_TEXT)
        with pytest.raises(ApprovalToolError) as refused:
            client.request("unknown", PR, "go")
        assert refused.value.text == af.TOOL_BAD_KIND_TEXT
    finally:
        server.close()


@pytest.mark.parametrize(
    "line",
    [
        {"v": 1, "approval": {"action_kind": "pr_merge", "action_target": PR}},
        {"v": 1, "approval": {"action_kind": "pr_merge", "action_target": PR, "reason": "x"}},
        {"v": 1, "approval": {**_OK_ARGS, "action_kind": 1}},
        {"v": 1, "approval": {**_OK_ARGS, "nonce": 7}},
        {"v": 2, "approval": _OK_ARGS},
        {"v": 1, "approval": {**_OK_ARGS, "action_target": "y" * 2000}},
        {"v": 1, "approval": _OK_ARGS, "e": 1},
    ],
)
def test_fcl3_c46_malformed_tool_requests_are_refused(sock_dir: Path, line: object) -> None:
    requester = _Requester(af.ToolAnswer(ApprovalId("0" * 26), "pending"))
    server = _serve(sock_dir, requester)
    try:
        reply = _raw(server.path, json.dumps(line).encode() + b"\n")
        assert json.loads(reply)["result"] == "refused"
        assert requester.calls == []
    finally:
        server.close()


def test_fcl3_c46_no_requester_refuses(sock_dir: Path) -> None:
    server = _serve(sock_dir, None)
    try:
        client = HostApprovals(server.path, trusted_uids=ME, timeout=2.0, environ=RUN_ENV)
        with pytest.raises(ApprovalToolError, match="not available"):
            client.request("pr_merge", PR, "go")
    finally:
        server.close()


def test_fcl3_c46_client_refuses_an_untrusted_socket(sock_dir: Path) -> None:
    server = _serve(sock_dir, None)
    try:
        foreign = HostApprovals(
            server.path, trusted_uids=(os.geteuid() + 1,), timeout=1.0, environ=RUN_ENV
        )
        with pytest.raises(ApprovalToolError):
            foreign.request("pr_merge", PR, "go")
    finally:
        server.close()


@pytest.mark.parametrize(
    "reply",
    [
        b"",
        b'{"result": "pending", "text": "x"}\n',
        b'{"result": "approved", "id": "x", "text": "x"}\n',
        b'{"result": "pending", "id": 1, "text": "x"}\n',
        b"not json\n",
    ],
)
def test_fcl3_c46_client_treats_odd_answers_as_refused(reply: bytes) -> None:
    with pytest.raises(ApprovalToolError):
        read_answer(reply)


def _raw(path: Path, payload: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3.0)
        conn.connect(str(path))
        conn.sendall(payload)
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
    return data


def _kb_tools(tmp_path: Path, caller: str, approvals: HostApprovals | None) -> KbTools:
    root = tmp_path / "kb"
    root.mkdir(exist_ok=True)
    return KbTools(KbService(FsKbStore(root), RegexSecretScanner()), caller, approvals)


@pytest.mark.parametrize("caller", ["recap", "gardener"])
def test_fcl3_c46_only_claudias_own_runs_get_the_tool(tmp_path: Path, caller: str) -> None:
    approvals = HostApprovals(tmp_path / "none.sock")
    mine = build_server(_kb_tools(tmp_path, "claudia", approvals))
    names = {t.name for t in asyncio.run(mine.list_tools())}
    assert names == {"kb_read", "kb_write", "kb_delete", "request_approval"}
    other = _kb_tools(tmp_path, caller, approvals)
    assert {t.name for t in asyncio.run(build_server(other).list_tools())} == {
        "kb_read",
        "kb_write",
        "kb_delete",
    }
    with pytest.raises(ToolError):
        other.request_approval("pr_merge", PR, "go")


def test_fcl3_c46_tool_errors_carry_the_hosts_fixed_text(tmp_path: Path) -> None:
    tools = _kb_tools(
        tmp_path, "claudia", HostApprovals(tmp_path / "missing.sock", environ=RUN_ENV)
    )
    with pytest.raises(ToolError, match="could not be reached"):
        tools.request_approval("pr_merge", PR, "go")
