"""C60: the `SendMessage` side of the risky-action hook (the C52 preventive layer).

Since F-CL3 (owner decision 2026-11-09, ADR 0041) the exact Claudia prefix
is the only rule, for every live session (headless, interactive or
unknown): with it the hook gives no decision (the guard decides); without
it the call is denied and the reason quotes the exact prefix, so one retry
fixes it. No approval is needed or consumed for a message any more.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from preview_dashboard.application.claudia.audit import PEER_PREFIX
from preview_dashboard.application.claudia.hook_gate import (
    REASON_MALFORMED,
    REASON_PEER_PREFIX,
    HookDecision,
    HookGate,
    HookVerdict,
)
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
)
from preview_dashboard.domain.risky_actions import PEER_MESSAGE_PREFIX, has_peer_prefix
from preview_dashboard.interfaces.claudia.hook import _REASON_RE
from preview_dashboard.interfaces.claudia.settings import REQUIRED_HOOK
from tests.claudia_host_support import WINDOW_A, FakeAuditLog
from tests.fakes import FixedClock

pytestmark = pytest.mark.security

HEADLESS = "aaaaaaaa-0000-4000-8000-000000000001"
INTERACTIVE = "bbbbbbbb-0000-4000-8000-000000000002"
TEXT = f"{PEER_MESSAGE_PREFIX} the build is green"


def send(to: object, message: object = TEXT) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": WINDOW_A,
        "cwd": "/w",
        "tool_name": "SendMessage",
        "tool_input": {"to": to, "message": message, "summary": "build"},
    }


def make_gate(*covers: ApprovalRequest, audit: FakeAuditLog | None = None) -> HookGate:
    g = HookGate(audit or FakeAuditLog(), FixedClock())
    g.begin_run(WINDOW_A, covers)
    return g


def is_deny(decision: HookDecision) -> bool:
    return decision.verdict is HookVerdict.DENY


def test_c60_prefix_is_the_audit_prefix() -> None:
    assert PEER_MESSAGE_PREFIX == PEER_PREFIX
    assert REQUIRED_HOOK["matcher"] == "*"  # every tool, SendMessage included


@pytest.mark.parametrize(
    "message",
    [
        "the build is green",
        f" {PEER_MESSAGE_PREFIX} x",
        PEER_MESSAGE_PREFIX.lower() + " x",
        "From Claudia (owner's companion) x",
        "",
        None,
        3,
    ],
)
def test_c60_missing_prefix_denied(message: object) -> None:
    audit = FakeAuditLog()
    g = make_gate(audit=audit)
    decision = g.decide(send("builder", message))
    assert decision == HookDecision.deny(REASON_PEER_PREFIX)
    assert not has_peer_prefix(message)
    assert audit.entries[-1]["reason"] == "missing_prefix"
    assert "the build" not in str(audit.entries)


def test_fcl3_c60_missing_prefix_reason_quotes_the_exact_prefix() -> None:
    decision = make_gate().decide(send(INTERACTIVE, "hello there"))
    assert decision.reason is not None
    assert decision.reason.endswith(PEER_MESSAGE_PREFIX)
    # The hook command passes it on unchanged (its reason charset allows the quote).
    assert _REASON_RE.fullmatch(decision.reason)


@pytest.mark.parametrize("target", ["builder", HEADLESS, "owner-tab", INTERACTIVE, "nobody-knows"])
def test_fcl3_c60_any_live_session_with_the_prefix_gets_no_decision(target: str) -> None:
    # Headless, interactive or unknown: the hook never grants, the guard decides.
    audit = FakeAuditLog()
    g = make_gate(audit=audit)
    assert g.decide(send(target)) == HookDecision.no_decision()
    assert g.decide(send(target)) == HookDecision.no_decision()  # no single-use cover involved
    assert audit.entries == []


def test_c60_action_approval_is_not_needed_and_never_used_for_a_message() -> None:
    clock = FixedClock()
    step = timedelta(seconds=1)
    action = (
        ApprovalRequest.new(
            id=ApprovalId(f"{2:026d}"),
            window_id=WINDOW_A,
            kind=ApprovalKind.ACTION,
            action_text="Remove a file",
            now=clock.now(),
            action_kind=ActionKind.RM,
            action_target=INTERACTIVE,
        )
        .tapped(clock.advance(step))
        .approved(clock.advance(step))
        .consumed(clock.advance(step))
    )
    audit = FakeAuditLog()
    g = make_gate(action, audit=audit)
    assert g.decide(send(INTERACTIVE)) == HookDecision.no_decision()
    assert not any(e.get("event") == "hook_cover_used" for e in audit.entries)


def test_c60_outside_a_run_still_denied() -> None:
    g = make_gate()
    g.end_run()
    assert is_deny(g.decide(send(INTERACTIVE)))


@pytest.mark.parametrize("to", [None, "", 5, "x" * 5000])
def test_c60_bad_target_denied(to: object) -> None:
    assert make_gate().decide(send(to)) == HookDecision.deny(REASON_MALFORMED)
