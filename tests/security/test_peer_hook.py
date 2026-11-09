"""C60: the `SendMessage` side of the risky-action hook (the C52 preventive layer).

A message needs the exact Claudia prefix; to an interactive or unknown
session it also needs a consumed `peer_message` approval for that session
id (single use, ends with the run). A headless target with the prefix
gets no decision (the guard decides).
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
from preview_dashboard.interfaces.claudia.settings import REQUIRED_HOOK
from preview_dashboard.ports.claudia_host import PeerInfo
from tests.claudia_host_support import WINDOW_A, FakeAuditLog, FakePeers
from tests.fakes import FixedClock

pytestmark = pytest.mark.security

HEADLESS = "aaaaaaaa-0000-4000-8000-000000000001"
INTERACTIVE = "bbbbbbbb-0000-4000-8000-000000000002"
OTHER = "cccccccc-0000-4000-8000-000000000003"
TEXT = f"{PEER_MESSAGE_PREFIX} the build is green"


def peer_approval(n: int, session: str) -> ApprovalRequest:
    clock = FixedClock()
    step = timedelta(seconds=1)
    return (
        ApprovalRequest.new(
            id=ApprovalId(f"{n:026d}"),
            window_id=WINDOW_A,
            kind=ApprovalKind.PEER_MESSAGE,
            action_text="Tell the dashboard session the build is green",
            now=clock.now(),
            action_kind=ActionKind.PEER_MESSAGE,
            action_target=session,
        )
        .tapped(clock.advance(step))
        .approved(clock.advance(step))
        .consumed(clock.advance(step))
    )


def send(to: object, message: object = TEXT) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": WINDOW_A,
        "cwd": "/w",
        "tool_name": "SendMessage",
        "tool_input": {"to": to, "message": message, "summary": "build"},
    }


def make_gate(*covers: ApprovalRequest, audit: FakeAuditLog | None = None) -> HookGate:
    peers = FakePeers(
        {
            "builder": PeerInfo(session_id=HEADLESS, interactive=False),
            HEADLESS: PeerInfo(session_id=HEADLESS, interactive=False),
            "owner-tab": PeerInfo(session_id=INTERACTIVE, interactive=True),
            INTERACTIVE: PeerInfo(session_id=INTERACTIVE, interactive=True),
        }
    )
    g = HookGate(peers, audit or FakeAuditLog(), FixedClock())
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
    g = make_gate(peer_approval(1, HEADLESS), audit=audit)
    decision = g.decide(send("builder", message))
    assert decision == HookDecision.deny(REASON_PEER_PREFIX)
    assert not has_peer_prefix(message)
    assert audit.entries[-1]["reason"] == "missing_prefix"
    assert "the build" not in str(audit.entries)


def test_c60_headless_target_with_prefix_no_decision() -> None:
    g = make_gate()
    assert g.decide(send("builder")) == HookDecision.no_decision()
    assert g.decide(send(HEADLESS)) == HookDecision.no_decision()


@pytest.mark.parametrize("target", ["owner-tab", INTERACTIVE, "nobody-knows", OTHER])
def test_c60_interactive_or_unknown_target_without_approval_denied(target: str) -> None:
    decision = make_gate().decide(send(target))
    assert is_deny(decision)
    assert decision.reason is not None
    assert decision.reason.startswith("peer_message")


def test_c60_approval_for_another_session_denied() -> None:
    g = make_gate(peer_approval(1, OTHER))
    assert is_deny(g.decide(send("owner-tab")))


def test_c60_approval_for_the_session_covers_one_message() -> None:
    g = make_gate(peer_approval(1, INTERACTIVE))
    assert g.decide(send("owner-tab")) == HookDecision.no_decision()
    assert is_deny(g.decide(send("owner-tab")))  # single use


def test_c60_unknown_target_matches_only_its_own_session_id() -> None:
    # Directory down: the target string itself must equal the approved session id.
    g = make_gate(peer_approval(1, OTHER))
    assert g.decide(send(OTHER)) == HookDecision.no_decision()


def test_c60_action_approval_never_covers_a_message() -> None:
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
    assert is_deny(make_gate(action).decide(send("owner-tab")))


def test_c60_cover_ends_with_the_run() -> None:
    g = make_gate(peer_approval(1, INTERACTIVE))
    g.end_run()
    assert is_deny(g.decide(send("owner-tab")))


def test_c60_peer_lookup_failure_is_interactive() -> None:
    class Broken(FakePeers):
        def lookup(self, target: str) -> PeerInfo | None:
            raise RuntimeError("claude agents failed")

    g = HookGate(Broken(), FakeAuditLog(), FixedClock())
    g.begin_run(WINDOW_A)
    assert is_deny(g.decide(send("builder")))


@pytest.mark.parametrize("to", [None, "", 5, "x" * 5000])
def test_c60_bad_target_denied(to: object) -> None:
    assert make_gate().decide(send(to)) == HookDecision.deny(REASON_MALFORMED)
