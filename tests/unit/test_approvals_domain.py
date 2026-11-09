"""Unit tests for `domain.approvals`: ids, lifecycle edges, successor rule, derived helpers."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from typing import Any

import pytest

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalState,
    check_successor,
    normalize_action_target,
    parse_approval_id,
    parse_window_id,
)
from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from tests.builders import T0
from tests.contracts.approval_store import consume, make_approval, make_flagged, wid

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "00000000-0000-4000-8000-00000000000",
        "00000000-0000-4000-8000-00000000000A",  # uppercase: one spelling per id
        "{00000000-0000-4000-8000-000000000001}",
        "00000000000040008000000000000001",
        None,
    ],
)
def test_bad_window_ids(raw: object) -> None:
    with pytest.raises(ValidationError):
        parse_window_id(raw)


def test_good_ids() -> None:
    assert parse_window_id(wid(1)) == wid(1)
    with pytest.raises(ValidationError):
        parse_approval_id("nope")


def test_full_lifecycle_stamps() -> None:
    request = make_approval(1)
    tapped, approved, consumed = consume(request)
    assert (tapped.state, approved.state, consumed.state) == (
        ApprovalState.TAPPED,
        ApprovalState.APPROVED,
        ApprovalState.CONSUMED,
    )
    assert consumed.tapped_at == T0 + timedelta(seconds=1)
    assert consumed.approved_at == T0 + timedelta(seconds=2)
    assert consumed.resolved_at == T0 + timedelta(seconds=3)
    for before, after in ((request, tapped), (tapped, approved), (approved, consumed)):
        check_successor(before, after)


def test_same_instant_steps_still_move_the_version() -> None:
    request = make_approval(1)
    tapped = request.tapped(T0)
    assert tapped.tapped_at == T0
    assert tapped.updated_at > request.updated_at
    check_successor(request, tapped)


def test_cancel_works_after_expiry_but_expire_needs_the_deadline() -> None:
    request = make_approval(1)
    late = request.expires_at + timedelta(hours=1)
    assert request.cancelled(late).state is ApprovalState.CANCELLED
    with pytest.raises(InvalidStateError):
        request.expired(request.expires_at - timedelta(microseconds=1))
    assert request.is_expired(request.expires_at)
    assert not request.is_expired(request.expires_at - timedelta(microseconds=1))
    assert request.expired(request.expires_at).is_expired(T0)


@pytest.mark.parametrize("terminal", ["consumed", "denied", "expired", "cancelled"])
def test_terminal_states_take_no_more_steps(terminal: str) -> None:
    request = make_approval(1)
    done = {
        "consumed": lambda: consume(request)[2],
        "denied": lambda: request.denied(T0),
        "expired": lambda: request.expired(request.expires_at),
        "cancelled": lambda: request.cancelled(T0),
    }[terminal]()
    late = done.updated_at
    for step in (done.tapped, done.approved, done.consumed, done.denied, done.cancelled):
        with pytest.raises(InvalidStateError):
            step(late)
    assert not done.state.is_open


def test_transitions_reject_naive_or_earlier_times() -> None:
    tapped = make_approval(1).tapped(T0 + timedelta(seconds=5))
    with pytest.raises(ValidationError):
        tapped.approved(datetime(2026, 1, 1, 12, 1))
    with pytest.raises(ValidationError):
        tapped.approved(T0 + timedelta(seconds=1))


def test_denied_from_tapped_but_not_from_approved() -> None:
    tapped, approved, _ = consume(make_approval(1))
    assert tapped.denied(tapped.updated_at).state is ApprovalState.DENIED
    with pytest.raises(InvalidStateError):
        approved.denied(approved.updated_at)


def test_expired_after_approval_keeps_its_stamps() -> None:
    _, approved, _ = consume(make_approval(1))
    expired = approved.expired(approved.expires_at)
    assert (expired.tapped_at, expired.approved_at) == (approved.tapped_at, approved.approved_at)


def test_check_successor_rules() -> None:
    request = make_approval(1)
    tapped, approved, consumed = consume(request)
    with pytest.raises(InvalidStateError):
        check_successor(consumed, consumed)  # terminal: nothing follows
    with pytest.raises(InvalidStateError):
        check_successor(tapped, request)  # backwards
    with pytest.raises(ValidationError):
        check_successor(request, make_approval(2).tapped(T0))  # another request
    restamped = dataclasses.replace(approved, tapped_at=T0 + timedelta(milliseconds=1500))
    with pytest.raises(ValidationError, match="tapped_at"):
        check_successor(tapped, restamped)
    stale = dataclasses.replace(request.tapped(T0), updated_at=request.updated_at)
    with pytest.raises(ValidationError, match="newer"):
        check_successor(request, stale)


@pytest.mark.parametrize(
    "fields",
    [
        {"state": ApprovalState.PENDING, "tapped_at": T0},
        {"state": ApprovalState.TAPPED},
        {"state": ApprovalState.DENIED},
        {"state": "bogus"},
        {"kind": "bogus"},
        {"updated_at": T0 - timedelta(seconds=1)},
        {"window_id": "w"},
        {"message_id": "m"},
    ],
)
def test_tampered_values_are_refused(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        dataclasses.replace(make_approval(1), **fields)


def test_covers_is_exact() -> None:
    consumed = consume(make_approval(1))[2]
    assert consumed.covers(ActionKind.PR_MERGE, "owner/repo#1")
    assert not consumed.covers(ActionKind.PR_MERGE, "owner/repo#1 ")
    assert not consumed.covers(ActionKind.DEPLOY, "owner/repo#1")
    assert not consume(make_approval(1))[1].covers(ActionKind.PR_MERGE, "owner/repo#1")
    assert not consume(make_flagged(1))[2].covers(ActionKind.PR_MERGE, "owner/repo#1")


def test_targets_are_normalized_once() -> None:
    assert normalize_action_target("  owner/repo#31\n") == "owner/repo#31"
    request = make_approval(1, action_target="  owner/repo#31 ")
    assert request.action_target == "owner/repo#31"
    with pytest.raises(ValidationError):
        normalize_action_target("https://github.com/owner/repo/pull/31")


def test_next_change_at_overflow() -> None:
    request = make_approval(1)
    assert request.next_change_at(T0) == T0 + timedelta(microseconds=1)
    with pytest.raises(ValidationError):
        request.next_change_at(datetime(2026, 1, 1))
