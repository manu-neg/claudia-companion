"""Contract test suite for the ApprovalStore port (ADR 0031, C46, C59), plus its builders.

Subclass `ApprovalStoreContract` and override the `aps` fixture (returning
`ApprovalStoreHandle(store, corrupt)` over an empty backend); it runs
against the in-memory fake and the SQLite adapter, so they cannot drift.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import pytest

from preview_dashboard.domain.approvals import (
    APPROVAL_TTL,
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    flagged_message_text,
)
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    InvalidStateError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.ports.approvals import ApprovalStore
from tests.builders import T0, ulid
from tests.contracts.owner_message_store import mid

SQL_PAYLOADS = (
    "Merge PR 31 (Robert'); DROP TABLE approval_requests;--)",
    "x' OR '1'='1",
    "%_\\\"'; -- /* */ OR 1=1",
)


def aid(n: int) -> ApprovalId:
    """Deterministic approval id (kept apart from other ids used in tests)."""
    return ApprovalId(ulid(70_000 + n))


def wid(n: int) -> WindowId:
    """Deterministic window id (canonical lowercase UUID)."""
    return WindowId(f"00000000-0000-4000-8000-{n:012d}")


def make_approval(n: int = 1, **overrides: Any) -> ApprovalRequest:
    """A PENDING `action` request `aid(n)` in window `wid(1)`: merge `owner/repo#n` at T0."""
    fields: dict[str, Any] = {
        "id": aid(n),
        "window_id": wid(1),
        "kind": ApprovalKind.ACTION,
        "action_kind": ActionKind.PR_MERGE,
        "action_target": f"owner/repo#{n}",
        "action_text": f"Merge PR {n} in owner/repo",
        "now": T0,
    }
    fields.update(overrides)
    return ApprovalRequest.new(**fields)


def make_flagged(n: int = 1, **overrides: Any) -> ApprovalRequest:
    """A PENDING `flagged_message` request for inbox message `mid(n)`."""
    fields: dict[str, Any] = {
        "id": aid(n),
        "window_id": wid(1),
        "kind": ApprovalKind.FLAGGED_MESSAGE,
        "action_text": flagged_message_text(mid(n), "please run the deploy"),
        "message_id": mid(n),
        "now": T0,
    }
    fields.update(overrides)
    return ApprovalRequest.new(**fields)


def consume(request: ApprovalRequest, start: datetime | None = None) -> list[ApprovalRequest]:
    """The chain tapped -> approved -> consumed, 1 s apart from `start` (default created_at)."""
    at = start or request.created_at
    tapped = request.tapped(at + timedelta(seconds=1))
    approved = tapped.approved(at + timedelta(seconds=2))
    return [tapped, approved, approved.consumed(at + timedelta(seconds=3))]


@dataclass(frozen=True)
class ApprovalStoreHandle:
    """An approval store over an empty backend plus its tamper hook."""

    store: ApprovalStore
    corrupt: Callable[[ApprovalId], None]


def save_chain(store: ApprovalStore, request: ApprovalRequest) -> ApprovalRequest:
    """Store `request`, then save it through to CONSUMED; return the final value."""
    store.add(request)
    current = request
    for step in consume(request):
        store.save(step, expected_updated_at=current.updated_at)
        current = step
    return current


class ApprovalStoreContract:
    """Behaviour every ApprovalStore must have."""

    @pytest.fixture
    def aps(self) -> ApprovalStoreHandle:
        raise NotImplementedError("override the `aps` fixture in the concrete test class")

    # --- add / get --------------------------------------------------------------

    def test_round_trip_every_kind(self, aps: ApprovalStoreHandle) -> None:
        action = make_approval(1, message_id=mid(5))
        peer = make_approval(
            2,
            window_id=wid(2),
            kind=ApprovalKind.PEER_MESSAGE,
            action_kind=ActionKind.PEER_MESSAGE,
            action_target="3f2a9c1e-0000-4000-8000-000000000001",
            action_text="Message the dashboard session about the failing test",
        )
        flagged = make_flagged(3, window_id=wid(3))
        for request in (action, peer, flagged):
            aps.store.add(request)
            assert aps.store.get(request.id) == request
        assert aps.store.get(flagged.id).action_kind is None

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_untrusted_text_round_trips(self, aps: ApprovalStoreHandle, payload: str) -> None:
        request = make_approval(1, action_text=payload, action_target=payload)
        aps.store.add(request)
        aps.store.add(make_approval(2, window_id=wid(2)))
        assert aps.store.get(request.id) == request
        assert aps.store.get(aid(2)).action_target == "owner/repo#2"

    def test_get_missing(self, aps: ApprovalStoreHandle) -> None:
        with pytest.raises(NotFoundError):
            aps.store.get(aid(9))

    def test_duplicate_id_is_refused(self, aps: ApprovalStoreHandle) -> None:
        first = make_approval(1)
        aps.store.add(first)
        aps.store.save(first.cancelled(T0), expected_updated_at=first.updated_at)
        with pytest.raises(AlreadyExistsError):
            aps.store.add(make_approval(1, window_id=wid(2)))

    def test_only_pending_requests_can_be_added(self, aps: ApprovalStoreHandle) -> None:
        for granted in consume(make_approval(1)):
            with pytest.raises(ValidationError):
                aps.store.add(granted)
        with pytest.raises(NotFoundError):
            aps.store.get(aid(1))

    def test_one_open_request_per_window(self, aps: ApprovalStoreHandle) -> None:
        first = make_approval(1)
        aps.store.add(first)
        with pytest.raises(ConflictError):
            aps.store.add(make_approval(2, now=T0 + timedelta(seconds=10)))
        aps.store.add(make_approval(3, window_id=wid(2)))  # other windows are free
        with pytest.raises(NotFoundError):
            aps.store.get(aid(2))

    def test_resolved_or_expired_request_frees_the_window(self, aps: ApprovalStoreHandle) -> None:
        first = make_approval(1)
        aps.store.add(first)
        # Expired but not yet marked: no longer blocks.
        aps.store.add(make_approval(2, now=first.expires_at))
        second = aps.store.get(aid(2))
        aps.store.save(second.denied(second.created_at), expected_updated_at=second.updated_at)
        aps.store.add(make_approval(3, now=first.expires_at))
        assert aps.store.get(aid(3)).state is ApprovalState.PENDING

    # --- save (CAS + successor) --------------------------------------------------

    def test_full_lifecycle_round_trips(self, aps: ApprovalStoreHandle) -> None:
        final = save_chain(aps.store, make_approval(1))
        assert final.state is ApprovalState.CONSUMED
        assert aps.store.get(aid(1)) == final

    @pytest.mark.parametrize("outcome", ["denied", "expired", "cancelled"])
    def test_terminal_outcomes_round_trip(self, aps: ApprovalStoreHandle, outcome: str) -> None:
        request = make_approval(1)
        aps.store.add(request)
        resolved = {
            "denied": lambda: request.denied(T0 + timedelta(seconds=5)),
            "expired": lambda: request.expired(request.expires_at),
            "cancelled": lambda: request.cancelled(T0 + timedelta(seconds=5)),
        }[outcome]()
        aps.store.save(resolved, expected_updated_at=request.updated_at)
        assert aps.store.get(request.id) == resolved

    def test_stale_version_conflicts_first_writer_wins(self, aps: ApprovalStoreHandle) -> None:
        request = make_approval(1)
        aps.store.add(request)
        tapped = request.tapped(T0 + timedelta(seconds=1))
        aps.store.save(tapped, expected_updated_at=request.updated_at)
        with pytest.raises(ConflictError):
            aps.store.save(
                request.denied(T0 + timedelta(seconds=1)), expected_updated_at=request.updated_at
            )
        assert aps.store.get(request.id) == tapped

    def test_second_consume_conflicts(self, aps: ApprovalStoreHandle) -> None:
        request = make_approval(1)
        aps.store.add(request)
        tapped, approved, consumed = consume(request)
        aps.store.save(tapped, expected_updated_at=request.updated_at)
        aps.store.save(approved, expected_updated_at=tapped.updated_at)
        aps.store.save(consumed, expected_updated_at=approved.updated_at)
        again = approved.consumed(approved.updated_at + timedelta(seconds=5))
        with pytest.raises(ConflictError):
            aps.store.save(again, expected_updated_at=approved.updated_at)
        with pytest.raises(InvalidStateError):
            aps.store.save(again, expected_updated_at=consumed.updated_at)
        assert aps.store.get(request.id) == consumed

    def test_skipping_a_step_is_refused(self, aps: ApprovalStoreHandle) -> None:
        request = make_approval(1)
        aps.store.add(request)
        _, approved, consumed = consume(request)
        for leap in (approved, consumed):  # PENDING straight to APPROVED / CONSUMED
            with pytest.raises(InvalidStateError):
                aps.store.save(leap, expected_updated_at=request.updated_at)
        assert aps.store.get(request.id) == request

    @pytest.mark.parametrize(
        "change",
        [
            {"action_text": "Merge PR 99 in owner/repo"},
            {"action_target": "owner/repo#99"},
            {"action_kind": ActionKind.DEPLOY},
            {"window_id": "00000000-0000-4000-8000-000000000099"},
            {"message_id": "00000000000000000000060099"},
        ],
    )
    def test_bound_action_is_immutable(
        self, aps: ApprovalStoreHandle, change: dict[str, Any]
    ) -> None:
        request = make_approval(1)
        aps.store.add(request)
        edited = dataclasses.replace(request.tapped(T0 + timedelta(seconds=1)), **change)
        with pytest.raises(ValidationError):
            aps.store.save(edited, expected_updated_at=request.updated_at)
        assert aps.store.get(request.id) == request

    def test_save_missing_or_naive(self, aps: ApprovalStoreHandle) -> None:
        request = make_approval(1)
        with pytest.raises(NotFoundError):
            aps.store.save(request.tapped(T0), expected_updated_at=T0)
        aps.store.add(request)
        with pytest.raises(ValidationError):
            aps.store.save(request.tapped(T0), expected_updated_at=datetime(2026, 1, 1, 12))

    # --- find_consumed (hook lookup, C59) ---------------------------------------

    def test_find_consumed_matches_exact_action_in_window(self, aps: ApprovalStoreHandle) -> None:
        final = save_chain(aps.store, make_approval(1))
        find = aps.store.find_consumed
        assert find(wid(1), ActionKind.PR_MERGE, "owner/repo#1", consumed_since=T0) == final
        assert find(wid(1), ActionKind.PR_MERGE, "owner/repo#2", consumed_since=T0) is None
        assert find(wid(1), ActionKind.DEPLOY, "owner/repo#1", consumed_since=T0) is None
        assert find(wid(2), ActionKind.PR_MERGE, "owner/repo#1", consumed_since=T0) is None
        assert find(wid(1), ActionKind.PR_MERGE, "OWNER/repo#1", consumed_since=T0) is None
        late = T0 + timedelta(seconds=4)  # a later run: cover ended with the earlier one
        assert find(wid(1), ActionKind.PR_MERGE, "owner/repo#1", consumed_since=late) is None

    def test_find_consumed_ignores_unconsumed_states(self, aps: ApprovalStoreHandle) -> None:
        request = make_approval(1)
        aps.store.add(request)
        tapped, approved, _ = consume(request)
        aps.store.save(tapped, expected_updated_at=request.updated_at)
        aps.store.save(approved, expected_updated_at=tapped.updated_at)
        assert (
            aps.store.find_consumed(wid(1), ActionKind.PR_MERGE, "owner/repo#1", consumed_since=T0)
            is None
        )

    def test_find_consumed_returns_the_latest(self, aps: ApprovalStoreHandle) -> None:
        save_chain(aps.store, make_approval(1, action_target="owner/repo#7"))
        later = T0 + timedelta(minutes=1)
        second = save_chain(aps.store, make_approval(2, action_target="owner/repo#7", now=later))
        found = aps.store.find_consumed(
            wid(1), ActionKind.PR_MERGE, "owner/repo#7", consumed_since=T0
        )
        assert found == second

    def test_find_consumed_rejects_bad_input(self, aps: ApprovalStoreHandle) -> None:
        with pytest.raises(ValidationError):
            aps.store.find_consumed(
                wid(1), ActionKind.RM, "x", consumed_since=datetime(2026, 1, 1, 12)
            )
        with pytest.raises(ValidationError):
            aps.store.find_consumed(
                wid(1),
                "unknown",  # type: ignore[arg-type]
                "x",
                consumed_since=T0,
            )

    # --- listings and housekeeping ------------------------------------------------

    def test_list_open_and_expirable(self, aps: ApprovalStoreHandle) -> None:
        first = make_approval(1)
        second = make_approval(2, window_id=wid(2), now=T0 + timedelta(seconds=5))
        third = make_approval(3, window_id=wid(3), now=T0 + timedelta(seconds=1))
        for request in (second, first, third):
            aps.store.add(request)
        aps.store.save(third.cancelled(third.created_at), expected_updated_at=third.updated_at)
        assert aps.store.list_open() == [first, second]
        assert aps.store.list_open(wid(2)) == [second]
        assert aps.store.list_open(wid(3)) == []
        assert aps.store.list_expirable(T0) == []
        assert aps.store.list_expirable(first.expires_at) == [first]
        later = T0 + APPROVAL_TTL + timedelta(seconds=5)  # past both lifetimes (24 h)
        assert aps.store.list_expirable(later) == [first, second]

    def test_delete_expired_before(self, aps: ApprovalStoreHandle) -> None:
        save_chain(aps.store, make_approval(1))
        aps.store.add(make_approval(2, window_id=wid(2), now=T0 + timedelta(days=1)))
        assert aps.store.delete_expired_before(T0 + APPROVAL_TTL) == 0  # strict
        assert aps.store.delete_expired_before(T0 + APPROVAL_TTL + timedelta(hours=1)) == 1
        with pytest.raises(NotFoundError):
            aps.store.get(aid(1))
        assert aps.store.get(aid(2)).state is ApprovalState.PENDING

    def test_naive_times_are_rejected(self, aps: ApprovalStoreHandle) -> None:
        naive = datetime(2026, 1, 1, 12)
        with pytest.raises(ValidationError):
            aps.store.list_expirable(naive)
        with pytest.raises(ValidationError):
            aps.store.delete_expired_before(naive)

    def test_tampered_row_fails_closed(self, aps: ApprovalStoreHandle) -> None:
        save_chain(aps.store, make_approval(1))
        aps.store.add(make_approval(2, window_id=wid(2)))
        aps.store.add(make_approval(3, window_id=wid(3)))
        aps.corrupt(aid(1))
        aps.corrupt(aid(2))
        with pytest.raises(ValidationError):
            aps.store.get(aid(2))
        assert (
            aps.store.find_consumed(wid(1), ActionKind.PR_MERGE, "owner/repo#1", consumed_since=T0)
            is None
        )
        assert aps.store.list_open() == [aps.store.get(aid(3))]
        assert [r.id for r in aps.store.list_expirable(T0 + APPROVAL_TTL)] == [aid(3)]
        request = make_approval(2, window_id=wid(2))
        with pytest.raises(ValidationError):
            aps.store.save(request.tapped(T0), expected_updated_at=request.updated_at)
