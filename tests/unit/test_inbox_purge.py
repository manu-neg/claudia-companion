"""Unit tests for the inbox step of `PurgeService.run` (ADR 0031, C44 30-day retention)."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from preview_dashboard.application.approvals import ApprovalService
from preview_dashboard.application.purge import InboxHousekeeping, PurgeService
from preview_dashboard.domain.approvals import APPROVAL_TTL, ApprovalRequest, ApprovalState
from tests.builders import T0
from tests.contracts.approval_store import make_approval, wid
from tests.contracts.owner_message_store import make_message
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryApprovalStore,
    InMemoryBlobStore,
    InMemoryItemRepository,
    InMemoryOwnerMessageStore,
    SequentialIdGenerator,
)

pytestmark = pytest.mark.unit


def _purge(inbox: InboxHousekeeping | None, compacted: list[int]) -> PurgeService:
    return PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(),
        clock=FixedClock(T0 + timedelta(days=31)),
        retention=timedelta(days=30),
        orphan_grace=timedelta(hours=1),
        post_purge=(lambda: compacted.append(1),),
        inbox=inbox,
    )


def test_old_messages_and_approvals_go_recent_ones_stay() -> None:
    messages, approvals = InMemoryOwnerMessageStore(), InMemoryApprovalStore()
    messages.add(make_message(1))
    messages.add(make_message(2, received_at=T0 + timedelta(days=2)))
    # Approvals go once they expired before the cutoff (24 h after creation, F-CL3).
    approvals.add(make_approval(1, now=T0 - timedelta(days=1)))
    approvals.add(make_approval(2, window_id=wid(2), now=T0 + timedelta(days=2)))
    compacted: list[int] = []
    report = _purge(InboxHousekeeping(messages=messages, approvals=approvals), compacted).run()
    assert (report.inbox_deleted, report.approvals_deleted, report.inbox_failed) == (1, 1, False)
    assert (messages.count(), approvals.count()) == (1, 1)
    assert compacted == [1]


def test_nothing_configured_or_nothing_old_does_nothing() -> None:
    compacted: list[int] = []
    report = _purge(None, compacted).run()
    assert (report.inbox_deleted, report.approvals_deleted, report.inbox_failed) == (0, 0, False)
    empty = InboxHousekeeping(
        messages=InMemoryOwnerMessageStore(), approvals=InMemoryApprovalStore()
    )
    assert _purge(empty, compacted).run().inbox_deleted == 0
    assert compacted == []


class _Broken(InMemoryOwnerMessageStore):
    def delete_received_before(self, cutoff: datetime) -> int:
        raise RuntimeError("secret text must not be logged")


def test_failure_is_contained_and_logged_by_type(caplog: pytest.LogCaptureFixture) -> None:
    compacted: list[int] = []
    inbox = InboxHousekeeping(messages=_Broken(), approvals=InMemoryApprovalStore())
    report = _purge(inbox, compacted).run()
    assert report.inbox_failed is True
    assert compacted == [1]
    assert "RuntimeError" in caplog.text
    assert "secret text" not in caplog.text


class _NoPrompts:
    def prompt(self, request: ApprovalRequest) -> None:
        raise AssertionError("purge never creates requests")


def test_s12_overdue_open_request_is_expired_by_purge() -> None:
    # S-C1 S12: an open request nobody touches again becomes EXPIRED hourly.
    clock = FixedClock(T0 + APPROVAL_TTL + timedelta(minutes=5))
    approvals, messages = InMemoryApprovalStore(), InMemoryOwnerMessageStore()
    overdue = make_approval(1)
    fresh = make_approval(2, window_id=wid(2), now=clock.now())
    approvals.add(overdue)
    approvals.add(fresh)
    service = ApprovalService(
        store=approvals,
        messages=messages,
        clock=clock,
        ids=SequentialIdGenerator(),
        scanner=FakeContentScanner(),
        prompts=_NoPrompts(),
    )
    purge = PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(),
        clock=clock,
        retention=timedelta(days=30),
        orphan_grace=timedelta(hours=1),
        inbox=InboxHousekeeping(
            messages=messages, approvals=approvals, expire_due=service.expire_due
        ),
    )
    report = purge.run()
    assert (report.approvals_expired, report.approvals_deleted) == (1, 0)
    assert approvals.get(overdue.id).state is ApprovalState.EXPIRED
    assert approvals.get(fresh.id).state is ApprovalState.PENDING
    assert purge.run().approvals_expired == 0  # idempotent


def test_retention_must_be_positive() -> None:
    with pytest.raises(ValueError):
        InboxHousekeeping(
            messages=InMemoryOwnerMessageStore(),
            approvals=InMemoryApprovalStore(),
            retention=timedelta(0),
        )
