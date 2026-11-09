"""Unit tests for the purge job's question housekeeping (expire due, delete after 30 days)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import pytest

from preview_dashboard.application import PurgeService, QuestionHousekeeping
from preview_dashboard.application.questions import AskCommand
from preview_dashboard.domain.models import Item
from preview_dashboard.domain.questions import QuestionState
from tests.builders import T0, make_file, make_item
from tests.fakes import InMemoryBlobStore, InMemoryItemRepository
from tests.notify_support import NotifyHarness, build_harness

pytestmark = pytest.mark.unit

ASK = AskCommand(
    session_label="s1", prompt="Which DB?", options=[("a", "SQLite"), ("b", "Postgres")]
)


def _purge(h: NotifyHarness, hooks: list[str] | None = None) -> PurgeService:
    calls = hooks if hooks is not None else []
    return PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(clock=h.clock),
        clock=h.clock,
        retention=timedelta(days=14),
        orphan_grace=timedelta(hours=1),
        post_purge=[lambda: calls.append("compact")],
        questions=QuestionHousekeeping(
            expire_due=h.questions.expire_due, questions=h.repo, outbox=h.outbox
        ),
    )


def test_purge_expires_due_questions() -> None:
    h = build_harness()
    q = h.questions.ask(ASK)
    h.clock.advance(timedelta(hours=25))
    report = _purge(h).run()
    assert report.questions_expired == 1
    assert h.repo.get(q.id).state is QuestionState.EXPIRED


def test_purge_deletes_after_thirty_days() -> None:
    h = build_harness()
    answered = h.questions.ask(ASK)
    h.notify.notify("done", "ok")
    h.clock.advance(timedelta(minutes=1))
    h.questions.answer(answered.id, "a", "telegram")  # resolved at T0 + 1 min
    hooks: list[str] = []
    purge = _purge(h, hooks)

    h.clock.set(T0 + timedelta(days=30))
    report = purge.run()
    assert (report.questions_deleted, report.notifications_deleted) == (0, 0)
    assert hooks == []

    # Notifications (created at T0) go first; the question follows once
    # its resolution is 30 days old.
    h.clock.set(T0 + timedelta(days=30, microseconds=1))
    report = purge.run()
    assert (report.questions_deleted, report.notifications_deleted) == (0, 2)
    assert h.outbox.notifications == {}
    assert h.outbox.tasks == {}
    assert hooks == ["compact"]  # rows went away: checkpoint the WAL

    h.clock.set(T0 + timedelta(days=30, minutes=1, microseconds=1))
    assert purge.run().questions_deleted == 1
    assert h.repo.count() == 0


def test_open_question_survives_until_expired_then_retention() -> None:
    h = build_harness()
    h.questions.ask(
        AskCommand(
            session_label="s1", prompt="p", options=ASK.options, expires_in=timedelta(days=7)
        )
    )
    h.clock.set(T0 + timedelta(days=36))
    report = _purge(h).run()
    # Expired just now: resolved today, so it is kept for another 30 days.
    assert (report.questions_expired, report.questions_deleted) == (1, 0)
    assert h.repo.count() == 1


def test_purge_without_housekeeping_reports_zeros() -> None:
    h = build_harness()
    purge = PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(clock=h.clock),
        clock=h.clock,
        retention=timedelta(days=14),
        orphan_grace=timedelta(hours=1),
    )
    report = purge.run()
    assert (report.questions_expired, report.questions_deleted, report.notifications_deleted) == (
        0,
        0,
        0,
    )


def test_housekeeping_retention_must_be_positive() -> None:
    h = build_harness()
    with pytest.raises(ValueError, match="retention"):
        QuestionHousekeeping(
            expire_due=h.questions.expire_due,
            questions=h.repo,
            outbox=h.outbox,
            retention=timedelta(0),
        )


def _failing_expire_due(_now: datetime) -> int:
    raise RuntimeError("row 42: prompt 'secret stuff' is invalid")


def test_failing_housekeeping_cannot_block_the_trash_purge(
    caplog: pytest.LogCaptureFixture,
) -> None:
    h = build_harness()
    items = InMemoryItemRepository()
    blobs = InMemoryBlobStore(clock=h.clock)
    ref = blobs.put([b"x"], max_bytes=10)
    file = make_file(blob_id=ref.blob_id, size=ref.size, sha256=ref.sha256)
    items.add(make_item(1, files=(file,)).trashed(T0))
    calls: list[str] = []

    def staging() -> int:
        calls.append("staging")
        return 0

    purge = PurgeService(
        repo=items,
        blobs=blobs,
        clock=h.clock,
        retention=timedelta(days=14),
        orphan_grace=timedelta(hours=1),
        maintenance={"staging": staging},
        post_purge=[lambda: calls.append("compact")],
        questions=QuestionHousekeeping(
            expire_due=_failing_expire_due, questions=h.repo, outbox=h.outbox
        ),
    )
    h.clock.set(T0 + timedelta(days=15))
    with caplog.at_level(logging.ERROR):
        report = purge.run()
    assert (report.items_purged, report.blobs_deleted) == (1, 1)
    assert report.questions_failed is True
    assert (report.questions_expired, report.questions_deleted) == (0, 0)
    assert calls == ["staging", "compact"]
    # Exception type only: its text may quote stored content.
    assert "RuntimeError" in caplog.text
    assert "secret stuff" not in caplog.text


class _OrderedItems(InMemoryItemRepository):
    """Records when the item purge lists its candidates."""

    def __init__(self, order: list[str]) -> None:
        super().__init__()
        self._order = order

    def list_purgeable(self, now: datetime, retention: timedelta) -> list[Item]:
        self._order.append("items")
        return super().list_purgeable(now, retention)


def test_housekeeping_runs_after_the_item_purge() -> None:
    h = build_harness()
    order: list[str] = []

    def expire_due(_now: datetime) -> int:
        order.append("questions")
        return 0

    report = PurgeService(
        repo=_OrderedItems(order),
        blobs=InMemoryBlobStore(clock=h.clock),
        clock=h.clock,
        retention=timedelta(days=14),
        orphan_grace=timedelta(hours=1),
        questions=QuestionHousekeeping(expire_due=expire_due, questions=h.repo, outbox=h.outbox),
    ).run()
    assert order == ["items", "questions"]
    assert report.questions_failed is False
