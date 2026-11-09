"""Behavior of the in-memory question repository + outbox fakes (the reference for N2's contracts).

The shared port-contract suites (unit N2, `tests/contracts/`) will run the
same checks against SQLite; these pin the fakes' semantics until then.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryState,
    DeliveryTask,
    Notification,
)
from preview_dashboard.domain.questions import Question, QuestionState
from preview_dashboard.ports.notify import NotificationOutbox, OutboxEvents
from preview_dashboard.ports.questions import QuestionEvents, QuestionRepository
from tests.builders import T0
from tests.fakes import (
    FakeOutboxEvents,
    FakeQuestionEvents,
    InMemoryNotificationOutbox,
    InMemoryQuestionRepository,
)
from tests.notify_support import make_notification, make_question, make_task, nid, qid, tid

pytestmark = pytest.mark.unit


def test_fakes_satisfy_ports_statically() -> None:
    outbox: NotificationOutbox = InMemoryNotificationOutbox()
    repo: QuestionRepository = InMemoryQuestionRepository()
    del outbox, repo


@pytest.fixture
def repo() -> InMemoryQuestionRepository:
    return InMemoryQuestionRepository()


def _question_rows(
    repo: InMemoryQuestionRepository, n: int = 1, *, tasks: int = 1
) -> tuple[Question, Notification, list[DeliveryTask]]:
    question = make_question(n)
    notification = make_notification(n, event_type="question", question_id=question.id)
    rows = [make_task(n * 10 + i, notification=n, channel=f"c{i}") for i in range(tasks)]
    repo.add_with_notification(question, notification, rows)
    return question, notification, rows


# --- QuestionRepository ------------------------------------------------------------


def test_add_with_notification_round_trip(repo: InMemoryQuestionRepository) -> None:
    question, notification, tasks = _question_rows(repo, tasks=2)
    assert repo.get(question.id) == question
    assert repo.outbox.notification_for_question(question.id) == notification
    assert repo.outbox.tasks_of(notification.id) == tasks


def test_add_with_notification_is_all_or_nothing(repo: InMemoryQuestionRepository) -> None:
    question = make_question()
    notification = make_notification(event_type="question", question_id=question.id)
    dup = [make_task(1), make_task(1, channel="other")]
    with pytest.raises(AlreadyExistsError):
        repo.add_with_notification(question, notification, dup)
    assert repo.count() == 0
    assert repo.outbox.notifications == {}
    _question_rows(repo)
    with pytest.raises(AlreadyExistsError):
        _question_rows(repo)


def test_add_with_notification_checks_ownership(repo: InMemoryQuestionRepository) -> None:
    question = make_question()
    with pytest.raises(ValidationError):
        repo.add_with_notification(question, make_notification(question_id=qid(2)), [])
    notification = make_notification(question_id=question.id)
    with pytest.raises(ValidationError):
        repo.add_with_notification(question, notification, [make_task(notification=2)])


def test_save_is_compare_and_swap_with_tasks(repo: InMemoryQuestionRepository) -> None:
    question, notification, _ = _question_rows(repo)
    at = T0 + timedelta(minutes=1)
    answered = question.answered("a", "telegram", at)
    resolve = make_task(
        5, action=DeliveryAction.RESOLVE, final_state=QuestionState.ANSWERED, created_at=at
    )
    repo.save(answered, expected_updated_at=question.updated_at, tasks=[resolve])
    assert repo.get(question.id) == answered
    assert repo.outbox.tasks_of(notification.id)[-1] == resolve
    with pytest.raises(ConflictError):
        repo.save(question.cancelled(at), expected_updated_at=question.updated_at)
    with pytest.raises(NotFoundError):
        repo.save(make_question(9), expected_updated_at=T0)


def test_save_rejects_foreign_tasks_and_writes_nothing(repo: InMemoryQuestionRepository) -> None:
    question, _, _ = _question_rows(repo)
    _question_rows(repo, 2)
    cancelled = question.cancelled(T0 + timedelta(seconds=1))
    foreign = make_task(
        7, notification=2, action=DeliveryAction.RESOLVE, final_state=QuestionState.CANCELLED
    )
    with pytest.raises(ValidationError):
        repo.save(cancelled, expected_updated_at=question.updated_at, tasks=[foreign])
    missing = make_task(
        8, notification=99, action=DeliveryAction.RESOLVE, final_state=QuestionState.CANCELLED
    )
    with pytest.raises(ValidationError):
        repo.save(cancelled, expected_updated_at=question.updated_at, tasks=[missing])
    assert repo.get(question.id) == question


def test_list_expirable_and_delete_resolved(repo: InMemoryQuestionRepository) -> None:
    soon = make_question(1, expires_at=T0 + timedelta(minutes=1))
    later = make_question(2, expires_at=T0 + timedelta(minutes=2))
    for n, q in ((2, later), (1, soon)):
        repo.add_with_notification(q, make_notification(n, question_id=q.id), [])
    assert repo.list_expirable(T0) == []
    assert repo.list_expirable(T0 + timedelta(minutes=1)) == [soon]  # boundary inclusive
    assert repo.list_expirable(T0 + timedelta(hours=1)) == [soon, later]
    expired = soon.expired(soon.expires_at)
    repo.save(expired, expected_updated_at=soon.updated_at)
    assert repo.list_expirable(T0 + timedelta(hours=1)) == [later]
    assert repo.delete_resolved_before(expired.expires_at) == 0  # strictly before
    assert repo.delete_resolved_before(expired.expires_at + timedelta(microseconds=1)) == 1
    assert repo.count() == 1  # the OPEN one is never deleted


# --- NotificationOutbox ---------------------------------------------------------------


@pytest.fixture
def outbox() -> InMemoryNotificationOutbox:
    return InMemoryNotificationOutbox()


def test_add_rejects_question_notifications(outbox: InMemoryNotificationOutbox) -> None:
    with pytest.raises(ValidationError):
        outbox.add(make_notification(question_id=qid(1)), [])
    with pytest.raises(ValidationError):
        outbox.add(make_notification(1), [make_task(notification=2)])
    outbox.add(make_notification(1), [make_task(1)])
    with pytest.raises(AlreadyExistsError):
        outbox.add(make_notification(2), [make_task(1, notification=2)])
    assert nid(2) not in outbox.notifications


def test_pending_order_limit_and_due_time(outbox: InMemoryNotificationOutbox) -> None:
    outbox.add(make_notification(1), [make_task(1, next_attempt_at=T0 + timedelta(seconds=5))])
    outbox.add(make_notification(2), [make_task(2, notification=2)])
    outbox.add(make_notification(3), [make_task(3, notification=3)])
    assert [p.id for p in outbox.pending(T0, 10)] == [tid(2), tid(3)]
    assert [p.id for p in outbox.pending(T0 + timedelta(seconds=5), 2)] == [tid(2), tid(3)]
    assert [p.id for p in outbox.pending(T0 + timedelta(seconds=5), 10)] == [
        tid(2),
        tid(3),
        tid(1),
    ]
    for bad in (0, 101):
        with pytest.raises(ValidationError):
            outbox.pending(T0, bad)


def _resolve_setup(
    repo: InMemoryQuestionRepository,
) -> tuple[Question, DeliveryTask, DeliveryTask]:
    question, _, (send,) = _question_rows(repo)
    at = T0 + timedelta(seconds=1)
    cancelled = question.cancelled(at)
    resolve = make_task(
        2, action=DeliveryAction.RESOLVE, final_state=QuestionState.CANCELLED, channel="c0"
    )
    repo.save(cancelled, expected_updated_at=question.updated_at, tasks=[resolve])
    return question, send, resolve


def test_resolve_waits_for_its_send_then_carries_its_ref(repo: InMemoryQuestionRepository) -> None:
    question, _, (send,) = _question_rows(repo)
    outbox = repo.outbox
    # Handed out while the question is open (in flight), resolved before it is reported.
    assert [p.id for p in outbox.pending(T0, 10)] == [send.id]
    resolve = make_task(
        2, action=DeliveryAction.RESOLVE, final_state=QuestionState.CANCELLED, channel="c0"
    )
    repo.save(
        question.cancelled(T0 + timedelta(seconds=1)),
        expected_updated_at=question.updated_at,
        tasks=[resolve],
    )
    outbox.mark_done(send.id, "chat:7")
    (pending,) = outbox.pending(T0, 10)
    assert (pending.id, pending.action, pending.message_ref) == (
        resolve.id,
        DeliveryAction.RESOLVE,
        "chat:7",
    )
    assert pending.payload.question_id == question.id
    assert pending.payload.final_state is QuestionState.CANCELLED
    assert outbox.message_ref_for(question.id, "c0") == "chat:7"
    assert outbox.message_ref_for(question.id, "other") is None


@pytest.mark.parametrize("send_outcome", ["failed", "done-without-ref"])
def test_resolve_dropped_when_nothing_to_edit(
    repo: InMemoryQuestionRepository, send_outcome: str
) -> None:
    _, send, resolve = _resolve_setup(repo)
    outbox = repo.outbox
    if send_outcome == "failed":
        now = T0
        for _ in range(8):
            now += timedelta(hours=1)
            outbox.mark_failed(send.id, now=now)
    else:
        outbox.mark_done(send.id, None)
    assert outbox.pending(T0 + timedelta(days=1), 10) == []
    assert outbox.get_task(resolve.id).state is DeliveryState.FAILED


def test_mark_done_and_failed_are_idempotent(outbox: InMemoryNotificationOutbox) -> None:
    outbox.add(make_notification(1), [make_task(1)])
    done = outbox.mark_done(tid(1), "m1")
    assert outbox.mark_done(tid(1), "m2") == done
    assert outbox.mark_failed(tid(1), now=T0) == done
    with pytest.raises(NotFoundError):
        outbox.mark_failed(tid(9), now=T0)
    with pytest.raises(NotFoundError):
        outbox.get_task(tid(9))


def test_delete_before_removes_notifications_with_their_tasks(
    outbox: InMemoryNotificationOutbox,
) -> None:
    outbox.add(make_notification(1), [make_task(1)])
    outbox.add(
        make_notification(2, created_at=T0 + timedelta(days=1)), [make_task(2, notification=2)]
    )
    assert outbox.delete_before(T0) == 0
    assert outbox.delete_before(T0 + timedelta(hours=1)) == 1
    assert set(outbox.notifications) == {nid(2)}
    assert set(outbox.tasks) == {tid(2)}


# --- wake-up fakes (async; the real adapters are unit N3's) -------------------------


async def test_fake_question_events_wake_waiters() -> None:
    events = FakeQuestionEvents()
    waiter = asyncio.create_task(events.wait(qid(1), timeout=5))
    await asyncio.sleep(0)
    events.notify(qid(2))
    events.notify(qid(1))
    assert await waiter is True
    assert await events.wait(qid(1), timeout=0.01) is False
    assert events.notified == [qid(2), qid(1)]


async def test_fake_outbox_events_wake_waiters() -> None:
    events = FakeOutboxEvents()
    waiter = asyncio.create_task(events.wait(timeout=5))
    await asyncio.sleep(0)
    events.notify()
    assert await waiter is True
    assert await events.wait(timeout=0.01) is False
    assert events.notified == 1


def test_wake_up_fakes_satisfy_ports_statically() -> None:
    question_events: QuestionEvents = FakeQuestionEvents()
    outbox_events: OutboxEvents = FakeOutboxEvents()
    del question_events, outbox_events
