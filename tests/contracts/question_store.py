"""Contract test suites for the QuestionRepository and NotificationOutbox ports (ADR 0021).

Both ports share one store, so each suite takes a `store` fixture returning a
`NotifyStore(repo, outbox)` over the same empty backend. Subclass
`QuestionRepositoryContract` / `NotificationOutboxContract` and override
`store`; they run against the in-memory fakes and the SQLite adapter, so the
two cannot drift. Only port methods are used, plus the store's two
`corrupt_*` hooks that simulate a tampered row.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

import pytest

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.models import ItemId
from preview_dashboard.domain.notifications import (
    BACKOFF_FIRST,
    MAX_DELIVERY_ATTEMPTS,
    DeliveryAction,
    DeliveryState,
    DeliveryTask,
    MessageContent,
    Notification,
    TaskId,
)
from preview_dashboard.domain.questions import Question, QuestionId, QuestionOption, QuestionState
from preview_dashboard.ports.notify import NotificationOutbox
from preview_dashboard.ports.questions import QuestionRepository
from tests.builders import T0, ulid
from tests.notify_support import (
    DASHBOARD,
    make_content,
    make_notification,
    make_options,
    make_question,
    make_task,
    qid,
    tid,
)

# SQL metacharacters and other hostile-but-valid text: must round-trip as data (C24).
SQL_PAYLOADS = (
    "Robert'); DROP TABLE questions;--",
    "x' OR '1'='1",
    "%_\\\"'; -- /* */ OR 1=1",
    "'||(SELECT sql FROM sqlite_master)||'",
)


@dataclass(frozen=True)
class NotifyStore:
    """A question repository and an outbox over one shared (empty) store.

    `corrupt_task` / `corrupt_question` make one stored row fail
    re-validation from now on (a tampered row), the backend's own way.
    """

    repo: QuestionRepository
    outbox: NotificationOutbox
    corrupt_task: Callable[[TaskId], None]
    corrupt_question: Callable[[QuestionId], None]


def add_question(
    store: NotifyStore,
    n: int = 1,
    *,
    channels: tuple[str, ...] = ("c0",),
    question: Question | None = None,
) -> tuple[Question, Notification, list[DeliveryTask]]:
    """Store question `n` with its notification `nid(n)` and one SEND per channel."""
    question = question or make_question(n)
    notification = make_notification(n, event_type="question", question_id=question.id)
    content = make_content("❓ pick", buttons=[(o.key, o.label) for o in question.options])
    tasks = [
        make_task(n * 10 + i, notification=n, channel=c, content=content)
        for i, c in enumerate(channels)
    ]
    store.repo.add_with_notification(question, notification, tasks)
    return question, notification, tasks


def resolve_task(n: int, *, notification: int = 1, **overrides: object) -> DeliveryTask:
    """A PENDING RESOLVE `tid(n)` (CANCELLED outcome by default) on channel `c0`."""
    fields: dict[str, object] = {
        "action": DeliveryAction.RESOLVE,
        "final_state": QuestionState.CANCELLED,
        "channel": "c0",
        "content": make_content("🚫 Withdrawn"),
    }
    fields.update(overrides)
    return make_task(n, notification=notification, **fields)


class QuestionRepositoryContract:
    """Behaviour every QuestionRepository (plus its shared outbox) must have."""

    @pytest.fixture
    def store(self) -> NotifyStore:
        raise NotImplementedError("override the `store` fixture in the concrete test class")

    # --- add_with_notification / get ------------------------------------------

    def test_round_trip_with_every_field(self, store: NotifyStore) -> None:
        question = make_question(
            1,
            prompt="Which DB? ✓ Ünïcode",
            options=make_options("SQLite", "Postgres", "Neither — later"),
            default_key="b",
            item_id=ItemId(ulid(7)),
            session_label="repo: dashboard",
            created_at=T0.replace(microsecond=123456),
            expires_at=T0 + timedelta(days=7),
            updated_at=T0 + timedelta(microseconds=123457),
        )
        _, notification, tasks = add_question(store, question=question, channels=("c0", "c1"))
        assert store.repo.get(question.id) == question
        assert store.outbox.notification_for_question(question.id) == notification
        for task in tasks:
            assert store.outbox.get_task(task.id) == task
        assert store.repo.get(question.id).options == question.options  # order kept

    def test_option_order_is_kept(self, store: NotifyStore) -> None:
        options = tuple(QuestionOption(key=k, label=k.upper()) for k in "hgfedcba")
        question, _, _ = add_question(store, question=make_question(1, options=options))
        assert [o.key for o in store.repo.get(question.id).options] == list("hgfedcba")

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_untrusted_text_round_trips(self, store: NotifyStore, payload: str) -> None:
        question = make_question(
            1,
            prompt="P " + payload,
            options=(
                QuestionOption(key="a", label=("L " + payload)[:40]),
                QuestionOption(key="b", label="plain"),
            ),
            session_label=("S " + payload)[:40],
        )
        _, notification, _ = add_question(store, question=question)
        add_question(store, 2)
        assert store.repo.get(question.id) == question
        assert store.outbox.notification_for_question(question.id) == notification
        assert store.repo.get(qid(2)).prompt == "Question 2?"

    def test_non_utc_input_round_trips_as_same_instant(self, store: NotifyStore) -> None:
        tz = timezone(timedelta(hours=5))
        question = make_question(
            1,
            created_at=T0.astimezone(tz),
            expires_at=(T0 + timedelta(hours=1)).astimezone(tz),
            updated_at=T0.astimezone(tz),
        )
        add_question(store, question=question)
        got = store.repo.get(question.id)
        assert got.created_at == T0
        assert got.created_at.tzinfo == UTC

    def test_get_missing_raises_not_found(self, store: NotifyStore) -> None:
        with pytest.raises(NotFoundError):
            store.repo.get(qid(9))

    def test_duplicate_question_raises_and_keeps_the_original(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        other = make_question(1, prompt="Other?")
        notification = make_notification(2, event_type="question", question_id=other.id)
        with pytest.raises(AlreadyExistsError):
            store.repo.add_with_notification(other, notification, [])
        assert store.repo.get(question.id) == question

    def test_duplicate_task_ids_store_nothing(self, store: NotifyStore) -> None:
        question = make_question()
        notification = make_notification(event_type="question", question_id=question.id)
        dup = [make_task(1), make_task(1, channel="other")]
        with pytest.raises(AlreadyExistsError):
            store.repo.add_with_notification(question, notification, dup)
        self._assert_nothing_stored(store, question)
        add_question(store)  # the same ids are still free

    def test_existing_task_id_stores_nothing(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(5), [make_task(1, notification=5)])
        question = make_question()
        notification = make_notification(1, event_type="question", question_id=question.id)
        with pytest.raises(AlreadyExistsError):
            store.repo.add_with_notification(question, notification, [make_task(1)])
        self._assert_nothing_stored(store, question)

    def test_existing_notification_id_stores_nothing(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [])
        question = make_question()
        notification = make_notification(1, event_type="question", question_id=question.id)
        with pytest.raises(AlreadyExistsError):
            store.repo.add_with_notification(question, notification, [make_task(2)])
        self._assert_nothing_stored(store, question)
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(2))

    def test_ownership_is_checked(self, store: NotifyStore) -> None:
        question = make_question()
        with pytest.raises(ValidationError):
            store.repo.add_with_notification(question, make_notification(question_id=qid(2)), [])
        with pytest.raises(ValidationError):
            store.repo.add_with_notification(question, make_notification(), [])
        notification = make_notification(question_id=question.id)
        with pytest.raises(ValidationError):
            store.repo.add_with_notification(question, notification, [make_task(notification=2)])
        self._assert_nothing_stored(store, question)

    @staticmethod
    def _assert_nothing_stored(store: NotifyStore, question: Question) -> None:
        with pytest.raises(NotFoundError):
            store.repo.get(question.id)
        assert store.outbox.notification_for_question(question.id) is None
        pending = store.outbox.pending(T0 + timedelta(days=1), 100)
        assert all(p.payload.question_id != question.id for p in pending)

    # --- save (compare-and-swap) ---------------------------------------------

    def test_save_answer_with_resolve_task(self, store: NotifyStore) -> None:
        question, notification, _ = add_question(store)
        at = T0 + timedelta(minutes=1)
        answered = question.answered("a", "telegram", at)
        resolve = resolve_task(5, final_state=QuestionState.ANSWERED, created_at=at)
        store.repo.save(answered, expected_updated_at=question.updated_at, tasks=[resolve])
        assert store.repo.get(question.id) == answered
        assert store.outbox.get_task(resolve.id) == resolve
        assert store.outbox.notification_for_question(question.id) == notification

    @pytest.mark.parametrize("outcome", ["answered", "expired", "cancelled"])
    def test_every_outcome_round_trips(self, store: NotifyStore, outcome: str) -> None:
        question, _, _ = add_question(store)
        resolved = {
            "answered": lambda: question.answered("b", "telegram", T0 + timedelta(seconds=1)),
            "expired": lambda: question.expired(question.expires_at + timedelta(seconds=3)),
            "cancelled": lambda: question.cancelled(T0 + timedelta(seconds=2)),
        }[outcome]()
        store.repo.save(resolved, expected_updated_at=question.updated_at)
        assert store.repo.get(question.id) == resolved

    def test_stale_version_conflicts_and_writes_nothing(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        at = T0 + timedelta(minutes=1)
        answered = question.answered("a", "telegram", at)
        store.repo.save(answered, expected_updated_at=question.updated_at)
        late = resolve_task(6, created_at=at)
        with pytest.raises(ConflictError):
            store.repo.save(
                question.cancelled(at), expected_updated_at=question.updated_at, tasks=[late]
            )
        assert store.repo.get(question.id) == answered
        with pytest.raises(NotFoundError):
            store.outbox.get_task(late.id)

    def test_save_missing_raises_not_found(self, store: NotifyStore) -> None:
        with pytest.raises(NotFoundError):
            store.repo.save(make_question(9), expected_updated_at=T0)

    def test_save_naive_expected_version_is_rejected(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        with pytest.raises(ValidationError):
            store.repo.save(question, expected_updated_at=datetime(2026, 1, 1, 12))

    def test_save_rejects_foreign_or_missing_notification(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        add_question(store, 2)
        store.outbox.add(make_notification(3), [])
        cancelled = question.cancelled(T0 + timedelta(seconds=1))
        for owner in (2, 3, 99):  # another question's, a non-question one, none at all
            with pytest.raises(ValidationError):
                store.repo.save(
                    cancelled,
                    expected_updated_at=question.updated_at,
                    tasks=[resolve_task(7, notification=owner)],
                )
        assert store.repo.get(question.id) == question
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(7))

    def test_save_with_existing_task_id_writes_nothing(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        cancelled = question.cancelled(T0 + timedelta(seconds=1))
        clash = resolve_task(10)  # add_question(1) gave its SEND tid(10)
        assert clash.id == send.id
        with pytest.raises(AlreadyExistsError):
            store.repo.save(cancelled, expected_updated_at=question.updated_at, tasks=[clash])
        assert store.repo.get(question.id) == question
        assert store.outbox.get_task(send.id) == send

    def test_saved_version_is_the_next_expected_one(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        cancelled = question.cancelled(T0 + timedelta(seconds=1))
        store.repo.save(cancelled, expected_updated_at=question.updated_at)
        # Whole-value replace is allowed with the new version; the old one conflicts.
        store.repo.save(cancelled, expected_updated_at=cancelled.updated_at)
        with pytest.raises(ConflictError):
            store.repo.save(cancelled, expected_updated_at=question.updated_at)

    # --- list_expirable / delete_resolved_before -------------------------------

    def test_list_expirable_order_and_boundary(self, store: NotifyStore) -> None:
        soon = make_question(1, expires_at=T0 + timedelta(minutes=1))
        later = make_question(2, expires_at=T0 + timedelta(minutes=2))
        tie = make_question(3, expires_at=T0 + timedelta(minutes=1))
        for n, q in ((2, later), (3, tie), (1, soon)):
            add_question(store, n, question=q)
        assert store.repo.list_expirable(T0) == []
        assert store.repo.list_expirable(T0 + timedelta(minutes=1)) == [soon, tie]
        assert store.repo.list_expirable(T0 + timedelta(hours=1)) == [soon, tie, later]
        expired = soon.expired(soon.expires_at)
        store.repo.save(expired, expected_updated_at=soon.updated_at)
        assert store.repo.list_expirable(T0 + timedelta(hours=1)) == [tie, later]

    def test_delete_resolved_before_is_strict_and_spares_open(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        add_question(store, 2)
        at = T0 + timedelta(hours=2)
        cancelled = question.cancelled(at)
        store.repo.save(cancelled, expected_updated_at=question.updated_at)
        assert store.repo.delete_resolved_before(at) == 0
        assert store.repo.delete_resolved_before(T0 + timedelta(days=365)) == 1
        with pytest.raises(NotFoundError):
            store.repo.get(question.id)
        assert store.repo.get(qid(2)).state is QuestionState.OPEN

    def test_list_expirable_skips_an_invalid_row(self, store: NotifyStore) -> None:
        # A tampered question must not stop the others from expiring (poison row).
        first, _, _ = add_question(store, 1)
        second, _, _ = add_question(store, 2)
        store.corrupt_question(first.id)
        assert store.repo.list_expirable(T0 + timedelta(days=2)) == [second]
        with pytest.raises(ValidationError):
            store.repo.get(first.id)

    def test_naive_times_are_rejected(self, store: NotifyStore) -> None:
        naive = datetime(2026, 1, 1, 12)
        with pytest.raises(ValidationError):
            store.repo.list_expirable(naive)
        with pytest.raises(ValidationError):
            store.repo.delete_resolved_before(naive)


class NotificationOutboxContract:
    """Behaviour every NotificationOutbox (plus its shared repository) must have."""

    @pytest.fixture
    def store(self) -> NotifyStore:
        raise NotImplementedError("override the `store` fixture in the concrete test class")

    # --- add / get_task -------------------------------------------------------

    def test_add_round_trip(self, store: NotifyStore) -> None:
        link = f"{DASHBOARD}/#/item/{ulid(7)}"
        notification = make_notification(1, item_id=ItemId(ulid(7)), title="Build ✅ it's done")
        content = MessageContent(text="✅ done\nsecond line", link=link)
        task = make_task(1, channel="telegram", content=content)
        store.outbox.add(notification, [task, make_task(2, channel="other")])
        assert store.outbox.get_task(task.id) == task
        assert store.outbox.get_task(tid(2)) == make_task(2, channel="other")

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_untrusted_text_round_trips(self, store: NotifyStore, payload: str) -> None:
        task = make_task(1, content=make_content("T " + payload))
        store.outbox.add(make_notification(1, title="N " + payload), [task])
        assert store.outbox.get_task(task.id) == task
        (pending,) = store.outbox.pending(T0, 10)
        assert pending.payload.content == task.content

    def test_add_rejects_question_notifications_and_foreign_tasks(self, store: NotifyStore) -> None:
        with pytest.raises(ValidationError):
            store.outbox.add(make_notification(question_id=qid(1)), [])
        with pytest.raises(ValidationError):
            store.outbox.add(make_notification(1), [make_task(notification=2)])
        store.outbox.add(make_notification(1), [make_task(1)])  # nothing was stored before

    def test_add_duplicates_store_nothing(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1)])
        with pytest.raises(AlreadyExistsError):
            store.outbox.add(
                make_notification(2), [make_task(2, notification=2), make_task(1, notification=2)]
            )
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(2))
        with pytest.raises(AlreadyExistsError):
            store.outbox.add(make_notification(1), [make_task(3)])
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(3))
        store.outbox.add(make_notification(2), [make_task(2, notification=2)])  # id 2 still free

    def test_get_task_missing(self, store: NotifyStore) -> None:
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(9))

    # --- pending -------------------------------------------------------------------

    def test_pending_order_limit_and_due_time(self, store: NotifyStore) -> None:
        later = T0 + timedelta(seconds=5)
        store.outbox.add(make_notification(1), [make_task(1, next_attempt_at=later)])
        store.outbox.add(make_notification(2), [make_task(2, notification=2)])
        store.outbox.add(make_notification(3), [make_task(3, notification=3)])
        assert [p.id for p in store.outbox.pending(T0, 10)] == [tid(2), tid(3)]
        assert [p.id for p in store.outbox.pending(later, 2)] == [tid(2), tid(3)]
        assert [p.id for p in store.outbox.pending(later, 10)] == [tid(2), tid(3), tid(1)]

    def test_pending_ties_break_by_created_at_then_id(self, store: NotifyStore) -> None:
        store.outbox.add(
            make_notification(1),
            [
                make_task(3, created_at=T0 - timedelta(seconds=1)),
                make_task(2, channel="b"),
                make_task(1, channel="c"),
            ],
        )
        assert [p.id for p in store.outbox.pending(T0, 10)] == [tid(3), tid(1), tid(2)]

    @pytest.mark.parametrize("limit", [0, 101, -1])
    def test_pending_limit_out_of_range(self, store: NotifyStore, limit: int) -> None:
        with pytest.raises(ValidationError):
            store.outbox.pending(T0, limit)

    def test_pending_payloads(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        store.outbox.add(make_notification(2), [make_task(2, notification=2)])
        by_id = {p.id: p for p in store.outbox.pending(T0, 10)}
        q_send = by_id[send.id]
        assert (q_send.action, q_send.channel, q_send.message_ref) == (
            DeliveryAction.SEND,
            "c0",
            None,
        )
        assert q_send.payload.question_id == question.id
        assert q_send.payload.content == send.content
        assert q_send.payload.final_state is None
        assert by_id[tid(2)].payload.question_id is None

    def test_pending_skips_finished_tasks(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1), make_task(2, channel="b")])
        store.outbox.mark_done(tid(1), "m1")
        assert [p.id for p in store.outbox.pending(T0, 10)] == [tid(2)]

    # --- RESOLVE rules -------------------------------------------------------------

    def _cancel_with_resolve(self, store: NotifyStore) -> tuple[Question, DeliveryTask]:
        question, _, (send,) = add_question(store)
        cancelled = question.cancelled(T0 + timedelta(seconds=1))
        resolve = resolve_task(2)
        store.repo.save(cancelled, expected_updated_at=question.updated_at, tasks=[resolve])
        return question, send

    def test_resolve_waits_for_its_send_then_carries_its_ref(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        # Handed out while open (in flight); the question resolves before it is reported.
        assert [p.id for p in store.outbox.pending(T0, 10)] == [send.id]
        store.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2)],
        )
        store.outbox.mark_done(send.id, "chat:7")
        (pending,) = store.outbox.pending(T0, 10)
        assert (pending.id, pending.action, pending.message_ref) == (
            tid(2),
            DeliveryAction.RESOLVE,
            "chat:7",
        )
        assert pending.payload.question_id == question.id
        assert pending.payload.final_state is QuestionState.CANCELLED
        assert pending.payload.content.buttons == ()

    def test_resolve_held_while_its_send_backs_off(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        store.outbox.mark_failed(send.id, now=T0)  # next try at T0 + 5 s
        store.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2)],
        )
        assert store.outbox.pending(T0 + timedelta(seconds=1), 10) == []
        assert store.outbox.get_task(tid(2)).state is DeliveryState.PENDING  # held, not dropped
        assert store.outbox.get_task(send.id).state is DeliveryState.PENDING

    # --- stale SENDs (question resolved before its alert went out) --------------

    def test_stale_send_is_settled_unsent_then_its_resolve_dropped(
        self, store: NotifyStore
    ) -> None:
        question, send = self._cancel_with_resolve(store)
        later = T0 + timedelta(seconds=1)
        store.outbox.add(make_notification(3), [make_task(3, notification=3, created_at=later)])
        # Neither the stale SEND nor the held RESOLVE uses up the limit.
        assert [p.id for p in store.outbox.pending(later, 1)] == [tid(3)]
        settled = store.outbox.get_task(send.id)
        assert (settled.state, settled.message_ref, settled.attempts) == (
            DeliveryState.DONE,
            None,
            0,
        )
        assert store.outbox.message_ref_for(question.id, "c0") is None
        store.outbox.mark_done(tid(3), "m3")
        assert store.outbox.pending(later, 10) == []
        assert store.outbox.get_task(tid(2)).state is DeliveryState.FAILED  # nothing to edit

    @pytest.mark.parametrize("outcome", ["answered", "expired"])
    def test_send_for_answered_or_expired_question_is_never_handed_out(
        self, store: NotifyStore, outcome: str
    ) -> None:
        question, _, (send,) = add_question(store)
        at = question.expires_at if outcome == "expired" else T0 + timedelta(seconds=1)
        resolved = question.expired(at) if outcome == "expired" else question.answered("a", "x", at)
        store.repo.save(resolved, expected_updated_at=question.updated_at)
        assert store.outbox.pending(at, 10) == []
        assert store.outbox.get_task(send.id).state is DeliveryState.DONE

    @pytest.mark.parametrize("send_outcome", ["failed", "done-without-ref"])
    def test_resolve_dropped_when_nothing_to_edit(
        self, store: NotifyStore, send_outcome: str
    ) -> None:
        _, send = self._cancel_with_resolve(store)
        if send_outcome == "failed":
            now = T0
            for _ in range(MAX_DELIVERY_ATTEMPTS):
                now += timedelta(hours=1)
                store.outbox.mark_failed(send.id, now=now)
        else:
            store.outbox.mark_done(send.id, None)
        assert store.outbox.pending(T0 + timedelta(days=1), 10) == []
        dropped = store.outbox.get_task(tid(2))
        assert (dropped.state, dropped.attempts) == (DeliveryState.FAILED, 0)

    def test_resolve_without_send_on_its_channel_is_dropped(self, store: NotifyStore) -> None:
        question, _, _ = add_question(store)
        cancelled = question.cancelled(T0 + timedelta(seconds=1))
        store.repo.save(
            cancelled,
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2, channel="other")],
        )
        assert store.outbox.pending(T0, 10) == []  # the SEND is stale, the RESOLVE has no SEND
        assert store.outbox.get_task(tid(10)).state is DeliveryState.DONE
        assert store.outbox.get_task(tid(2)).state is DeliveryState.FAILED

    def test_dropped_resolves_do_not_use_up_the_limit(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        store.outbox.mark_done(send.id, None)
        store.repo.save(
            question.cancelled(T0),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2, created_at=T0 - timedelta(seconds=1))],
        )
        store.outbox.add(make_notification(3), [make_task(3, notification=3)])
        assert [p.id for p in store.outbox.pending(T0, 1)] == [tid(3)]
        assert store.outbox.get_task(tid(2)).state is DeliveryState.FAILED

    def test_message_ref_for(self, store: NotifyStore) -> None:
        question, _, (send, other) = add_question(store, channels=("c0", "c1"))
        assert store.outbox.message_ref_for(question.id, "c0") is None  # still PENDING
        store.outbox.mark_done(send.id, "chat:7")
        store.outbox.mark_done(other.id, None)
        assert store.outbox.message_ref_for(question.id, "c0") == "chat:7"
        assert store.outbox.message_ref_for(question.id, "c1") is None
        assert store.outbox.message_ref_for(question.id, "nope") is None
        assert store.outbox.message_ref_for(qid(9), "c0") is None

    def test_notification_for_unknown_question(self, store: NotifyStore) -> None:
        assert store.outbox.notification_for_question(qid(9)) is None

    # --- mark_done / mark_failed -------------------------------------------------

    def test_mark_done_then_idempotent(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1)])
        done = store.outbox.mark_done(tid(1), "m1")
        assert (done.state, done.message_ref) == (DeliveryState.DONE, "m1")
        assert store.outbox.get_task(tid(1)) == done
        assert store.outbox.mark_done(tid(1), "m2") == done
        assert store.outbox.mark_failed(tid(1), now=T0) == done
        assert store.outbox.get_task(tid(1)) == done

    def test_mark_unknown_or_malformed(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1)])
        with pytest.raises(NotFoundError):
            store.outbox.mark_done(tid(9), "m1")
        with pytest.raises(NotFoundError):
            store.outbox.mark_failed(tid(9), now=T0)
        for bad in ("", "has space", "x" * 65):
            with pytest.raises(ValidationError):
                store.outbox.mark_done(tid(1), bad)
        assert store.outbox.get_task(tid(1)).state is DeliveryState.PENDING

    def test_mark_failed_backs_off_then_gives_up(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1)])
        first = store.outbox.mark_failed(tid(1), now=T0)
        assert (first.state, first.attempts) == (DeliveryState.PENDING, 1)
        assert first.next_attempt_at == T0 + BACKOFF_FIRST
        assert store.outbox.get_task(tid(1)) == first
        assert store.outbox.pending(T0, 10) == []
        assert [p.id for p in store.outbox.pending(T0 + BACKOFF_FIRST, 10)] == [tid(1)]
        task = first
        for _ in range(MAX_DELIVERY_ATTEMPTS - 1):
            task = store.outbox.mark_failed(tid(1), now=T0)
        assert (task.state, task.attempts) == (DeliveryState.FAILED, MAX_DELIVERY_ATTEMPTS)
        assert store.outbox.get_task(tid(1)) == task
        assert store.outbox.pending(T0 + timedelta(days=1), 10) == []

    # --- delete_before -------------------------------------------------------------

    def test_delete_before_removes_notifications_with_their_tasks(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1)])
        store.outbox.add(
            make_notification(2, created_at=T0 + timedelta(days=1)),
            [make_task(2, notification=2)],
        )
        assert store.outbox.delete_before(T0) == 0  # strictly before
        assert store.outbox.delete_before(T0 + timedelta(hours=1)) == 1
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(1))
        assert store.outbox.get_task(tid(2)).id == tid(2)

    def test_delete_before_removes_question_notifications(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        assert store.outbox.delete_before(T0 + timedelta(seconds=1)) == 1
        assert store.outbox.notification_for_question(question.id) is None
        with pytest.raises(NotFoundError):
            store.outbox.get_task(send.id)
        assert store.repo.get(question.id) == question  # the question itself stays

    def test_naive_times_are_rejected(self, store: NotifyStore) -> None:
        naive = datetime(2026, 1, 1, 12)
        with pytest.raises(ValidationError):
            store.outbox.pending(naive, 10)
        with pytest.raises(ValidationError):
            store.outbox.delete_before(naive)

    # --- invariants shared with SQLite's schema, poison rows --------------------------

    def test_second_send_per_notification_and_channel_is_rejected(self, store: NotifyStore) -> None:
        with pytest.raises(AlreadyExistsError):
            store.outbox.add(make_notification(1), [make_task(1), make_task(2)])
        with pytest.raises(NotFoundError):
            store.outbox.get_task(tid(1))  # nothing was stored
        question, _, _ = add_question(store, 2)
        with pytest.raises(AlreadyExistsError):
            store.repo.save(
                question.cancelled(T0),
                expected_updated_at=question.updated_at,
                tasks=[make_task(3, notification=2, channel="c0")],
            )
        assert store.repo.get(question.id) == question  # the save was rolled back

    def test_invalid_task_row_is_failed_and_the_rest_delivered(self, store: NotifyStore) -> None:
        store.outbox.add(make_notification(1), [make_task(1)])
        store.outbox.add(make_notification(2), [make_task(2, notification=2)])
        store.corrupt_task(tid(1))
        assert [p.id for p in store.outbox.pending(T0, 1)] == [tid(2)]
        with pytest.raises(ValidationError):
            store.outbox.get_task(tid(1))
        store.outbox.mark_done(tid(2), "m2")
        assert store.outbox.pending(T0 + timedelta(days=1), 10) == []

    def test_resolve_of_an_invalid_send_row_is_failed(self, store: NotifyStore) -> None:
        question, _, (send,) = add_question(store)
        store.outbox.pending(T0, 10)  # SEND handed out while open
        store.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2)],
        )
        store.outbox.mark_done(send.id, "chat:1")
        store.corrupt_task(send.id)
        assert store.outbox.pending(T0, 10) == []
        assert store.outbox.get_task(tid(2)).state is DeliveryState.FAILED
