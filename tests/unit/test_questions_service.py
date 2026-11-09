"""Unit tests for QuestionService: ask, lazy expiry, first-answer-wins, cancel, expire_due."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from datetime import datetime, timedelta

import pytest

from preview_dashboard.application.questions import AskCommand, QuestionService
from preview_dashboard.domain.errors import (
    ConflictError,
    NotFoundError,
    RateLimitedError,
    ValidationError,
)
from preview_dashboard.domain.notifications import DeliveryAction, DeliveryState, DeliveryTask
from preview_dashboard.domain.questions import AnswerResult, Question, QuestionState
from tests.builders import T0, ulid
from tests.fakes import InMemoryQuestionRepository
from tests.notify_support import DASHBOARD, NotifyHarness, build_harness

pytestmark = pytest.mark.unit

ASK = AskCommand(
    session_label="s1", prompt="Which DB?", options=[("a", "SQLite"), ("b", "Postgres")]
)


@pytest.fixture
def h() -> NotifyHarness:
    return build_harness()


def _tasks(h: NotifyHarness, q: Question) -> list[DeliveryTask]:
    notification = h.outbox.notification_for_question(q.id)
    assert notification is not None
    return h.outbox.tasks_of(notification.id)


# --- ask -------------------------------------------------------------------------


def test_ask_stores_question_notification_and_one_send_per_channel() -> None:
    h = build_harness(channels=("fake", "other"))
    q = h.questions.ask(
        AskCommand(
            prompt="Which DB?",
            options=[("a", "SQLite"), ("b", "Postgres")],
            default_key="a",
            item_id=ulid(9),
            session_label="R4",
        )
    )
    assert h.repo.get(q.id) == q
    assert (q.state, q.default_key, q.item_id, q.session_label) == (
        QuestionState.OPEN,
        "a",
        ulid(9),
        "R4",
    )
    assert q.expires_at == T0 + timedelta(hours=24)
    notification = h.outbox.notification_for_question(q.id)
    assert notification is not None
    assert (notification.event_type, notification.title, notification.item_id) == (
        "question",
        "Which DB?",
        ulid(9),
    )
    tasks = _tasks(h, q)
    assert [(t.channel, t.action) for t in tasks] == [
        ("fake", DeliveryAction.SEND),
        ("other", DeliveryAction.SEND),
    ]
    content = tasks[0].content
    assert content.text == "❓ Which DB?\nSession: R4"
    assert [b.key for b in content.buttons] == ["a", "b"]
    assert content.link == f"{DASHBOARD}/#/item/{ulid(9)}"
    assert h.outbox_events.notified == 1


def test_ask_without_item_links_the_dashboard_home(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    assert _tasks(h, q)[0].content.link == f"{DASHBOARD}/"


def test_ask_without_dashboard_has_no_link() -> None:
    h = build_harness(dashboard=None)
    q = h.questions.ask(ASK)
    assert _tasks(h, q)[0].content.link is None


def test_ask_with_notifications_disabled_still_stores_the_question() -> None:
    h = build_harness(channels=())
    q = h.questions.ask(ASK)
    assert h.repo.get(q.id) == q
    assert _tasks(h, q) == []
    assert h.outbox_events.notified == 0


def test_ask_custom_expiry_bounds(h: NotifyHarness) -> None:
    for expires_in in (timedelta(seconds=60), timedelta(days=7)):
        q = h.questions.ask(
            AskCommand(session_label="s1", prompt="p", options=ASK.options, expires_in=expires_in)
        )
        assert q.expires_at - q.created_at == expires_in


@pytest.mark.parametrize("expires_in", [timedelta(seconds=59), timedelta(days=7, seconds=1)])
def test_ask_expiry_out_of_range(h: NotifyHarness, expires_in: timedelta) -> None:
    with pytest.raises(ValidationError):
        h.questions.ask(
            AskCommand(session_label="s1", prompt="p", options=ASK.options, expires_in=expires_in)
        )
    assert h.repo.count() == 0


def test_default_ttl_must_be_in_range() -> None:
    with pytest.raises(ValueError, match="expiry"):
        build_harness(ttl=timedelta(days=8))


@pytest.mark.parametrize(
    "options",
    [
        [("a", "only one")],
        [(f"k{i}", "x") for i in range(9)],
        [("a", "x"), ("a", "y")],
        [("a", "x", "extra"), ("b", "y")],
        "ab",
        [("A", "x"), ("b", "y")],
    ],
)
def test_ask_rejects_bad_options(h: NotifyHarness, options: object) -> None:
    with pytest.raises(ValidationError):
        h.questions.ask(AskCommand(session_label="s1", prompt="p", options=options))  # type: ignore[arg-type]
    assert h.repo.count() == 0
    assert h.outbox.notifications == {}


@pytest.mark.parametrize(
    "overrides",
    [{"default_key": "zz"}, {"item_id": "nope"}, {"prompt": ""}, {"session_label": "x" * 41}],
)
def test_ask_rejects_bad_fields(h: NotifyHarness, overrides: dict[str, object]) -> None:
    fields: dict[str, object] = {
        "prompt": "p",
        "options": ASK.options,
        "session_label": "s1",
        **overrides,
    }
    with pytest.raises(ValidationError):
        h.questions.ask(AskCommand(**fields))  # type: ignore[arg-type]
    assert h.repo.count() == 0


def test_ask_is_rate_limited() -> None:
    h = build_harness(rate_per_hour=2)
    h.questions.ask(ASK)
    h.questions.ask(ASK)
    with pytest.raises(RateLimitedError, match="notification rate limit"):
        h.questions.ask(ASK)
    assert h.repo.count() == 2
    h.monotonic.advance(3600)
    h.questions.ask(ASK)


# --- get -------------------------------------------------------------------------


def test_get_returns_open_question(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    assert h.questions.get(q.id) == q
    assert h.events.notified == []


def test_get_expires_lazily_and_enqueues_resolve(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.clock.advance(timedelta(hours=24))
    got = h.questions.get(q.id)
    assert got.state is QuestionState.EXPIRED
    assert h.repo.get(q.id) == got
    resolve = _tasks(h, q)[-1]
    assert (resolve.action, resolve.final_state) == (DeliveryAction.RESOLVE, QuestionState.EXPIRED)
    assert resolve.content.text.endswith("⌛ Expired")
    assert resolve.content.buttons == ()
    assert h.events.notified == [q.id]


def test_get_unknown_and_malformed(h: NotifyHarness) -> None:
    with pytest.raises(NotFoundError):
        h.questions.get(ulid(123))
    with pytest.raises(ValidationError):
        h.questions.get("../x")


# --- answer ----------------------------------------------------------------------


def test_answer_records_and_resolves(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.clock.advance(timedelta(minutes=3))
    assert h.questions.answer(q.id, "b", "telegram") is AnswerResult.RECORDED
    stored = h.repo.get(q.id)
    assert (stored.state, stored.answer_key, stored.answer_source) == (
        QuestionState.ANSWERED,
        "b",
        "telegram",
    )
    assert stored.resolved_at == T0 + timedelta(minutes=3)
    send, resolve = _tasks(h, q)
    assert resolve.action is DeliveryAction.RESOLVE
    assert resolve.final_state is QuestionState.ANSWERED
    assert resolve.content.text == "❓ Which DB?\nSession: s1\n✅ Answered: Postgres"
    assert resolve.notification_id == send.notification_id
    assert h.events.notified == [q.id]
    assert h.outbox_events.notified == 2  # SEND, then RESOLVE


def test_first_answer_wins(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.RECORDED
    assert h.questions.answer(q.id, "b", "telegram") is AnswerResult.ALREADY_ANSWERED
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.ALREADY_ANSWERED
    assert h.repo.get(q.id).answer_key == "a"
    assert len(_tasks(h, q)) == 2  # one RESOLVE only


@pytest.mark.parametrize(
    ("question_id", "key"),
    [(ulid(404), "a"), ("garbage", "a"), (None, "a"), ("QID", "zz"), ("QID", ""), ("QID", None)],
)
def test_unknown_question_or_key(h: NotifyHarness, question_id: object, key: object) -> None:
    q = h.questions.ask(ASK)
    qid_value = q.id if question_id == "QID" else question_id
    result = h.questions.answer(qid_value, key, "telegram")  # type: ignore[arg-type]
    assert result is AnswerResult.UNKNOWN
    assert h.repo.get(q.id).state is QuestionState.OPEN


def test_answer_rejects_a_malformed_source(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    with pytest.raises(ValidationError):
        h.questions.answer(q.id, "a", "Tele gram")


def test_answer_after_deadline_expires_instead(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.clock.advance(timedelta(hours=24))
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.EXPIRED
    assert h.repo.get(q.id).state is QuestionState.EXPIRED
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.EXPIRED


def test_answer_on_cancelled(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.questions.cancel(q.id)
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.CANCELLED


def test_answer_survives_a_clock_step_back(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.clock.advance(timedelta(seconds=-30))
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.RECORDED
    assert h.repo.get(q.id).updated_at > q.updated_at


class RacingRepo(InMemoryQuestionRepository):
    """Each of the first `races` saves loses to a rival writer (answer or plain bump)."""

    def __init__(self, races: int, *, rival_answers: bool) -> None:
        super().__init__()
        self.races = races
        self.rival_answers = rival_answers

    def save(
        self,
        question: Question,
        *,
        expected_updated_at: datetime,
        tasks: Sequence[DeliveryTask] = (),
    ) -> None:
        if self.races > 0:
            self.races -= 1
            current = self.get(question.id)
            stamp = current.next_change_at(T0)
            rival = (
                current.answered("a", "dashboard", stamp)
                if self.rival_answers
                else dataclasses.replace(current, updated_at=stamp)
            )
            super().save(rival, expected_updated_at=current.updated_at)
        super().save(question, expected_updated_at=expected_updated_at, tasks=tasks)


def _racing_service(repo: InMemoryQuestionRepository) -> tuple[QuestionService, NotifyHarness]:
    h = build_harness()
    service = QuestionService(
        repo=repo,
        outbox=repo.outbox,
        events=h.events,
        clock=h.clock,
        ids=h.ids,
        scanner=h.scanner,
        rate_limiter=h.limiter,
        channels=("fake",),
    )
    return service, h


def test_concurrent_answer_first_wins_after_one_retry() -> None:
    repo = RacingRepo(races=1, rival_answers=True)
    service, _ = _racing_service(repo)
    q = service.ask(ASK)
    assert service.answer(q.id, "b", "telegram") is AnswerResult.ALREADY_ANSWERED
    assert repo.get(q.id).answer_key == "a"


def test_second_conflict_propagates() -> None:
    repo = RacingRepo(races=2, rival_answers=False)
    service, _ = _racing_service(repo)
    q = service.ask(ASK)
    with pytest.raises(ConflictError):
        service.answer(q.id, "b", "telegram")


# --- cancel ------------------------------------------------------------------------


def test_cancel_withdraws_and_is_idempotent(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    cancelled = h.questions.cancel(q.id)
    assert cancelled.state is QuestionState.CANCELLED
    assert h.questions.cancel(q.id) == cancelled
    tasks = _tasks(h, q)
    assert len(tasks) == 2
    assert tasks[1].content.text.endswith("🚫 Withdrawn")
    assert h.events.notified == [q.id]


def test_cancel_of_an_answered_question_returns_it(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.questions.answer(q.id, "a", "telegram")
    assert h.questions.cancel(q.id).state is QuestionState.ANSWERED


def test_cancel_past_deadline_expires(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    h.clock.advance(timedelta(days=2))
    assert h.questions.cancel(q.id).state is QuestionState.EXPIRED


def test_cancel_unknown(h: NotifyHarness) -> None:
    with pytest.raises(NotFoundError):
        h.questions.cancel(ulid(77))


# --- expire_due -----------------------------------------------------------------------


def test_expire_due(h: NotifyHarness) -> None:
    short = h.questions.ask(
        AskCommand(
            session_label="s1", prompt="short", options=ASK.options, expires_in=timedelta(minutes=5)
        )
    )
    long = h.questions.ask(ASK)
    answered = h.questions.ask(
        AskCommand(
            session_label="s1", prompt="done", options=ASK.options, expires_in=timedelta(minutes=5)
        )
    )
    h.questions.answer(answered.id, "a", "telegram")
    h.events.notified.clear()
    assert h.questions.expire_due(T0 + timedelta(minutes=5)) == 1
    assert h.repo.get(short.id).state is QuestionState.EXPIRED
    assert h.repo.get(long.id).state is QuestionState.OPEN
    assert h.events.notified == [short.id]
    assert _tasks(h, short)[-1].final_state is QuestionState.EXPIRED
    assert h.questions.expire_due(T0 + timedelta(minutes=5)) == 0


def test_expire_due_defaults_to_the_clock(h: NotifyHarness) -> None:
    h.questions.ask(ASK)
    h.clock.advance(timedelta(hours=25))
    assert h.questions.expire_due() == 1


def test_expire_due_skips_a_question_changed_meanwhile() -> None:
    class Stale(InMemoryQuestionRepository):
        def list_expirable(self, now: datetime) -> list[Question]:
            stale = super().list_expirable(now)
            for q in stale:  # someone answers between listing and saving
                super().save(q.cancelled(q.next_change_at(now)), expected_updated_at=q.updated_at)
            return stale

    repo = Stale()
    service, _ = _racing_service(repo)
    service.ask(
        AskCommand(
            session_label="s1", prompt="p", options=ASK.options, expires_in=timedelta(minutes=1)
        )
    )
    assert service.expire_due(T0 + timedelta(hours=1)) == 0


def test_resolve_tasks_need_a_notification_and_channels() -> None:
    h = build_harness(channels=())
    q = h.questions.ask(ASK)
    h.questions.answer(q.id, "a", "telegram")
    assert h.outbox.tasks == {}
    assert h.outbox_events.notified == 0


def test_resolve_waits_for_send_state_in_outbox(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    # The SEND is handed out (in flight) before the question is withdrawn.
    pending = h.outbox_service.pending(20)
    assert [p.action for p in pending] == [DeliveryAction.SEND]
    h.questions.cancel(q.id)
    h.outbox_service.done(pending[0].id, "m-1")
    pending = h.outbox_service.pending(20)
    assert [(p.action, p.message_ref) for p in pending] == [(DeliveryAction.RESOLVE, "m-1")]
    assert pending[0].payload.final_state is QuestionState.CANCELLED
    h.outbox_service.done(pending[0].id, None)
    assert {t.state for t in h.outbox.tasks.values()} == {DeliveryState.DONE}


def test_alert_resolved_before_it_went_out_is_never_sent(h: NotifyHarness) -> None:
    q = h.questions.ask(ASK)
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.RECORDED
    # Stale SEND: settled unsent; its RESOLVE then has nothing to edit.
    assert h.outbox_service.pending(20) == []
    assert h.outbox_service.pending(20) == []
    send, resolve = _tasks(h, q)
    assert (send.state, send.message_ref) == (DeliveryState.DONE, None)
    assert resolve.state is DeliveryState.FAILED


def test_ask_requires_a_session_label(h: NotifyHarness) -> None:
    for label in (None, "", "   ", "x" * 41):
        with pytest.raises(ValidationError):
            h.questions.ask(
                AskCommand(prompt="p", options=ASK.options, session_label=label)  # type: ignore[arg-type]
            )
    assert h.repo.count() == 0
