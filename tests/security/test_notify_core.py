"""Security tests for the core parts of C34-C37 (questions + notifications, ADR 0021).

C34 answer authorization (core: OPEN + offered key + first wins, never
auto-answered), C35 outbound content (secret scan, sanitizing, server-built
links, plain channel-neutral messages), C36 (the delivery loop never logs
exception text), C37 (one shared alert rate limit, every attempt counts).
Route/token/Telegram parts are tested by units N3/N4.
"""

from __future__ import annotations

import inspect
from datetime import timedelta

import pytest

from preview_dashboard.application.notify import NotifyService
from preview_dashboard.application.questions import AskCommand, QuestionService
from preview_dashboard.domain.errors import (
    RateLimitedError,
    SecretDetectedError,
    ValidationError,
)
from preview_dashboard.domain.notifications import MessageContent
from preview_dashboard.domain.questions import AnswerResult, QuestionState
from tests.builders import ulid
from tests.fakes import FAKE_SECRET
from tests.notify_support import DASHBOARD, NotifyHarness, build_harness

pytestmark = pytest.mark.security

SECRET = FAKE_SECRET.decode()
ZWSP = chr(0x200B)
RLO = chr(0x202E)
OPTIONS = [("a", "SQLite"), ("b", "Postgres")]


@pytest.fixture
def h() -> NotifyHarness:
    return build_harness()


# --- C34: answer authorization (core) --------------------------------------------------


def test_c34_only_an_offered_key_on_an_open_question_is_recorded(h: NotifyHarness) -> None:
    q = h.questions.ask(AskCommand(session_label="s1", prompt="p", options=OPTIONS))
    for forged in ("c", "A", "a:b", "", "a" * 17):
        assert h.questions.answer(q.id, forged, "telegram") is AnswerResult.UNKNOWN
    assert h.repo.get(q.id).state is QuestionState.OPEN
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.RECORDED
    # First wins: no later answer, from any source, can change it.
    for source in ("telegram", "dashboard"):
        assert h.questions.answer(q.id, "b", source) is AnswerResult.ALREADY_ANSWERED
    assert h.repo.get(q.id).answer_key == "a"


def test_c34_forged_ids_learn_nothing(h: NotifyHarness) -> None:
    # Malformed and well-formed-but-unknown ids answer the same, and never raise.
    for forged in (ulid(404), "../../etc", "", "01ARZ3NDEKTSV4RRFFQ69G5FAV"):
        assert h.questions.answer(forged, "a", "telegram") is AnswerResult.UNKNOWN


def test_c34_expiry_never_auto_answers(h: NotifyHarness) -> None:
    q = h.questions.ask(
        AskCommand(session_label="s1", prompt="p", options=OPTIONS, default_key="a")
    )
    h.clock.advance(timedelta(hours=24))
    got = h.questions.get(q.id)
    assert got.state is QuestionState.EXPIRED
    assert got.answer_key is None  # the default is reported, never recorded
    assert got.default_key == "a"
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.EXPIRED


def test_c34_withdrawn_question_cannot_be_answered(h: NotifyHarness) -> None:
    q = h.questions.ask(AskCommand(session_label="s1", prompt="p", options=OPTIONS))
    h.questions.cancel(q.id)
    assert h.questions.answer(q.id, "a", "telegram") is AnswerResult.CANCELLED


def test_c34_services_expose_answering_only_through_answer() -> None:
    # The admin token's routes use ask/get/cancel; only `answer` records a
    # choice, so N3 can keep it behind the notifier token alone.
    public = {n for n, _ in inspect.getmembers(QuestionService) if not n.startswith("_")}
    assert public == {"ask", "get", "answer", "cancel", "expire_due"}


# --- C35: outbound content -------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd",
    [
        AskCommand(session_label="s1", prompt=f"deploy with {SECRET}?", options=OPTIONS),
        AskCommand(session_label="s1", prompt="p", options=[("a", f"use {SECRET}"), ("b", "no")]),
        AskCommand(prompt="p", options=OPTIONS, session_label=f"s {SECRET}"),
        # Only the sanitized form reveals it (ZWSP inside the marker).
        AskCommand(session_label="s1", prompt=f"x {SECRET[:4]}{ZWSP}{SECRET[4:]}", options=OPTIONS),
    ],
)
def test_c35_secrets_never_leave_via_questions(h: NotifyHarness, cmd: AskCommand) -> None:
    with pytest.raises(SecretDetectedError) as err:
        h.questions.ask(cmd)
    assert SECRET not in str(err.value)
    assert h.repo.count() == 0
    assert h.outbox.tasks == {}


def test_c35_secrets_never_leave_via_notifications(h: NotifyHarness) -> None:
    for title in (f"done: {SECRET}", f"{SECRET[:3]}{ZWSP}{SECRET[3:]}"):
        with pytest.raises(SecretDetectedError):
            h.notify.notify("done", title)
    assert h.outbox.notifications == {}


def test_c35_message_carries_only_sanitized_fields_and_a_server_link(h: NotifyHarness) -> None:
    q = h.questions.ask(
        AskCommand(
            prompt=f"Pick{RLO} one\nplease",
            options=[("a", f"Ye{RLO}s"), ("b", "No")],
            session_label="R4",
            item_id=ulid(5),
        )
    )
    (pending,) = h.outbox_service.pending(20)
    content = pending.payload.content
    assert content.text == "❓ Pick one please\nSession: R4"
    assert [(b.key, b.label) for b in content.buttons] == [("a", "Yes"), ("b", "No")]
    assert content.link == f"{DASHBOARD}/#/item/{ulid(5)}"
    assert pending.payload.question_id == q.id


def test_c35_callers_cannot_supply_links() -> None:
    # No link parameter exists anywhere a caller can reach.
    for fn in (QuestionService.ask, NotifyService.notify):
        assert "link" not in inspect.signature(fn).parameters
    assert "link" not in AskCommand.__dataclass_fields__


def test_c35_messages_reject_markup_breaking_characters() -> None:
    for text in (f"a{RLO}b", "a" + chr(0) + "b", "a\rb"):
        with pytest.raises(ValidationError):
            MessageContent(text=text)
    with pytest.raises(ValidationError):
        MessageContent(text="x", link="https://evil.example/?next=javascript:x")


# --- C36: the delivery loop never logs exception text ----------------------------------
# (covered in tests/unit/test_delivery_service.py::test_failure_logs_only_the_exception_type)


# --- C37: notification rate limit ------------------------------------------------------


def test_c37_one_budget_for_questions_and_notifications() -> None:
    h = build_harness(rate_per_hour=20)
    for i in range(10):
        h.questions.ask(AskCommand(session_label="s1", prompt=f"q{i}", options=OPTIONS))
        h.notify.notify("done", f"n{i}")
    with pytest.raises(RateLimitedError):
        h.notify.notify("failed", "one too many")
    with pytest.raises(RateLimitedError):
        h.questions.ask(AskCommand(session_label="s1", prompt="one too many", options=OPTIONS))
    h.monotonic.advance(3600)
    h.notify.notify("done", "next hour")


def test_c37_refused_attempts_count_too() -> None:
    h = build_harness(rate_per_hour=2)
    with pytest.raises(SecretDetectedError):
        h.questions.ask(AskCommand(session_label="s1", prompt=SECRET, options=OPTIONS))
    with pytest.raises(ValidationError):
        h.notify.notify("done", "")
    with pytest.raises(RateLimitedError):
        h.notify.notify("done", "valid, but the budget is spent on probes")
