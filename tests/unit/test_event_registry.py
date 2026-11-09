"""Unit tests for the `events/` registry and the built-in event types."""

from __future__ import annotations

import pytest

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import MESSAGE_TEXT_MAX_CHARS, MessageContent
from preview_dashboard.domain.questions import QuestionState
from preview_dashboard.events import (
    DONE_EVENT,
    FAILED_EVENT,
    QUESTION_EVENT,
    EventRegistry,
    EventType,
    RenderContext,
    compose_text,
    default_event_registry,
)
from preview_dashboard.events.done import DoneEventType
from tests.notify_support import DASHBOARD, make_options

pytestmark = pytest.mark.unit

LINK = f"{DASHBOARD}/"


def test_default_registry_lists_the_builtins() -> None:
    registry = default_event_registry()
    assert registry.names() == (
        QUESTION_EVENT,
        DONE_EVENT,
        FAILED_EVENT,
        "reply",
        "voice",
        "approval",
    )
    flags = {n: registry.get(n).actionable for n in registry.names()}
    assert flags == {
        "question": True,
        "done": False,
        "failed": False,
        "reply": False,
        "voice": False,
        "approval": True,  # so `dashboard_notify` can never send one
    }
    assert {registry.get(n).emoji for n in registry.names()} == {
        "❓",
        "✅",
        "❌",
        "💬",
        "🔊",
        "🔐",
    }


def test_register_rejects_duplicates_and_bad_names() -> None:
    registry = EventRegistry()
    registry.register(DoneEventType())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(DoneEventType())

    class Bad(DoneEventType):
        name = "Bad Name"

    with pytest.raises(ValidationError):
        registry.register(Bad())


@pytest.mark.parametrize("name", ["nope", "", "QUESTION"])
def test_unknown_event_type_is_a_validation_error(name: str) -> None:
    with pytest.raises(ValidationError):
        default_event_registry().get(name)


def test_question_open_render() -> None:
    kind = default_event_registry().get(QUESTION_EVENT)
    content = kind.render(
        RenderContext(title="Which DB?", link=LINK, session_label="R4", options=make_options())
    )
    assert content.text == "❓ Which DB?\nSession: R4"
    assert [(b.key, b.label) for b in content.buttons] == [("a", "SQLite"), ("b", "Postgres")]
    assert content.link == LINK


@pytest.mark.parametrize(
    ("state", "label", "status"),
    [
        (QuestionState.ANSWERED, "Postgres", "✅ Answered: Postgres"),
        (QuestionState.EXPIRED, None, "⌛ Expired"),
        (QuestionState.CANCELLED, None, "🚫 Withdrawn"),
    ],
)
def test_question_resolved_render(state: QuestionState, label: str | None, status: str) -> None:
    kind = default_event_registry().get(QUESTION_EVENT)
    content = kind.render(
        RenderContext(
            title="Which DB?",
            link=LINK,
            options=make_options(),  # ignored once resolved: no late buttons
            final_state=state,
            answer_label=label,
        )
    )
    assert content.text == f"❓ Which DB?\n{status}"
    assert content.buttons == ()
    assert content.link == LINK


def test_longest_question_still_fits_with_its_status() -> None:
    kind = default_event_registry().get(QUESTION_EVENT)
    ctx = RenderContext(
        title="x" * 200,
        session_label="s" * 40,
        final_state=QuestionState.ANSWERED,
        answer_label="L" * 40,
    )
    text = kind.render(ctx).text
    assert len(text) <= MESSAGE_TEXT_MAX_CHARS
    assert text.endswith("✅ Answered: " + "L" * 40)
    assert "…" in text


@pytest.mark.parametrize(("name", "emoji"), [(DONE_EVENT, "✅"), (FAILED_EVENT, "❌")])
def test_informational_render(name: str, emoji: str) -> None:
    kind: EventType = default_event_registry().get(name)
    content = kind.render(RenderContext(title="Deploy", link=LINK, options=make_options()))
    assert content.text == f"{emoji} Deploy"
    assert content.buttons == ()
    assert content.link == LINK


@pytest.mark.parametrize(
    "seq",
    [
        "\U0001f469\u200d\U0001f4bb",  # ZWJ sequence
        "\u2764\ufe0f\u200d\U0001f525",  # VS16 + ZWJ
        "1\ufe0f\u20e3",  # keycap
        "\u0915\u094d\u200d\u0937",  # Devanagari half form
    ],
)
def test_title_cut_inside_a_joiner_sequence_still_renders(seq: str) -> None:
    # Every cut position: a joiner/selector whose partner is cut off must go too.
    for pad in range(len(seq) + 1):
        title = "t" * (MESSAGE_TEXT_MAX_CHARS - 3 - pad) + seq
        text = compose_text("x", title)
        assert len(text) <= MESSAGE_TEXT_MAX_CHARS
        MessageContent(text=text)  # passes the outgoing-text policy


def test_compose_text_rejects_lines_that_leave_no_room() -> None:
    with pytest.raises(ValidationError):
        compose_text("x", "title", ["y" * 300])
    assert compose_text("x", "title") == "x title"
