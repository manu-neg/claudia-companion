"""Unit tests for `domain/questions.py`: option/question invariants and state transitions."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.questions import (
    AnswerResult,
    Question,
    QuestionOption,
    QuestionState,
    parse_question_id,
    validate_option_key,
    validate_plugin_name,
)
from tests.builders import T0, ulid
from tests.notify_support import make_options, make_question, qid

pytestmark = pytest.mark.unit

LATER = T0 + timedelta(minutes=5)
# Invisible characters built from code points (never literal in source).
RLO = chr(0x202E)
ZWSP = chr(0x200B)
EXPIRY = T0 + timedelta(hours=24)


# --- small validators ---------------------------------------------------------


@pytest.mark.parametrize("key", ["a", "yes", "opt_1", "x-2", "0", "a" * 16])
def test_option_keys_accepted(key: str) -> None:
    assert validate_option_key(key) == key


@pytest.mark.parametrize("key", ["", "A", "a:b", "a b", "a" * 17, "é", "a/b", None, 1])
def test_option_keys_rejected(key: object) -> None:
    with pytest.raises(ValidationError):
        validate_option_key(key)


@pytest.mark.parametrize("name", ["", "Telegram", "1tg", "a_b", "x" * 33, None])
def test_plugin_names_rejected(name: object) -> None:
    with pytest.raises(ValidationError):
        validate_plugin_name(name, "channel")


def test_parse_question_id() -> None:
    assert parse_question_id(ulid(7)) == ulid(7)
    for bad in ("", "x", "01ARZ3NDEKTSV4RRFFQ69G5FAV".lower(), None, 7):
        with pytest.raises(ValidationError):
            parse_question_id(bad)


def test_answer_result_values_are_wire_strings() -> None:
    assert {r.value for r in AnswerResult} == {
        "recorded",
        "already_answered",
        "expired",
        "cancelled",
        "unknown",
    }


# --- options ------------------------------------------------------------------


def test_option_label_is_sanitized() -> None:
    option = QuestionOption(key="a", label=f"  Post{RLO}gres\n ")
    assert option.label == "Postgres"


@pytest.mark.parametrize("label", ["", "   ", ZWSP * 2, "x" * 41])
def test_bad_option_labels_rejected(label: str) -> None:
    with pytest.raises(ValidationError):
        QuestionOption(key="a", label=label)


# --- question invariants --------------------------------------------------------


def test_valid_question_defaults() -> None:
    q = make_question()
    assert q.state is QuestionState.OPEN
    assert (q.answer_key, q.answer_source, q.resolved_at) == (None, None, None)
    assert q.option("a") == QuestionOption(key="a", label="SQLite")
    assert q.option("zz") is None


def test_prompt_and_session_label_are_sanitized() -> None:
    q = make_question(prompt=f" Pick{RLO} one\r\nplease ", session_label=f"R4{ZWSP} review")
    assert q.prompt == "Pick one please"
    assert q.session_label == "R4 review"


@pytest.mark.parametrize(
    "overrides",
    [
        {"prompt": ""},
        {"prompt": "x" * 201},
        {"prompt": RLO},
        {"session_label": ""},
        {"session_label": "x" * 41},
        {"options": make_options("one")},
        {"options": make_options(*"abcdefghi")},
        {"options": (QuestionOption(key="a", label="x"), QuestionOption(key="a", label="y"))},
        {"options": ("a", "b")},
        {"default_key": "zz"},
        {"item_id": "not-an-id"},
        {"id": "nope"},
        {"expires_at": T0},
        {"expires_at": T0 - timedelta(seconds=1)},
        {"expires_at": T0 + timedelta(days=7, microseconds=1)},
        {"updated_at": T0 - timedelta(microseconds=1)},
        {"created_at": datetime(2026, 1, 1)},  # naive on purpose
        {"state": "maybe"},
    ],
)
def test_invalid_questions_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_question(**overrides)


def test_seven_days_is_the_longest_lifetime() -> None:
    assert make_question(expires_at=T0 + timedelta(days=7)).expires_at == T0 + timedelta(days=7)


def test_default_key_must_be_an_option() -> None:
    assert make_question(default_key="b").default_label == "Postgres"
    assert make_question().default_label is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"answer_key": "a"},  # OPEN with an outcome
        {"resolved_at": LATER},
        {"state": QuestionState.ANSWERED, "answer_key": "a", "answer_source": "tg"},  # no time
        {
            "state": QuestionState.ANSWERED,
            "answer_key": "zz",
            "answer_source": "tg",
            "resolved_at": LATER,
            "updated_at": LATER,
        },
        {
            "state": QuestionState.ANSWERED,
            "answer_key": "a",
            "answer_source": "TG!",
            "resolved_at": LATER,
            "updated_at": LATER,
        },
        {
            "state": QuestionState.CANCELLED,
            "answer_key": "a",
            "resolved_at": LATER,
            "updated_at": LATER,
        },
        {"state": QuestionState.EXPIRED, "resolved_at": LATER, "updated_at": LATER},
        {"state": QuestionState.CANCELLED, "resolved_at": LATER, "updated_at": T0},
    ],
)
def test_inconsistent_outcomes_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_question(**overrides)


def test_replace_revalidates() -> None:
    with pytest.raises(ValidationError):
        dataclasses.replace(make_question(), prompt="")


def test_times_are_normalized_to_utc() -> None:
    tz = timezone(timedelta(hours=2))
    q = make_question(created_at=T0.astimezone(tz), updated_at=T0.astimezone(tz))
    assert q.created_at.tzinfo is UTC
    assert q.created_at == T0


# --- transitions --------------------------------------------------------------


def test_answered() -> None:
    q = make_question().answered("b", "telegram", LATER)
    assert q.state is QuestionState.ANSWERED
    assert (q.answer_key, q.answer_source, q.resolved_at, q.updated_at) == (
        "b",
        "telegram",
        LATER,
        LATER,
    )
    assert q.answer_label == "Postgres"


def test_answer_with_unknown_key_rejected() -> None:
    with pytest.raises(ValidationError):
        make_question().answered("zz", "telegram", LATER)


def test_answer_with_bad_source_rejected() -> None:
    with pytest.raises(ValidationError):
        make_question().answered("a", "Tele gram", LATER)


def test_answer_after_expiry_is_illegal() -> None:
    with pytest.raises(InvalidStateError):
        make_question().answered("a", "telegram", EXPIRY)


@pytest.mark.parametrize(
    "resolve",
    [
        lambda q: q.answered("a", "telegram", LATER),
        lambda q: q.cancelled(LATER),
        lambda q: q.expired(EXPIRY),
    ],
)
def test_terminal_states_are_final(resolve: Callable[[Question], Question]) -> None:
    done = resolve(make_question())
    assert done.state.is_terminal
    later = EXPIRY + timedelta(hours=1)
    with pytest.raises(InvalidStateError):
        done.answered("b", "telegram", later)
    with pytest.raises(InvalidStateError):
        done.cancelled(later)
    with pytest.raises(InvalidStateError):
        done.expired(later)


def test_expired_only_at_or_after_deadline() -> None:
    with pytest.raises(InvalidStateError):
        make_question().expired(EXPIRY - timedelta(microseconds=1))
    q = make_question().expired(EXPIRY)
    assert (q.state, q.resolved_at) == (QuestionState.EXPIRED, EXPIRY)
    assert (q.answer_key, q.answer_source) == (None, None)


def test_cancelled() -> None:
    q = make_question().cancelled(LATER)
    assert (q.state, q.resolved_at, q.updated_at) == (QuestionState.CANCELLED, LATER, LATER)


def test_transition_time_must_not_run_backwards() -> None:
    q = make_question(updated_at=LATER)
    with pytest.raises(ValidationError):
        q.cancelled(T0)


def test_is_expired() -> None:
    q = make_question()
    assert not q.is_expired(EXPIRY - timedelta(microseconds=1))
    assert q.is_expired(EXPIRY)
    assert q.expired(EXPIRY).is_expired(T0)  # an EXPIRED question stays expired
    assert not q.answered("a", "telegram", LATER).is_expired(EXPIRY)


def test_next_change_at_is_strictly_after_updated_at() -> None:
    q = make_question(updated_at=LATER)
    assert q.next_change_at(T0) == LATER + timedelta(microseconds=1)
    assert q.next_change_at(LATER + timedelta(hours=1)) == LATER + timedelta(hours=1)


def test_question_ids_are_distinct_from_builders() -> None:
    assert qid(1) != ulid(1)
