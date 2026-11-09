"""Unit tests for `domain.owner_messages`: ids, invariants, transitions and redaction edges."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta
from typing import cast

import pytest

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.owner_messages import (
    CODE_REDACTED,
    QUOTE_MAX_CHARS,
    STORED_MESSAGE_MAX_CHARS,
    InboxState,
    OwnerMessage,
    parse_owner_message_id,
    redact_code_runs,
)
from tests.builders import T0
from tests.contracts.owner_message_store import make_message, mid

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("raw", ["", "x", "0" * 25, "8" + "0" * 25, "0" * 25 + "u", None, 1])
def test_bad_ids_are_refused(raw: object) -> None:
    with pytest.raises(ValidationError):
        parse_owner_message_id(raw)


@pytest.mark.parametrize(
    "fields",
    [
        {"update_id": -1},
        {"update_id": True},
        {"update_id": 2**63},
        {"telegram_message_id": 0},
        {"telegram_message_id": "5"},
        {"reply_to_message_id": 0},
        {"is_forwarded": 1},
        {"received_at": datetime(2026, 1, 1, 12)},
        {"quote_text": ""},
        {"quote_text": "x" * (QUOTE_MAX_CHARS + 1)},
        {"text": 5},
    ],
)
def test_invariants(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        make_message(1, **fields)


def test_new_is_received_and_handled_once() -> None:
    message = make_message(1)
    assert (message.state, message.handled_at) == (InboxState.RECEIVED, None)
    at = T0 + timedelta(minutes=5)
    handled = message.handled(at)
    assert (handled.state, handled.handled_at) == (InboxState.HANDLED, at)
    with pytest.raises(InvalidStateError):
        handled.handled(at)


def test_handled_time_rules() -> None:
    message = make_message(1)
    with pytest.raises(ValidationError):
        message.handled(message.received_at - timedelta(microseconds=1))
    with pytest.raises(ValidationError):
        dataclasses.replace(message, state=InboxState.HANDLED)  # no handled_at
    with pytest.raises(ValidationError):
        dataclasses.replace(message, handled_at=T0)  # received with a handled time
    with pytest.raises(ValidationError):
        dataclasses.replace(message, state=cast(InboxState, "bogus"))


def test_direct_constructor_refuses_unredacted_text() -> None:
    with pytest.raises(ValidationError, match="unredacted"):
        OwnerMessage(
            id=mid(1), update_id=1, telegram_message_id=1, text="code 123456", received_at=T0
        )


def test_redaction_may_lengthen_within_the_stored_bound() -> None:
    worst = ("123456a" * 600)[:4096]
    message = make_message(1, text=worst)
    assert len(message.text) <= STORED_MESSAGE_MAX_CHARS
    assert "123456" not in message.text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", ""),
        ("no digits", "no digits"),
        ("12345 6", CODE_REDACTED),  # one blank between digits joins the run
        ("123  456", CODE_REDACTED),  # several blanks join it too (S-C1 S4)
        ("123 4567", "123 4567"),  # no group window adds up to exactly 6: kept
        ("⑽23456", "⑽23456"),  # NFKC "(10)" is not a digit char
        ("x 123456", f"x {CODE_REDACTED}"),
        ("123456 ", f"{CODE_REDACTED} "),  # trailing blank stays
    ],
)
def test_redaction_edges(text: str, expected: str) -> None:
    assert redact_code_runs(text) == expected
    assert redact_code_runs(expected) == expected
