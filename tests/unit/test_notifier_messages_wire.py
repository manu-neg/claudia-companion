"""Unit tests for `wire/notifier_messages.py`: round trips and strict parsing (M2/M3 shapes)."""

from __future__ import annotations

from typing import Any

import pytest

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_messages import STORED_MESSAGE_MAX_CHARS, STORED_QUOTE_MAX_CHARS
from preview_dashboard.wire import notifier_messages as wm
from tests.owner_updates_support import APPROVAL_ID

pytestmark = pytest.mark.unit


def _message(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "update_id": 1,
        "message_id": 2,
        "sender_id": 3,
        "text": "hello",
        "is_forwarded": False,
        "reply_to_message_id": None,
        "quote_text": None,
    }
    body.update(overrides)
    return body


def test_paths_live_under_the_notifier_prefix() -> None:
    assert wm.MESSAGES_PATH == "/v1/notifier/messages"
    assert wm.APPROVALS_PATH == "/v1/notifier/approvals"
    assert wm.CODES_PATH == "/v1/notifier/codes"


def test_message_round_trip() -> None:
    sub = wm.MessageSubmission(
        update_id=0,
        message_id=1,
        sender_id=9,
        text="hi\nthere",
        is_forwarded=True,
        reply_to_message_id=4,
        quote_text="q",
    )
    assert wm.parse_message_request(wm.message_request_to_json(sub)) == sub


def test_message_optional_keys_may_be_absent() -> None:
    body = _message()
    del body["reply_to_message_id"], body["quote_text"]
    assert wm.parse_message_request(body).quote_text is None


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("update_id", -1),
        ("update_id", True),
        ("update_id", "1"),
        ("message_id", 0),
        ("sender_id", 0),
        ("sender_id", 2**63),
        ("text", ""),
        ("text", " \n "),
        ("text", "a\x00b"),
        ("text", "\ud800"),
        ("text", "123456"),
        ("text", "code 123456"),
        ("text", "x" * (STORED_MESSAGE_MAX_CHARS + 1)),
        ("text", 5),
        ("is_forwarded", 1),
        ("reply_to_message_id", 0),
        ("quote_text", ""),
        ("quote_text", "x" * (STORED_QUOTE_MAX_CHARS + 1)),
        ("quote_text", "654321 inside"),
        ("extra", 1),
    ],
)
def test_message_parse_is_strict(key: str, value: object) -> None:
    with pytest.raises(ValidationError):
        wm.parse_message_request(_message(**{key: value}))


def test_message_missing_key_is_refused() -> None:
    body = _message()
    del body["text"]
    with pytest.raises(ValidationError):
        wm.parse_message_request(body)
    with pytest.raises(ValidationError):
        wm.parse_message_request([body])


@pytest.mark.parametrize("decision", list(wm.ApprovalDecision))
def test_approval_callback_round_trip(decision: wm.ApprovalDecision) -> None:
    data = wm.approval_callback_data(APPROVAL_ID, decision)
    assert len(data.encode()) <= 64
    assert wm.parse_approval_callback(data) == (APPROVAL_ID, decision)


def test_approval_callback_data_needs_a_ulid() -> None:
    with pytest.raises(ValidationError):
        wm.approval_callback_data("nope", wm.ApprovalDecision.APPROVE)


@pytest.mark.parametrize(
    "data",
    [
        None,
        5,
        "",
        f"p:{APPROVAL_ID}",
        f"p:{APPROVAL_ID}:yes",
        f"a:{APPROVAL_ID}:ok",
        f"p:{APPROVAL_ID}:ok\n",
        "p:8ZZZZZZZZZZZZZZZZZZZZZZZZZ:ok",
    ],
)
def test_approval_callback_parse_is_strict(data: object) -> None:
    assert wm.parse_approval_callback(data) is None


def test_tap_round_trip_and_strictness() -> None:
    sub = wm.ApprovalTapSubmission(
        request_id=APPROVAL_ID, decision=wm.ApprovalDecision.DENY, source="telegram", actor_ref="1"
    )
    body = wm.approval_tap_request_to_json(sub)
    assert body["decision"] == "deny"
    assert wm.parse_approval_tap_request(body) == sub
    for key, value in [
        ("request_id", "x"),
        ("decision", "ok"),
        ("decision", 1),
        ("source", "Tele gram"),
        ("actor_ref", "has space"),
    ]:
        with pytest.raises(ValidationError):
            wm.parse_approval_tap_request({**body, key: value})
    with pytest.raises(ValidationError):
        wm.parse_approval_tap_request({**body, "extra": 1})


def test_code_round_trip_and_strictness() -> None:
    sub = wm.CodeSubmission(update_id=1, message_id=2, sender_id=3, code="012345")
    assert wm.parse_code_request(wm.code_request_to_json(sub)) == sub
    for code in ["12345", "1234567", "12 345", "\uff11" * 6, 123456, "abcdef"]:
        with pytest.raises(ValidationError):
            wm.parse_code_request({**wm.code_request_to_json(sub), "code": code})


@pytest.mark.parametrize(
    ("enum", "to_json", "parse"),
    [
        (wm.MessageResult, wm.message_result_to_json, wm.parse_message_result),
        (wm.TapResult, wm.tap_result_to_json, wm.parse_tap_result),
        (wm.CodeResult, wm.code_result_to_json, wm.parse_code_result),
    ],
)
def test_results_round_trip_and_refuse_unknowns(enum: Any, to_json: Any, parse: Any) -> None:
    for member in enum:
        assert parse(to_json(member)) is member
    for bad in [{"result": "nope"}, {"result": 1}, {}, {"result": "x", "y": 1}, None]:
        with pytest.raises(ValidationError):
            parse(bad)


def test_every_tap_result_has_a_fixed_ack() -> None:
    assert set(wm.TAP_ACK_TEXTS) == set(wm.TapResult)
    assert all(len(t) <= 200 for t in wm.TAP_ACK_TEXTS.values())
