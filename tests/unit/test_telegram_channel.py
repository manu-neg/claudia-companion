"""Unit tests for TelegramChannel: plain-text messages, button layout, edits (C35)."""

from __future__ import annotations

import pytest

from preview_dashboard.adapters.telegram.channel import (
    LINK_BUTTON_TEXT,
    TelegramChannel,
    callback_data,
)
from preview_dashboard.adapters.telegram.client import TelegramConfigError, TelegramError
from preview_dashboard.domain.notifications import DeliveryPayload, MessageButton, MessageContent
from preview_dashboard.domain.questions import QuestionState
from tests.notify_support import DASHBOARD, qid
from tests.telegram_support import OWNER, STRANGER, FakeBotApi, error, message, ok

pytestmark = pytest.mark.unit

LINK = f"{DASHBOARD}/#/item/{qid(9)}"


def channel(api: FakeBotApi, origin: str | None = DASHBOARD) -> TelegramChannel:
    return TelegramChannel(api.client(), OWNER, dashboard_origin=origin)


def question_payload() -> DeliveryPayload:
    return DeliveryPayload(
        content=MessageContent(
            text="❓ Which DB?\nSession: s1",
            buttons=(
                MessageButton(key="a", label="SQLite"),
                MessageButton(key="b", label="Postgres"),
            ),
            link=LINK,
        ),
        question_id=qid(1),
    )


def outcome_payload(link: str | None = LINK) -> DeliveryPayload:
    return DeliveryPayload(
        content=MessageContent(text="❓ Which DB?\n✅ Answered: SQLite", link=link),
        question_id=qid(1),
        final_state=QuestionState.ANSWERED,
    )


def test_send_posts_plain_text_with_buttons_and_link() -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok(message(55)))
    ref = channel(api).send(question_payload())
    assert ref == f"{OWNER}:55"
    (call,) = api.calls
    assert call.method == "sendMessage"
    assert call.body["chat_id"] == OWNER
    assert call.body["text"] == "❓ Which DB?\nSession: s1"
    assert "parse_mode" not in call.body  # plain text only (C35)
    assert call.body["link_preview_options"] == {"is_disabled": True}
    assert call.body["reply_markup"] == {
        "inline_keyboard": [
            [{"text": "SQLite", "callback_data": f"a:{qid(1)}:a"}],
            [{"text": "Postgres", "callback_data": f"a:{qid(1)}:b"}],
            [{"text": LINK_BUTTON_TEXT, "url": LINK}],
        ]
    }


def test_link_goes_to_a_button_not_the_text() -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok(message()))
    channel(api).send(question_payload())
    assert LINK not in api.calls[0].body["text"]


def test_callback_data_fits_telegram_limit() -> None:
    data = callback_data(qid(1), "k" * 16)
    assert len(data.encode()) <= 64
    with pytest.raises(ValueError):
        callback_data("x" * 60, "abc")


def test_send_without_buttons_or_link_has_empty_keyboard() -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok(message()))
    payload = DeliveryPayload(content=MessageContent(text="✅ done"))
    channel(api).send(payload)
    assert api.calls[0].body["reply_markup"] == {"inline_keyboard": []}


@pytest.mark.parametrize(
    "result",
    [
        message(chat_id=STRANGER),
        {"message_id": "7", "chat": {"id": OWNER}},
        {"message_id": True, "chat": {"id": OWNER}},
        {"message_id": 0, "chat": {"id": OWNER}},
        [],
        None,
    ],
)
def test_send_rejects_replies_that_are_not_an_owner_message(result: object) -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok(result))
    with pytest.raises(TelegramError):
        channel(api).send(question_payload())


def test_send_failure_propagates() -> None:
    api = FakeBotApi()
    api.script("sendMessage", error(403, "Forbidden: bot was blocked by the user"))
    with pytest.raises(TelegramError):
        channel(api).send(question_payload())


def test_resolve_edits_text_and_drops_answer_buttons() -> None:
    api = FakeBotApi()
    channel(api).resolve(f"{OWNER}:55", outcome_payload())
    (call,) = api.calls
    assert call.method == "editMessageText"
    assert call.body["chat_id"] == OWNER and call.body["message_id"] == 55
    assert call.body["text"] == "❓ Which DB?\n✅ Answered: SQLite"
    assert "parse_mode" not in call.body
    assert call.body["reply_markup"] == {
        "inline_keyboard": [[{"text": LINK_BUTTON_TEXT, "url": LINK}]]
    }


def test_resolve_without_link_removes_the_whole_keyboard() -> None:
    api = FakeBotApi()
    channel(api).resolve(f"{OWNER}:55", outcome_payload(link=None))
    assert api.calls[0].body["reply_markup"] == {"inline_keyboard": []}


def test_resolve_not_modified_counts_as_done() -> None:
    api = FakeBotApi()
    api.script("editMessageText", error(400, "Bad Request: message is not modified: same"))
    channel(api).resolve(f"{OWNER}:55", outcome_payload())


def test_resolve_other_errors_propagate() -> None:
    api = FakeBotApi()
    api.script("editMessageText", error(400, "Bad Request: message to edit not found"))
    with pytest.raises(TelegramError):
        channel(api).resolve(f"{OWNER}:55", outcome_payload())


@pytest.mark.parametrize("ref", [f"{STRANGER}:5", "55", f"{OWNER}:x", f"{OWNER}:5:6", "msg-1"])
def test_resolve_only_edits_messages_in_the_owner_chat(ref: str) -> None:
    api = FakeBotApi()
    with pytest.raises(ValueError):
        channel(api).resolve(ref, outcome_payload())
    assert api.calls == []


def test_owner_chat_id_is_validated() -> None:
    with pytest.raises(TelegramConfigError):
        TelegramChannel(FakeBotApi().client(), -100, dashboard_origin=DASHBOARD)


@pytest.mark.parametrize("origin", [f"{DASHBOARD}/", DASHBOARD.replace("https", "http"), ""])
def test_dashboard_origin_is_validated(origin: str) -> None:
    with pytest.raises(TelegramConfigError):
        channel(FakeBotApi(), origin)


def test_resolve_keeps_the_link_only_on_the_dashboard_origin() -> None:
    api = FakeBotApi()
    channel(api, "https://other.example").resolve(f"{OWNER}:55", outcome_payload())
    assert api.calls[0].body["reply_markup"] == {"inline_keyboard": []}


def test_without_an_origin_answer_buttons_still_go_out() -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok(message()))
    channel(api, None).send(question_payload())
    rows = api.calls[0].body["reply_markup"]["inline_keyboard"]
    assert [b["text"] for row in rows for b in row] == ["SQLite", "Postgres"]
