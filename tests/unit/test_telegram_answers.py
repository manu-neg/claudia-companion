"""Unit tests for TelegramAnswerSource: owner-only taps, strict callback data, offsets (C34)."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
from preview_dashboard.adapters.telegram.client import TelegramError
from preview_dashboard.ports.notify import AnswerEvent
from tests.notify_support import qid
from tests.telegram_support import OWNER, STRANGER, FakeBotApi, callback_update, error, ok

pytestmark = pytest.mark.unit

DATA = f"a:{qid(1)}:b"


def source(api: FakeBotApi) -> TelegramAnswerSource:
    return TelegramAnswerSource(api.client(), OWNER)


def test_owner_tap_becomes_an_answer_event() -> None:
    api = FakeBotApi()
    api.script("getUpdates", ok([callback_update(10, DATA, query_id="cbq-9")]))
    events = source(api).poll(50)
    assert events == [
        AnswerEvent(question_id=qid(1), key="b", actor_ref=str(OWNER), ack_handle="cbq-9")
    ]


def test_poll_requests_only_callback_queries_with_bounded_wait() -> None:
    api = FakeBotApi()
    source(api).poll(999)
    body = api.calls[0].body
    assert body["allowed_updates"] == ["callback_query"]
    assert body["timeout"] == 50
    assert body["limit"] == 20
    assert "offset" not in body
    assert api.calls[0].request.extensions["timeout"]["read"] == 65


def test_offset_advances_past_every_update_including_ignored_ones() -> None:
    api = FakeBotApi()
    api.script(
        "getUpdates",
        ok([callback_update(10, DATA, sender=STRANGER), {"update_id": 11, "message": {}}]),
        ok([]),
    )
    src = source(api)
    assert src.poll(50) == []
    src.poll(50)
    assert api.calls[1].body["offset"] == 12


@pytest.mark.parametrize(
    "update",
    [
        callback_update(1, DATA, sender=STRANGER),
        callback_update(1, DATA, chat=STRANGER),
        callback_update(1, DATA, sender=STRANGER, chat=STRANGER),
        callback_update(1, DATA, chat=-1001234),
        callback_update(1, f"a:{qid(1)}:B"),
        callback_update(1, f"a:{qid(1)}:"),
        callback_update(1, f"a:{qid(1)}:b:c"),
        callback_update(1, f"x:{qid(1)}:b"),
        callback_update(1, "a:0000000000000000000000000a:b"),  # lowercase ULID
        callback_update(1, f"a:8{qid(1)[1:]}:b"),  # not a ULID (first char > 7)
        callback_update(1, f"a:{qid(1)}:b\n"),
        callback_update(1, f" a:{qid(1)}:b"),
        callback_update(1, DATA, query_id=""),
        callback_update(1, DATA, query_id="has space"),
        {"update_id": 1, "message": {"text": "/start", "chat": {"id": OWNER}}},
        {"update_id": 1},
    ],
)
def test_everything_but_a_well_formed_owner_tap_is_ignored(update: dict[str, Any]) -> None:
    api = FakeBotApi()
    api.script("getUpdates", ok([update]))
    assert source(api).poll(50) == []


def test_missing_message_or_sender_is_ignored() -> None:
    update = callback_update(1, DATA)
    del update["callback_query"]["message"]
    other = callback_update(2, DATA)
    other["callback_query"]["from"] = {"id": str(OWNER)}  # string id, not int
    api = FakeBotApi()
    api.script("getUpdates", ok([update, other]))
    assert source(api).poll(50) == []


def test_bool_ids_are_not_ints() -> None:
    update = callback_update(1, DATA, sender=OWNER)
    update["callback_query"]["from"]["id"] = True
    api = FakeBotApi()
    api.script("getUpdates", ok([update]))
    assert TelegramAnswerSource(api.client(), 1).poll(50) == []


@pytest.mark.parametrize("result", [{"not": "a list"}, None, [1, "x", {"update_id": "3"}]])
def test_malformed_update_lists_are_ignored(result: object) -> None:
    api = FakeBotApi()
    api.script("getUpdates", ok(result))
    assert source(api).poll(50) == []


def test_ignored_updates_log_no_content(caplog: pytest.LogCaptureFixture) -> None:
    api = FakeBotApi()
    marker = "CALLBACK-CONTENT-MARKER"
    api.script("getUpdates", ok([callback_update(1, marker, sender=STRANGER)]))
    with caplog.at_level(logging.DEBUG):
        source(api).poll(50)
    assert marker not in caplog.text and str(STRANGER) not in caplog.text


def test_poll_errors_propagate() -> None:
    api = FakeBotApi()
    api.script("getUpdates", error(409, "Conflict: terminated by other getUpdates request"))
    with pytest.raises(TelegramError) as info:
        source(api).poll(50)
    assert info.value.status == 409


def test_ack_answers_the_callback_query() -> None:
    api = FakeBotApi()
    source(api).ack("cbq-1", "Recorded: b")
    assert api.calls[0].method == "answerCallbackQuery"
    assert api.calls[0].body == {"callback_query_id": "cbq-1", "text": "Recorded: b"}


def test_ack_bounds_text_and_validates_handle() -> None:
    api = FakeBotApi()
    source(api).ack("cbq-1", "x" * 500)
    assert len(api.calls[0].body["text"]) == 200
    with pytest.raises(ValueError):
        source(api).ack("bad handle", "x")
