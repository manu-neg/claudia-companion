"""Unit tests for the notifier wire format (`wire/notifier.py`).

Round trips of every body, and strict rejection of malformed input.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    MessageButton,
    MessageContent,
    PendingTask,
)
from preview_dashboard.domain.questions import AnswerResult, QuestionState
from preview_dashboard.wire import notifier as wire
from tests.notify_support import DASHBOARD, qid, tid

pytestmark = pytest.mark.unit


def send_task() -> PendingTask:
    content = MessageContent(
        text="❓ Which DB?\nSession: s1",
        buttons=(MessageButton(key="a", label="SQLite"), MessageButton(key="b", label="Postgres")),
        link=f"{DASHBOARD}/",
    )
    return PendingTask(
        id=tid(1),
        channel="telegram",
        action=DeliveryAction.SEND,
        payload=DeliveryPayload(content=content, question_id=qid(1)),
    )


def resolve_task() -> PendingTask:
    return PendingTask(
        id=tid(2),
        channel="telegram",
        action=DeliveryAction.RESOLVE,
        payload=DeliveryPayload(
            content=MessageContent(text="❓ Which DB?\n✅ Answered: SQLite"),
            question_id=qid(1),
            final_state=QuestionState.ANSWERED,
        ),
        message_ref="424242:7",
    )


def test_task_json_shape_is_the_documented_one() -> None:
    assert wire.task_to_json(send_task()) == {
        "id": tid(1),
        "channel": "telegram",
        "action": "send",
        "payload": {
            "text": "❓ Which DB?\nSession: s1",
            "buttons": [{"key": "a", "label": "SQLite"}, {"key": "b", "label": "Postgres"}],
            "link": f"{DASHBOARD}/",
            "question_id": qid(1),
            "final_state": None,
        },
        "message_ref": None,
    }


@pytest.mark.parametrize("task", [send_task(), resolve_task()], ids=["send", "resolve"])
def test_tasks_round_trip(task: PendingTask) -> None:
    body = wire.tasks_to_json([task])
    parsed = [wire.parse_task(t) for t in wire.parse_tasks_envelope(body)]
    assert parsed == [task]


def test_optional_task_fields_may_be_absent() -> None:
    raw: dict[str, Any] = {
        "id": tid(3),
        "channel": "telegram",
        "action": "send",
        "payload": {"text": "✅ done", "buttons": []},
    }
    task = wire.parse_task(raw)
    assert task.payload.content.link is None and task.message_ref is None


def _mutated(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    raw = copy.deepcopy(wire.task_to_json(send_task()))
    target: Any = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return raw


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("extra",), 1),
        (("payload", "extra"), 1),
        (("id",), "../x"),
        (("action",), "delete"),
        (("channel",), "Tele gram"),
        (("payload", "text"), 5),
        (("payload", "text"), "bad\x1b[31m"),
        (("payload", "text"), "x" * 301),
        (("payload", "buttons"), "a"),
        (("payload", "buttons"), [{"key": "A:B", "label": "x"}]),
        (("payload", "buttons"), [{"key": "a", "label": "x", "url": "https://evil"}]),
        (("payload", "link"), "https://evil.example/phish?x=1"),
        (("payload", "link"), "javascript:alert(1)"),
        (("payload", "question_id"), "nope"),
        (("payload", "final_state"), "open"),
        (("message_ref",), "has space"),
    ],
)
def test_parse_task_rejects_malformed_fields(path: tuple[str, ...], value: Any) -> None:
    with pytest.raises(ValidationError):
        wire.parse_task(_mutated(path, value))


def test_resolve_without_message_ref_is_rejected() -> None:
    raw = wire.task_to_json(resolve_task())
    raw["message_ref"] = None
    with pytest.raises(ValidationError):
        wire.parse_task(raw)


@pytest.mark.parametrize(
    "body",
    [[], {"tasks": {}}, {"tasks": []} | {"more": 1}, {"tasks": [{}] * 21}, None],
)
def test_tasks_envelope_is_strict(body: object) -> None:
    with pytest.raises(ValidationError):
        wire.parse_tasks_envelope(body)


def test_task_id_of_extracts_only_valid_ids() -> None:
    assert wire.task_id_of({"id": tid(4), "junk": True}) == tid(4)
    assert wire.task_id_of({"id": "../../x"}) is None
    assert wire.task_id_of("x") is None


def test_paths_validate_task_ids() -> None:
    assert wire.task_done_path(tid(1)) == f"/v1/notifier/tasks/{tid(1)}/done"
    assert wire.task_failed_path(tid(1)) == f"/v1/notifier/tasks/{tid(1)}/failed"
    with pytest.raises(ValidationError):
        wire.task_done_path("../../items")


@pytest.mark.parametrize(("raw", "expected"), [(None, 0), ("0", 0), ("60", 60), ("7", 7)])
def test_wait_param(raw: str | None, expected: int) -> None:
    assert wire.parse_wait_param(raw) == expected


@pytest.mark.parametrize("raw", ["61", "-1", "+5", " 5", "1_0", "\u0665", "", "1e3", "9999999"])
def test_wait_param_rejects(raw: str) -> None:
    with pytest.raises(ValidationError):
        wire.parse_wait_param(raw)


def test_limit_param() -> None:
    assert wire.parse_limit_param(None) == 20
    assert wire.parse_limit_param("1") == 1
    for bad in ("0", "21"):
        with pytest.raises(ValidationError):
            wire.parse_limit_param(bad)


def test_done_and_failed_requests() -> None:
    assert wire.parse_done_request(wire.done_request_to_json("424242:7")) == "424242:7"
    assert wire.parse_done_request({}) is None
    assert wire.parse_done_request({"message_ref": None}) is None
    wire.parse_failed_request(wire.failed_request_to_json())
    bads: list[object] = [{"message_ref": "a b"}, {"message_ref": 5}, {"x": 1}, []]
    for bad in bads:
        with pytest.raises(ValidationError):
            wire.parse_done_request(bad)
    with pytest.raises(ValidationError):
        wire.parse_failed_request({"x": 1})


def test_answer_request_round_trip_keeps_raw_ids() -> None:
    # Unknown/malformed ids pass through: the admin answers them `unknown` (C34).
    sub = wire.AnswerSubmission(
        question_id="not-a-ulid", key="Z!", source="telegram", actor_ref="42"
    )
    assert wire.parse_answer_request(wire.answer_request_to_json(sub)) == sub


@pytest.mark.parametrize(
    "change",
    [
        {"question_id": "x" * 65},
        {"key": "k" * 65},
        {"question_id": 5},
        {"source": "Telegram!"},
        {"actor_ref": ""},
        {"actor_ref": "a b"},
        {"extra": 1},
    ],
)
def test_answer_request_rejects(change: dict[str, Any]) -> None:
    raw: dict[str, Any] = {
        "question_id": qid(1),
        "key": "a",
        "source": "telegram",
        "actor_ref": "4",
    }
    raw.update(change)
    with pytest.raises(ValidationError):
        wire.parse_answer_request(raw)


@pytest.mark.parametrize("result", list(AnswerResult))
def test_answer_result_round_trip(result: AnswerResult) -> None:
    assert wire.parse_answer_result(wire.answer_result_to_json(result)) is result


@pytest.mark.parametrize(
    "raw", [{"result": "maybe"}, {"result": 1}, {}, {"result": "recorded", "x": 1}]
)
def test_answer_result_rejects(raw: object) -> None:
    with pytest.raises(ValidationError):
        wire.parse_answer_result(raw)
