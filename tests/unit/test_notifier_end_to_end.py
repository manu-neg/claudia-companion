"""End to end in memory: question -> Telegram message -> owner tap -> answer -> edited message.

The admin side is the real in-memory core behind a MockTransport that
speaks `wire/notifier.py` (what unit N3's routes will do); the
notifier side is the real `AdminDeliveryQueue`, `TelegramChannel`,
`TelegramAnswerSource` and `DeliveryService` over a fake Bot API.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.application.delivery import DeliveryService
from preview_dashboard.application.questions import AskCommand
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.questions import QuestionState
from preview_dashboard.wire import notifier as wire
from tests.notify_support import DASHBOARD, NotifyHarness, build_harness
from tests.telegram_support import (
    FAKE_NOTIFIER_TOKEN,
    OWNER,
    STRANGER,
    FakeBotApi,
    callback_update,
    message,
    ok,
)

pytestmark = pytest.mark.unit


class InMemoryNotifierRoutes:
    """The `/notifier/*` routes over the in-memory core, using only the wire module."""

    def __init__(self, harness: NotifyHarness) -> None:
        self.h = harness

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {FAKE_NOTIFIER_TOKEN.decode()}"
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        try:
            if request.method == "GET" and path == wire.TASKS_PATH:
                wire.parse_wait_param(request.url.params.get("wait"))
                limit = wire.parse_limit_param(request.url.params.get("limit"))
                tasks = self.h.outbox_service.pending(limit)
                return httpx.Response(200, json=wire.tasks_to_json(tasks))
            if request.method == "POST" and path == wire.ANSWERS_PATH:
                sub = wire.parse_answer_request(body)
                result = self.h.questions.answer(sub.question_id, sub.key, sub.source)
                return httpx.Response(200, json=wire.answer_result_to_json(result))
            if request.method == "POST" and path.startswith(wire.TASKS_PATH + "/"):
                task_id, action = path.removeprefix(wire.TASKS_PATH + "/").split("/")
                if action == "done":
                    self.h.outbox_service.done(task_id, wire.parse_done_request(body))
                else:
                    wire.parse_failed_request(body)
                    self.h.outbox_service.failed(task_id)
                return httpx.Response(200, json={})
        except ValidationError:
            return httpx.Response(400, json={"error": "invalid_input"})
        return httpx.Response(404, json={"error": "not_found"})


def rig() -> tuple[NotifyHarness, FakeBotApi, DeliveryService]:
    harness = build_harness(channels=("telegram",))
    routes = InMemoryNotifierRoutes(harness)
    queue = AdminDeliveryQueue(
        Path("/nonexistent.sock"),
        FAKE_NOTIFIER_TOKEN,
        transport=httpx.MockTransport(routes.handler),
    )
    api = FakeBotApi()
    client = api.client()
    service = DeliveryService(
        queue=queue,
        channels=[TelegramChannel(client, OWNER, dashboard_origin=DASHBOARD)],
        answers=TelegramAnswerSource(client, OWNER),
    )
    return harness, api, service


def test_question_is_sent_answered_and_edited() -> None:
    harness, api, service = rig()
    question = harness.questions.ask(
        AskCommand(
            prompt="Which DB?",
            options=[("a", "SQLite"), ("b", "Postgres")],
            session_label="R4",
        )
    )
    api.script("sendMessage", ok(message(99)))
    assert service.run_once_deliveries() == 1
    sent = api.calls[-1].body
    assert sent["text"].startswith("❓ Which DB?") and "Session: R4" in sent["text"]
    buttons = [row[0] for row in sent["reply_markup"]["inline_keyboard"]]
    tap_data = next(b["callback_data"] for b in buttons if b.get("text") == "Postgres")

    # A stranger's tap first (ignored), then the owner's.
    api.script(
        "getUpdates",
        ok(
            [
                callback_update(1, tap_data, sender=STRANGER, chat=STRANGER, query_id="x1"),
                callback_update(2, tap_data, query_id="cbq-owner"),
            ]
        ),
    )
    assert service.run_once_answers() == 1
    ack = api.calls[-1]
    assert ack.method == "answerCallbackQuery"
    assert ack.body == {"callback_query_id": "cbq-owner", "text": "Recorded: b"}
    stored = harness.questions.get(question.id)
    assert stored.state is QuestionState.ANSWERED and stored.answer_source == "telegram"

    assert service.run_once_deliveries() == 1
    edit = api.calls[-1]
    assert edit.method == "editMessageText"
    assert edit.body["message_id"] == 99
    assert "Answered: Postgres" in edit.body["text"]
    assert all(
        "callback_data" not in b
        for row in edit.body["reply_markup"]["inline_keyboard"]
        for b in row
    )

    # A late second tap: already answered, nothing changes.
    api.script("getUpdates", ok([callback_update(3, tap_data, query_id="cbq-late")]))
    assert service.run_once_answers() == 0
    assert api.calls[-1].body["text"] == "Already answered"


def test_telegram_failure_is_retried_later() -> None:
    harness, api, service = rig()
    harness.questions.ask(
        AskCommand(session_label="s1", prompt="Q?", options=[("a", "A"), ("b", "B")])
    )
    api.script("sendMessage", httpx.ConnectError("down"))
    assert service.run_once_deliveries() == 0
    # Backed off: not due again right away.
    assert harness.outbox_service.pending(20) == []
