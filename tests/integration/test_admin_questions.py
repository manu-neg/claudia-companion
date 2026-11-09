"""Integration tests for the admin question, alert and notifier routes (unit N3).

Real admin core (SQLite store, in-process wake-ups) behind the real admin
app: request/response shapes, strict body parsing, the notifier's task
flow (send → done → answer → resolve), and N4's `AdminDeliveryQueue`
talking to these routes over a real Unix socket with the notifier token.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue, AdminQueueError
from preview_dashboard.application import AskCommand
from preview_dashboard.domain.questions import AnswerResult, QuestionState
from tests.admin_support import DASHBOARD_HOST, publish
from tests.mcp_support import fake_aws_key
from tests.notify_admin_support import (
    answer_body,
    ask_body,
    bearer,
    live_notify_admin,
    notify_app,
)

pytestmark = pytest.mark.integration

QUESTION_KEYS = {
    "id",
    "prompt",
    "options",
    "default_key",
    "item_id",
    "session_label",
    "state",
    "answer_key",
    "answer_source",
    "created_at",
    "expires_at",
    "resolved_at",
    "viewer_url",
}


@pytest.fixture
def rig(tmp_path: Path) -> Any:
    with notify_app(tmp_path, notify_rate_per_hour=100) as app, TestClient(app.app) as client:
        yield app, client


def _ask(client: TestClient, token: str, **overrides: Any) -> Any:
    return client.post("/v1/questions", json=ask_body(**overrides), headers=bearer(token))


class TestAsk:
    def test_created_question_json(self, rig):
        app, client = rig
        response = _ask(client, app.admin_token, default_key="b", expires_in_s=600)
        assert response.status_code == 201
        assert response.headers["cache-control"] == "no-store"
        question = response.json()["question"]
        assert set(question) == QUESTION_KEYS
        assert question["state"] == "open"
        assert question["options"] == [
            {"key": "a", "label": "SQLite"},
            {"key": "b", "label": "Postgres"},
        ]
        assert question["default_key"] == "b"
        assert question["session_label"] == "db-choice task"
        assert question["viewer_url"] is None  # no item
        assert (question["answer_key"], question["resolved_at"]) == (None, None)

    def test_item_question_links_the_item(self, rig):
        app, client = rig
        item = publish(client, app.admin_token, [("a.txt", b"hi")]).json()
        question = _ask(client, app.admin_token, item_id=item["id"]).json()["question"]
        assert question["item_id"] == item["id"]
        assert question["viewer_url"] == f"https://{DASHBOARD_HOST}/#/item/{item['id']}"

    @pytest.mark.parametrize(
        "body",
        [
            {k: v for k, v in ask_body().items() if k != "session_label"},  # required
            {k: v for k, v in ask_body().items() if k != "options"},
            {**ask_body(), "extra": 1},
            {**ask_body(), "options": "a,b"},
            {**ask_body(), "options": [{"key": "a", "label": "A", "x": 1}, {"key": "b"}]},
            {**ask_body(), "options": [{"key": str(i), "label": "L"} for i in range(9)]},
            {**ask_body(), "options": [{"key": "a", "label": "only one"}]},
            {**ask_body(), "options": [{"key": "A!", "label": "x"}, {"key": "b", "label": "y"}]},
            {**ask_body(), "prompt": 5},
            {**ask_body(), "session_label": None},
            {**ask_body(), "default_key": "zz"},
            {**ask_body(), "item_id": "../items"},
            {**ask_body(), "expires_in_s": 59},
            {**ask_body(), "expires_in_s": 604801},
            {**ask_body(), "expires_in_s": True},
            {**ask_body(), "expires_in_s": 600.5},
        ],
    )
    def test_malformed_body_is_400_without_echo(self, rig, body):
        app, client = rig
        response = client.post("/v1/questions", json=body, headers=bearer(app.admin_token))
        assert response.status_code == 400, response.text
        assert "SQLite" not in response.text
        assert app.core.outbox.pending(20) == []  # nothing queued

    def test_non_json_is_415(self, rig):
        app, client = rig
        response = client.post(
            "/v1/questions",
            content=b"prompt=x",
            headers={**bearer(app.admin_token), "Content-Type": "text/plain"},
        )
        assert response.status_code == 415

    def test_secret_in_prompt_is_422_without_echo(self, rig):
        app, client = rig
        response = _ask(client, app.admin_token, prompt=f"Use key {fake_aws_key()}?")
        assert response.status_code == 422
        assert response.json()["error"] == "secret_detected"
        assert fake_aws_key() not in response.text

    def test_one_send_task_per_enabled_channel(self, rig):
        app, client = rig
        qid = _ask(client, app.admin_token).json()["question"]["id"]
        tasks = client.get("/v1/notifier/tasks", headers=bearer(app.notifier_token)).json()
        assert len(tasks["tasks"]) == 1
        task = tasks["tasks"][0]
        assert (task["channel"], task["action"], task["message_ref"]) == ("telegram", "send", None)
        assert task["payload"]["question_id"] == qid
        assert [b["key"] for b in task["payload"]["buttons"]] == ["a", "b"]
        assert "db-choice task" in task["payload"]["text"]


class TestGetAndCancel:
    def test_get_and_cancel_is_idempotent(self, rig):
        app, client = rig
        admin = bearer(app.admin_token)
        qid = _ask(client, app.admin_token).json()["question"]["id"]
        assert client.get(f"/v1/questions/{qid}?wait=0", headers=admin).status_code == 200
        first = client.post(f"/v1/questions/{qid}/cancel", headers=admin).json()["question"]
        again = client.post(f"/v1/questions/{qid}/cancel", headers=admin).json()["question"]
        assert first["state"] == again["state"] == "cancelled"
        assert first["resolved_at"] == again["resolved_at"]

    @pytest.mark.parametrize(("path", "status"), [("0" * 26, 404), ("nope", 400)])
    def test_unknown_or_malformed_id(self, rig, path, status):
        app, client = rig
        admin = bearer(app.admin_token)
        assert client.get(f"/v1/questions/{path}", headers=admin).status_code == status
        assert client.post(f"/v1/questions/{path}/cancel", headers=admin).status_code == status

    def test_wait_on_a_resolved_question_returns_at_once(self, rig):
        app, client = rig
        admin = bearer(app.admin_token)
        qid = _ask(client, app.admin_token).json()["question"]["id"]
        client.post(f"/v1/questions/{qid}/cancel", headers=admin)
        reply = client.get(f"/v1/questions/{qid}?wait=60", headers=admin)
        assert reply.json()["question"]["state"] == "cancelled"


class TestNotifications:
    def test_done_alert(self, rig):
        app, client = rig
        item = publish(client, app.admin_token, [("a.txt", b"hi")]).json()
        body = {"event": "done", "title": "Report ready", "item_id": item["id"]}
        response = client.post("/v1/notifications", json=body, headers=bearer(app.admin_token))
        assert response.status_code == 201
        notification = response.json()["notification"]
        assert set(notification) == {"id", "event", "title", "item_id", "created_at"}
        assert (notification["event"], notification["item_id"]) == ("done", item["id"])
        [task] = client.get("/v1/notifier/tasks", headers=bearer(app.notifier_token)).json()[
            "tasks"
        ]
        assert task["payload"]["link"] == f"https://{DASHBOARD_HOST}/#/item/{item['id']}"
        assert task["payload"]["buttons"] == []

    @pytest.mark.parametrize(
        "body",
        [
            {"event": "question", "title": "x"},  # actionable: only via /v1/questions
            {"event": "nope", "title": "x"},
            {"event": "done"},
            {"event": "done", "title": "x", "link": "https://evil.example"},
            {"event": "done", "title": ["x"]},
        ],
    )
    def test_bad_alert_is_400(self, rig, body):
        app, client = rig
        response = client.post("/v1/notifications", json=body, headers=bearer(app.admin_token))
        assert response.status_code == 400


class TestNotifierFlow:
    def test_send_done_answer_resolve(self, rig):
        app, client = rig
        notifier = bearer(app.notifier_token)
        qid = _ask(client, app.admin_token).json()["question"]["id"]
        [send] = client.get("/v1/notifier/tasks?limit=5", headers=notifier).json()["tasks"]
        done = client.post(
            f"/v1/notifier/tasks/{send['id']}/done", json={"message_ref": "42:7"}, headers=notifier
        )
        assert done.status_code == 200
        assert client.get("/v1/notifier/tasks", headers=notifier).json() == {"tasks": []}
        answered = client.post("/v1/notifier/answers", json=answer_body(qid, "b"), headers=notifier)
        assert answered.json() == {"result": "recorded"}
        [resolve] = client.get("/v1/notifier/tasks", headers=notifier).json()["tasks"]
        assert (resolve["action"], resolve["message_ref"]) == ("resolve", "42:7")
        assert resolve["payload"]["final_state"] == "answered"
        assert resolve["payload"]["buttons"] == []

    def test_failed_backs_off(self, rig):
        app, client = rig
        notifier = bearer(app.notifier_token)
        _ask(client, app.admin_token)
        [send] = client.get("/v1/notifier/tasks", headers=notifier).json()["tasks"]
        failed = client.post(f"/v1/notifier/tasks/{send['id']}/failed", json={}, headers=notifier)
        assert failed.status_code == 200
        assert client.get("/v1/notifier/tasks", headers=notifier).json() == {"tasks": []}

    @pytest.mark.parametrize(
        ("task_id", "body", "status"),
        [
            ("0" * 26, {}, 404),
            ("nope", {}, 400),
            (None, {"message_ref": "x", "extra": 1}, 400),
            (None, {"message_ref": "bad ref"}, 400),
        ],
    )
    def test_bad_done_reports(self, rig, task_id, body, status):
        app, client = rig
        notifier = bearer(app.notifier_token)
        _ask(client, app.admin_token)
        real = client.get("/v1/notifier/tasks", headers=notifier).json()["tasks"][0]["id"]
        path = f"/v1/notifier/tasks/{task_id or real}/done"
        assert client.post(path, json=body, headers=notifier).status_code == status

    def test_failed_report_body_must_be_empty(self, rig):
        app, client = rig
        notifier = bearer(app.notifier_token)
        _ask(client, app.admin_token)
        task = client.get("/v1/notifier/tasks", headers=notifier).json()["tasks"][0]["id"]
        response = client.post(f"/v1/notifier/tasks/{task}/failed", json={"x": 1}, headers=notifier)
        assert response.status_code == 400

    @pytest.mark.parametrize(
        "body",
        [
            {"question_id": "x", "key": "a", "source": "telegram"},  # missing actor_ref
            {**answer_body("0" * 26), "key": "k" * 65},
            {**answer_body("0" * 26), "actor_ref": "has space"},
            {**answer_body("0" * 26), "source": "Tele gram"},
        ],
    )
    def test_malformed_answer_is_400(self, rig, body):
        app, client = rig
        response = client.post(
            "/v1/notifier/answers", json=body, headers=bearer(app.notifier_token)
        )
        assert response.status_code == 400


class TestDeliveryQueueOverSocket:
    """N4's notifier-side client against these routes, over a real Unix socket."""

    def test_notifier_queue_round_trip(self, tmp_path):
        with live_notify_admin(tmp_path) as live:
            question = live.core.questions.ask(_command())
            queue = AdminDeliveryQueue(live.settings.admin_socket, live.notifier_token.encode())
            with_admin = AdminDeliveryQueue(live.settings.admin_socket, live.admin_token.encode())
            try:
                [task] = queue.pending(wait=0)
                assert task.payload.question_id == question.id
                queue.done(task.id, "99:1")
                assert queue.submit_answer(question.id, "a", "telegram", "424242") is (
                    AnswerResult.RECORDED
                )
                [resolve] = queue.pending(wait=5)
                assert resolve.message_ref == "99:1"
                queue.done(resolve.id, None)
                # The admin token is refused on the notifier routes (403).
                with pytest.raises(AdminQueueError) as refused:
                    with_admin.pending(wait=0)
                assert refused.value.status == 403
            finally:
                queue.close()
                with_admin.close()
            assert live.core.questions.get(question.id).state is QuestionState.ANSWERED


def _command() -> AskCommand:
    return AskCommand(
        prompt="Ship it?",
        options=[("a", "Yes"), ("b", "No")],
        session_label="integration test",
    )
