"""Unit tests for AdminDeliveryQueue: `/notifier/*` requests, errors, bounds, token hygiene.

Controls C33 (notifier routes only) and C36 (token never in reprs or errors).
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters import admin_queue as queue_mod
from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue, AdminQueueError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    MessageContent,
    PendingTask,
)
from preview_dashboard.domain.questions import AnswerResult
from preview_dashboard.wire import notifier as wire
from tests.notify_support import qid, tid
from tests.telegram_support import FAKE_NOTIFIER_TOKEN, FakeNotifierAdmin

pytestmark = pytest.mark.unit

TASK = PendingTask(
    id=tid(1),
    channel="telegram",
    action=DeliveryAction.SEND,
    payload=DeliveryPayload(content=MessageContent(text="✅ done")),
)


def make(admin: FakeNotifierAdmin, **kwargs: int) -> AdminDeliveryQueue:
    return AdminDeliveryQueue(
        Path("/nonexistent.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport(), **kwargs
    )


def test_pending_long_polls_with_the_notifier_token() -> None:
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json=wire.tasks_to_json([TASK])))
    assert make(admin).pending(60) == [TASK]
    (call,) = admin.calls
    request = call.request
    assert request.headers["authorization"] == f"Bearer {FAKE_NOTIFIER_TOKEN.decode()}"
    assert request.url.params["wait"] == "60" and request.url.params["limit"] == "20"
    assert request.extensions["timeout"]["read"] == 75


def test_pending_clamps_wait() -> None:
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json={"tasks": []}))
    q = make(admin, limit=5)
    q.pending(500)
    q.pending(-3)
    assert [c.request.url.params["wait"] for c in admin.calls] == ["60", "0"]
    assert admin.calls[0].request.url.params["limit"] == "5"


def test_limit_is_validated() -> None:
    with pytest.raises(ValueError):
        make(FakeNotifierAdmin(), limit=21)


def test_malformed_task_is_reported_failed_and_skipped(caplog: pytest.LogCaptureFixture) -> None:
    bad = wire.task_to_json(TASK) | {"id": tid(2), "channel": "BAD CHANNEL"}
    admin = FakeNotifierAdmin()
    admin.route(
        "GET", wire.TASKS_PATH, httpx.Response(200, json={"tasks": [bad, wire.task_to_json(TASK)]})
    )
    admin.route("POST", wire.task_failed_path(tid(2)), httpx.Response(200, json={}))
    with caplog.at_level(logging.WARNING):
        assert make(admin).pending(0) == [TASK]
    assert [c.request.url.path for c in admin.calls][1] == wire.task_failed_path(tid(2))
    assert "BAD CHANNEL" not in caplog.text


def test_malformed_task_without_id_is_only_skipped() -> None:
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json={"tasks": [{"id": "../x"}]}))
    assert make(admin).pending(0) == []
    assert len(admin.calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, json={"items": []}),
        httpx.Response(200, content=b"nope"),
        httpx.Response(200, json={"tasks": [{}] * 21}),
    ],
)
def test_malformed_envelope_raises(response: httpx.Response) -> None:
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, response)
    with pytest.raises(AdminQueueError, match="malformed"):
        make(admin).pending(0)


@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (401, "unauthorized", "401 unauthorized"),
        (403, "forbidden", "403 forbidden"),
        (500, "Internal <script>", "500 error"),
    ],
)
def test_error_statuses_raise_with_safe_labels(status: int, code: str, expected: str) -> None:
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(status, json={"error": code}))
    with pytest.raises(AdminQueueError) as info:
        make(admin).pending(0)
    assert str(info.value) == f"admin API tasks: {expected}"
    assert info.value.status == status


def test_transport_errors_raise_type_name_only() -> None:
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.ConnectError("/run/x/admin.sock refused"))
    with pytest.raises(AdminQueueError) as info:
        make(admin).pending(0)
    assert str(info.value) == "admin API tasks: request failed (ConnectError)"
    assert info.value.__context__ is None


def test_oversized_response_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(queue_mod, "MAX_RESPONSE_BYTES", 50)
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json=wire.tasks_to_json([TASK])))
    with pytest.raises(AdminQueueError, match="ResponseTooLarge"):
        make(admin).pending(0)


def test_done_and_failed_post_the_wire_bodies() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wire.task_done_path(tid(1)), httpx.Response(200, json={}))
    admin.route("POST", wire.task_failed_path(tid(1)), httpx.Response(200, json={}))
    q = make(admin)
    q.done(tid(1), "424242:7")
    q.failed(tid(1))
    assert [c.body for c in admin.calls] == [{"message_ref": "424242:7"}, {}]


def test_report_of_a_vanished_task_is_ignored() -> None:
    admin = FakeNotifierAdmin()  # every route 404
    make(admin).done(tid(1), None)
    make(admin).failed(tid(1))


def test_report_other_errors_raise() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wire.task_done_path(tid(1)), httpx.Response(503, json={}))
    with pytest.raises(AdminQueueError):
        make(admin).done(tid(1), None)


def test_submit_answer_round_trip() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wire.ANSWERS_PATH, httpx.Response(200, json={"result": "already_answered"}))
    result = make(admin).submit_answer(qid(1), "a", "telegram", "42")
    assert result is AnswerResult.ALREADY_ANSWERED
    assert admin.calls[0].body == {
        "question_id": qid(1),
        "key": "a",
        "source": "telegram",
        "actor_ref": "42",
    }


def test_submit_answer_malformed_verdict_raises() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wire.ANSWERS_PATH, httpx.Response(200, json={"result": "yes!"}))
    with pytest.raises(AdminQueueError, match="malformed"):
        make(admin).submit_answer(qid(1), "a", "telegram", "42")


def test_token_not_in_repr_or_errors() -> None:
    admin = FakeNotifierAdmin()
    q = make(admin)
    assert FAKE_NOTIFIER_TOKEN.decode() not in repr(q)
    with pytest.raises(AdminQueueError) as info:
        q.pending(0)
    assert FAKE_NOTIFIER_TOKEN.decode() not in str(info.value)


def test_client_ignores_env_proxies() -> None:
    q = make(FakeNotifierAdmin())
    assert q._http.trust_env is False and q._http.follow_redirects is False


def test_reports_accept_no_content() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wire.task_done_path(tid(1)), httpx.Response(204))
    make(admin).done(tid(1), None)
