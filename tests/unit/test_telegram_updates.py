"""Unit tests for the owner-update plumbing: update source offsets, router retries, client
uploads, `deleteMessage`, the admin client routes and `build_notifier(owner_messages=...)`."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue, AdminQueueError
from preview_dashboard.adapters.telegram.client import TelegramError
from preview_dashboard.interfaces.notifier.owner_updates import (
    MAX_STORE_ATTEMPTS,
    InboxUnavailableError,
)
from preview_dashboard.wire import notifier_messages as wm
from tests.owner_updates_support import Harness, result
from tests.telegram_support import (
    FAKE_NOTIFIER_TOKEN,
    OWNER,
    FakeBotApi,
    FakeNotifierAdmin,
    error,
    message_update,
    ok,
)

pytestmark = pytest.mark.unit


# --- TelegramUpdateSource ------------------------------------------------------------------


def test_offset_advances_past_ignored_updates_and_rewind_moves_it_back() -> None:
    h = Harness()
    h.updates(message_update(10, sender=1, chat=1), message_update(11))
    assert len(h.source.poll(50)) == 1
    h.source.rewind(11)
    h.source.rewind(12)  # never moves forward
    h.source.poll(50)
    assert h.api.calls[-1].body["offset"] == 11


def test_unrequested_update_types_and_bad_ids_are_ignored() -> None:
    h = Harness()
    h.api.script(
        "getUpdates",
        ok(
            [
                {"update_id": 1, "my_chat_member": {}},
                {"update_id": True, "message": message_update(2)["message"]},
                {"message": message_update(3)["message"]},
                "junk",
            ]
        ),
    )
    assert h.source.poll(50) == []
    h.api.script("getUpdates", ok({"not": "a list"}))
    assert h.source.poll(50) == []


def test_poll_wait_is_bounded() -> None:
    h = Harness()
    h.source.poll(500)
    assert h.api.calls[0].body["timeout"] == 50


# --- OwnerUpdateRouter -------------------------------------------------------------------------


def test_a_message_that_keeps_failing_is_given_up_after_max_attempts() -> None:
    h = Harness()
    h.admin.route("POST", wm.MESSAGES_PATH, result("x", status=500))
    update = message_update(7, "hi")
    for _ in range(MAX_STORE_ATTEMPTS - 1):
        h.updates(update)
        with pytest.raises(InboxUnavailableError):
            h.router.poll(50)
    h.updates(update)
    assert h.router.poll(50) == []  # dropped: later updates are no longer held back
    h.router.poll(50)
    assert h.api.calls[-1].body["offset"] == 8


def test_token_scope_errors_are_retried_not_dropped() -> None:
    h = Harness()
    h.admin.route("POST", wm.MESSAGES_PATH, result("x", status=403))
    h.updates(message_update(7, "hi"))
    with pytest.raises(InboxUnavailableError):
        h.router.poll(50)


def test_router_reports_the_source_name_and_delegates_acks() -> None:
    h = Harness()
    assert h.router.name == "telegram"
    h.router.ack("cbq-1", "Recorded: yes")
    assert h.api.calls[-1].body == {"callback_query_id": "cbq-1", "text": "Recorded: yes"}


def test_tap_ack_failure_is_swallowed() -> None:
    h = Harness()
    h.api.script("answerCallbackQuery", error(400, "query is too old"))
    h.updates(
        {
            "update_id": 1,
            "callback_query": {
                "id": "t",
                "from": {"id": OWNER},
                "message": {"chat": {"id": OWNER}},
                "data": "p:01J00000000000000000000AP1:ok",
            },
        }
    )
    assert h.router.poll(50) == []


# --- client uploads and deleteMessage ------------------------------------------------------------


def test_upload_is_only_for_upload_methods_and_bounded() -> None:
    client = FakeBotApi().client()
    with pytest.raises(ValueError):
        client.upload(
            "sendMessage", {}, file_field="f", filename="a", data=b"x", content_type="text/plain"
        )
    with pytest.raises(ValueError):
        client.upload(
            "sendVoice",
            {"chat-id": "1"},
            file_field="voice",
            filename="a",
            data=b"x",
            content_type="audio/ogg",
        )
    with pytest.raises(ValueError):
        client.upload(
            "sendVoice",
            {},
            file_field="voice",
            filename="a",
            data=b"x" * (1024 * 1024 + 1),
            content_type="audio/ogg",
        )
    with pytest.raises(ValueError):
        client.upload(
            "sendVoice", {}, file_field="voice", filename="a", data=b"", content_type="audio/ogg"
        )


def test_delete_message_targets_the_owner_chat_and_tolerates_gone_messages() -> None:
    h = Harness()
    h.api.script("deleteMessage", error(400, "Bad Request: message to delete not found"))
    h.channel.delete_message(5)
    assert h.deleted() == [{"chat_id": OWNER, "message_id": 5}]
    h.api.script("deleteMessage", error(403, "Forbidden: bot was blocked"))
    with pytest.raises(TelegramError):
        h.channel.delete_message(5)
    for bad in (0, -1, True):
        with pytest.raises(ValueError):
            h.channel.delete_message(bad)


# --- AdminDeliveryQueue owner-update routes ----------------------------------------------


def _queue(admin: FakeNotifierAdmin) -> AdminDeliveryQueue:
    return AdminDeliveryQueue(Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport())


def test_queue_posts_with_the_notifier_token_and_parses_verdicts() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wm.CODES_PATH, result("locked"))
    sub = wm.CodeSubmission(update_id=1, message_id=2, sender_id=OWNER, code="123456")
    assert _queue(admin).submit_code(sub) is wm.CodeResult.LOCKED
    [call] = admin.calls
    assert call.request.headers["authorization"] == "Bearer " + FAKE_NOTIFIER_TOKEN.decode()


@pytest.mark.parametrize(
    "response",
    [httpx.Response(200, json={"result": "maybe"}), httpx.Response(200, content=b"not json")],
)
def test_queue_refuses_malformed_verdicts(response: httpx.Response) -> None:
    admin = FakeNotifierAdmin()
    for path in (wm.MESSAGES_PATH, wm.APPROVALS_PATH, wm.CODES_PATH):
        admin.route("POST", path, response)
    queue = _queue(admin)
    sub = wm.MessageSubmission(update_id=1, message_id=2, sender_id=OWNER, text="hi")
    with pytest.raises(AdminQueueError, match="malformed"):
        queue.submit_message(sub)
    with pytest.raises(AdminQueueError, match="malformed"):
        queue.submit_approval_tap(
            wm.ApprovalTapSubmission(
                request_id="01J00000000000000000000AP1",
                decision=wm.ApprovalDecision.APPROVE,
                source="telegram",
                actor_ref="1",
            )
        )
    with pytest.raises(AdminQueueError, match="malformed"):
        queue.submit_code(wm.CodeSubmission(update_id=1, message_id=2, sender_id=1, code="111111"))


def test_queue_error_carries_the_status_but_no_code() -> None:
    admin = FakeNotifierAdmin()
    admin.route("POST", wm.CODES_PATH, httpx.Response(422, json={"error": "invalid"}))
    with pytest.raises(AdminQueueError) as info:
        _queue(admin).submit_code(
            wm.CodeSubmission(update_id=1, message_id=2, sender_id=1, code="987654")
        )
    assert info.value.status == 422
    assert "987654" not in str(info.value)


# --- build_notifier wiring ------------------------------------------------------------


def test_serve_passes_owner_messages_only_when_on() -> None:
    from preview_dashboard.interfaces.notifier import commands

    seen: list[dict[str, object]] = []

    def build(config: object, **kwargs: object) -> commands.NotifierParts:
        seen.append(kwargs)
        raise commands.NotifierError("stop here")

    class Cfg:
        def __init__(self, flag: object) -> None:
            self.claudia_enabled = flag

    for flag in (False, True):
        with pytest.raises(commands.NotifierError):
            commands.serve_notifier(Cfg(flag), build=build)  # type: ignore[arg-type]
    assert seen == [{"token_groups": None}, {"token_groups": None, "owner_messages": True}]


def test_answer_taps_pass_through_unchanged() -> None:
    h = Harness()
    h.api.script("getUpdates", ok([]))
    assert h.router.poll(50) == []
