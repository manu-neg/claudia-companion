"""Security tests for the notifier and Telegram adapters (docs/security.md C34, C35, C36).

C34: only the owner's taps in the owner's chat become answers. C35: plain
text only, no invisible chars, the only link is a URL button pinned to the
configured dashboard origin. C36: the bot and
notifier tokens never reach logs, exception text or reprs; no env proxies.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
import pytest

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.application.delivery import DeliveryService
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    MessageButton,
    MessageContent,
    PendingTask,
)
from preview_dashboard.interfaces.notifier.runner import NotifierRunner
from preview_dashboard.wire import notifier as wire
from tests.notify_support import DASHBOARD, qid, tid
from tests.telegram_support import (
    FAKE_BOT_SECRET,
    FAKE_NOTIFIER_TOKEN,
    OWNER,
    STRANGER,
    FakeBotApi,
    FakeNotifierAdmin,
    callback_update,
    error,
    ok,
)

pytestmark = pytest.mark.security

QUESTION = DeliveryPayload(
    content=MessageContent(
        text="❓ Deploy now?",
        buttons=(MessageButton(key="yes", label="Yes"), MessageButton(key="no", label="No")),
        link=f"{DASHBOARD}/",
    ),
    question_id=qid(1),
)


def test_c34_only_owner_taps_in_the_owner_chat_are_answers() -> None:
    data = f"a:{qid(1)}:yes"
    api = FakeBotApi()
    api.script(
        "getUpdates",
        ok(
            [
                callback_update(1, data, sender=STRANGER, chat=STRANGER),
                callback_update(2, data, sender=STRANGER, chat=OWNER),
                callback_update(3, data, sender=OWNER, chat=STRANGER),
                callback_update(4, data, sender=OWNER, chat=OWNER, query_id="ok"),
            ]
        ),
    )
    events = TelegramAnswerSource(api.client(), OWNER).poll(50)
    assert [e.ack_handle for e in events] == ["ok"]
    assert api.calls[0].body["allowed_updates"] == ["callback_query"]


def test_c34_callback_data_parsing_is_strict() -> None:
    api = FakeBotApi()
    api.script(
        "getUpdates",
        ok(
            [
                callback_update(1, f"a:{qid(1)}:yes:extra"),
                callback_update(2, f"a:{qid(1)}:YES"),
                callback_update(3, "a:../../items:yes"),
            ]
        ),
    )
    assert TelegramAnswerSource(api.client(), OWNER).poll(50) == []


def test_c35_messages_are_plain_text_with_only_the_dashboard_link() -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok({"message_id": 5, "chat": {"id": OWNER}}))
    channel = TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD)
    channel.send(QUESTION)
    body = api.calls[0].body
    assert "parse_mode" not in body and "entities" not in body
    assert body["link_preview_options"] == {"is_disabled": True}
    urls = [b["url"] for row in body["reply_markup"]["inline_keyboard"] for b in row if "url" in b]
    assert urls == [f"{DASHBOARD}/"]


def test_c35_notifier_refuses_foreign_links_from_the_admin() -> None:
    # Even a compromised admin reply cannot make the notifier send another link.
    raw = wire.task_to_json(
        PendingTask(id=tid(1), channel="telegram", action=DeliveryAction.SEND, payload=QUESTION)
    )
    raw["payload"]["link"] = "https://evil.example/login?next=x"  # type: ignore[index]
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json={"tasks": [raw]}))
    admin.route("POST", wire.task_failed_path(tid(1)), httpx.Response(200, json={}))
    queue = AdminDeliveryQueue(Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport())
    assert queue.pending(0) == []


# Invisible chars from the Copilot review of PR #1 (backlog G1).
INVISIBLE = ["\u200b", "\u2060", "\U000e0041", "\u2800", "\u3164", "\u00ad", "\u034f"]


@pytest.mark.parametrize("ch", INVISIBLE)
@pytest.mark.parametrize("field", ["text", "label"])
def test_c35_invisible_chars_never_reach_a_channel(ch: str, field: str) -> None:
    # Refused where the message is built and again where the notifier parses it.
    with pytest.raises(ValidationError):
        if field == "text":
            MessageContent(text=f"Deploy{ch} now?")
        else:
            MessageButton(key="yes", label=f"Y{ch}es")
    raw = wire.task_to_json(
        PendingTask(id=tid(1), channel="telegram", action=DeliveryAction.SEND, payload=QUESTION)
    )
    payload: Any = raw["payload"]
    if field == "text":
        payload["text"] = f"Deploy{ch} now?"
    else:
        payload["buttons"][0]["label"] = f"Y{ch}es"
    with pytest.raises(ValidationError):
        wire.parse_task(raw)


FOREIGN_LINKS = [
    "https://evil.example/login",  # Copilot's case: passes the domain shape check
    f"{DASHBOARD}.evil.example/",
    f"{DASHBOARD}@evil.example/",
    f"{DASHBOARD}:8443/",
    DASHBOARD.replace("https://", "http://") + "/",
]


def _send_link(link: str, origin: str | None) -> list[str]:
    """Send a question whose content carries `link`; return the URL buttons Telegram got."""
    api = FakeBotApi()
    api.script("sendMessage", ok({"message_id": 5, "chat": {"id": OWNER}}))
    content = MessageContent(text="❓ Deploy now?", buttons=QUESTION.content.buttons)
    # Bypass the domain's shape check: a forged row may carry any link.
    object.__setattr__(content, "link", link)
    payload = DeliveryPayload(content=content, question_id=qid(1))
    TelegramChannel(api.client(), OWNER, dashboard_origin=origin).send(payload)
    rows = api.calls[0].body["reply_markup"]["inline_keyboard"]
    return [b["url"] for row in rows for b in row if "url" in b]


@pytest.mark.parametrize("link", FOREIGN_LINKS)
def test_c35_link_button_is_pinned_to_the_dashboard_origin(
    link: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        assert _send_link(link, DASHBOARD) == []  # sent, without the button
    assert "link button dropped" in caplog.text
    assert "evil" not in caplog.text and link not in caplog.text  # ids only
    assert _send_link(f"{DASHBOARD}/", DASHBOARD) == [f"{DASHBOARD}/"]


def test_c35_no_dashboard_origin_means_no_link_buttons() -> None:
    assert _send_link(f"{DASHBOARD}/", None) == []


def test_c35_forged_task_link_from_the_admin_is_not_shown() -> None:
    # A tampered row / compromised admin: the link passes the wire's shape
    # check, the alert still goes out, but without the phishing button.
    raw = wire.task_to_json(
        PendingTask(id=tid(1), channel="telegram", action=DeliveryAction.SEND, payload=QUESTION)
    )
    raw["payload"]["link"] = "https://evil.example/login"  # type: ignore[index]
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json={"tasks": [raw]}))
    admin.route("POST", wire.task_done_path(tid(1)), httpx.Response(200, json={}))
    api = FakeBotApi()
    api.script("sendMessage", ok({"message_id": 5, "chat": {"id": OWNER}}))
    client = api.client()
    service = DeliveryService(
        queue=AdminDeliveryQueue(Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport()),
        channels=[TelegramChannel(client, OWNER, dashboard_origin=DASHBOARD)],
        answers=TelegramAnswerSource(client, OWNER),
    )
    assert service.run_once_deliveries() == 1
    (send,) = [c for c in api.calls if c.method == "sendMessage"]
    assert "evil" not in json.dumps(send.body)


def test_c36_tokens_never_reach_logs_or_errors(caplog: pytest.LogCaptureFixture) -> None:
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    logging.getLogger("httpcore").setLevel(logging.DEBUG)
    api = FakeBotApi()
    api.script("sendMessage", error(400, f"bad token {FAKE_BOT_SECRET}"))
    api.script("getUpdates", httpx.ReadTimeout("timed out"))
    admin = FakeNotifierAdmin()
    task = PendingTask(id=tid(1), channel="telegram", action=DeliveryAction.SEND, payload=QUESTION)
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json=wire.tasks_to_json([task])))
    admin.route("POST", wire.task_failed_path(tid(1)), httpx.Response(500, json={}))
    client = api.client()  # silences httpx/httpcore again
    service = DeliveryService(
        queue=AdminDeliveryQueue(Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport()),
        channels=[TelegramChannel(client, OWNER, dashboard_origin=DASHBOARD)],
        answers=TelegramAnswerSource(client, OWNER),
    )
    runner = NotifierRunner(service, backoff_first=0.001, backoff_max=0.001, min_idle_round=0)
    errors: list[str] = []
    with caplog.at_level(logging.DEBUG):
        for round_fn in (service.run_once_deliveries, service.run_once_answers):
            try:
                round_fn()
            except Exception as exc:
                errors.append(f"{exc!s} {exc!r}")
        runner.stop()
        runner.loop("deliveries", service.run_once_deliveries)
    assert len(errors) == 2
    haystack = caplog.text + " ".join(errors)
    for secret in (FAKE_BOT_SECRET, FAKE_NOTIFIER_TOKEN.decode(), "api.telegram.org/bot"):
        assert secret not in haystack
    for name in ("httpx", "httpcore"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING


def test_c36_clients_ignore_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:8080")
    monkeypatch.setenv("ALL_PROXY", "http://attacker.invalid:8080")
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/evil.pem")  # noqa: S108 - never read
    client = FakeBotApi().client()
    queue = AdminDeliveryQueue(Path("/x.sock"), FAKE_NOTIFIER_TOKEN)
    for http in (client._http, queue._http):
        assert http.trust_env is False
        assert all(t is None for t in http._mounts.values())
