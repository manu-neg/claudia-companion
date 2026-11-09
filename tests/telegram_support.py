"""A scripted fake Telegram Bot API (httpx.MockTransport) and admin `/notifier/*` API for tests.

No network: `FakeBotApi` answers Bot API calls from per-method scripts and
records every request; `FakeNotifierAdmin` does the same for the admin
socket routes. Tokens here are obviously fake (never real credentials).
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from preview_dashboard.adapters.telegram.client import BotToken, TelegramBotClient

# Shaped like a BotFather token, but made up: "<bot id>:<35 chars>".
FAKE_BOT_TOKEN = "123456789:AAFakeFakeFakeTokenForTestsOnly_x-9Z"  # noqa: S105 - fake
FAKE_BOT_SECRET = FAKE_BOT_TOKEN.split(":", 1)[1]
FAKE_NOTIFIER_TOKEN = b"notifier-test-token-0123456789-abcdefghijklmnopqrstuvwxyz"
OWNER = 424242
STRANGER = 777001

Handler = Callable[[httpx.Request], httpx.Response]


def ok(result: Any) -> httpx.Response:
    """A successful Bot API reply."""
    return httpx.Response(200, json={"ok": True, "result": result})


def error(code: int, description: str, **parameters: Any) -> httpx.Response:
    """A failed Bot API reply (`ok: false`)."""
    body: dict[str, Any] = {"ok": False, "error_code": code, "description": description}
    if parameters:
        body["parameters"] = parameters
    return httpx.Response(code, json=body)


def message(message_id: int = 7, chat_id: int = OWNER) -> dict[str, Any]:
    """A `Message` object as sendMessage returns it."""
    return {"message_id": message_id, "chat": {"id": chat_id, "type": "private"}, "text": "x"}


def callback_update(
    update_id: int,
    data: str,
    *,
    sender: int = OWNER,
    chat: int = OWNER,
    query_id: str = "cbq-1",
) -> dict[str, Any]:
    """A `callback_query` update as getUpdates returns it."""
    return {
        "update_id": update_id,
        "callback_query": {
            "id": query_id,
            "from": {"id": sender, "is_bot": False, "first_name": "Owner"},
            "message": {"message_id": 7, "chat": {"id": chat, "type": "private"}},
            "chat_instance": "1",
            "data": data,
        },
    }


def message_update(
    update_id: int,
    text: str | None = "hello",
    *,
    sender: int = OWNER,
    chat: int = OWNER,
    chat_type: str = "private",
    is_bot: bool = False,
    message_id: int = 50,
    **extra: Any,
) -> dict[str, Any]:
    """A `message` update as getUpdates returns it (`extra` keys merge into the message)."""
    msg: dict[str, Any] = {
        "message_id": message_id,
        "from": {"id": sender, "is_bot": is_bot, "first_name": "Owner"},
        "chat": {"id": chat, "type": chat_type},
        "date": 1_700_000_000,
    }
    if text is not None:
        msg["text"] = text
    msg.update(extra)
    return {"update_id": update_id, "message": msg}


@dataclass
class Call:
    """One recorded request."""

    method: str
    url: str
    body: dict[str, Any]
    request: httpx.Request


@dataclass
class FakeBotApi:
    """Scripted Bot API: `script(method, response...)`; unscripted methods reply `ok(True)`."""

    calls: list[Call] = field(default_factory=list)
    scripts: dict[str, deque[httpx.Response | Exception]] = field(
        default_factory=lambda: defaultdict(deque)
    )

    def script(self, method: str, *responses: httpx.Response | Exception) -> None:
        self.scripts[method].extend(responses)

    def handler(self, request: httpx.Request) -> httpx.Response:
        method = request.url.path.rsplit("/", 1)[-1]
        content = request.read()
        is_json = request.headers.get("content-type", "").startswith("application/json")
        # Multipart uploads (sendVoice) stay in `request`; tests read them there.
        body = json.loads(content) if content and is_json else {}
        self.calls.append(Call(method, str(request.url), body, request))
        queue = self.scripts.get(method)
        if queue:
            item = queue.popleft()
            if isinstance(item, Exception):
                raise item
            return item
        if method == "getUpdates":
            return ok([])
        return ok(True)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def client(self) -> TelegramBotClient:
        return TelegramBotClient(BotToken(FAKE_BOT_TOKEN), transport=self.transport())

    def methods(self) -> list[str]:
        return [c.method for c in self.calls]


@dataclass
class FakeNotifierAdmin:
    """Scripted admin socket: `routes[(method, path)]` -> list of responses (last one repeats)."""

    calls: list[Call] = field(default_factory=list)
    routes: dict[tuple[str, str], list[httpx.Response | Exception]] = field(default_factory=dict)

    def route(self, method: str, path: str, *responses: httpx.Response | Exception) -> None:
        self.routes[(method, path)] = list(responses)

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        self.calls.append(Call(request.method, str(request.url), body, request))
        responses = self.routes.get((request.method, request.url.path))
        if not responses:
            return httpx.Response(404, json={"error": "not_found", "message": "no route"})
        item = responses.pop(0) if len(responses) > 1 else responses[0]
        if isinstance(item, Exception):
            raise item
        return item

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
