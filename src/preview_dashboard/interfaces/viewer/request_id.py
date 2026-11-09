"""Per-request id: generated server-side, stored in the ASGI scope, echoed as a header.

The id lets the owner correlate a generic error body with a log line
without the error revealing anything else (docs/security.md C21, C29).
"""

from __future__ import annotations

import secrets

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

REQUEST_ID_KEY = "pdash.request_id"
REQUEST_ID_HEADER = "X-Request-Id"


def request_id_of(scope: Scope) -> str:
    """Return the request id stored in `scope`, or "-" if none was assigned."""
    state = scope.get("state")
    if isinstance(state, dict):
        value = state.get(REQUEST_ID_KEY)
        if isinstance(value, str):
            return value
    return "-"


class RequestIdMiddleware:
    """Assign a fresh random id to every HTTP request and return it in a header.

    A client-supplied `X-Request-Id` is ignored, never echoed: it is
    attacker-controlled input and would enable log forging.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        request_id = secrets.token_hex(8)
        scope.setdefault("state", {})[REQUEST_ID_KEY] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers[REQUEST_ID_HEADER] = request_id
            await send(message)

        await self._app(scope, receive, send_with_id)
