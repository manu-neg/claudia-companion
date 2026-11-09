"""Request hygiene middleware: HTTP method allowlist and request-body size cap.

The dashboard app accepts at most 1 KiB of JSON (trash/restore bodies are
tiny); the preview app accepts no body at all and only GET/HEAD
(docs/security.md C4, C21). Limits count streamed bytes, never trusting
`Content-Length` alone (C18).
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from preview_dashboard.interfaces.viewer._http import (
    DuplicateHeaderError,
    header_values,
    single_header,
)
from preview_dashboard.interfaces.viewer.errors import send_error

DASHBOARD_MAX_BODY_BYTES = 1024


class MethodAllowlistMiddleware:
    """Answer 405 (with `Allow`) to any HTTP method outside `methods`.

    OPTIONS is never in an allowlist here: answering preflights is how
    CORS starts, and the viewer never does CORS (C19).
    """

    def __init__(self, app: ASGIApp, *, methods: Iterable[str]) -> None:
        self._app = app
        self._methods = frozenset(methods)
        if "OPTIONS" in self._methods:
            raise ValueError("OPTIONS must not be allowed (no CORS preflights)")
        self._allow = ", ".join(sorted(self._methods)).encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] not in self._methods:
            await send_error(scope, send, 405, [(b"allow", self._allow)])
            return
        await self._app(scope, receive, send)


class _BodyTooLargeError(Exception):
    """Internal signal: the streamed body crossed the limit."""


class BodyLimitMiddleware:
    """Reject request bodies larger than `max_bytes` with 413.

    Checks `Content-Length` up front (malformed or duplicated → 400), and
    counts the bytes actually received, so a lying or absent length (chunked
    encoding) cannot get more than `max_bytes` through. With `max_bytes=0`
    any declared or chunked body is refused before the app runs.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes < 0:
            raise ValueError("max_bytes must be >= 0")
        self._app = app
        self._max = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        status = self._precheck(scope)
        if status is not None:
            await send_error(scope, send, status)
            return

        received = 0
        exceeded = False
        started = False

        async def counting_receive() -> Message:
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max:
                    exceeded = True
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            # Once over the limit, drop whatever the app answers (e.g. the
            # framework's own 500 for our signal): the client gets a 413.
            if exceeded:
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        with contextlib.suppress(_BodyTooLargeError):
            await self._app(scope, counting_receive, tracking_send)
        if exceeded and not started:
            await send_error(scope, send, 413)

    def _precheck(self, scope: Scope) -> int | None:
        try:
            length = single_header(scope, b"content-length")
        except DuplicateHeaderError:
            return 400
        if length is not None:
            if not length.isdigit() or len(length) > 19:
                return 400
            if int(length) > self._max:
                return 413
        if self._max == 0 and header_values(scope, b"transfer-encoding"):
            return 413
        return None
