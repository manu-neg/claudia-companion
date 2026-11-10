"""Generic error responses for both viewer apps (docs/security.md C21).

Every error body is a fixed `{"error": <code>, "request_id": <id>}` JSON
object chosen by status alone: no exception message, no stack trace, no
echo of request input. Details go to the log, keyed by the request id.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    DomainError,
    InvalidStateError,
    LimitExceededError,
    NotFoundError,
    RateLimitedError,
    StorageUnavailableError,
    UnsupportedContentError,
    ValidationError,
)
from preview_dashboard.interfaces.viewer.request_id import request_id_of

logger = logging.getLogger("preview_dashboard.viewer")

# A 503 is a transient server-side refusal (C24: e.g. a -wal sidecar briefly
# owned by another uid); the client may retry shortly. Same value as the admin.
STORAGE_RETRY_AFTER_SECONDS = 5

_CODES: dict[int, str] = {
    400: "bad_request",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    411: "length_required",
    413: "payload_too_large",
    415: "unsupported_media_type",
    416: "range_not_satisfiable",
    421: "misdirected_request",
    429: "too_many_requests",
    500: "internal_error",
    503: "service_unavailable",
}

# Most specific first: the first isinstance match wins.
_DOMAIN_STATUS: tuple[tuple[type[DomainError], int], ...] = (
    (NotFoundError, 404),
    (ConflictError, 409),  # concurrent edit: the client re-reads and retries
    (InvalidStateError, 409),
    (AlreadyExistsError, 409),
    (RateLimitedError, 429),  # before its base class: a rate, not a size (F-CL6 decisions)
    (LimitExceededError, 413),
    (UnsupportedContentError, 415),
    (StorageUnavailableError, 503),  # server-side refusal (C24), not bad input (ADR 0025)
    (ValidationError, 400),
)


def status_for(exc: DomainError) -> int:
    """Map a domain error to its HTTP status (unknown subclasses → 400)."""
    for cls, status in _DOMAIN_STATUS:
        if isinstance(exc, cls):
            return status
    return 400


def error_body(status: int, request_id: str) -> bytes:
    """Return the generic JSON error body for `status`."""
    code = _CODES.get(status, "error")
    return json.dumps({"error": code, "request_id": request_id}).encode("ascii")


def error_response(
    status: int, request_id: str, extra_headers: Iterable[tuple[str, str]] = ()
) -> Response:
    """Build a generic JSON error `Response` for `status`."""
    response = Response(
        content=error_body(status, request_id),
        status_code=status,
        media_type="application/json",
    )
    for name, value in extra_headers:
        response.headers[name] = value
    return response


async def send_error(
    scope: Scope,
    send: Send,
    status: int,
    extra_headers: Iterable[tuple[bytes, bytes]] = (),
) -> None:
    """Send a complete generic JSON error response from pure ASGI middleware."""
    body = error_body(status, request_id_of(scope))
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


def register_exception_handlers(app: FastAPI) -> None:
    """Install handlers that turn every error into a generic JSON response.

    Covers domain errors (a 503 carries `Retry-After` and is logged at
    WARNING, C24), Starlette `HTTPException` (routing 404/405: detail
    dropped, `Allow` kept) and FastAPI's `RequestValidationError`, whose
    default 422 body would echo the offending input back.
    """

    async def on_domain_error(request: Request, exc: Exception) -> Response:
        status = status_for(exc) if isinstance(exc, DomainError) else 400
        # A 5xx is the server failing closed (e.g. a C24 trust check): worth a warning.
        logger.log(
            logging.WARNING if status >= 500 else logging.INFO,
            "domain error %s -> %d request_id=%s",
            type(exc).__name__,
            status,
            request_id_of(request.scope),
        )
        extra = [("Retry-After", str(STORAGE_RETRY_AFTER_SECONDS))] if status == 503 else []
        return error_response(status, request_id_of(request.scope), extra)

    async def on_http_error(request: Request, exc: Exception) -> Response:
        status = exc.status_code if isinstance(exc, StarletteHTTPException) else 400
        extra: list[tuple[str, str]] = []
        if isinstance(exc, StarletteHTTPException) and exc.headers and "Allow" in exc.headers:
            extra.append(("Allow", exc.headers["Allow"]))
        return error_response(status, request_id_of(request.scope), extra)

    async def on_validation_error(request: Request, exc: Exception) -> Response:
        return error_response(400, request_id_of(request.scope))

    async def on_unhandled(request: Request, exc: Exception) -> Response:
        # Starlette's ServerErrorMiddleware calls this, sends it, then
        # re-raises; `CatchAllMiddleware` logs the traceback once.
        return error_response(500, request_id_of(request.scope))

    app.add_exception_handler(DomainError, on_domain_error)
    app.add_exception_handler(StarletteHTTPException, on_http_error)
    app.add_exception_handler(RequestValidationError, on_validation_error)
    app.add_exception_handler(Exception, on_unhandled)


class CatchAllMiddleware:
    """Last-resort handler: an unhandled exception becomes a generic 500.

    Sits inside the security-headers middleware so the 500 still carries the
    full header set, and outside everything else. The traceback is logged
    server-side only; the client sees the generic body and request id.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._app(scope, receive, tracking_send)
        except Exception:
            logger.exception("unhandled error request_id=%s", request_id_of(scope))
            if not started:
                await send_error(scope, send, 500)
            # Response already started: nothing safe to send; the server closes
            # the connection when we return without completing it.
