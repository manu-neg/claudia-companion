"""Admin API error responses, request ids and request logging (C21/C26/C29 style).

Domain errors map to fixed statuses with a JSON body `{"error", "message",
"request_id"}`; domain messages are designed to be caller-safe (no disk
paths, no secret bytes). Anything unexpected is a generic 500 carrying only
the request id. Logs record method, route path, status and peer uid — never
headers, query strings or bodies.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    DomainError,
    InvalidStateError,
    LimitExceededError,
    NotFoundError,
    RateLimitedError,
    SecretDetectedError,
    StorageUnavailableError,
    UnsupportedContentError,
    ValidationError,
)

logger = logging.getLogger("preview_dashboard.admin")

REQUEST_ID_KEY = "pdash.request_id"
REQUEST_ID_HEADER = "X-Request-Id"
_MAX_MESSAGE_CHARS = 500
# Seconds the caller should wait after a 429; the window is an hour, so
# this is a polite floor rather than an exact reset time.
RETRY_AFTER_SECONDS = 60
# 503 storage refusals (ADR 0025) are usually transient (a sidecar mid-
# handover) — a short hint; a persistent one keeps failing closed anyway.
STORAGE_RETRY_AFTER_SECONDS = 5

_CODES: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "unprocessable",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}

# Most specific first: the first isinstance match wins.
_DOMAIN_STATUS: tuple[tuple[type[DomainError], int, str], ...] = (
    (NotFoundError, 404, "not_found"),
    (InvalidStateError, 409, "invalid_state"),
    (AlreadyExistsError, 409, "conflict"),
    (ConflictError, 409, "conflict"),
    (RateLimitedError, 429, "rate_limited"),
    (LimitExceededError, 413, "limit_exceeded"),
    (SecretDetectedError, 422, "secret_detected"),
    (UnsupportedContentError, 422, "unsupported_content"),
    # Server-side refusal (e.g. untrusted DB file owner): never a 400 (ADR 0025).
    (StorageUnavailableError, 503, "storage_unavailable"),
    (ValidationError, 400, "invalid_input"),
)
_RETRY_AFTER = {429: RETRY_AFTER_SECONDS, 503: STORAGE_RETRY_AFTER_SECONDS}


class RequestTimeoutError(DomainError):
    """The request body stalled or took longer than the admin API allows (408)."""


class UnsupportedMediaTypeError(DomainError):
    """The request's Content-Type is not the one this endpoint accepts (415)."""


class ClientDisconnectedError(DomainError):
    """The client went away mid-request (nothing is sent; logged as one INFO line).

    Replaces Starlette's `ClientDisconnect`, which would otherwise surface as
    an unhandled error with a full traceback.
    """


class ForbiddenError(DomainError):
    """The caller's token role may not use this route (403; defense in depth, C33/C34)."""


_LOCAL_STATUS: tuple[tuple[type[DomainError], int, str], ...] = (
    (ForbiddenError, 403, "forbidden"),
    (ClientDisconnectedError, 400, "client_disconnected"),
    (RequestTimeoutError, 408, "request_timeout"),
    (UnsupportedMediaTypeError, 415, "unsupported_media_type"),
)


def classify(exc: DomainError) -> tuple[int, str]:
    """Return `(HTTP status, error code)` for a domain error (unknown → 400)."""
    for cls, status, code in (*_LOCAL_STATUS, *_DOMAIN_STATUS):
        if isinstance(exc, cls):
            return status, code
    return 400, "invalid_input"


def request_id_of(scope: Scope) -> str:
    """Return the request id stored in `scope`, or "-" if none was assigned."""
    state = scope.get("state")
    if isinstance(state, dict):
        value = state.get(REQUEST_ID_KEY)
        if isinstance(value, str):
            return value
    return "-"


def _body(status: int, request_id: str, message: str | None = None) -> dict[str, object]:
    body: dict[str, object] = {"error": _CODES.get(status, "error"), "request_id": request_id}
    if message is not None:
        body["message"] = message
    return body


async def send_error(
    scope: Scope,
    send: Send,
    status: int,
    extra_headers: Iterable[tuple[bytes, bytes]] = (),
) -> None:
    """Send a complete generic JSON error response from pure ASGI middleware."""
    payload = json.dumps(_body(status, request_id_of(scope))).encode("ascii")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(payload)).encode("ascii")),
        (b"cache-control", b"no-store"),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": payload, "more_body": False})


def domain_error_response(exc: DomainError, request_id: str) -> Response:
    """Build the JSON response for a domain error.

    The message is the domain's own (caller-safe by contract) capped at 500
    chars. A secret-scan hit adds the neutral rule label, plus the relpath
    only when the match was in that file's *content*: a hit in the metadata
    (title, description or a relpath itself) carries no relpath, so the key
    is omitted and a secret-bearing relpath is never echoed.
    """
    status, code = classify(exc)
    body = _body(status, request_id, str(exc)[:_MAX_MESSAGE_CHARS])
    body["error"] = code
    if isinstance(exc, SecretDetectedError):
        body["rule"] = exc.rule
        if exc.relpath is not None:
            body["relpath"] = exc.relpath
    retry_after = _RETRY_AFTER.get(status)
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
    return JSONResponse(body, status_code=status, headers=headers)


def register_exception_handlers(app: FastAPI) -> None:
    """Map every error to a JSON response that never echoes request input.

    FastAPI's default 422 validation body would echo the offending input
    back, so it is replaced by a generic 400.
    """

    async def on_domain_error(request: Request, exc: Exception) -> Response:
        request_id = request_id_of(request.scope)
        if not isinstance(exc, DomainError):  # pragma: no cover - registered for DomainError
            return JSONResponse(_body(500, request_id), status_code=500)
        status, code = classify(exc)
        # A 5xx is the server failing closed (e.g. a C24 trust check): worth a warning.
        level = logging.WARNING if status >= 500 else logging.INFO
        logger.log(
            level, "admin %s -> %d (%s) request_id=%s", type(exc).__name__, status, code, request_id
        )
        return domain_error_response(exc, request_id)

    async def on_http_error(request: Request, exc: Exception) -> Response:
        status = exc.status_code if isinstance(exc, StarletteHTTPException) else 400
        headers: dict[str, str] = {}
        if isinstance(exc, StarletteHTTPException) and exc.headers and "Allow" in exc.headers:
            headers["Allow"] = exc.headers["Allow"]
        return JSONResponse(
            _body(status, request_id_of(request.scope)), status_code=status, headers=headers
        )

    async def on_validation_error(request: Request, exc: Exception) -> Response:
        return JSONResponse(_body(400, request_id_of(request.scope)), status_code=400)

    async def on_unhandled(request: Request, exc: Exception) -> Response:
        return JSONResponse(_body(500, request_id_of(request.scope)), status_code=500)

    app.add_exception_handler(DomainError, on_domain_error)
    app.add_exception_handler(StarletteHTTPException, on_http_error)
    app.add_exception_handler(RequestValidationError, on_validation_error)
    app.add_exception_handler(Exception, on_unhandled)


class RequestIdMiddleware:
    """Assign a fresh random id per request and return it as `X-Request-Id`.

    A client-supplied id is ignored (log forging); the id correlates a
    generic error body with the server log line.
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
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        await self._app(scope, receive, send_with_id)


class AccessLogMiddleware:
    """One log line per request: method, path, status, peer uid, duration.

    Replaces uvicorn's access log (disabled): no query string, no headers
    (so never `Authorization`), no body (C29).
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        # Imported lazily: auth imports this module for send_error.
        from preview_dashboard.interfaces.admin.auth import peer_of

        started = time.monotonic()
        status = 0

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self._app(scope, receive, capture)
        finally:
            peer = peer_of(scope)
            logger.info(
                "admin %s %s %d peer_uid=%s %.0fms request_id=%s",
                scope.get("method", "-"),
                # Path only (no query string); escaped so a hostile path
                # can't forge log lines.
                scope.get("path", "-")[:200].encode("unicode_escape").decode("ascii"),
                status,
                peer.uid if peer is not None else "-",
                (time.monotonic() - started) * 1000,
                request_id_of(scope),
            )


class CatchAllMiddleware:
    """Last resort: an unhandled exception becomes a generic 500 (logged once)."""

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
            logger.exception("admin unhandled error request_id=%s", request_id_of(scope))
            if not started:
                await send_error(scope, send, 500)
