"""CSRF gate for the dashboard app's state-changing requests (docs/security.md C4).

Tailscale identity is ambient (any site the owner visits can make the
browser send requests "as the owner"), so every POST must prove it came
from the dashboard's own JavaScript: exact JSON content type, exact
same-origin `Origin`, `Sec-Fetch-Site: same-origin` and a custom header that
no cross-site form or no-cors request can set. Never any CORS.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

from preview_dashboard.interfaces.viewer._http import DuplicateHeaderError, single_header
from preview_dashboard.interfaces.viewer.errors import send_error
from preview_dashboard.interfaces.viewer.request_id import request_id_of

logger = logging.getLogger("preview_dashboard.viewer")

CSRF_HEADER = b"x-pdash-csrf"
_SAFE_METHODS = frozenset({"GET", "HEAD"})
_ALLOW = b"GET, HEAD, POST"


class CsrfMiddleware:
    """Enforce the CSRF matrix on POST; 405 for any method but GET/HEAD/POST.

    A POST passes only if all hold (each header exactly once):
    - `Content-Type` is exactly `application/json` (no parameters, so no
      form/`text/plain` "simple request" can pass);
    - `Origin` is one of `dashboard_origins` **and** equals
      `https://<Host>` of this request (`null` from sandboxed previews and a
      missing `Origin` are rejected);
    - `Sec-Fetch-Site` is exactly `same-origin`;
    - `X-PDash-CSRF` is exactly `1`.

    Args:
        app: the wrapped ASGI app.
        dashboard_origins: `https://<host>` values of the dashboard app.
    """

    def __init__(self, app: ASGIApp, *, dashboard_origins: Iterable[str]) -> None:
        origins = frozenset(o.encode("ascii") for o in dashboard_origins)
        if not origins:
            raise ValueError("dashboard_origins must not be empty")
        self._app = app
        self._origins = origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in _SAFE_METHODS:
            await self._app(scope, receive, send)
            return
        if scope["method"] != "POST":
            await send_error(scope, send, 405, [(b"allow", _ALLOW)])
            return
        reason = self._violation(scope)
        if reason:
            logger.warning("csrf check failed: %s request_id=%s", reason, request_id_of(scope))
            await send_error(scope, send, 403)
            return
        await self._app(scope, receive, send)

    def _violation(self, scope: Scope) -> str:
        """Return why the POST fails the matrix, or "" if it passes."""
        try:
            content_type = single_header(scope, b"content-type")
            origin = single_header(scope, b"origin")
            fetch_site = single_header(scope, b"sec-fetch-site")
            token = single_header(scope, CSRF_HEADER)
            host = single_header(scope, b"host")
        except DuplicateHeaderError as exc:
            return f"duplicate {exc} header"
        if content_type != b"application/json":
            return "content-type"
        if origin is None or origin not in self._origins:
            return "origin"
        if host is None or origin != b"https://" + host:
            return "origin/host mismatch"
        if fetch_site != b"same-origin":
            return "sec-fetch-site"
        if token != b"1":
            return "csrf header"
        return ""
