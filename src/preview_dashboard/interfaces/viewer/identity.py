"""Host and owner-identity gate for both viewer apps (docs/security.md C2, C3).

Pure ASGI middleware: the request must carry exactly one `Host` equal to one
of the app's configured values and exactly one `Tailscale-User-Login` equal
to the owner. Anything else is rejected before any route runs. WebSockets
are refused outright (the viewer has none).
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

from preview_dashboard.interfaces.viewer._http import DuplicateHeaderError, single_header
from preview_dashboard.interfaces.viewer.errors import send_error
from preview_dashboard.interfaces.viewer.request_id import request_id_of

logger = logging.getLogger("preview_dashboard.viewer")

LOGIN_HEADER = b"tailscale-user-login"
# RFC 9110 optional whitespace; ASGI servers already trim it, stripped again
# so behaviour does not depend on the server. `owner_login` never contains
# whitespace (config validator), so this cannot widen the match.
_OWS = b" \t"


class IdentityMiddleware:
    """Reject requests with the wrong `Host` (400/421) or not from the owner (403).

    Args:
        app: the wrapped ASGI app.
        owner_login: the configured owner login; must be non-empty.
        allowed_hosts: exact `Host` header values this app answers to.

    Raises:
        ValueError: `owner_login` or `allowed_hosts` is empty (fail closed).
    """

    def __init__(self, app: ASGIApp, *, owner_login: str, allowed_hosts: Iterable[str]) -> None:
        hosts = frozenset(h.encode("ascii") for h in allowed_hosts)
        if not owner_login or not hosts:
            raise ValueError("owner_login and allowed_hosts must be configured")
        self._app = app
        self._owner = owner_login.encode("utf-8")
        self._hosts = hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        status, reason = self._check(scope)
        if status is not None:
            # Log the reason only: header values are attacker-controlled (C29).
            logger.warning("viewer request denied: %s request_id=%s", reason, request_id_of(scope))
            await send_error(scope, send, status)
            return
        await self._app(scope, receive, send)

    def _check(self, scope: Scope) -> tuple[int | None, str]:
        try:
            host = single_header(scope, b"host")
        except DuplicateHeaderError:
            return 400, "duplicate host header"
        if host is None:
            return 400, "missing host"
        # 421 Misdirected Request: well-formed but not ours (DNS rebinding,
        # or a dashboard request sent to the preview app and vice versa).
        if host not in self._hosts:
            return 421, "host not allowed"
        try:
            login = single_header(scope, LOGIN_HEADER)
        except DuplicateHeaderError:
            return 403, "duplicate identity header"
        if login is None:
            return 403, "missing identity"
        if not hmac.compare_digest(login.strip(_OWS), self._owner):
            return 403, "identity mismatch"
        return None, ""
