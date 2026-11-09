"""Service-worker guard for both viewer apps (docs/security.md C5, C31).

A service worker registered on an origin would outlive the page, intercept
every later request to that origin, and could serve forged previews or
UI. Browsers fetch SW scripts with `Service-Worker: script` and
`Sec-Fetch-Dest: serviceworker`; either one gets a 403, so no registration
can ever succeed (and `Service-Worker-Allowed` is never sent, see headers.py).
"""

from __future__ import annotations

import logging

from starlette.types import ASGIApp, Receive, Scope, Send

from preview_dashboard.interfaces.viewer._http import header_values
from preview_dashboard.interfaces.viewer.errors import send_error
from preview_dashboard.interfaces.viewer.request_id import request_id_of

logger = logging.getLogger("preview_dashboard.viewer")


def is_service_worker_request(scope: Scope) -> bool:
    """True if the request is (or claims to be) a service-worker script fetch.

    Any `Service-Worker` header counts, whatever its value (fail closed:
    `script` is the only value browsers send today).
    """
    if header_values(scope, b"service-worker"):
        return True
    return any(
        v.strip().lower() == b"serviceworker" for v in header_values(scope, b"sec-fetch-dest")
    )


class ServiceWorkerGuardMiddleware:
    """Answer 403 to every service-worker script fetch."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and is_service_worker_request(scope):
            logger.warning("service worker fetch refused request_id=%s", request_id_of(scope))
            await send_error(scope, send, 403)
            return
        await self._app(scope, receive, send)
