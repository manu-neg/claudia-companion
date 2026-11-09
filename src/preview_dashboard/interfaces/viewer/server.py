"""Runs the dashboard and preview apps: two hardened uvicorn servers, one process.

Called by `preview-dashboard serve-viewer` with the viewer core from
`bootstrap.build_core(role="viewer")`. Both servers share one event loop and
one set of signal handlers; if either stops (error or signal), the other is
stopped too, so the viewer never runs half-up (fail closed). Uvicorn trusts
no proxy headers, sends no `Server` header, keeps no access log (query
strings could leak, C29), caps concurrency and reaps connections that don't
deliver a request head in time (`interfaces/http_server.py`), so idle
connections can't pin every slot (docs/security.md C1, C21).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Generator, Sequence
from types import FrameType
from typing import Any, Protocol

import uvicorn
from starlette.types import ASGIApp

from preview_dashboard.config import Settings
from preview_dashboard.interfaces.http_server import (
    HEADER_TIMEOUT_SECONDS,
    HeaderTimeoutH11Protocol,
    with_header_timeout,
)
from preview_dashboard.interfaces.viewer.app_factory import build_dashboard_app, build_preview_app
from preview_dashboard.interfaces.viewer.knowledge import build_knowledge
from preview_dashboard.interfaces.viewer.services import ViewerServices

logger = logging.getLogger("preview_dashboard.viewer")

# Connections (idle ones included) + running requests; over it uvicorn
# answers a bare 503. Idle/partial-header connections are reaped after
# HEADER_TIMEOUT_SECONDS, idle keep-alive ones after TIMEOUT_KEEP_ALIVE_SECONDS.
LIMIT_CONCURRENCY = 64
TIMEOUT_KEEP_ALIVE_SECONDS = 5
H11_MAX_INCOMPLETE_EVENT_BYTES = 16 * 1024  # request line + headers
BACKLOG = 128
# On shutdown, in-flight responses (e.g. a long download) get this long to
# finish before their tasks are cancelled; without it a stuck client could
# hold the process (and the restart) forever.
TIMEOUT_GRACEFUL_SHUTDOWN_SECONDS = 10
_SIGNALS = (signal.SIGINT, signal.SIGTERM)


class ViewerCoreLike(ViewerServices, Protocol):
    """`bootstrap.ViewerCore`: the viewer services plus settings and `close()`."""

    @property
    def settings(self) -> Settings:
        """The validated settings the core was built from."""
        ...

    def close(self) -> None:
        """Release the core's resources (idempotent)."""
        ...


class ManagedServer(uvicorn.Server):
    """A uvicorn server whose signals are handled by `serve` for both servers at once.

    uvicorn's own per-server signal capture would let only the last-started
    server see SIGTERM.
    """

    @contextlib.contextmanager
    def capture_signals(self) -> Generator[None, None, None]:
        yield


def uvicorn_config(
    app: ASGIApp,
    *,
    host: str,
    port: int,
    header_timeout: float = HEADER_TIMEOUT_SECONDS,
    **overrides: Any,  # noqa: ANN401 - uvicorn kwargs
) -> uvicorn.Config:
    """Hardened uvicorn settings for one viewer app (C21).

    `header_timeout` and `overrides` exist for tests (e.g. shorter timers).

    Raises:
        ValueError: `header_timeout` is not positive.
    """
    protocol = (
        HeaderTimeoutH11Protocol
        if header_timeout == HeaderTimeoutH11Protocol.header_timeout
        else with_header_timeout(HeaderTimeoutH11Protocol, header_timeout)
    )
    options: dict[str, Any] = {
        "host": host,
        "port": port,
        "http": protocol,
        "ws": "none",
        "lifespan": "off",
        "proxy_headers": False,
        "forwarded_allow_ips": "",
        "server_header": False,
        "access_log": False,
        "log_config": None,  # keep the process's logging (journald via stderr)
        "limit_concurrency": LIMIT_CONCURRENCY,
        "timeout_keep_alive": TIMEOUT_KEEP_ALIVE_SECONDS,
        "h11_max_incomplete_event_size": H11_MAX_INCOMPLETE_EVENT_BYTES,
        "backlog": BACKLOG,
        "timeout_graceful_shutdown": TIMEOUT_GRACEFUL_SHUTDOWN_SECONDS,
    }
    options.update(overrides)
    return uvicorn.Config(app, **options)


def build_servers(core: ViewerCoreLike) -> tuple[ManagedServer, ManagedServer]:
    """Build (dashboard, preview) servers on `viewer_host` : `viewer_port` / `preview_port`.

    Raises:
        ConfigError: owner/hosts/preview origin unset or invalid (fail closed).
        StaticAssetError: the packaged static directory is unsafe.
    """
    settings = core.settings
    dashboard = build_dashboard_app(settings, core, knowledge=build_knowledge(settings))
    preview = build_preview_app(settings, core)
    host = settings.viewer_host
    return (
        ManagedServer(uvicorn_config(dashboard, host=host, port=settings.viewer_port)),
        ManagedServer(uvicorn_config(preview, host=host, port=settings.preview_port)),
    )


async def run_servers(servers: Sequence[uvicorn.Server]) -> None:
    """Serve until a signal arrives or any server stops; then stop them all.

    Raises:
        Exception: the first error a server raised (after stopping the rest).
    """

    def stop_all(sig: int, frame: FrameType | None) -> None:
        for server in servers:
            # A second SIGINT forces exit, like uvicorn's own handler.
            if server.should_exit and sig == signal.SIGINT:
                server.force_exit = True
            server.should_exit = True

    previous = {sig: signal.signal(sig, stop_all) for sig in _SIGNALS}
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for server in servers:
            server.should_exit = True
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    for result in results:
        if isinstance(result, BaseException):
            raise result


def serve(core: ViewerCoreLike) -> None:
    """Run both viewer apps until SIGINT/SIGTERM (blocking); close the core afterwards."""
    try:
        dashboard, preview = build_servers(core)
        settings = core.settings
        logger.info(
            "viewer listening: dashboard %s:%d, preview %s:%d",
            settings.viewer_host,
            settings.viewer_port,
            settings.viewer_host,
            settings.preview_port,
        )
        asyncio.run(run_servers((dashboard, preview)))
    finally:
        core.close()
