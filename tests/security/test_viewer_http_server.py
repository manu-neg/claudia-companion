"""Security tests: the viewer servers' header-phase deadline over real TCP (C21, ADR 0014).

Both viewer apps run on uvicorn with `HeaderTimeoutH11Protocol`: idle,
partial-header and dripping connections are closed so they can't pin every
`limit_concurrency` slot (→ bare 503 for the owner); the deadline re-arms
between keep-alive requests; slow but valid clients are still served.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from typing import Any

import pytest

from preview_dashboard.interfaces.http_server import (
    HEADER_TIMEOUT_SECONDS,
    HeaderTimeoutH11Protocol,
)
from preview_dashboard.interfaces.viewer import server as server_module
from preview_dashboard.interfaces.viewer.server import uvicorn_config
from tests.viewer_support import DASH_HOST, PREVIEW_HOST, make_env
from tests.viewer_wire_support import (
    closed_by_server_within,
    connect,
    read_response,
    request_head,
    running_viewer_server,
)

pytestmark = pytest.mark.security

LIMIT = 4
HEADER_TIMEOUT = 0.5
_APPS = {"dashboard": (DASH_HOST, "/api/kinds"), "preview": (PREVIEW_HOST, "/no-such-route")}


@contextmanager
def _server(which: str, **overrides: Any) -> Iterator[tuple[int, bytes]]:
    """One viewer app on real TCP with a small slot limit and a short deadline.

    Yields (port, a complete valid request head for that app).
    """
    env = make_env()
    app = env.dashboard if which == "dashboard" else env.preview
    host, path = _APPS[which]
    options: dict[str, Any] = {
        "header_timeout": HEADER_TIMEOUT,
        "limit_concurrency": LIMIT,
        **overrides,
    }
    with running_viewer_server(app, **options) as port:
        yield port, request_head(path, host)


def _status(port: int, head: bytes) -> int:
    with connect(port) as conn:
        conn.sendall(head)
        status_line = read_response(conn)[0].split(b"\r\n", 1)[0]
    return int(status_line.split()[1])


def _served(status: int) -> bool:
    return status != 503  # the app answered (200 / 404), not uvicorn's slot guard


@pytest.mark.parametrize("which", ["dashboard", "preview"])
class TestHeaderDeadline:
    def test_idle_connections_are_reaped_and_service_recovers(self, which: str) -> None:
        with _server(which) as (port, head), ExitStack() as stack:
            idle = [stack.enter_context(connect(port)) for _ in range(LIMIT + 1)]
            time.sleep(0.1)  # let the server accept them all
            assert _status(port, head) == 503  # slots pinned without a deadline...
            started = time.monotonic()
            assert all(closed_by_server_within(c, 5) for c in idle)
            assert time.monotonic() - started < 3
            assert _served(_status(port, head))  # ...and freed by it

    def test_partial_header_connections_are_reaped(self, which: str) -> None:
        with _server(which) as (port, head), ExitStack() as stack:
            partial = [stack.enter_context(connect(port)) for _ in range(LIMIT + 1)]
            for conn in partial:
                conn.sendall(head[: len(head) // 2])
            assert all(closed_by_server_within(c, 5) for c in partial)
            assert _served(_status(port, head))

    def test_dripping_header_bytes_does_not_extend_the_deadline(self, which: str) -> None:
        with _server(which) as (port, _), connect(port) as conn:
            conn.sendall(b"GET / HTTP/1.1\r\n")
            started = time.monotonic()
            closed = False
            while time.monotonic() - started < 5 and not closed:
                try:
                    conn.sendall(b"X-Drip: 1\r\n")
                except OSError:
                    closed = True  # server hung up on us
                    break
                closed = closed_by_server_within(conn, 0.1)
            assert closed
            assert time.monotonic() - started < HEADER_TIMEOUT + 2

    def test_slow_but_valid_client_is_served(self, which: str) -> None:
        with _server(which, header_timeout=1.5) as (port, head), connect(port) as conn:
            for start in range(0, len(head), 10):  # whole head over ~0.5 s
                conn.sendall(head[start : start + 10])
                time.sleep(0.5 / (len(head) / 10))
            status_line = read_response(conn)[0].split(b"\r\n", 1)[0]
            assert _served(int(status_line.split()[1]))

    def test_deadline_rearms_between_keep_alive_requests(self, which: str) -> None:
        # Keep-alive is long here, so only the header deadline can close these.
        with _server(which, timeout_keep_alive=30) as (port, head):
            with connect(port) as conn:
                conn.sendall(head)
                assert _served(int(read_response(conn)[0].split()[1]))
                conn.sendall(b"GET / HTTP/1.1\r\n")  # next head, never finished
                started = time.monotonic()
                assert closed_by_server_within(conn, 5)
                assert time.monotonic() - started < HEADER_TIMEOUT + 2
            with connect(port) as conn:
                conn.sendall(head)
                assert _served(int(read_response(conn)[0].split()[1]))
                assert closed_by_server_within(conn, 5)  # idle after a response
            with connect(port) as conn:  # keep-alive itself still works
                for _ in range(2):
                    conn.sendall(head)
                    assert _served(int(read_response(conn)[0].split()[1]))


class TestViewerProtocolWiring:
    def test_default_config_uses_the_shared_deadline_protocol(self) -> None:
        config = uvicorn_config(lambda s, r, w: None, host="127.0.0.1", port=1)  # type: ignore[arg-type,return-value]
        assert config.http is HeaderTimeoutH11Protocol
        assert HeaderTimeoutH11Protocol.header_timeout == HEADER_TIMEOUT_SECONDS
        assert config.timeout_graceful_shutdown == server_module.TIMEOUT_GRACEFUL_SHUTDOWN_SECONDS
        assert config.timeout_graceful_shutdown == 10

    def test_custom_deadline_is_a_subclass(self) -> None:
        config = uvicorn_config(
            lambda s, r, w: None,  # type: ignore[arg-type,return-value]
            host="127.0.0.1",
            port=1,
            header_timeout=2.5,
        )
        protocol = config.http
        assert isinstance(protocol, type)
        assert issubclass(protocol, HeaderTimeoutH11Protocol)
        assert protocol.header_timeout == 2.5

    @pytest.mark.parametrize("seconds", [0, -1.0, float("nan")])
    def test_non_positive_deadline_is_refused(self, seconds: float) -> None:
        with pytest.raises(ValueError, match="positive"):
            uvicorn_config(lambda s, r, w: None, host="127.0.0.1", port=1, header_timeout=seconds)  # type: ignore[arg-type,return-value]
