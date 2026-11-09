"""Security tests for the shared header-phase deadline (C26, ADR 0014) over a real Unix socket.

Idle and partial-header connections used to hold `limit_concurrency` slots
forever (every later request → 503, before auth). With the deadline they
are closed and service recovers; valid slow clients and long request
bodies are unaffected; the timer re-arms between keep-alive requests.
"""

from __future__ import annotations

import secrets
import socket
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

from preview_dashboard.bootstrap import build_core
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.server import PeerCredH11Protocol, uvicorn_config
from preview_dashboard.interfaces.http_server import (
    HEADER_TIMEOUT_SECONDS,
    HeaderTimeoutH11Protocol,
    with_header_timeout,
)
from tests.admin_support import (
    make_settings,
    multipart_headers,
    publish_body,
    running_admin_server,
    uds_client,
)

pytestmark = pytest.mark.security

LIMIT = 4
HEADER_TIMEOUT = 0.5


@contextmanager
def _server(tmp_path: Path, **overrides: object) -> Iterator[tuple[Path, str]]:
    """Admin app on a real socket with a small concurrency limit and short header deadline."""
    token = secrets.token_urlsafe(32)
    options: dict[str, object] = {
        "header_timeout": HEADER_TIMEOUT,
        "limit_concurrency": LIMIT,
        **overrides,
    }
    with build_core(make_settings(tmp_path), role="admin") as core:
        app = build_admin_app(core, token=token.encode())
        sock_path = tmp_path / "run" / "admin.sock"
        with running_admin_server(app, sock_path, **options):
            yield sock_path, token


def _connect(sock_path: Path) -> socket.socket:
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect(str(sock_path))
    return conn


def _head(token: str, path: str = "/v1/health") -> bytes:
    auth = f"Authorization: Bearer {token}\r\n"
    return f"GET {path} HTTP/1.1\r\nHost: admin.local\r\n{auth}\r\n".encode()


def _read_response(conn: socket.socket) -> bytes:
    """Read one response with a Content-Length body."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = next(
        int(line.split(b":", 1)[1])
        for line in head.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    while len(body) < length:
        body += conn.recv(4096)
    return head


def _closed_by_server_within(conn: socket.socket, seconds: float) -> bool:
    """True if the server closes `conn` (EOF) within `seconds`, sending nothing."""
    conn.settimeout(seconds)
    try:
        return conn.recv(1) == b""
    except TimeoutError:
        return False


def _health(sock_path: Path, token: str) -> int:
    with uds_client(sock_path) as client:
        status: int = client.get(
            "/v1/health", headers={"Authorization": f"Bearer {token}"}
        ).status_code
    return status


class TestHeaderDeadline:
    def test_idle_connections_are_reaped_and_service_recovers(self, tmp_path):
        with _server(tmp_path) as (sock_path, token), ExitStack() as stack:
            idle = [stack.enter_context(_connect(sock_path)) for _ in range(LIMIT + 1)]
            time.sleep(0.1)  # let the server accept them all
            assert _health(sock_path, token) == 503  # the attack works without a deadline...
            started = time.monotonic()
            assert all(_closed_by_server_within(c, 5) for c in idle)
            assert time.monotonic() - started < 3
            assert _health(sock_path, token) == 200  # ...and is undone by it

    def test_partial_header_connections_are_reaped(self, tmp_path):
        with _server(tmp_path) as (sock_path, token), ExitStack() as stack:
            partial = [stack.enter_context(_connect(sock_path)) for _ in range(LIMIT + 1)]
            for conn in partial:
                conn.sendall(b"GET /v1/health HTTP/1.1\r\nHost: admin.local\r\n")
            assert all(_closed_by_server_within(c, 5) for c in partial)
            assert _health(sock_path, token) == 200

    def test_dripping_header_bytes_does_not_extend_the_deadline(self, tmp_path):
        with _server(tmp_path) as (sock_path, _), _connect(sock_path) as conn:
            conn.sendall(b"GET /v1/health HTTP/1.1\r\n")
            started = time.monotonic()
            closed = False
            while time.monotonic() - started < 5 and not closed:
                try:
                    conn.sendall(b"X-Drip: 1\r\n")
                except OSError:
                    closed = True  # server hung up on us
                    break
                closed = _closed_by_server_within(conn, 0.1)
            assert closed
            assert time.monotonic() - started < HEADER_TIMEOUT + 2

    def test_slow_but_valid_client_is_served(self, tmp_path):
        with _server(tmp_path, header_timeout=1.5) as (sock_path, token), ExitStack() as stack:
            conn = stack.enter_context(_connect(sock_path))
            head = _head(token)
            for start in range(0, len(head), 10):  # whole head over ~0.5 s
                conn.sendall(head[start : start + 10])
                time.sleep(0.5 / (len(head) / 10))
            assert _read_response(conn).startswith(b"HTTP/1.1 200")

    def test_long_request_body_is_not_cut_by_the_header_deadline(self, tmp_path):
        with _server(tmp_path, header_timeout=0.3) as (sock_path, token):
            body = publish_body([("a.bin", b"x" * 20_000)])
            headers = multipart_headers(token)
            head = (
                "POST /v1/items HTTP/1.1\r\nHost: admin.local\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                + f"Content-Length: {len(body)}\r\n\r\n"
            ).encode()
            with _connect(sock_path) as conn:
                conn.sendall(head)
                for start in range(0, len(body), 4000):  # body over ~1 s > deadline
                    time.sleep(0.2)
                    conn.sendall(body[start : start + 4000])
                assert _read_response(conn).startswith(b"HTTP/1.1 201")

    def test_deadline_rearms_between_keep_alive_requests(self, tmp_path):
        # Keep-alive is long here, so only the header deadline can close these.
        with _server(tmp_path, timeout_keep_alive=30) as (sock_path, token):
            with _connect(sock_path) as conn:
                conn.sendall(_head(token))
                assert _read_response(conn).startswith(b"HTTP/1.1 200")
                conn.sendall(b"GET /v1/health HTTP/1.1\r\n")  # next head, never finished
                started = time.monotonic()
                assert _closed_by_server_within(conn, 5)
                assert time.monotonic() - started < HEADER_TIMEOUT + 2
            with _connect(sock_path) as conn:
                conn.sendall(_head(token))
                assert _read_response(conn).startswith(b"HTTP/1.1 200")
                assert _closed_by_server_within(conn, 5)  # idle after a response
                conn.close()
            with _connect(sock_path) as conn:  # keep-alive itself still works
                conn.sendall(_head(token))
                assert _read_response(conn).startswith(b"HTTP/1.1 200")
                conn.sendall(_head(token))
                assert _read_response(conn).startswith(b"HTTP/1.1 200")


class TestProtocolWiring:
    def test_admin_protocol_composes_peer_credentials_and_deadline(self):
        assert issubclass(PeerCredH11Protocol, HeaderTimeoutH11Protocol)
        config = uvicorn_config(lambda scope, receive, send: None)  # type: ignore[arg-type,return-value]
        assert config.http is PeerCredH11Protocol
        assert PeerCredH11Protocol.header_timeout == HEADER_TIMEOUT_SECONDS

    def test_custom_deadline_is_a_subclass(self):
        config = uvicorn_config(lambda scope, receive, send: None, header_timeout=2.5)  # type: ignore[arg-type,return-value]
        protocol = config.http
        assert isinstance(protocol, type)
        assert issubclass(protocol, PeerCredH11Protocol)
        assert protocol.header_timeout == 2.5

    @pytest.mark.parametrize("seconds", [0, -1.0, float("nan")])
    def test_non_positive_deadline_is_refused(self, seconds):
        with pytest.raises(ValueError, match="positive"):
            with_header_timeout(HeaderTimeoutH11Protocol, seconds)
