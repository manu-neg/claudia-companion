"""Wire-level helpers for viewer tests: a real uvicorn server on a tmp TCP port.

Runs a viewer app with the production `viewer.server.uvicorn_config` in a
thread, and speaks raw HTTP/1.1 over sockets so tests can see exactly what
reaches the client (bytes vs Content-Length, connection closes).
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from preview_dashboard.interfaces.viewer.server import ManagedServer, uvicorn_config
from tests.viewer_support import OWNER


@contextmanager
def running_viewer_server(app: Any, **overrides: Any) -> Iterator[int]:
    """Serve `app` on 127.0.0.1:<ephemeral port> (thread); yield the port, stop on exit."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    server = ManagedServer(uvicorn_config(app, host="127.0.0.1", port=port, **overrides))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline or not thread.is_alive():
                raise RuntimeError("viewer test server did not start")
            time.sleep(0.01)
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        sock.close()


def connect(port: int, timeout: float = 5.0) -> socket.socket:
    """A plain TCP connection to the test server."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    conn.settimeout(timeout)
    return conn


def request_head(
    path: str, host: str, extra: Mapping[str, str] | None = None, method: str = "GET"
) -> bytes:
    """A complete owner request head (the identity header the viewer requires)."""
    headers = {"Host": host, "Tailscale-User-Login": OWNER, **(extra or {})}
    lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return f"{method} {path} HTTP/1.1\r\n{lines}\r\n".encode("ascii")


def read_head(conn: socket.socket) -> tuple[bytes, bytes]:
    """Read up to the end of a response head; return (head, body bytes already read)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            raise ConnectionError(f"closed before a response head: {data!r}")
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


def header(head: bytes, name: str) -> str | None:
    """First value of header `name` in a raw response head (case-insensitive)."""
    wanted = name.lower().encode("ascii") + b":"
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(wanted):
            return line.split(b":", 1)[1].strip().decode("latin-1")
    return None


def read_response(conn: socket.socket) -> tuple[bytes, bytes]:
    """Read one response with a Content-Length body (or none); return (head, body)."""
    head, body = read_head(conn)
    length = int(header(head, "content-length") or 0)
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return head, body


def read_until_close(conn: socket.socket) -> tuple[bytes, bytes]:
    """Read a response head and then everything until the server closes the connection."""
    head, body = read_head(conn)
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            return head, body
        body += chunk


def closed_by_server_within(conn: socket.socket, seconds: float) -> bool:
    """True if the server closes `conn` (EOF/reset) within `seconds`, sending nothing."""
    conn.settimeout(seconds)
    try:
        return conn.recv(1) == b""
    except TimeoutError:
        return False
    except ConnectionResetError:
        return True
