"""Serves the admin app with uvicorn on a Unix socket we bind ourselves.

Why not `uvicorn --uds`: uvicorn chmods a fresh socket to 0666 (world
connectable). We bind under a restrictive umask and set 0660 explicitly
(C26), refuse a non-socket or an untrusted parent directory, and attach
each connection's `SO_PEERCRED` to its requests. Uvicorn is configured with
no proxy headers, no `Server` header, no access log, bounded concurrency,
h11 header limits and a header-phase deadline (`interfaces/http_server.py`).
Starting refuses to replace a socket another live instance still answers on.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import stat
from collections.abc import Collection, Iterator
from pathlib import Path
from typing import Any

import uvicorn
from starlette.types import ASGIApp

from preview_dashboard.interfaces.admin.auth import PeerCredentialsApp, read_peer_credentials
from preview_dashboard.interfaces.http_server import (
    HEADER_TIMEOUT_SECONDS,
    HeaderTimeoutH11Protocol,
    with_header_timeout,
)

logger = logging.getLogger("preview_dashboard.admin")

SOCKET_MODE = 0o660
_BIND_UMASK = 0o177  # socket born 0600; widened to exactly 0660 below, never wider
_UNTRUSTED_DIR_BITS = stat.S_IWGRP | stat.S_IWOTH
# Connections (idle ones included) + running requests; over it → 503. Idle
# or partial-header connections are reaped after HEADER_TIMEOUT_SECONDS and
# keep-alive ones after TIMEOUT_KEEP_ALIVE_SECONDS, so slots can't be pinned.
LIMIT_CONCURRENCY = 32
H11_MAX_INCOMPLETE_EVENT_BYTES = 64 * 1024
TIMEOUT_KEEP_ALIVE_SECONDS = 5
BACKLOG = 64
_PROBE_TIMEOUT_SECONDS = 1.0


class UnsafeSocketPathError(RuntimeError):
    """The admin socket path or its directory can't be trusted; refuse to start."""


class PeerCredH11Protocol(HeaderTimeoutH11Protocol):
    """h11 protocol (with the header-phase deadline) that tags requests with peer credentials.

    One protocol instance serves one connection, so wrapping `self.app` in
    `connection_made` scopes the credentials to exactly that connection.
    """

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        """Read `SO_PEERCRED` once per connection and attach it to its requests."""
        super().connection_made(transport)
        peer = read_peer_credentials(transport.get_extra_info("socket"))
        self.app = PeerCredentialsApp(self.config.loaded_app, peer)


def _check_parent(path: Path) -> None:
    parent = os.lstat(path.parent)
    if not stat.S_ISDIR(parent.st_mode):
        raise UnsafeSocketPathError(f"{path.parent} is not a directory")
    if parent.st_uid not in {0, os.geteuid()} or parent.st_mode & _UNTRUSTED_DIR_BITS:
        raise UnsafeSocketPathError(
            f"{path.parent} must be owned by root or this user and not group/world-writable"
        )


def _socket_answers(path: Path) -> bool:
    """True if something accepts connections on `path` (or we can't tell: fail closed)."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_PROBE_TIMEOUT_SECONDS)
    try:
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        return False  # nobody listening: a stale file from a previous run
    except OSError:
        return True  # timeout (full backlog), EACCES, ...: treat as alive
    finally:
        probe.close()
    return True


def _remove_stale(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise UnsafeSocketPathError(f"{path} exists and is not a socket; refusing to replace it")
    # Unlinking a live socket would silently orphan a running instance (and
    # two servers would then share the token and database): refuse instead.
    if _socket_answers(path):
        raise UnsafeSocketPathError(
            f"{path} is in use by another running instance (or can't be probed); refusing to start"
        )
    os.unlink(path)


def bind_admin_socket(path: Path, *, mode: int = SOCKET_MODE) -> socket.socket:
    """Create, bind and listen on the admin Unix socket with exactly `mode`.

    Raises:
        UnsafeSocketPathError: parent dir untrusted, a non-socket at `path`,
            or a live socket another instance still answers on.
        ValueError: `mode` grants anything to others.
    """
    if mode & stat.S_IRWXO:
        raise ValueError("admin socket mode must not grant access to others")
    path = Path(path)
    _check_parent(path)
    _remove_stale(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        old_umask = os.umask(_BIND_UMASK)
        try:
            sock.bind(str(path))
        finally:
            os.umask(old_umask)
        os.chmod(path, mode, follow_symlinks=False)
        if stat.S_IMODE(os.lstat(path).st_mode) != mode:
            raise UnsafeSocketPathError(f"could not set mode {mode:o} on {path}")
        sock.listen(BACKLOG)
    except BaseException:
        sock.close()
        raise
    return sock


def uvicorn_config(
    app: ASGIApp,
    *,
    header_timeout: float = HEADER_TIMEOUT_SECONDS,
    **overrides: Any,  # noqa: ANN401 - uvicorn kwargs
) -> uvicorn.Config:
    """Hardened uvicorn settings for the admin app (C21/C26/C29).

    `header_timeout` and `overrides` exist for tests (e.g. shorter timers).
    """
    protocol = (
        PeerCredH11Protocol
        if header_timeout == PeerCredH11Protocol.header_timeout
        else with_header_timeout(PeerCredH11Protocol, header_timeout)
    )
    options: dict[str, Any] = {
        "http": protocol,
        "ws": "none",
        "lifespan": "off",
        "proxy_headers": False,
        "server_header": False,
        "access_log": False,  # AccessLogMiddleware logs without query strings/headers
        "log_config": None,  # keep the process's logging config (journald via stderr)
        "limit_concurrency": LIMIT_CONCURRENCY,
        "h11_max_incomplete_event_size": H11_MAX_INCOMPLETE_EVENT_BYTES,
        "timeout_keep_alive": TIMEOUT_KEEP_ALIVE_SECONDS,
        "backlog": BACKLOG,
    }
    options.update(overrides)
    return uvicorn.Config(app, **options)


@contextlib.contextmanager
def admin_socket(path: Path) -> Iterator[socket.socket]:
    """Bind the admin socket for the duration of the block; unlink it afterwards."""
    sock = bind_admin_socket(path)
    try:
        yield sock
    finally:
        sock.close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)


def serve(app: ASGIApp, socket_path: Path, *, allowed_peer_uids: Collection[int] = ()) -> None:
    """Run the admin app on `socket_path` until interrupted (blocking)."""
    with admin_socket(socket_path) as sock:
        logger.info(
            "admin API listening on %s (peer uid allowlist: %s)",
            socket_path,
            sorted(allowed_peer_uids) or "socket permissions only",
        )
        uvicorn.Server(uvicorn_config(app)).run(sockets=[sock])
