"""Tests for interfaces/mcp/admin_socket.py: admin-socket trust checks (unit 10b M1/G).

Covers the fail-closed rules `verify_admin_socket` enforces before the MCP
client ever sends the bearer token: real socket, trusted owner/peer, a
non-writable parent directory, and returning the socket's own gid (never a
hardcoded group name) for the token file.
"""

from __future__ import annotations

import os
import socket as socket_module
from collections.abc import Iterator
from pathlib import Path

import pytest

from preview_dashboard.interfaces.mcp.admin_socket import (
    AdminSocketTrustError,
    admin_service_uid,
    verify_admin_socket,
)
from tests.mcp_support import LiveAdmin, live_admin

pytestmark = pytest.mark.unit


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[LiveAdmin]:
    with live_admin(tmp_path) as live:
        yield live


def test_missing_socket_refused(tmp_path: Path) -> None:
    with pytest.raises(AdminSocketTrustError, match="could not be checked"):
        verify_admin_socket(tmp_path / "run" / "nope.sock")


def test_non_socket_path_refused(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir(mode=0o750)
    regular = run / "admin.sock"
    regular.write_text("not a socket")
    with pytest.raises(AdminSocketTrustError, match="not a Unix socket"):
        verify_admin_socket(regular)


def test_socket_with_untrusted_owner_refused(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir(mode=0o750)
    sock_path = run / "admin.sock"
    raw = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    try:
        raw.bind(str(sock_path))
        # Untrusted only if this uid differs from 0, our own euid and
        # (if it exists) the pdash-admin uid -- 65533 is out of the normal
        # system-user range, so it is never any of those on a real host.
        untrusted_uid = 65533
        os.chown(sock_path, untrusted_uid, os.getegid())
        with pytest.raises(AdminSocketTrustError, match="untrusted owner"):
            verify_admin_socket(sock_path)
    finally:
        raw.close()


def test_untrusted_owner_parent_refused(tmp_path: Path) -> None:
    """An untrusted directory owner can replace the socket even without
    write bits reaching us (e.g. by controlling the mount), so the parent's
    *owner* must be trusted too, not just its mode bits."""
    run = tmp_path / "run"
    run.mkdir(mode=0o750)
    sock_path = run / "admin.sock"
    raw = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    try:
        raw.bind(str(sock_path))
        untrusted_uid = 65533  # see test_socket_with_untrusted_owner_refused
        os.chown(run, untrusted_uid, os.getegid())
        with pytest.raises(AdminSocketTrustError, match="untrusted owner"):
            verify_admin_socket(sock_path)
    finally:
        raw.close()


def test_group_writable_parent_refused(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir(mode=0o770)
    os.chmod(run, 0o770)  # noqa: S103 - deliberately permissive, this is the case under test
    sock_path = run / "admin.sock"
    raw = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    try:
        raw.bind(str(sock_path))
        with pytest.raises(AdminSocketTrustError, match="group/world-writable"):
            verify_admin_socket(sock_path)
    finally:
        raw.close()


def test_socket_that_answers_nobody_refused(tmp_path: Path) -> None:
    """A trusted-looking socket file with no live listener fails the peer probe."""
    run = tmp_path / "run"
    run.mkdir(mode=0o750)
    sock_path = run / "admin.sock"
    raw = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
    raw.bind(str(sock_path))
    raw.close()  # bound, never listened on: connect() gets ConnectionRefusedError
    with pytest.raises(AdminSocketTrustError, match="did not answer"):
        verify_admin_socket(sock_path)


def test_live_trusted_socket_returns_its_gid(tmp_path: Path, admin: LiveAdmin) -> None:
    gid = verify_admin_socket(admin.settings.admin_socket)
    assert gid == os.lstat(admin.settings.admin_socket).st_gid


def test_untrusted_peer_uid_refused(
    tmp_path: Path, admin: LiveAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even a trusted-owned socket is refused if the live peer uid isn't trusted."""
    monkeypatch.setattr(
        "preview_dashboard.interfaces.mcp.admin_socket._peer_uid", lambda path: 65533
    )
    with pytest.raises(AdminSocketTrustError, match="did not answer"):
        verify_admin_socket(admin.settings.admin_socket)


def test_unreadable_peer_probe_refused(
    tmp_path: Path, admin: LiveAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "preview_dashboard.interfaces.mcp.admin_socket._peer_uid", lambda path: None
    )
    with pytest.raises(AdminSocketTrustError, match="did not answer"):
        verify_admin_socket(admin.settings.admin_socket)


def test_admin_service_uid_resolves_or_is_none() -> None:
    import pwd

    try:
        expected: int | None = pwd.getpwnam("pdash-admin").pw_uid
    except KeyError:
        expected = None
    assert admin_service_uid() == expected


def test_unreadable_socket_directory_refused(tmp_path: Path) -> None:
    """A parent directory that can't even be stat()'d fails closed."""
    run = tmp_path / "gone"
    sock_path = run / "admin.sock"
    # No parent directory at all: os.lstat(sock_path) itself fails first.
    with pytest.raises(AdminSocketTrustError, match="could not be checked"):
        verify_admin_socket(sock_path)


def test_symlinked_socket_path_refused(tmp_path: Path, admin: LiveAdmin) -> None:
    """`lstat`, never `stat`: a symlink to a real socket must not be trusted."""
    run = tmp_path / "run2"
    run.mkdir(mode=0o750)
    link = run / "admin.sock"
    link.symlink_to(admin.settings.admin_socket)
    with pytest.raises(AdminSocketTrustError, match="not a Unix socket"):
        verify_admin_socket(link)
