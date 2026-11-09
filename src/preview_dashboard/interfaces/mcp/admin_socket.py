"""Trust checks on the admin Unix socket, run before the MCP client ever uses it.

Before `preview-dashboard-mcp` sends the bearer token anywhere, it verifies
the socket it is about to talk to is actually the admin API: a real Unix
socket, owned by a trusted identity, in a directory nobody untrusted can
tamper with, and actually answered (`SO_PEERCRED`) by a trusted process —
not merely "some socket file that happens to sit at the configured path"
(docs/security.md C12, C30). The socket's own gid, read only after those
checks pass, becomes the trusted group for the token file: the group name
is never hardcoded here (ADR 0017 amendment, "G" in the unit 10b backlog),
only derived from what is actually on disk.
"""

from __future__ import annotations

import os
import pwd
import socket
import stat
import struct
from pathlib import Path
from typing import Final

# The admin/mcp service *user* names are a fixed, documented convention
# (docs/operations.md, ADR 0017) that this module is allowed to name
# directly; only the *group* name is not (see module docstring).
ADMIN_SERVICE_USER: Final = "pdash-admin"

_UCRED = struct.Struct("3i")  # struct ucred {pid_t pid; uid_t uid; gid_t gid;}
_PROBE_TIMEOUT_SECONDS = 2.0
_UNTRUSTED_DIR_BITS = stat.S_IWGRP | stat.S_IWOTH


class AdminSocketTrustError(RuntimeError):
    """The admin Unix socket cannot be trusted; refuse to start (fail closed)."""


def admin_service_uid() -> int | None:
    """uid of the `pdash-admin` user on this host, or None if it doesn't exist.

    A name lookup goes through NSS (`/etc/passwd` or a configured directory
    service); if that is unavailable the lookup fails closed to None (the
    caller then trusts only uid 0), see docs/security.md Known limitations.
    """
    try:
        return pwd.getpwnam(ADMIN_SERVICE_USER).pw_uid
    except KeyError:
        return None


def _trusted_uids() -> frozenset[int]:
    # 0 (root, the deployed admin socket's peer/owner) and this process's
    # own euid (the MCP server always runs as root in production, so this
    # is redundant there; it lets tests run the "admin" side as themselves).
    extra = admin_service_uid()
    return frozenset({0, os.geteuid(), *((extra,) if extra is not None else ())})


def _peer_uid(path: Path) -> int | None:
    """Connect to `path` and read the `SO_PEERCRED` uid of whatever answers.

    Returns None if nothing answers, the connection can't be probed, or the
    platform has no `SO_PEERCRED` -- callers must treat that as untrusted.
    """
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(_PROBE_TIMEOUT_SECONDS)
    try:
        probe.connect(str(path))
        raw: bytes = probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    except OSError:
        return None
    finally:
        probe.close()
    if len(raw) != _UCRED.size:
        return None
    _pid, uid, _gid = _UCRED.unpack(raw)
    return int(uid)


def verify_admin_socket(path: Path) -> int:
    """Check the admin socket is trustworthy; return its gid for the token file.

    Refuses (fail closed) unless: `path` is a real Unix socket (`lstat`,
    never followed -- a symlink could point anywhere); its owner is uid 0 or
    the `pdash-admin` user; its parent directory is owned by a trusted uid
    and is not group/world-writable (an untrusted owner or a writable parent
    would let another user replace the socket -- an untrusted *owner* can
    still rename/recreate entries even without write bits reaching us, e.g.
    by controlling the mount); and a live probe connection answers with a
    `SO_PEERCRED` peer uid that is also trusted. Only then is the socket's
    own gid (not a hardcoded group name) returned as the group the caller
    may additionally trust on the token file (docs/security.md C12; ADR
    0017 "G").

    Raises:
        AdminSocketTrustError: any check fails. Messages name the path
            (configuration, not a secret) and the rule, never peer data.
    """
    trusted = _trusted_uids()
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise AdminSocketTrustError(
            f"admin socket {path} could not be checked: {exc.strerror or exc}"
        ) from None
    if not stat.S_ISSOCK(st.st_mode):
        raise AdminSocketTrustError(f"{path} is not a Unix socket")
    if st.st_uid not in trusted:
        raise AdminSocketTrustError(f"admin socket {path} has an untrusted owner")
    try:
        parent = os.stat(path.parent)
    except OSError as exc:
        raise AdminSocketTrustError(
            f"directory of admin socket {path} could not be checked: {exc.strerror or exc}"
        ) from None
    if parent.st_uid not in trusted:
        raise AdminSocketTrustError(f"directory of admin socket {path} has an untrusted owner")
    if parent.st_mode & _UNTRUSTED_DIR_BITS:
        raise AdminSocketTrustError(f"directory of admin socket {path} is group/world-writable")
    peer_uid = _peer_uid(path)
    if peer_uid is None or peer_uid not in trusted:
        raise AdminSocketTrustError(f"admin socket {path} did not answer from a trusted process")
    return st.st_gid
