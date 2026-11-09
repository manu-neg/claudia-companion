"""TOTP secret file adapter: load with the C12 file rules, create once (`O_EXCL`) at setup.

`FileTotpSecret` is the admin's `TotpSecretSource`: it re-reads and re-checks
the file on every verification (root-owned or ours, group root or an
explicitly trusted one, no group-write or other access, no symlink, no
POSIX ACL, trusted parent directory, one line of canonical base32 for
20..64 bytes). Any failure raises `StorageUnavailableError`, so every code
is refused (C47, fail closed). `write_totp_secret` is used only by
`claudia totp setup`. Errors name the rule, never the secret.

Unlike token files, this process's own group is **not** trusted by default
(S-C1 S2): the admin's primary group `pdash` is shared with the viewer, so
a `root:pdash` secret would be readable by the viewer. The dedicated
`pdash-totp` group (admin only) is passed in as `trusted_gids`.
"""

from __future__ import annotations

import errno
import logging
import os
import stat
from collections.abc import Collection
from pathlib import Path
from typing import Final

from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.totp import TotpError, decode_secret, encode_secret

logger = logging.getLogger("preview_dashboard.admin")

SECRET_FILE_MODE: Final = 0o640
_MAX_FILE_BYTES: Final = 4096
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
_CREATE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# Group-write or any "other" bit lets someone else read or replace the secret.
_FORBIDDEN_FILE_BITS: Final = stat.S_IWGRP | stat.S_IRWXO
_FORBIDDEN_DIR_BITS: Final = stat.S_IWGRP | stat.S_IWOTH
_ACL_XATTR: Final = "system.posix_acl_access"


class TotpSecretFileError(StorageUnavailableError):
    """The TOTP secret file is missing, unsafe or malformed (message names the rule only)."""


def _refuse_acl(fd: int) -> None:
    # An ACL can grant read access invisible in st_mode (same rule as token files).
    try:
        names = os.listxattr(fd)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise TotpSecretFileError("cannot check ACLs on the TOTP secret file") from None
    if _ACL_XATTR in names:
        raise TotpSecretFileError("the TOTP secret file carries a POSIX ACL")


def load_totp_secret(
    path: Path,
    *,
    trusted_uids: Collection[int] | None = None,
    trusted_gids: Collection[int] = (),
) -> bytes:
    """Read and validate the TOTP secret file; return the raw secret bytes.

    Args:
        path: the secret file (default `/etc/preview-dashboard/totp.secret`).
        trusted_uids: allowed owners (default: root and this euid).
        trusted_gids: allowed groups besides root (this egid is not implied).

    Raises:
        TotpSecretFileError: any file rule fails or the content isn't a
            canonical base32 secret of 20..64 bytes.
    """
    owners = frozenset(trusted_uids) if trusted_uids is not None else {0, os.geteuid()}
    groups = {0, *trusted_gids}
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError:
        raise TotpSecretFileError("the TOTP secret file is missing or unreadable") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise TotpSecretFileError("the TOTP secret file is not a regular file")
        if st.st_uid not in owners:
            raise TotpSecretFileError("the TOTP secret file has an untrusted owner")
        if st.st_gid not in groups:
            raise TotpSecretFileError("the TOTP secret file has an untrusted group")
        if st.st_mode & _FORBIDDEN_FILE_BITS:
            raise TotpSecretFileError("the TOTP secret file must be mode 0640 or stricter")
        _refuse_acl(fd)
        raw = os.read(fd, _MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    parent = os.stat(Path(path).parent)
    if parent.st_uid not in owners or parent.st_mode & _FORBIDDEN_DIR_BITS:
        raise TotpSecretFileError("the TOTP secret file's directory is not trusted")
    if len(raw) > _MAX_FILE_BYTES:
        raise TotpSecretFileError("the TOTP secret file is too large")
    try:
        return decode_secret(raw.decode("ascii").strip())
    except (UnicodeDecodeError, TotpError):
        raise TotpSecretFileError("the TOTP secret file does not hold a valid secret") from None


class FileTotpSecret:
    """`TotpSecretSource` over the secret file, re-checked on every load (C47).

    Re-reading per code means a file replaced by `--rotate`, or loosened
    by mistake, takes effect at once without a restart (fail closed).
    """

    def __init__(self, path: Path, *, trusted_gids: Collection[int] = ()) -> None:
        self._path = Path(path)
        self._gids = tuple(trusted_gids)

    def load(self) -> bytes:
        """Return the secret bytes.

        Raises:
            TotpSecretFileError: see `load_totp_secret` (logged by rule, no content).
        """
        try:
            return load_totp_secret(self._path, trusted_gids=self._gids)
        except TotpSecretFileError as exc:
            logger.warning("TOTP secret refused: %s", exc)
            raise


def write_totp_secret(path: Path, secret: bytes, *, gid: int | None, replace: bool) -> None:
    """Create the secret file (0640, group `gid`) without following symlinks.

    A new file is created with `O_EXCL` at `path`; with `replace` a sibling
    temp file is created the same way and renamed over `path` atomically.
    `gid` None keeps the creator's group (tests; setup always passes one).
    The result is re-read with `load_totp_secret` (trusting that group
    only) and removed again if it would be refused or its group is not
    `gid` (e.g. a setgid directory changed it).

    Raises:
        FileExistsError: `path` (or the temp file) already exists and
            `replace` is False (or a stale temp file is in the way).
        TotpSecretFileError: the written file fails the load checks.
        OSError: the file can't be created or written.
    """
    target = Path(path)
    if not replace and os.path.lexists(target):
        raise FileExistsError(str(target))
    staging = target.with_name(target.name + ".new") if replace else target
    data = (encode_secret(secret) + "\n").encode("ascii")
    fd = os.open(staging, _CREATE_FLAGS, SECRET_FILE_MODE)
    try:
        os.fchmod(fd, SECRET_FILE_MODE)  # exact mode, whatever the umask
        if gid is not None:
            os.fchown(fd, -1, gid)
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(staging)
        raise
    os.close(fd)
    expected_gid = os.getegid() if gid is None else gid
    try:
        load_totp_secret(staging, trusted_gids=(expected_gid,))
        if os.lstat(staging).st_gid != expected_gid:
            raise TotpSecretFileError("the TOTP secret file did not get the requested group")
    except TotpSecretFileError:
        os.unlink(staging)
        raise
    if replace:
        os.replace(staging, target)
