"""SQLite connection factory: hardened pragmas, safe directory/file creation.

`connect(db_path, ...)` is the single place a raw `sqlite3.Connection` is
created. It validates (or creates, with exact modes) the `db/` directory and
the database file through directory fds, refuses untrusted owners/modes on
the directory, the DB file and its `-wal`/`-shm` sidecars (shared-group
model, docs/security.md C24/C28; sidecars may also be owned by the other
DB writer, ADR 0025), verifies after connecting that SQLite opened the very
inodes that were checked, and applies the hardening pragmas.
"""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
import threading
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from preview_dashboard.adapters.sqlite.migrations import CURRENT_VERSION
from preview_dashboard.adapters.sqlite.migrations import (
    DatabaseSetupError as DatabaseSetupError,  # re-exported: its historical home
)
from preview_dashboard.adapters.sqlite.migrations import migrate as apply_migrations
from preview_dashboard.domain.errors import StorageUnavailableError

# Where the database file lives under a configured `data_dir`
# (docs/operations.md): `data_dir/db/items.sqlite3`.
DB_SUBDIR = "db"
DB_FILENAME = "items.sqlite3"

# Shared-group model (docs/security.md C28): admin and viewer both write the
# DB, so both belong to the service group; nobody else gets any access.
DB_FILE_MODE = 0o660
# setgid: files SQLite creates in db/ (-wal, -shm, -journal) inherit the
# service group instead of the creating process's primary group.
DB_DIR_MODE = 0o2770
# Checkpoints truncate the WAL back to at most this size (C24: less residue).
JOURNAL_SIZE_LIMIT_BYTES = 1024 * 1024
BUSY_TIMEOUT_MS = 5000
# SQLite's sidecar files; they hold the same data as the DB, so same checks.
SIDECAR_SUFFIXES = ("-wal", "-shm")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# Errors meaning "a symlink or non-directory sits where a directory should be".
_NOT_A_REAL_DIR = frozenset({errno.ELOOP, errno.ENOTDIR})
# Serializes DB file creation against other threads' connect() (see
# `_create_db_file`); held only around a stat/create, never around queries.
_CREATE_LOCK = threading.Lock()

_PRAGMA_JOURNAL_MODE_WAL_SQL = "PRAGMA journal_mode = WAL"
_PRAGMA_BUSY_TIMEOUT_SQL = "PRAGMA busy_timeout = 5000"
_PRAGMA_FOREIGN_KEYS_SQL = "PRAGMA foreign_keys = ON"
_PRAGMA_SECURE_DELETE_SQL = "PRAGMA secure_delete = ON"
_PRAGMA_TRUSTED_SCHEMA_SQL = "PRAGMA trusted_schema = OFF"
_PRAGMA_SYNCHRONOUS_SQL = "PRAGMA synchronous = NORMAL"
_PRAGMA_JOURNAL_SIZE_LIMIT_SQL = "PRAGMA journal_size_limit = 1048576"
_PRAGMA_USER_VERSION_SQL = "PRAGMA user_version"


class UnsafeDatabasePathError(StorageUnavailableError):
    """The database location can't be trusted.

    Raised when the data dir, `db/` dir, DB file or a `-wal`/`-shm` sidecar
    is a symlink or the wrong file type, has an untrusted owner, has a mode
    outside the shared-group model, or was swapped between validation and
    SQLite opening it. A server-side refusal, not bad input: interfaces
    answer 503 (ADR 0025).
    """


@dataclass(frozen=True, slots=True)
class _TrustPolicy:
    """Who may own the database files, and which group may write them.

    `sidecar_uids` may additionally own `-wal`/`-shm` (never dirs or the DB
    file): SQLite deletes them on the last close and whichever DB writer
    opens next recreates them as its own uid (ADR 0025).
    """

    uids: frozenset[int]
    gid: int
    sidecar_uids: frozenset[int] = frozenset()

    def for_sidecars(self) -> _TrustPolicy:
        """The policy for `-wal`/`-shm`: same checks, owners widened by `sidecar_uids`."""
        return _TrustPolicy(uids=self.uids | self.sidecar_uids, gid=self.gid)

    def check(self, st: os.stat_result, what: str, *, allow_world_read: bool = False) -> None:
        """Raise `UnsafeDatabasePathError` unless `st` fits the shared-group model."""
        if st.st_uid not in self.uids:
            raise UnsafeDatabasePathError(f"{what} is owned by an untrusted uid")
        if allow_world_read and st.st_mode & stat.S_IWOTH:
            raise UnsafeDatabasePathError(f"{what} must not be world-writable")
        if not allow_world_read and st.st_mode & stat.S_IRWXO:
            raise UnsafeDatabasePathError(f"{what} must not grant any access to others")
        if st.st_mode & stat.S_IWGRP and st.st_gid != self.gid:
            raise UnsafeDatabasePathError(f"{what} is group-writable by an untrusted group")


def default_db_path(data_dir: Path) -> Path:
    """Return the standard database file path under `data_dir`."""
    return Path(data_dir) / DB_SUBDIR / DB_FILENAME


def _open_dir(name: str, parent_fd: int | None, what: str) -> int:
    """Open a directory without following a symlink in its last component."""
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in _NOT_A_REAL_DIR:
            raise UnsafeDatabasePathError(f"{what} must be a real directory") from None
        raise


def _set_group(fd: int, policy: _TrustPolicy, what: str) -> None:
    """Hand a freshly created entry to the service group (needs membership)."""
    if os.fstat(fd).st_gid == policy.gid:
        return
    try:
        os.fchown(fd, -1, policy.gid)
    except PermissionError:
        raise UnsafeDatabasePathError(f"cannot give {what} to the service group") from None


_NOT_CREATED_YET = (
    "database does not exist yet (start the admin service or run `preview-dashboard migrate`)"
)


def _open_or_create_db_dir(data_fd: int, name: str, policy: _TrustPolicy, *, create: bool) -> int:
    """Open `db/` under `data_fd` (creating it 2770 if missing and allowed) and validate it."""
    created = False
    try:
        fd = _open_dir(name, data_fd, "db directory")
    except FileNotFoundError:
        if not create:
            raise DatabaseSetupError(_NOT_CREATED_YET) from None
        try:
            os.mkdir(name, DB_DIR_MODE, dir_fd=data_fd)
            created = True
        except FileExistsError:
            pass  # a concurrent process won the race; validate what it made
        fd = _open_dir(name, data_fd, "db directory")
    try:
        if created:
            _set_group(fd, policy, "db directory")
            os.fchmod(fd, DB_DIR_MODE)  # mkdir's mode is filtered by the umask
            os.fsync(data_fd)
        policy.check(os.fstat(fd), "db directory")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _lstat_at(dir_fd: int, name: str) -> os.stat_result | None:
    """`lstat` an entry relative to `dir_fd`; None if absent.

    Files are only ever *stat*-ed here, never opened: closing any fd on a
    file drops every POSIX lock this process holds on it, which would
    silently break the locks of SQLite connections open in other threads
    (SQLITE_PROTOCOL errors, lost writes, corruption).
    """
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _check_file(st: os.stat_result, policy: _TrustPolicy, what: str) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise UnsafeDatabasePathError(f"{what} must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise UnsafeDatabasePathError(f"{what} must be a regular file")
    policy.check(st, what)


def _create_db_file(db_fd: int, name: str, policy: _TrustPolicy) -> None:
    """Create the DB file with exactly `DB_FILE_MODE` and the service group.

    `O_CREAT|O_EXCL|O_NOFOLLOW` never creates through (or opens) a symlink.
    Closing this fd is safe: the inode is brand new, and `_CREATE_LOCK`
    keeps every other thread's `connect()` from opening it until we're done.
    """
    try:
        fd = os.open(name, _CREATE_FLAGS, DB_FILE_MODE, dir_fd=db_fd)
    except FileExistsError:
        return  # another process won the race; the caller validates its file
    try:
        _set_group(fd, policy, "database file")
        os.fchmod(fd, DB_FILE_MODE)  # os.open's mode is filtered by the umask
    finally:
        os.close(fd)
    os.fsync(db_fd)


def _ensure_db_file(
    db_fd: int, name: str, policy: _TrustPolicy, *, create: bool
) -> tuple[int, int]:
    """Create the DB file if missing (and allowed), validate it, return `(st_dev, st_ino)`."""
    with _CREATE_LOCK:
        st = _lstat_at(db_fd, name)
        if st is None:
            if not create:
                raise DatabaseSetupError(_NOT_CREATED_YET)
            _create_db_file(db_fd, name, policy)
            st = _lstat_at(db_fd, name)
    if st is None:
        raise UnsafeDatabasePathError("database file vanished during validation")
    _check_file(st, policy, "database file")
    return st.st_dev, st.st_ino


def _check_sidecars(db_fd: int, db_name: str, policy: _TrustPolicy) -> None:
    """Validate `-wal`/`-shm` if present (SQLite creates them with the DB file's mode)."""
    sidecar_policy = policy.for_sidecars()
    for suffix in SIDECAR_SUFFIXES:
        st = _lstat_at(db_fd, db_name + suffix)
        if st is not None:
            _check_file(st, sidecar_policy, f"database {suffix} file")


def _identity_at(path: Path, what: str) -> tuple[int, int]:
    try:
        st = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise UnsafeDatabasePathError(f"{what} was replaced while connecting") from None
    return st.st_dev, st.st_ino


def _check_unchanged(db_path: Path, db_fd: int, file_identity: tuple[int, int]) -> None:
    """Refuse if `db/` or the DB file is no longer the inode validated before connecting."""
    dir_st = os.fstat(db_fd)
    if _identity_at(db_path.parent, "db directory") != (dir_st.st_dev, dir_st.st_ino):
        raise UnsafeDatabasePathError("db directory was replaced while connecting")
    if _identity_at(db_path, "database file") != file_identity:
        raise UnsafeDatabasePathError("database file was replaced while connecting")


@contextmanager
def _validated_location(
    db_path: Path, policy: _TrustPolicy, *, create: bool
) -> Iterator[tuple[int, tuple[int, int]]]:
    """Yield the validated `db/` fd (held while SQLite connects) and the DB file identity."""
    db_dir = db_path.parent
    data_fd = _open_dir(os.fspath(db_dir.parent), None, "data directory")
    try:
        # The data dir is also the blob store root (validated by FsBlobStore,
        # C25); here: real dir, trusted owner, no foreign write access.
        policy.check(os.fstat(data_fd), "data directory", allow_world_read=True)
        db_fd = _open_or_create_db_dir(data_fd, db_dir.name, policy, create=create)
    finally:
        os.close(data_fd)
    try:
        file_identity = _ensure_db_file(db_fd, db_path.name, policy, create=create)
        _check_sidecars(db_fd, db_path.name, policy)
        yield db_fd, file_identity
    finally:
        os.close(db_fd)


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    (mode,) = conn.execute(_PRAGMA_JOURNAL_MODE_WAL_SQL).fetchone()
    # SQLite silently keeps the old mode when it can't switch; readers would
    # then block writers and the WAL-based guarantees (C11) would not hold.
    if str(mode).lower() != "wal":
        raise DatabaseSetupError(f"journal_mode=WAL refused (got {mode!r})")
    conn.execute(_PRAGMA_BUSY_TIMEOUT_SQL)
    conn.execute(_PRAGMA_FOREIGN_KEYS_SQL)
    conn.execute(_PRAGMA_SECURE_DELETE_SQL)
    conn.execute(_PRAGMA_TRUSTED_SCHEMA_SQL)
    conn.execute(_PRAGMA_SYNCHRONOUS_SQL)
    conn.execute(_PRAGMA_JOURNAL_SIZE_LIMIT_SQL)


def _require_current_schema(conn: sqlite3.Connection) -> None:
    (version,) = conn.execute(_PRAGMA_USER_VERSION_SQL).fetchone()
    if version != CURRENT_VERSION:
        raise DatabaseSetupError(
            f"database schema is at version {version}, expected {CURRENT_VERSION} "
            "(start the admin service or run `preview-dashboard migrate` first)"
        )


def connect(
    db_path: Path,
    *,
    trusted_uids: Collection[int] | None = None,
    trusted_gid: int | None = None,
    trusted_sidecar_uids: Collection[int] = (),
    migrate: bool = True,
) -> sqlite3.Connection:
    """Open a hardened (and, by default, migrated) connection to the database at `db_path`.

    `db_path` is `data_dir/db/<file>`. The data dir must already exist; `db/`
    (mode 2770) and the DB file (mode 0660) are created if missing, handed to
    `trusted_gid` and chmod-ed exactly (umask-independent). Existing entries
    are never modified, only validated (shared-group model, C24/C28):

    - data dir, `db/`, DB file, `-wal`, `-shm`: no symlinks, right file type,
      owner in `trusted_uids`, never world-writable, group-writable only if
      the group is `trusted_gid`; `db/` and the files grant nothing to others.
      `-wal`/`-shm` may also be owned by `trusted_sidecar_uids` (ADR 0025).
    - after `sqlite3.connect`, `db/` (via the fd held since validation) and
      the DB file must still be the inodes validated above (swap refused).
    - files are checked with `lstat`, never opened: closing an fd on a DB
      file would drop this process's SQLite POSIX locks.

    Pragmas: `journal_mode=WAL` (asserted: readers never block writers),
    `busy_timeout=5000` (contending writers wait instead of failing),
    `foreign_keys=ON` (file rows cascade on delete), `secure_delete=ON`
    (freed pages zeroed: trashed content is sensitive), `trusted_schema=OFF`
    (schema can't carry authority; defense in depth),
    `synchronous=NORMAL` (safe under WAL: a crash may lose the last commit,
    never corrupt), `journal_size_limit=1 MiB` (WAL shrinks after
    checkpoints). `isolation_level=None`: the repository issues its own
    `BEGIN`/`BEGIN IMMEDIATE`, so upgrades from read to write can't deadlock.

    Args:
        db_path: database file path (normally `default_db_path(data_dir)`).
        trusted_uids: uids allowed to own the files; defaults to the
            effective uid. The viewer passes {admin uid, viewer uid}.
        trusted_gid: the service group (`pdash`); defaults to the effective gid.
        trusted_sidecar_uids: extra uids allowed to own `-wal`/`-shm` only
            (the admin/purge pass the viewer's uid: it is a legitimate DB
            writer and recreates them whenever it opens the DB first).
        migrate: apply pending schema migrations (admin, `migrate` CLI).
            False (viewer, purge): never create `db/` or the DB file and never
            change the schema; require it to be exactly `CURRENT_VERSION`,
            so only the process that owns the schema ever runs DDL.

    Raises:
        UnsafeDatabasePathError: any check above fails.
        DatabaseSetupError: SQLite refused WAL mode, or (`migrate=False`) the
            database is missing or its schema is not at `CURRENT_VERSION`.
        FileNotFoundError: the data dir does not exist.
    """
    db_path = Path(db_path).absolute()
    policy = _TrustPolicy(
        uids=frozenset(trusted_uids if trusted_uids is not None else (os.geteuid(),)),
        gid=trusted_gid if trusted_gid is not None else os.getegid(),
        sidecar_uids=frozenset(trusted_sidecar_uids),
    )
    # No-migrate roles never create the DB either: an empty file owned by
    # them would later be refused by the admin (untrusted owner).
    with _validated_location(db_path, policy, create=migrate) as (db_fd, file_identity):
        conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
        try:
            _check_unchanged(db_path, db_fd, file_identity)
            _apply_pragmas(conn)
            if migrate:
                apply_migrations(conn)
            else:
                _require_current_schema(conn)
            # WAL mode has now opened (maybe created) -wal/-shm: check them too.
            _check_sidecars(db_fd, db_path.name, policy)
        except BaseException:
            conn.close()
            raise
    return conn
