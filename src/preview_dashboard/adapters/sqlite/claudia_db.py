"""The admin-only Claudia database: inbox + approval requests (ADR 0031, C44, C46, S-C1 S1).

`connect_claudia(db_path, create=...)` opens `data_dir/claudia/claudia.sqlite3`,
a SQLite file separate from the shared item DB: the viewer writes that one,
so approvals or owner messages stored there could be forged by a
compromised viewer. This file is private to the admin uid (dir 0700, file
and sidecars 0600, owner = this process's uid); anything looser, a symlink,
a hardlink or a swapped inode is refused (fail closed), and existing
entries are never "fixed". Own schema (`user_version` 2: 1 + the media
columns of F-CL4), applied only by the admin role (`create=True`); the
purge job opens it with `create=False`.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from collections.abc import Callable
from pathlib import Path

from preview_dashboard.adapters.sqlite.connection import (
    _CREATE_LOCK,
    UnsafeDatabasePathError,
    _apply_pragmas,
    _identity_at,
    _lstat_at,
    _open_dir,
)
from preview_dashboard.adapters.sqlite.migrations import (
    DatabaseSetupError,
    Migration,
    apply_migrations,
)

CLAUDIA_SUBDIR = "claudia"
CLAUDIA_DB_FILENAME = "claudia.sqlite3"
# Owner only: neither the viewer nor the `pdash` group may read or write it.
CLAUDIA_DIR_MODE = 0o700
CLAUDIA_FILE_MODE = 0o600
_SIDECAR_SUFFIXES = ("-wal", "-shm")
# Any group/other bit is "looser". A POSIX ACL with named entries shows up
# in the group bits (the ACL mask), so it is refused by the same check.
_FOREIGN_BITS = stat.S_IRWXG | stat.S_IRWXO
_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC

_GET_VERSION_SQL = "PRAGMA user_version"
_BUSY_TIMEOUT_SQL = "PRAGMA busy_timeout = 5000"
_CHECKPOINT_TRUNCATE_SQL = "PRAGMA wal_checkpoint(TRUNCATE)"
# Short per attempt so `compact_claudia`'s bounded retry loop stays bounded in time.
_COMPACT_BUSY_TIMEOUT_SQL = "PRAGMA busy_timeout = 200"

# Schema 1. Same tables as the unreleased shared migration 5 had (moved here).
#
# - `owner_messages`: UNIQUE (update_id, telegram_message_id) makes the
#   idempotent add atomic (a re-delivered update is stored once). Text is
#   stored verbatim (the screen must see invisible chars, C48).
# - `approval_requests`: `message_id` has no foreign key, since inbox rows
#   are deleted after 30 days while the audit may still name them.
#   `action_kind` has no CHECK list: the domain re-validates it on every read
#   (a closed enum, `unknown` impossible), and a CHECK would need a table
#   rebuild to extend it. Kind and state keep CHECKs like the other tables.
# - Partial indexes use literal state names so the planner can apply them.
_C1_CREATE_OWNER_MESSAGES_SQL = """
    CREATE TABLE owner_messages (
        id TEXT PRIMARY KEY,
        update_id INTEGER NOT NULL CHECK (update_id >= 0),
        telegram_message_id INTEGER NOT NULL CHECK (telegram_message_id >= 1),
        text TEXT NOT NULL,
        received_us INTEGER NOT NULL,
        is_forwarded INTEGER NOT NULL CHECK (is_forwarded IN (0, 1)),
        reply_to_message_id INTEGER,
        quote_text TEXT,
        state TEXT NOT NULL CHECK (state IN ('received', 'handled')),
        handled_us INTEGER,
        UNIQUE (update_id, telegram_message_id)
    ) STRICT
    """
# Serves `list_unhandled`: WHERE state = 'received' ORDER BY received_us, id.
_C1_INDEX_UNHANDLED_SQL = """
    CREATE INDEX idx_owner_messages_unhandled
        ON owner_messages (received_us, id) WHERE state = 'received'
    """
# Serves `delete_received_before`: WHERE received_us < ?
_C1_INDEX_RECEIVED_SQL = "CREATE INDEX idx_owner_messages_received ON owner_messages (received_us)"
_C1_CREATE_APPROVALS_SQL = """
    CREATE TABLE approval_requests (
        id TEXT PRIMARY KEY,
        window_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('action', 'flagged_message', 'peer_message')),
        action_kind TEXT,
        action_target TEXT,
        action_text TEXT NOT NULL,
        message_id TEXT,
        state TEXT NOT NULL CHECK (state IN (
            'pending', 'tapped', 'approved', 'consumed', 'denied', 'expired', 'cancelled'
        )),
        created_us INTEGER NOT NULL,
        expires_us INTEGER NOT NULL,
        updated_us INTEGER NOT NULL,
        tapped_us INTEGER,
        approved_us INTEGER,
        resolved_us INTEGER
    ) STRICT
    """
# Serves the one-open-request-per-window check and `list_open`.
_C1_INDEX_APPROVALS_OPEN_SQL = """
    CREATE INDEX idx_approval_requests_open
        ON approval_requests (window_id, created_us, id)
        WHERE state IN ('pending', 'tapped', 'approved')
    """
# Serves `find_consumed` (the risky-action hook's lookup, C59).
_C1_INDEX_APPROVALS_CONSUMED_SQL = """
    CREATE INDEX idx_approval_requests_consumed
        ON approval_requests (window_id, action_kind, action_target, resolved_us)
        WHERE state = 'consumed'
    """
# Serves `list_expirable` and `delete_expired_before`.
_C1_INDEX_APPROVALS_EXPIRES_SQL = (
    "CREATE INDEX idx_approval_requests_expires ON approval_requests (expires_us, id)"
)
_C1_SET_VERSION_SQL = "PRAGMA user_version = 1"


# Schema 2 (F-CL4, C61): owner voice notes and photos. Additive only: every
# existing row becomes `kind = 'text'` with no media ref, nothing is rewritten.
# The bytes live in the admin-only media dir (`adapters/media_store.py`),
# named by `media_id`; the domain re-checks kind/ref/size on every read.
_C2_ADD_KIND_SQL = (
    "ALTER TABLE owner_messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text' "
    "CHECK (kind IN ('text', 'voice', 'photo'))"
)
_C2_ADD_MEDIA_ID_SQL = "ALTER TABLE owner_messages ADD COLUMN media_id TEXT"
_C2_ADD_MEDIA_BYTES_SQL = (
    "ALTER TABLE owner_messages ADD COLUMN media_bytes INTEGER CHECK (media_bytes >= 1)"
)
_C2_SET_VERSION_SQL = "PRAGMA user_version = 2"


def _claudia_migration_1(conn: sqlite3.Connection) -> None:
    conn.execute(_C1_CREATE_OWNER_MESSAGES_SQL)
    conn.execute(_C1_INDEX_UNHANDLED_SQL)
    conn.execute(_C1_INDEX_RECEIVED_SQL)
    conn.execute(_C1_CREATE_APPROVALS_SQL)
    conn.execute(_C1_INDEX_APPROVALS_OPEN_SQL)
    conn.execute(_C1_INDEX_APPROVALS_CONSUMED_SQL)
    conn.execute(_C1_INDEX_APPROVALS_EXPIRES_SQL)
    conn.execute(_C1_SET_VERSION_SQL)


def _claudia_migration_2(conn: sqlite3.Connection) -> None:
    conn.execute(_C2_ADD_KIND_SQL)
    conn.execute(_C2_ADD_MEDIA_ID_SQL)
    conn.execute(_C2_ADD_MEDIA_BYTES_SQL)
    conn.execute(_C2_SET_VERSION_SQL)


_CLAUDIA_MIGRATIONS: tuple[Migration, ...] = (
    (1, _claudia_migration_1),
    (2, _claudia_migration_2),
)

CLAUDIA_SCHEMA_VERSION = _CLAUDIA_MIGRATIONS[-1][0]

_NOT_CREATED_YET = "Claudia database does not exist yet (start the admin service first)"


def default_claudia_db_path(data_dir: Path) -> Path:
    """Return the Claudia database path under `data_dir` (`claudia/claudia.sqlite3`)."""
    return Path(data_dir) / CLAUDIA_SUBDIR / CLAUDIA_DB_FILENAME


def migrate_claudia(conn: sqlite3.Connection) -> None:
    """Bring a Claudia-database connection up to `CLAUDIA_SCHEMA_VERSION` (forward-only).

    Raises:
        DatabaseSetupError: the schema is newer than this code knows.
    """
    apply_migrations(conn, _CLAUDIA_MIGRATIONS)


def compact_claudia(
    conn_factory: Callable[[], sqlite3.Connection],
    *,
    attempts: int = 10,
    delay_seconds: float = 0.05,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Checkpoint the Claudia WAL and truncate it (like the item DB's `compact()`, C24).

    `secure_delete` zeroes deleted rows in the main file, but older page
    images (message text, action texts) stay in `-wal` until a TRUNCATE
    checkpoint. A reader holding an older snapshot blocks it, so it is
    retried a bounded number of times and otherwise left to the next run.

    Returns:
        True if the WAL was fully checkpointed and truncated.

    Raises:
        ValueError: `attempts < 1` or `delay_seconds < 0`.
    """
    if attempts < 1 or delay_seconds < 0:
        raise ValueError("attempts must be >= 1 and delay_seconds >= 0")
    conn = conn_factory()
    try:
        conn.execute(_COMPACT_BUSY_TIMEOUT_SQL)
        for attempt in range(attempts):
            (busy, _log_frames, _done_frames) = conn.execute(_CHECKPOINT_TRUNCATE_SQL).fetchone()
            if busy == 0:
                return True
            if attempt + 1 < attempts:
                sleep(delay_seconds * (attempt + 1))
        return False
    finally:
        conn.close()


def _check_private(
    st: os.stat_result, uid: int, what: str, *, regular: bool, sidecar: bool = False
) -> None:
    """Refuse unless `st` is the right type, owned by `uid` and grants nothing to others.

    `sidecar`: a link count of 0 is accepted too. SQLite unlinks `-shm`
    (and `-wal`) when the last connection closes, so a concurrent `lstat`
    can see the inode mid-unlink; an inode with no name can't be reached
    under other modes, so only extra links (>= 2) are a hardlink attack.
    """
    if stat.S_ISLNK(st.st_mode):
        raise UnsafeDatabasePathError(f"{what} must not be a symlink")
    if regular and not stat.S_ISREG(st.st_mode):
        raise UnsafeDatabasePathError(f"{what} must be a regular file")
    if not regular and not stat.S_ISDIR(st.st_mode):
        raise UnsafeDatabasePathError(f"{what} must be a real directory")
    if st.st_uid != uid:
        raise UnsafeDatabasePathError(f"{what} is not owned by the admin user")
    if st.st_mode & _FOREIGN_BITS:
        raise UnsafeDatabasePathError(f"{what} must grant no access to group or others")
    # A second link elsewhere would expose the same inode under other modes.
    allowed_links = (0, 1) if sidecar else (1,)
    if regular and st.st_nlink not in allowed_links:
        raise UnsafeDatabasePathError(f"{what} must have exactly one link")


def _check_data_dir(fd: int, uid: int) -> None:
    """The parent data dir: trusted owner, nobody else may write (can't swap our dir)."""
    st = os.fstat(fd)
    if st.st_uid != uid:
        raise UnsafeDatabasePathError("data directory is not owned by the admin user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise UnsafeDatabasePathError("data directory must not be group- or world-writable")


def _open_claudia_dir(data_fd: int, name: str, uid: int, *, create: bool) -> int:
    """Open (creating 0700 if missing and allowed) and validate the `claudia/` directory."""
    created = False
    try:
        fd = _open_dir(name, data_fd, "Claudia directory")
    except FileNotFoundError:
        if not create:
            raise DatabaseSetupError(_NOT_CREATED_YET) from None
        try:
            os.mkdir(name, CLAUDIA_DIR_MODE, dir_fd=data_fd)
            created = True
        except FileExistsError:
            pass  # a concurrent opener won the race; validate what it made
        fd = _open_dir(name, data_fd, "Claudia directory")
    try:
        if created:
            os.fchmod(fd, CLAUDIA_DIR_MODE)  # mkdir's mode is filtered by the umask
            os.fsync(data_fd)
        _check_private(os.fstat(fd), uid, "Claudia directory", regular=False)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _ensure_file(dir_fd: int, name: str, uid: int, *, create: bool) -> tuple[int, int]:
    """Create the DB file 0600 if missing (and allowed), validate it, return its identity.

    Only stat-ed afterwards, never opened: closing an fd on a live SQLite
    file drops this process's POSIX locks (see `connection._lstat_at`).
    """
    with _CREATE_LOCK:
        st = _lstat_at(dir_fd, name)
        if st is None:
            if not create:
                raise DatabaseSetupError(_NOT_CREATED_YET)
            try:
                fd = os.open(name, _CREATE_FLAGS, CLAUDIA_FILE_MODE, dir_fd=dir_fd)
            except FileExistsError:
                pass  # another process won the race; validated below
            else:
                try:
                    os.fchmod(fd, CLAUDIA_FILE_MODE)
                finally:
                    os.close(fd)
                os.fsync(dir_fd)
            st = _lstat_at(dir_fd, name)
    if st is None:
        raise UnsafeDatabasePathError("Claudia database file vanished during validation")
    _check_private(st, uid, "Claudia database file", regular=True)
    return st.st_dev, st.st_ino


def _check_sidecars(dir_fd: int, name: str, uid: int) -> None:
    for suffix in _SIDECAR_SUFFIXES:
        st = _lstat_at(dir_fd, name + suffix)
        if st is not None:
            _check_private(st, uid, f"Claudia database {suffix} file", regular=True, sidecar=True)


def _require_current(conn: sqlite3.Connection) -> None:
    (version,) = conn.execute(_GET_VERSION_SQL).fetchone()
    if version != CLAUDIA_SCHEMA_VERSION:
        raise DatabaseSetupError(
            f"Claudia database schema is at version {version}, expected "
            f"{CLAUDIA_SCHEMA_VERSION} (start the admin service first)"
        )


def connect_claudia(db_path: Path, *, create: bool = True) -> sqlite3.Connection:
    """Open a hardened connection to the admin-only Claudia database.

    Every entry is validated before SQLite opens it, and the directory and
    file inodes are re-checked afterwards (swap refused). The owner must be
    this process's effective uid: only the admin user (and the purge job,
    same user) ever opens this file. Pragmas as `connection.connect`.

    Args:
        db_path: normally `default_claudia_db_path(data_dir)`; its parent's
            parent (the data dir) must already exist.
        create: admin role: create the dir (0700) and file (0600) if missing
            and migrate the schema. False (purge): never create anything and
            require the schema at exactly `CLAUDIA_SCHEMA_VERSION`.

    Raises:
        UnsafeDatabasePathError: a symlink, wrong type, foreign owner, any
            group/other mode bit, extra hardlink, or a swapped inode on the
            data dir, `claudia/`, the DB file or its `-wal`/`-shm`.
        DatabaseSetupError: WAL refused; the database is missing
            (`create=False`); the schema is newer than this code, or not
            current (`create=False`).
        FileNotFoundError: the data dir does not exist.
    """
    db_path = Path(db_path).absolute()
    uid = os.geteuid()
    claudia_dir = db_path.parent
    data_fd = _open_dir(os.fspath(claudia_dir.parent), None, "data directory")
    try:
        _check_data_dir(data_fd, uid)
        dir_fd = _open_claudia_dir(data_fd, claudia_dir.name, uid, create=create)
    finally:
        os.close(data_fd)
    try:
        identity = _ensure_file(dir_fd, db_path.name, uid, create=create)
        _check_sidecars(dir_fd, db_path.name, uid)
        conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
        try:
            dir_st = os.fstat(dir_fd)
            if _identity_at(claudia_dir, "Claudia directory") != (dir_st.st_dev, dir_st.st_ino):
                raise UnsafeDatabasePathError("Claudia directory was replaced while connecting")
            if _identity_at(db_path, "Claudia database file") != identity:
                raise UnsafeDatabasePathError("Claudia database file was replaced while connecting")
            # Wait before the WAL switch too: two first opens race on it.
            conn.execute(_BUSY_TIMEOUT_SQL)
            _apply_pragmas(conn)
            if create:
                migrate_claudia(conn)
            else:
                _require_current(conn)
            # WAL mode has now opened (maybe created) -wal/-shm: check them too.
            _check_sidecars(dir_fd, db_path.name, uid)
        except BaseException:
            conn.close()
            raise
    finally:
        os.close(dir_fd)
    return conn
