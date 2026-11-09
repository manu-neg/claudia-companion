"""Versioned, forward-only SQLite schema migrations (`PRAGMA user_version`).

`migrate(conn)` brings a connection's schema up to `CURRENT_VERSION`,
applying only the scripts above its current `user_version`, inside one
`BEGIN IMMEDIATE` transaction. Two processes dialling in for the first time
at the same instant race on schema creation; `BEGIN IMMEDIATE` plus
`busy_timeout` (set by `connection.connect`) makes the loser simply wait and
then see the already-migrated schema, instead of hitting a locking error or
racing on `CREATE TABLE`. A schema newer than this code is refused
(`DatabaseSetupError`), never written. `apply_migrations` is the shared
engine, also used by the admin-only Claudia database (`claudia_db`).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

# Migration 1: the `items` + `item_files` schema, one statement per constant.
#
# Applied via individual `execute()` calls rather than `executescript()`:
# `executescript()` issues an implicit COMMIT first (ending our own
# `BEGIN IMMEDIATE`) and doesn't wrap its statements in a transaction, so a
# second process migrating at the same instant could see a half-created
# schema. Each statement is its own module-level constant, passed by name,
# so the C24 allowlist check can prove no SQL text is built at runtime.
#
# - Datetimes are integer microseconds since the Unix epoch, UTC
#   (`created_us`/`updated_us`/`trashed_us`) — matches `domain.query`'s
#   cursor encoding exactly.
# - `STRICT` tables reject a value of the wrong storage class outright.
# - `item_files.item_id ... ON DELETE CASCADE` needs `PRAGMA foreign_keys=ON`
#   (set on every connection).
# - `item_files.blob_id` is UNIQUE: two files can never claim the same blob,
#   which is what makes `all_blob_ids()` and the orphan sweep meaningful.
# - `position` preserves the manifest's file order; `PRIMARY KEY (item_id,
#   relpath)` repeats the domain's per-item relpath uniqueness.
_M1_CREATE_ITEMS_SQL = """
    CREATE TABLE items (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        kind TEXT NOT NULL,
        entry_file TEXT NOT NULL,
        created_us INTEGER NOT NULL,
        updated_us INTEGER NOT NULL,
        pinned INTEGER NOT NULL CHECK (pinned IN (0, 1)),
        state TEXT NOT NULL CHECK (state IN ('active', 'trashed')),
        trashed_us INTEGER
    ) STRICT
    """
_M1_CREATE_ITEM_FILES_SQL = """
    CREATE TABLE item_files (
        item_id TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
        relpath TEXT NOT NULL,
        blob_id TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        media_type TEXT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (item_id, relpath)
    ) STRICT
    """
# Serves `list()` with no kind filter: WHERE state = ? ORDER BY
# pinned DESC, created_us DESC, id DESC (docs/architecture.md "Ordering").
_M1_INDEX_STATE_ORDER_SQL = """
    CREATE INDEX idx_items_state_order
        ON items (state, pinned DESC, created_us DESC, id DESC)
    """
# Serves `list()` filtered by kind (same ordering, plus an equality on kind).
_M1_INDEX_STATE_KIND_ORDER_SQL = """
    CREATE INDEX idx_items_state_kind_order
        ON items (state, kind, pinned DESC, created_us DESC, id DESC)
    """
# Serves `list_purgeable`: WHERE state = 'trashed' AND trashed_us <= ?
# ORDER BY trashed_us ASC (oldest trash first).
_M1_INDEX_PURGE_SQL = "CREATE INDEX idx_items_purge ON items (state, trashed_us)"
# Serves per-item file lookups in manifest order (`get`, `list`).
_M1_INDEX_FILES_SQL = "CREATE INDEX idx_item_files_item ON item_files (item_id, position)"
# PRAGMA does not accept bound parameters, hence one literal per version.
_M1_SET_VERSION_SQL = "PRAGMA user_version = 1"
_GET_VERSION_SQL = "PRAGMA user_version"
_BEGIN_IMMEDIATE_SQL = "BEGIN IMMEDIATE"


# Migration 2: revisions (ADR 0019). Existing items become revision 1.
#
# - `revisions` holds every kept revision, head included; the head's number
#   is `items.revision`. `items.kind`/`items.entry_file` stay as copies of
#   the head's values (the kind filter of `list()` keeps its index); the
#   repository refuses a row whose copies disagree with its head (tamper).
# - `item_files` gains a `revision` column. SQLite can't change a primary
#   key in place, so the table is rebuilt: create, copy, drop, rename. Its
#   composite foreign key to `revisions` cascades, so deleting an item (or
#   pruning a revision) removes its file rows in the same statement.
# - `blob_id` stays globally UNIQUE: revisions never share blobs.
_M2_CREATE_REVISIONS_SQL = """
    CREATE TABLE revisions (
        item_id TEXT NOT NULL REFERENCES items (id) ON DELETE CASCADE,
        number INTEGER NOT NULL CHECK (number >= 1),
        kind TEXT NOT NULL,
        entry_file TEXT NOT NULL,
        created_us INTEGER NOT NULL,
        PRIMARY KEY (item_id, number)
    ) STRICT
    """
_M2_COPY_REVISIONS_SQL = """
    INSERT INTO revisions (item_id, number, kind, entry_file, created_us)
        SELECT id, 1, kind, entry_file, created_us FROM items
    """
_M2_ADD_ITEM_REVISION_SQL = (
    "ALTER TABLE items ADD COLUMN revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)"
)
_M2_CREATE_FILES_SQL = """
    CREATE TABLE item_files_v2 (
        item_id TEXT NOT NULL,
        revision INTEGER NOT NULL,
        relpath TEXT NOT NULL,
        blob_id TEXT NOT NULL UNIQUE,
        size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        media_type TEXT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (item_id, revision, relpath),
        FOREIGN KEY (item_id, revision) REFERENCES revisions (item_id, number)
            ON DELETE CASCADE
    ) STRICT
    """
_M2_COPY_FILES_SQL = """
    INSERT INTO item_files_v2
        (item_id, revision, relpath, blob_id, size, sha256, media_type, position)
        SELECT item_id, 1, relpath, blob_id, size, sha256, media_type, position
        FROM item_files
    """
_M2_DROP_OLD_FILES_SQL = "DROP TABLE item_files"
_M2_RENAME_FILES_SQL = "ALTER TABLE item_files_v2 RENAME TO item_files"
# Serves per-revision file lookups in manifest order (`get`, `list`).
_M2_INDEX_FILES_SQL = "CREATE INDEX idx_item_files_item ON item_files (item_id, revision, position)"
_M2_SET_VERSION_SQL = "PRAGMA user_version = 2"


# Migration 3: questions, notifications and their deliveries (ADR 0021).
#
# - One shared store for `SqliteQuestionRepository` and
#   `SqliteNotificationOutbox` (transactional outbox): a question, its
#   notification and its tasks commit together.
# - Options and buttons are rows (ordered by `position`), not JSON: every
#   field keeps a STRICT storage class and is rebuilt through its
#   constructor on read.
# - A notification belongs to at most one question (`question_id UNIQUE`);
#   deleting a question cascades to its notification, tasks and buttons.
#   Purge deletes notifications first anyway (a question's notification is
#   never younger than its resolution), so the cascade removes nothing early.
# - At most one SEND per notification and channel (partial UNIQUE index):
#   a RESOLVE always edits exactly one message.
# - `item_id` columns carry no foreign key: an item may be purged while an
#   old notification still names it.
_M3_CREATE_QUESTIONS_SQL = """
    CREATE TABLE questions (
        id TEXT PRIMARY KEY,
        prompt TEXT NOT NULL,
        default_key TEXT,
        item_id TEXT,
        session_label TEXT,
        created_us INTEGER NOT NULL,
        expires_us INTEGER NOT NULL,
        updated_us INTEGER NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('open', 'answered', 'expired', 'cancelled')),
        answer_key TEXT,
        answer_source TEXT,
        resolved_us INTEGER
    ) STRICT
    """
_M3_CREATE_OPTIONS_SQL = """
    CREATE TABLE question_options (
        question_id TEXT NOT NULL REFERENCES questions (id) ON DELETE CASCADE,
        position INTEGER NOT NULL CHECK (position >= 0),
        key TEXT NOT NULL,
        label TEXT NOT NULL,
        PRIMARY KEY (question_id, position),
        UNIQUE (question_id, key)
    ) STRICT
    """
_M3_CREATE_NOTIFICATIONS_SQL = """
    CREATE TABLE notifications (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        title TEXT NOT NULL,
        item_id TEXT,
        question_id TEXT UNIQUE REFERENCES questions (id) ON DELETE CASCADE,
        created_us INTEGER NOT NULL
    ) STRICT
    """
_M3_CREATE_TASKS_SQL = """
    CREATE TABLE delivery_tasks (
        id TEXT PRIMARY KEY,
        notification_id TEXT NOT NULL REFERENCES notifications (id) ON DELETE CASCADE,
        channel TEXT NOT NULL,
        action TEXT NOT NULL CHECK (action IN ('send', 'resolve')),
        state TEXT NOT NULL CHECK (state IN ('pending', 'done', 'failed')),
        attempts INTEGER NOT NULL CHECK (attempts >= 0),
        next_attempt_us INTEGER NOT NULL,
        created_us INTEGER NOT NULL,
        message_ref TEXT,
        final_state TEXT CHECK (final_state IN ('answered', 'expired', 'cancelled')),
        text TEXT NOT NULL,
        link TEXT
    ) STRICT
    """
_M3_CREATE_BUTTONS_SQL = """
    CREATE TABLE delivery_buttons (
        task_id TEXT NOT NULL REFERENCES delivery_tasks (id) ON DELETE CASCADE,
        position INTEGER NOT NULL CHECK (position >= 0),
        key TEXT NOT NULL,
        label TEXT NOT NULL,
        PRIMARY KEY (task_id, position),
        UNIQUE (task_id, key)
    ) STRICT
    """
# Serves `list_expirable`: WHERE state = 'open' AND expires_us <= ?
# ORDER BY expires_us, id (partial: resolved questions never match).
_M3_INDEX_EXPIRABLE_SQL = """
    CREATE INDEX idx_questions_expirable ON questions (expires_us, id) WHERE state = 'open'
    """
# Serves `delete_resolved_before`: WHERE state <> 'open' AND resolved_us < ?
_M3_INDEX_RESOLVED_SQL = """
    CREATE INDEX idx_questions_resolved ON questions (resolved_us) WHERE state <> 'open'
    """
# Serves `NotificationOutbox.delete_before`: WHERE created_us < ?
_M3_INDEX_NOTIFICATIONS_CREATED_SQL = (
    "CREATE INDEX idx_notifications_created ON notifications (created_us)"
)
# Serves `pending`: WHERE state = 'pending' AND next_attempt_us <= ?
# ORDER BY next_attempt_us, created_us, id (partial: finished tasks drop out).
_M3_INDEX_TASKS_DUE_SQL = """
    CREATE INDEX idx_delivery_tasks_due
        ON delivery_tasks (next_attempt_us, created_us, id) WHERE state = 'pending'
    """
# One SEND per notification + channel; also serves the RESOLVE -> SEND lookup.
_M3_INDEX_TASKS_SEND_SQL = """
    CREATE UNIQUE INDEX idx_delivery_tasks_send
        ON delivery_tasks (notification_id, channel) WHERE action = 'send'
    """
# Foreign-key child index (a partial index can't serve the cascade).
_M3_INDEX_TASKS_NOTIFICATION_SQL = (
    "CREATE INDEX idx_delivery_tasks_notification ON delivery_tasks (notification_id)"
)
_M3_SET_VERSION_SQL = "PRAGMA user_version = 3"


# Migration 4: folders (ADR 0027). Existing items become unfiled (NULL).
#
# - `name_key` is the compatibility caseless key of the sanitized name
#   (`domain.folders.folder_name_key`); its UNIQUE constraint makes the
#   uniqueness check atomic with every insert/rename.
# - `items.folder_id` references `folders` with ON DELETE RESTRICT: a
#   folder any item (active or trashed) still references can never be
#   deleted, and an item can never point at a missing folder (the
#   repositories also check both explicitly, inside the write transaction).
#   SQLite adds such a column only with a NULL default, which is "unfiled".
# - One index serves the folder-filtered listings (`folder_id IS ?`, then
#   state and the feed ordering), the per-folder counts, the emptiness
#   check and the foreign-key lookups on folder delete.
_M4_CREATE_FOLDERS_SQL = """
    CREATE TABLE folders (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        name_key TEXT NOT NULL UNIQUE,
        created_us INTEGER NOT NULL,
        updated_us INTEGER NOT NULL
    ) STRICT
    """
_M4_ADD_ITEM_FOLDER_SQL = (
    "ALTER TABLE items ADD COLUMN folder_id TEXT REFERENCES folders (id) ON DELETE RESTRICT"
)
_M4_INDEX_FOLDER_ORDER_SQL = """
    CREATE INDEX idx_items_folder_order
        ON items (folder_id, state, pinned DESC, created_us DESC, id DESC)
    """
_M4_SET_VERSION_SQL = "PRAGMA user_version = 4"


# Migration 5: Claudia's outbox columns (ADR 0031, C46, C56). Columns only:
# no existing row changes. The inbox and approval tables are NOT here: they
# live in the admin-only Claudia database (`adapters/sqlite/claudia_db.py`),
# which the viewer can never open (S-C1 S1: the viewer writes this file).
#
# `delivery_tasks.long_form` (C56): 1 only for `reply`/`voice` text (up to
# 4096 UTF-16 units); existing rows default to 0, i.e. the 300-char alert cap.
_M5_ADD_TASK_LONG_FORM_SQL = (
    "ALTER TABLE delivery_tasks ADD COLUMN long_form INTEGER NOT NULL DEFAULT 0 "
    "CHECK (long_form IN (0, 1))"
)
# `notifications.approval_id` (C46): set only on an approval request's prompt.
# No foreign key: approval rows are deleted by housekeeping on their own
# schedule; a prompt whose request is gone is settled unsent (`pending`).
_M5_ADD_NOTIFICATION_APPROVAL_SQL = "ALTER TABLE notifications ADD COLUMN approval_id TEXT"
_M5_SET_VERSION_SQL = "PRAGMA user_version = 5"


def _migration_1(conn: sqlite3.Connection) -> None:
    conn.execute(_M1_CREATE_ITEMS_SQL)
    conn.execute(_M1_CREATE_ITEM_FILES_SQL)
    conn.execute(_M1_INDEX_STATE_ORDER_SQL)
    conn.execute(_M1_INDEX_STATE_KIND_ORDER_SQL)
    conn.execute(_M1_INDEX_PURGE_SQL)
    conn.execute(_M1_INDEX_FILES_SQL)
    conn.execute(_M1_SET_VERSION_SQL)


def _migration_2(conn: sqlite3.Connection) -> None:
    conn.execute(_M2_CREATE_REVISIONS_SQL)
    conn.execute(_M2_COPY_REVISIONS_SQL)
    conn.execute(_M2_ADD_ITEM_REVISION_SQL)
    conn.execute(_M2_CREATE_FILES_SQL)
    conn.execute(_M2_COPY_FILES_SQL)
    conn.execute(_M2_DROP_OLD_FILES_SQL)
    conn.execute(_M2_RENAME_FILES_SQL)
    conn.execute(_M2_INDEX_FILES_SQL)
    conn.execute(_M2_SET_VERSION_SQL)


def _migration_3(conn: sqlite3.Connection) -> None:
    conn.execute(_M3_CREATE_QUESTIONS_SQL)
    conn.execute(_M3_CREATE_OPTIONS_SQL)
    conn.execute(_M3_CREATE_NOTIFICATIONS_SQL)
    conn.execute(_M3_CREATE_TASKS_SQL)
    conn.execute(_M3_CREATE_BUTTONS_SQL)
    conn.execute(_M3_INDEX_EXPIRABLE_SQL)
    conn.execute(_M3_INDEX_RESOLVED_SQL)
    conn.execute(_M3_INDEX_NOTIFICATIONS_CREATED_SQL)
    conn.execute(_M3_INDEX_TASKS_DUE_SQL)
    conn.execute(_M3_INDEX_TASKS_SEND_SQL)
    conn.execute(_M3_INDEX_TASKS_NOTIFICATION_SQL)
    conn.execute(_M3_SET_VERSION_SQL)


def _migration_4(conn: sqlite3.Connection) -> None:
    conn.execute(_M4_CREATE_FOLDERS_SQL)
    conn.execute(_M4_ADD_ITEM_FOLDER_SQL)
    conn.execute(_M4_INDEX_FOLDER_ORDER_SQL)
    conn.execute(_M4_SET_VERSION_SQL)


def _migration_5(conn: sqlite3.Connection) -> None:
    conn.execute(_M5_ADD_TASK_LONG_FORM_SQL)
    conn.execute(_M5_ADD_NOTIFICATION_APPROVAL_SQL)
    conn.execute(_M5_SET_VERSION_SQL)


Migration = tuple[int, Callable[[sqlite3.Connection], None]]
"""One `(version, apply)` step; `apply` ends by setting `user_version` to `version`."""

# (version, apply) pairs, in order; each `apply` ends by setting user_version.
_MIGRATIONS: tuple[Migration, ...] = (
    (1, _migration_1),
    (2, _migration_2),
    (3, _migration_3),
    (4, _migration_4),
    (5, _migration_5),
)

CURRENT_VERSION = _MIGRATIONS[-1][0]


class DatabaseSetupError(RuntimeError):
    """The database can't be used as is: WAL refused, wrong or newer schema, or missing.

    Defined here (re-exported by `connection`) so `migrate` can raise it
    without an import cycle.
    """


def _newer_schema(current: int, latest: int) -> DatabaseSetupError:
    # Old code must never write a schema it does not know (a rollback that
    # skipped the backup restore): refuse instead of half-working (S-C1 S8).
    return DatabaseSetupError(
        f"database schema is at version {current}, newer than this code's {latest} "
        "(restore the pre-upgrade backup, docs/operations.md)"
    )


def apply_migrations(conn: sqlite3.Connection, migrations: tuple[Migration, ...]) -> None:
    """Bring `conn` up to the last version in `migrations`, forward-only, in one transaction.

    Shared by the item database (`migrate`) and the Claudia database.

    Raises:
        DatabaseSetupError: the schema is newer than `migrations` know
            (checked before and again under the `BEGIN IMMEDIATE` lock).
    """
    latest = migrations[-1][0]
    (current,) = conn.execute(_GET_VERSION_SQL).fetchone()
    if current > latest:
        raise _newer_schema(current, latest)
    if current == latest:
        return
    conn.execute(_BEGIN_IMMEDIATE_SQL)
    try:
        (current,) = conn.execute(_GET_VERSION_SQL).fetchone()  # re-check under the lock
        if current > latest:
            raise _newer_schema(current, latest)
        for version, apply in migrations:
            if version > current:
                apply(conn)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def migrate(conn: sqlite3.Connection) -> None:
    """Apply every item-DB migration above `conn`'s current `user_version`, forward-only.

    Idempotent: calling this again on an up-to-date connection runs one
    read-only `PRAGMA user_version` check and nothing else.

    Raises:
        DatabaseSetupError: the schema is newer than `CURRENT_VERSION`.
    """
    apply_migrations(conn, _MIGRATIONS)
