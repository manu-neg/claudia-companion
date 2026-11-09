"""SqliteItemRepository: the `ItemRepository` port backed by SQLite.

Every value is bound as a parameter and every SQL text is a module-level
constant (the twelve `list()` shapes are picked among them, never built at
runtime; a multi-kind filter binds a fixed-width `IN` list) — docs/security.md
C24. Multi-statement reads run in one deferred read transaction (one
snapshot); writes use `BEGIN IMMEDIATE`. Every `Item`/`Revision`/`ItemFile`
read back is rebuilt through its constructor, so a tampered or corrupted
row fails with `ValidationError`. An item is stored as one `items` row
(head copies of kind/entry file + head number, its folder), one `revisions`
row per kept revision and their `item_files` rows. Filing an item into a
folder that does not exist fails with `NotFoundError` inside the write
transaction (the foreign key is the backstop, ADR 0027).
"""

from __future__ import annotations

import builtins
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.folders import FolderId
from preview_dashboard.domain.models import (
    Item,
    ItemFile,
    ItemId,
    ItemState,
    Revision,
    ensure_utc,
)
from preview_dashboard.domain.query import (
    MAX_QUERY_KINDS,
    ItemQuery,
    Page,
    SortKey,
    created_us_to_datetime,
    encode_cursor,
    item_sort_key,
)
from preview_dashboard.ports.repository import RepositoryUsage

ConnectionFactory = Callable[[], sqlite3.Connection]
"""Zero-argument factory returning a fresh, hardened `sqlite3.Connection`
(typically `functools.partial(connection.connect, db_path)`). The repository
opens and closes one connection per call, so the factory may safely be
shared across threads and processes (docs/security.md C11, C24)."""

_BEGIN_READ_SQL = "BEGIN"
_BEGIN_IMMEDIATE_SQL = "BEGIN IMMEDIATE"
_CHECKPOINT_TRUNCATE_SQL = "PRAGMA wal_checkpoint(TRUNCATE)"
# A TRUNCATE checkpoint waits on the busy handler for readers; keep each
# `compact()` attempt short so the bounded retry loop stays bounded in time.
_COMPACT_BUSY_TIMEOUT_SQL = "PRAGMA busy_timeout = 200"

_INSERT_ITEM_SQL = (
    "INSERT INTO items "
    "(id, title, description, kind, entry_file, created_us, updated_us, pinned, state, trashed_us, "
    "revision, folder_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_INSERT_REVISION_SQL = (
    "INSERT INTO revisions (item_id, number, kind, entry_file, created_us) VALUES (?, ?, ?, ?, ?)"
)
_INSERT_FILE_SQL = (
    "INSERT INTO item_files "
    "(item_id, revision, relpath, blob_id, size, sha256, media_type, position) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_ITEM_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE id = ?"
)
_SELECT_REVISIONS_SQL = (
    "SELECT number, kind, entry_file, created_us FROM revisions WHERE item_id = ? ORDER BY number"
)
_SELECT_FILES_SQL = (
    "SELECT revision, relpath, blob_id, size, sha256, media_type FROM item_files "
    "WHERE item_id = ? ORDER BY revision, position"
)
# Compare-and-swap on updated_us (optimistic concurrency, port `save`).
_UPDATE_ITEM_SQL = (
    "UPDATE items SET title = ?, description = ?, kind = ?, entry_file = ?, created_us = ?, "
    "updated_us = ?, pinned = ?, state = ?, trashed_us = ?, revision = ?, folder_id = ? "
    "WHERE id = ? AND updated_us = ?"
)
_ITEM_EXISTS_SQL = "SELECT 1 FROM items WHERE id = ?"
_FOLDER_EXISTS_SQL = "SELECT 1 FROM folders WHERE id = ?"
# Cascades to the revisions' item_files rows (composite foreign key).
_DELETE_REVISIONS_SQL = "DELETE FROM revisions WHERE item_id = ?"
_DELETE_ITEM_SQL = "DELETE FROM items WHERE id = ?"
_ALL_BLOB_IDS_SQL = "SELECT blob_id FROM item_files"
_USAGE_SQL = "SELECT (SELECT COUNT(*) FROM items), (SELECT COALESCE(SUM(size), 0) FROM item_files)"
_SELECT_PURGEABLE_BY_ID_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE id = ? AND state = ? "
    "AND trashed_us IS NOT NULL AND trashed_us <= ?"
)
_PURGEABLE_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE state = ? AND trashed_us IS NOT NULL "
    "AND trashed_us <= ? ORDER BY trashed_us ASC, id ASC"
)

# The shapes `list()` can need (folder filter x kind filter x cursor),
# spelled out as static literals so no query is ever assembled from parts at
# runtime. `folder_id IS ?` matches one folder (an id) or unfiled items
# (NULL) with one shape, and can use `idx_items_folder_order`.
_LIST_ALL_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE state = ? "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_CURSOR_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items "
    "WHERE state = ? AND (pinned, created_us, id) < (?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_KIND_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE state = ? AND kind = ? "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_KIND_CURSOR_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE state = ? AND kind = ? "
    "AND (pinned, created_us, id) < (?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_FOLDER_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE folder_id IS ? AND state = ? "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_FOLDER_CURSOR_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE folder_id IS ? AND state = ? "
    "AND (pinned, created_us, id) < (?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_FOLDER_KIND_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE folder_id IS ? AND state = ? "
    "AND kind = ? ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_FOLDER_KIND_CURSOR_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE folder_id IS ? AND state = ? "
    "AND kind = ? AND (pinned, created_us, id) < (?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
# Several kinds (ItemQuery.kinds, 2..MAX_QUERY_KINDS): a literal `IN` list of
# exactly MAX_QUERY_KINDS placeholders, padded by repeating a kind
# (`_padded_kinds`), so the SQL text stays a static constant (C24) and every
# value is still bound. One kind keeps the `kind = ?` shapes above (index
# order, no sort).
_LIST_KINDS_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE state = ? "
    "AND kind IN (?, ?, ?, ?, ?, ?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_KINDS_CURSOR_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE state = ? "
    "AND kind IN (?, ?, ?, ?, ?, ?, ?, ?) AND (pinned, created_us, id) < (?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_FOLDER_KINDS_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE folder_id IS ? AND state = ? "
    "AND kind IN (?, ?, ?, ?, ?, ?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)
_LIST_FOLDER_KINDS_CURSOR_SQL = (
    "SELECT id, title, description, kind, entry_file, created_us, updated_us, pinned, "
    "state, trashed_us, revision, folder_id FROM items WHERE folder_id IS ? AND state = ? "
    "AND kind IN (?, ?, ?, ?, ?, ?, ?, ?) AND (pinned, created_us, id) < (?, ?, ?) "
    "ORDER BY pinned DESC, created_us DESC, id DESC LIMIT ?"
)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_US = timedelta(microseconds=1)

_ItemRow = tuple[str, str, str, str, str, int, int, int, str, int | None, int, str | None]


def _to_us(value: datetime) -> int:
    """Convert a tz-aware UTC datetime to epoch microseconds.

    Mirrors `domain.query.item_sort_key`'s epoch (kept local rather than
    importing that module's private constants): `Item.__post_init__`
    already guarantees `created_at`/`updated_at`/`trashed_at` are tz-aware
    and within `datetime.min`..`datetime.max`, so the result always fits
    SQLite's 64-bit INTEGER (`domain.query.MIN/MAX_CREATED_US` bound the
    same range and are themselves well within `2**63-1`).
    """
    return (value - _EPOCH) // _ONE_US


def _parse_state(raw: str) -> ItemState:
    """Convert a stored state string to `ItemState`.

    Raises:
        ValidationError: `raw` is not a recognized state (a tampered or
            corrupted row — the `CHECK` constraint stops this for rows
            written through this module, but not rows written by other means).
    """
    try:
        return ItemState(raw)
    except ValueError:
        raise ValidationError("invalid state in stored item") from None


@contextmanager
def _writing(conn: sqlite3.Connection) -> Iterator[None]:
    """Wrap a write in `BEGIN IMMEDIATE` / `COMMIT`-or-`ROLLBACK` (docs/security.md C11).

    `BEGIN IMMEDIATE` acquires the write lock up front (rather than
    opportunistically on the first write statement), so a writer either
    gets the lock or waits on `busy_timeout`; it never discovers a conflict
    only after doing partial work.
    """
    conn.execute(_BEGIN_IMMEDIATE_SQL)
    try:
        yield
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


@contextmanager
def _reading(conn: sqlite3.Connection) -> Iterator[None]:
    """Run several SELECTs against one snapshot (a deferred read transaction).

    In WAL mode the snapshot is fixed by the first SELECT and held until
    COMMIT, so an item row and its file rows can't be torn apart by a
    concurrent delete between the two queries (which would surface as a
    spurious `ValidationError`: "an item needs at least one file").
    Chosen over one big JOIN: keeps the static per-shape SQL constants, and
    the per-item file query is an in-process index lookup, not a network
    round trip, so the N+1 pattern costs microseconds here.
    """
    conn.execute(_BEGIN_READ_SQL)
    try:
        yield
    finally:
        conn.rollback()  # read-only: nothing to commit; ends the snapshot


class SqliteItemRepository:
    """`ItemRepository` backed by SQLite (see `ports.repository.ItemRepository`).

    Opens one connection per call via `conn_factory` (never shared across
    threads); `conn_factory` is expected to apply the pragmas in
    `adapters.sqlite.connection.connect` and to have already migrated the
    schema, so every operation here can assume `items`/`item_files` exist.

    Args:
        conn_factory: see `ConnectionFactory`.
        sleep: waits between `compact()` retries (tests inject a no-op).
    """

    def __init__(
        self, conn_factory: ConnectionFactory, *, sleep: Callable[[float], None] = time.sleep
    ) -> None:
        self._conn_factory = conn_factory
        self._sleep = sleep

    # --- add / get -----------------------------------------------------------

    def add(self, item: Item) -> None:
        """See `ItemRepository.add`."""
        conn = self._conn_factory()
        try:
            with _writing(conn):
                self._check_folder(conn, item)
                try:
                    conn.execute(_INSERT_ITEM_SQL, self._item_params(item))
                except sqlite3.IntegrityError as exc:
                    raise AlreadyExistsError(f"item {item.id} already exists") from exc
                self._insert_revisions(conn, item)
        finally:
            conn.close()

    def get(self, item_id: ItemId) -> Item:
        """See `ItemRepository.get`."""
        conn = self._conn_factory()
        try:
            with _reading(conn):
                row = conn.execute(_SELECT_ITEM_SQL, (item_id,)).fetchone()
                if row is None:
                    raise NotFoundError(f"item {item_id} not found")
                return self._load_item(conn, row)
        finally:
            conn.close()

    # --- list ------------------------------------------------------------------

    def list(self, query: ItemQuery) -> Page[Item]:
        """See `ItemRepository.list`."""
        after = query.after
        sql, params = self._list_query(query, after)
        conn = self._conn_factory()
        try:
            with _reading(conn):
                rows = conn.execute(sql, params).fetchall()
                has_more = len(rows) > query.limit
                items = [self._load_item(conn, row) for row in rows[: query.limit]]
        finally:
            conn.close()
        next_cursor = encode_cursor(item_sort_key(items[-1])) if has_more else None
        return Page(items=tuple(items), next_cursor=next_cursor)

    @staticmethod
    def _list_query(query: ItemQuery, after: SortKey | None) -> tuple[str, tuple[object, ...]]:
        state, kinds, limit_plus_one = query.state.value, query.kinds, query.limit + 1
        # Every branch returns a module constant directly (the C24 AST
        # allowlist follows one helper level only).
        if len(kinds) > 1:
            padded = _padded_kinds(kinds)
            if query.folder is not None:
                folder = query.folder_id
                if after is not None:
                    params = (folder, state, *padded, *after, limit_plus_one)
                    return _LIST_FOLDER_KINDS_CURSOR_SQL, params
                return _LIST_FOLDER_KINDS_SQL, (folder, state, *padded, limit_plus_one)
            if after is not None:
                return _LIST_KINDS_CURSOR_SQL, (state, *padded, *after, limit_plus_one)
            return _LIST_KINDS_SQL, (state, *padded, limit_plus_one)
        kind = kinds[0] if kinds else None
        if query.folder is not None:
            # `query.folder_id` is None for UNFILED: `folder_id IS NULL`.
            folder = query.folder_id
            if kind is not None and after is not None:
                return _LIST_FOLDER_KIND_CURSOR_SQL, (folder, state, kind, *after, limit_plus_one)
            if kind is not None:
                return _LIST_FOLDER_KIND_SQL, (folder, state, kind, limit_plus_one)
            if after is not None:
                return _LIST_FOLDER_CURSOR_SQL, (folder, state, *after, limit_plus_one)
            return _LIST_FOLDER_SQL, (folder, state, limit_plus_one)
        if kind is not None and after is not None:
            return _LIST_KIND_CURSOR_SQL, (state, kind, *after, limit_plus_one)
        if kind is not None:
            return _LIST_KIND_SQL, (state, kind, limit_plus_one)
        if after is not None:
            return _LIST_CURSOR_SQL, (state, *after, limit_plus_one)
        return _LIST_ALL_SQL, (state, limit_plus_one)

    # --- save / delete -----------------------------------------------------

    def save(self, item: Item, *, expected_updated_at: datetime) -> None:
        """See `ItemRepository.save`.

        One `BEGIN IMMEDIATE` transaction: the conditional `UPDATE ... WHERE
        id = ? AND updated_us = ?` is the compare-and-swap; on no match, an
        existence check (same transaction, write lock held) tells a missing
        row from a concurrent change.

        Raises:
            ValidationError: `expected_updated_at` is naive.
            NotFoundError: no such item, or `item.folder_id` names no folder.
            ConflictError: see the port.
        """
        expected_us = _to_us(ensure_utc(expected_updated_at, "expected_updated_at"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                self._check_folder(conn, item)
                # id and the expected version move to the WHERE clause.
                params = (*self._item_params(item)[1:], item.id, expected_us)
                cur = conn.execute(_UPDATE_ITEM_SQL, params)
                if cur.rowcount == 0:
                    if conn.execute(_ITEM_EXISTS_SQL, (item.id,)).fetchone() is None:
                        raise NotFoundError(f"item {item.id} not found")
                    raise ConflictError(f"item {item.id} was changed concurrently")
                # Revisions are rewritten whole: pruned ones disappear with
                # their file rows (cascade), new ones are inserted.
                conn.execute(_DELETE_REVISIONS_SQL, (item.id,))
                self._insert_revisions(conn, item)
        finally:
            conn.close()

    def delete(self, item_id: ItemId) -> bool:
        """See `ItemRepository.delete`."""
        conn = self._conn_factory()
        try:
            with _writing(conn):
                cur = conn.execute(_DELETE_ITEM_SQL, (item_id,))
            return cur.rowcount > 0
        finally:
            conn.close()

    # --- purge support -----------------------------------------------------

    def list_purgeable(self, now: datetime, retention: timedelta) -> builtins.list[Item]:
        """See `ItemRepository.list_purgeable`."""
        try:
            cutoff = ensure_utc(now, "now") - retention
        except OverflowError:
            raise ValidationError("purge cutoff is out of range") from None
        cutoff_us = _to_us(cutoff)
        conn = self._conn_factory()
        try:
            with _reading(conn):
                rows = conn.execute(_PURGEABLE_SQL, (ItemState.TRASHED.value, cutoff_us)).fetchall()
                return [self._load_item(conn, row) for row in rows]
        finally:
            conn.close()

    def delete_if_purgeable(self, item_id: ItemId, cutoff: datetime) -> Item | None:
        """See `ItemRepository.delete_if_purgeable`.

        One `BEGIN IMMEDIATE` transaction: select the row only if it is
        TRASHED with `trashed_us <= cutoff`, rebuild it (re-validated), then
        delete it. The write lock is held from the check to the delete, so a
        concurrent restore either commits first (no match) or waits.

        Raises:
            ValidationError: `cutoff` is naive/out of range, or the stored
                row is invalid (nothing is deleted: fail closed).
        """
        cutoff_us = _to_us(ensure_utc(cutoff, "cutoff"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                row = conn.execute(
                    _SELECT_PURGEABLE_BY_ID_SQL, (item_id, ItemState.TRASHED.value, cutoff_us)
                ).fetchone()
                if row is None:
                    return None
                item = self._load_item(conn, row)
                conn.execute(_DELETE_ITEM_SQL, (item_id,))
            return item
        finally:
            conn.close()

    def all_blob_ids(self) -> set[str]:
        """See `ItemRepository.all_blob_ids`."""
        conn = self._conn_factory()
        try:
            rows = conn.execute(_ALL_BLOB_IDS_SQL).fetchall()
            return {row[0] for row in rows}
        finally:
            conn.close()

    def usage(self) -> RepositoryUsage:
        """See `ItemRepository.usage`.

        Both aggregates come from one `SELECT` (each a correlated
        subquery), so they see the same consistent snapshot of the
        database — no separate `BEGIN` is needed for a single statement.
        """
        conn = self._conn_factory()
        try:
            item_count, total_bytes = conn.execute(_USAGE_SQL).fetchone()
            return RepositoryUsage(item_count=item_count, total_bytes=total_bytes)
        finally:
            conn.close()

    # --- adapter-specific maintenance (not part of the port) -------------------

    def compact(self, *, attempts: int = 10, delay_seconds: float = 0.05) -> bool:
        """Checkpoint the WAL into the DB and truncate the WAL file to zero bytes.

        Deleted rows are zeroed in the main file by `secure_delete`, but
        older page images stay in `-wal` until a TRUNCATE checkpoint
        (docs/security.md C24). Run as the purge job's `post_purge` hook.
        A checkpoint can't finish while another connection reads an older
        snapshot, so it is retried (bounded, linear backoff) and otherwise
        left to the next run.

        Returns:
            True if the WAL was fully checkpointed and truncated.
        """
        if attempts < 1 or delay_seconds < 0:
            raise ValueError("attempts must be >= 1 and delay_seconds >= 0")
        conn = self._conn_factory()
        try:
            conn.execute(_COMPACT_BUSY_TIMEOUT_SQL)
            for attempt in range(attempts):
                (busy, _log_frames, _done_frames) = conn.execute(
                    _CHECKPOINT_TRUNCATE_SQL
                ).fetchone()
                if busy == 0:
                    return True
                if attempt + 1 < attempts:
                    self._sleep(delay_seconds * (attempt + 1))
            return False
        finally:
            conn.close()

    # --- row <-> domain mapping ----------------------------------------------

    @staticmethod
    def _check_folder(conn: sqlite3.Connection, item: Item) -> None:
        """Refuse to file `item` into a missing folder (call inside `_writing`).

        The write lock is held until commit, so the folder can't be deleted
        in between; the foreign key would reject it anyway, but as an
        opaque `IntegrityError` instead of a `NotFoundError` (C41).
        """
        if (
            item.folder_id is not None
            and conn.execute(_FOLDER_EXISTS_SQL, (item.folder_id,)).fetchone() is None
        ):
            raise NotFoundError(f"folder {item.folder_id} not found")

    @staticmethod
    def _item_params(item: Item) -> _ItemRow:
        return (
            item.id,
            item.title,
            item.description,
            item.kind,
            item.entry_file,
            _to_us(item.created_at),
            _to_us(item.updated_at),
            int(item.pinned),
            item.state.value,
            _to_us(item.trashed_at) if item.trashed_at is not None else None,
            item.revision,
            item.folder_id,
        )

    @staticmethod
    def _insert_revisions(conn: sqlite3.Connection, item: Item) -> None:
        revisions = item.revisions
        conn.executemany(
            _INSERT_REVISION_SQL,
            [(item.id, r.number, r.kind, r.entry_file, _to_us(r.created_at)) for r in revisions],
        )
        conn.executemany(
            _INSERT_FILE_SQL,
            [
                (item.id, r.number, f.relpath, f.blob_id, f.size, f.sha256, f.media_type, position)
                for r in revisions
                for position, f in enumerate(r.files)
            ],
        )

    def _load_item(self, conn: sqlite3.Connection, row: _ItemRow) -> Item:
        """Rebuild one `Item` (and its files) from a row, re-validating every field.

        Raises:
            ValidationError: the row (or one of its files) fails a domain
                invariant — a tampered or corrupted row, never silently
                turned into a usable `Item`.
        """
        (
            id_,
            title,
            description,
            kind,
            entry_file,
            created_us,
            updated_us,
            pinned,
            state,
            trashed_us,
            head_number,
            folder_id,
        ) = row
        revisions = self._load_revisions(conn, id_)
        head = next((r for r in revisions if r.number == head_number), None)
        # The items row repeats the head's kind/entry file (for the kind
        # index); a row that disagrees with its head was tampered with.
        if head is None or head.kind != kind or head.entry_file != entry_file:
            raise ValidationError("stored item does not match its head revision")
        return Item(
            id=ItemId(id_),
            title=title,
            description=description,
            kind=head.kind,
            files=head.files,
            entry_file=head.entry_file,
            created_at=created_us_to_datetime(created_us),
            updated_at=created_us_to_datetime(updated_us),
            pinned=bool(pinned),
            state=_parse_state(state),
            trashed_at=created_us_to_datetime(trashed_us) if trashed_us is not None else None,
            revision=head.number,
            revision_at=head.created_at,
            # Anything numbered above the head is rejected by Item's ordering rule.
            history=tuple(r for r in revisions if r.number != head_number),
            folder_id=None if folder_id is None else FolderId(folder_id),
        )

    @staticmethod
    def _load_revisions(conn: sqlite3.Connection, item_id: str) -> builtins.list[Revision]:
        """Rebuild every stored revision of `item_id` (validated), oldest first."""
        files: dict[int, builtins.list[ItemFile]] = {}
        for number, relpath, blob_id, size, sha256, mt in conn.execute(
            _SELECT_FILES_SQL, (item_id,)
        ).fetchall():
            files.setdefault(number, []).append(
                ItemFile(relpath=relpath, blob_id=blob_id, size=size, sha256=sha256, media_type=mt)
            )
        return [
            Revision(
                number=number,
                kind=kind,
                files=tuple(files.get(number, ())),
                entry_file=entry_file,
                created_at=created_us_to_datetime(created_us),
            )
            for number, kind, entry_file, created_us in conn.execute(
                _SELECT_REVISIONS_SQL, (item_id,)
            ).fetchall()
        ]


def _padded_kinds(kinds: tuple[str, ...]) -> tuple[str, ...]:
    """`kinds` (1..MAX_QUERY_KINDS, validated by ItemQuery) padded to exactly
    MAX_QUERY_KINDS by repeating the last one; a repeat changes no result."""
    if not 0 < len(kinds) <= MAX_QUERY_KINDS:
        raise ValidationError(f"at most {MAX_QUERY_KINDS} kinds")
    return kinds + (kinds[-1],) * (MAX_QUERY_KINDS - len(kinds))
