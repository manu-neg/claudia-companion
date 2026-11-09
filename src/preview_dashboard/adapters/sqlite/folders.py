"""SqliteFolderRepository: the `FolderRepository` port backed by SQLite (ADR 0027).

Same rules as `repository.py` (docs/security.md C24): one connection per
call, `BEGIN IMMEDIATE` writers, every value bound as a parameter, every SQL
text a module-level constant, and every row rebuilt through `Folder(...)`
on read. Quota, name uniqueness and "only empty folders are deleted" are
checked inside the write transaction (C39, C41); the UNIQUE `name_key` and
the `items.folder_id` foreign key (`ON DELETE RESTRICT`) are the backstops.
`rename` is a compare-and-swap on `updated_us`, like `SqliteItemRepository.save`.
"""

from __future__ import annotations

import builtins
import logging
import sqlite3
from datetime import datetime

from preview_dashboard.adapters.sqlite.repository import (
    ConnectionFactory,
    _reading,
    _to_us,
    _writing,
)
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    LimitExceededError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.folders import Folder, FolderId
from preview_dashboard.domain.models import ItemState, ensure_utc, is_ulid
from preview_dashboard.domain.query import created_us_to_datetime
from preview_dashboard.ports.folders import FolderCounts

_log = logging.getLogger(__name__)

_COUNT_FOLDERS_SQL = "SELECT COUNT(*) FROM folders"
_FOLDER_ID_EXISTS_SQL = "SELECT 1 FROM folders WHERE id = ?"
_NAME_KEY_TAKEN_SQL = "SELECT 1 FROM folders WHERE name_key = ? AND id <> ?"
_INSERT_FOLDER_SQL = (
    "INSERT INTO folders (id, name, name_key, created_us, updated_us) VALUES (?, ?, ?, ?, ?)"
)
_SELECT_FOLDER_SQL = "SELECT id, name, name_key, created_us, updated_us FROM folders WHERE id = ?"
_LIST_FOLDERS_SQL = (
    "SELECT id, name, name_key, created_us, updated_us FROM folders ORDER BY name_key, id"
)
# Compare-and-swap on updated_us (optimistic concurrency, like item `save`).
_RENAME_FOLDER_SQL = (
    "UPDATE folders SET name = ?, name_key = ?, updated_us = ? WHERE id = ? AND updated_us = ?"
)
# Any state: a trashed item keeps its folder and goes back there on restore.
_FOLDER_IN_USE_SQL = "SELECT 1 FROM items WHERE folder_id = ? LIMIT 1"
_DELETE_FOLDER_SQL = "DELETE FROM folders WHERE id = ?"
_COUNT_BY_FOLDER_SQL = (
    "SELECT f.id, (SELECT COUNT(*) FROM items i WHERE i.folder_id = f.id AND i.state = ?) "
    "FROM folders f"
)
_COUNT_UNFILED_SQL = "SELECT COUNT(*) FROM items WHERE folder_id IS NULL AND state = ?"

_FolderRow = tuple[str, str, str, int, int]


class SqliteFolderRepository:
    """`FolderRepository` over SQLite (see `ports.folders.FolderRepository`).

    Shares the database (and so the transactions' write lock) with
    `SqliteItemRepository`; pass it the same `conn_factory`.
    """

    def __init__(self, conn_factory: ConnectionFactory) -> None:
        self._conn_factory = conn_factory

    def add(self, folder: Folder, *, max_folders: int) -> None:
        """See `FolderRepository.add`."""
        conn = self._conn_factory()
        try:
            with _writing(conn):
                (count,) = conn.execute(_COUNT_FOLDERS_SQL).fetchone()
                if count >= max_folders:
                    raise LimitExceededError(f"folder quota reached (max {max_folders})")
                if conn.execute(_FOLDER_ID_EXISTS_SQL, (folder.id,)).fetchone() is not None:
                    raise AlreadyExistsError(f"folder {folder.id} already exists")
                self._check_name_free(conn, folder)
                try:
                    conn.execute(
                        _INSERT_FOLDER_SQL,
                        (
                            folder.id,
                            folder.name,
                            folder.name_key,
                            _to_us(folder.created_at),
                            _to_us(folder.updated_at),
                        ),
                    )
                except sqlite3.IntegrityError as exc:  # backstop: UNIQUE / PRIMARY KEY
                    raise AlreadyExistsError("folder already exists") from exc
        finally:
            conn.close()

    def get(self, folder_id: FolderId) -> Folder:
        """See `FolderRepository.get`."""
        conn = self._conn_factory()
        try:
            row = conn.execute(_SELECT_FOLDER_SQL, (folder_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            raise NotFoundError(f"folder {folder_id} not found")
        return _load_folder(row)

    def list(self) -> builtins.list[Folder]:
        """See `FolderRepository.list`.

        A row that fails re-validation is skipped (logged by id only, never
        by name): one tampered row must not take `/api/folders` (and every
        item listing that renders `folder`) down with it. `counts()` is
        unaffected — it never rebuilds a `Folder`, only counts by id.
        """
        conn = self._conn_factory()
        try:
            rows = conn.execute(_LIST_FOLDERS_SQL).fetchall()
        finally:
            conn.close()
        folders: builtins.list[Folder] = []
        for row in rows:
            try:
                folders.append(_load_folder(row))
            except ValidationError:
                _log.warning("skipping invalid folder row %s", _log_id(row[0]))
        return folders

    def rename(self, folder: Folder, *, expected_updated_at: datetime) -> None:
        """See `FolderRepository.rename`."""
        expected_us = _to_us(ensure_utc(expected_updated_at, "expected_updated_at"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                self._check_name_free(conn, folder)
                try:
                    cur = conn.execute(
                        _RENAME_FOLDER_SQL,
                        (
                            folder.name,
                            folder.name_key,
                            _to_us(folder.updated_at),
                            folder.id,
                            expected_us,
                        ),
                    )
                except sqlite3.IntegrityError as exc:  # backstop: UNIQUE name_key
                    raise AlreadyExistsError("a folder with that name already exists") from exc
                if cur.rowcount == 0:
                    if conn.execute(_FOLDER_ID_EXISTS_SQL, (folder.id,)).fetchone() is None:
                        raise NotFoundError(f"folder {folder.id} not found")
                    raise ConflictError(f"folder {folder.id} was changed concurrently")
        finally:
            conn.close()

    def delete_if_empty(self, folder_id: FolderId) -> None:
        """See `FolderRepository.delete_if_empty`.

        Check and delete run under one write lock, so an item filed (or
        published) into the folder concurrently either commits first (then
        the folder is not empty) or waits and then fails its own folder check.
        """
        conn = self._conn_factory()
        try:
            with _writing(conn):
                if conn.execute(_FOLDER_ID_EXISTS_SQL, (folder_id,)).fetchone() is None:
                    raise NotFoundError(f"folder {folder_id} not found")
                if conn.execute(_FOLDER_IN_USE_SQL, (folder_id,)).fetchone() is not None:
                    raise ConflictError("folder is not empty (active or trashed items)")
                try:
                    conn.execute(_DELETE_FOLDER_SQL, (folder_id,))
                except sqlite3.IntegrityError as exc:  # backstop: ON DELETE RESTRICT
                    raise ConflictError("folder is not empty") from exc
        finally:
            conn.close()

    def counts(self, state: ItemState) -> FolderCounts:
        """See `FolderRepository.counts` (both counts from one read snapshot)."""
        conn = self._conn_factory()
        try:
            with _reading(conn):
                by_folder = {
                    FolderId(folder_id): count
                    for folder_id, count in conn.execute(
                        _COUNT_BY_FOLDER_SQL, (state.value,)
                    ).fetchall()
                }
                (unfiled,) = conn.execute(_COUNT_UNFILED_SQL, (state.value,)).fetchone()
        finally:
            conn.close()
        return FolderCounts(by_folder=by_folder, unfiled=unfiled)

    @staticmethod
    def _check_name_free(conn: sqlite3.Connection, folder: Folder) -> None:
        # Explicit check for a clear error; the UNIQUE index is the backstop.
        if conn.execute(_NAME_KEY_TAKEN_SQL, (folder.name_key, folder.id)).fetchone() is not None:
            raise AlreadyExistsError("a folder with that name already exists")


def _log_id(raw: object) -> str:
    """A row id safe to log: the id itself if canonical, else a placeholder (tampered)."""
    return str(raw) if is_ulid(raw) else "<malformed id>"


def _load_folder(row: _FolderRow) -> Folder:
    """Rebuild one `Folder` from a row, re-validating every field.

    Raises:
        ValidationError: the row fails a domain invariant, or its stored
            `name_key` is not the key of its name (a tampered row could
            otherwise dodge the uniqueness rule).
    """
    folder_id, name, name_key, created_us, updated_us = row
    folder = Folder(
        id=FolderId(folder_id),
        name=name,
        created_at=created_us_to_datetime(created_us),
        updated_at=created_us_to_datetime(updated_us),
    )
    if folder.name_key != name_key:
        raise ValidationError("stored folder name does not match its key")
    return folder
