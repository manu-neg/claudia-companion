"""Integration tests for folders in SQLite: contract, migration 4, tamper checks, FK backstop.

Migration 4 must leave every existing item unfiled and untouched; a tampered
folder row must fail closed on `get` but be skipped (not raised) by `list`
(docs/security.md C24, C39); the `items.folder_id` foreign key must refuse
dangling references and the deletion of a referenced folder even for raw SQL
(C41); and folder-filtered listings must use their index.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import sqlite3
import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import connection as connection_module
from preview_dashboard.adapters.sqlite import migrations
from preview_dashboard.adapters.sqlite import repository as repository_module
from preview_dashboard.adapters.sqlite.connection import (
    DatabaseSetupError,
    connect,
    default_db_path,
)
from preview_dashboard.adapters.sqlite.folders import SqliteFolderRepository
from preview_dashboard.adapters.sqlite.repository import ConnectionFactory, SqliteItemRepository
from preview_dashboard.domain.errors import (
    ConflictError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.folders import MAX_FOLDERS, UNFILED
from preview_dashboard.domain.models import ItemId, ItemState
from preview_dashboard.domain.query import ItemQuery
from tests.builders import T0, folder_id, make_folder, make_item, ulid
from tests.contracts.folder_repository import FolderRepositoryContract, FolderStore

pytestmark = pytest.mark.integration

_US = 1_767_268_800_000_000  # T0 in epoch microseconds


def _factory(db_path: Path, *, migrate: bool = True) -> ConnectionFactory:
    return functools.partial(connect, db_path, migrate=migrate)


def _corrupt_name_key(db_path: Path, fid: str) -> None:
    # A name_key that disagrees with its name is the smallest possible tamper.
    _raw(db_path, "UPDATE folders SET name_key = 'not-the-real-key' WHERE id = ?", (fid,))


def _store(db_path: Path) -> FolderStore:
    factory = _factory(db_path)
    return FolderStore(
        items=SqliteItemRepository(factory),
        folders=SqliteFolderRepository(factory),
        corrupt_folder=functools.partial(_corrupt_name_key, db_path),
    )


def _raw(db_path: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    """Write through a plain connection with foreign keys OFF (a tampering process)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = default_db_path(tmp_path)
    connect(path).close()  # create + migrate once, like the admin at startup
    return path


class TestSqliteFolderRepositoryContract(FolderRepositoryContract):
    @pytest.fixture
    def store(self, db_path: Path) -> FolderStore:
        return _store(db_path)


# --- migration 4 ----------------------------------------------------------------


@pytest.fixture
def v3_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A database at schema version 3 (before folders): one active and one trashed item."""
    path = default_db_path(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:3])
        patch.setattr(migrations, "CURRENT_VERSION", 3)
        patch.setattr(connection_module, "CURRENT_VERSION", 3)
        conn = connect(path)
        try:
            # Raw rows in the v3 shape: today's repository writes `folder_id`.
            for n, state, trashed_us, pinned in ((1, "active", None, 1), (2, "trashed", _US, 0)):
                conn.execute(
                    "INSERT INTO items (id, title, description, kind, entry_file, created_us, "
                    "updated_us, pinned, state, trashed_us, revision) "
                    "VALUES (?, ?, '', 'html', 'index.html', ?, ?, ?, ?, ?, 1)",
                    (ulid(n), f"Item {n}", _US, _US, pinned, state, trashed_us),
                )
                conn.execute(
                    "INSERT INTO revisions (item_id, number, kind, entry_file, created_us) "
                    "VALUES (?, 1, 'html', 'index.html', ?)",
                    (ulid(n), _US),
                )
                conn.execute(
                    "INSERT INTO item_files (item_id, revision, relpath, blob_id, size, sha256, "
                    "media_type, position) VALUES (?, 1, 'index.html', ?, 10, ?, 'text/html', 0)",
                    (ulid(n), ulid(10_000 + n), hashlib.sha256(b"x").hexdigest()),
                )
            conn.commit()
            assert conn.execute("PRAGMA user_version").fetchone() == (3,)
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master").fetchall()}
            assert "folders" not in tables
        finally:
            conn.close()
    yield path


class TestMigration4:
    def test_migration_4_is_registered(self) -> None:
        # Later migrations (5: Claudia inbox/approvals) build on it; the version only grows.
        assert [v for v, _ in migrations._MIGRATIONS][:4] == [1, 2, 3, 4]
        assert migrations.CURRENT_VERSION >= 4

    def test_v3_items_become_unfiled_and_unchanged(self, v3_db: Path) -> None:
        store = _store(v3_db)  # the admin's connect() migrates
        active = store.items.get(ItemId(ulid(1)))
        trashed = store.items.get(ItemId(ulid(2)))
        assert active.folder_id is None
        assert active.pinned is True
        assert active.created_at == T0
        assert trashed.folder_id is None
        assert trashed.state is ItemState.TRASHED
        assert store.items.all_blob_ids() == {ulid(10_001), ulid(10_002)}
        assert store.folders.list() == []
        counts = store.folders.counts(ItemState.ACTIVE)
        assert counts.unfiled == 1
        assert [i.id for i in store.items.list(ItemQuery(folder=UNFILED)).items] == [ulid(1)]
        conn = connect(v3_db)
        try:
            assert conn.execute("PRAGMA user_version").fetchone() == (migrations.CURRENT_VERSION,)
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
            assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master").fetchall()}
            assert "idx_items_folder_order" in indexes
        finally:
            conn.close()

    def test_migrated_items_can_be_filed(self, v3_db: Path) -> None:
        store = _store(v3_db)
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        item = store.items.get(ItemId(ulid(1)))
        moved = item.moved_to(folder_id(1), at=item.next_change_at(T0))
        store.items.save(moved, expected_updated_at=item.updated_at)
        assert store.items.get(item.id) == moved
        with pytest.raises(ConflictError):
            store.folders.delete_if_empty(folder_id(1))

    def test_no_migrate_roles_refuse_a_v3_database_untouched(self, v3_db: Path) -> None:
        with pytest.raises(DatabaseSetupError, match="version 3"):
            connect(v3_db, migrate=False)
        raw = sqlite3.connect(v3_db)
        try:
            assert raw.execute("PRAGMA user_version").fetchone() == (3,)
            columns = {r[1] for r in raw.execute("PRAGMA table_info(items)").fetchall()}
            assert "folder_id" not in columns
        finally:
            raw.close()

    def test_viewer_connections_read_folders(self, db_path: Path) -> None:
        admin = _store(db_path)
        admin.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        admin.items.add(make_item(1, folder_id=folder_id(1)))
        factory = _factory(db_path, migrate=False)
        viewer_folders = SqliteFolderRepository(factory)
        viewer_items = SqliteItemRepository(factory)
        assert viewer_folders.list() == [make_folder(1)]
        assert viewer_folders.counts(ItemState.ACTIVE).by_folder == {folder_id(1): 1}
        # A viewer write (pin) keeps the folder.
        item = viewer_items.get(ItemId(ulid(1)))
        pinned = item.with_metadata(now=item.next_change_at(T0), pinned=True)
        viewer_items.save(pinned, expected_updated_at=item.updated_at)
        assert viewer_items.get(item.id).folder_id == folder_id(1)


# --- foreign key backstop (C41) ---------------------------------------------------


class TestForeignKeyBackstop:
    """Even SQL that skips the repositories' checks can't break referential integrity."""

    def test_raw_insert_with_missing_folder_is_refused(self, db_path: Path) -> None:
        conn = connect(db_path)
        try:
            with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
                conn.execute(
                    "INSERT INTO items (id, title, description, kind, entry_file, created_us, "
                    "updated_us, pinned, state, trashed_us, revision, folder_id) "
                    "VALUES (?, 't', '', 'html', 'index.html', 0, 0, 0, 'active', NULL, 1, ?)",
                    (ulid(1), folder_id(404)),
                )
        finally:
            conn.close()

    def test_raw_delete_of_a_referenced_folder_is_refused(self, db_path: Path) -> None:
        store = _store(db_path)
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=folder_id(1)).trashed(T0))
        conn = connect(db_path)
        try:
            with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
                conn.execute("DELETE FROM folders WHERE id = ?", (folder_id(1),))
        finally:
            conn.close()
        assert store.folders.get(folder_id(1)) == make_folder(1)

    def test_backstop_maps_to_domain_errors(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With the explicit checks disabled, the FK alone still fails closed.
        store = _store(db_path)
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=folder_id(1)))
        from preview_dashboard.adapters.sqlite import folders as folders_module

        monkeypatch.setattr(folders_module, "_FOLDER_IN_USE_SQL", "SELECT 1 WHERE 0 AND ?")
        with pytest.raises(ConflictError):
            store.folders.delete_if_empty(folder_id(1))
        assert store.folders.get(folder_id(1)) == make_folder(1)

    def test_concurrent_moves_and_delete_never_dangle(self, db_path: Path) -> None:
        store = _store(db_path)
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        items = [make_item(n) for n in range(1, 9)]
        for item in items:
            store.items.add(item)
        outcomes: list[str] = []
        barrier = threading.Barrier(len(items) + 1)

        def move(n: int) -> None:
            item = items[n]
            barrier.wait()
            try:
                store.items.save(
                    item.moved_to(folder_id(1), at=T0 + timedelta(seconds=1)),
                    expected_updated_at=item.updated_at,
                )
                outcomes.append("moved")
            except NotFoundError:
                outcomes.append("missing")

        def delete() -> None:
            barrier.wait()
            try:
                store.folders.delete_if_empty(folder_id(1))
                outcomes.append("deleted")
            except ConflictError:
                outcomes.append("kept")

        threads = [threading.Thread(target=move, args=(n,)) for n in range(len(items))]
        threads.append(threading.Thread(target=delete))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        conn = connect(db_path)
        try:
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        finally:
            conn.close()
        moved = outcomes.count("moved")
        if "deleted" in outcomes:
            # Every move after the delete failed; any before it would have blocked it.
            assert moved == 0
        else:
            assert moved >= 1
        assert moved + outcomes.count("missing") == len(items)


# --- tampered rows (C24) ------------------------------------------------------------


class TestTamperedFolderRows:
    @pytest.fixture
    def stored(self, db_path: Path) -> FolderStore:
        store = _store(db_path)
        store.folders.add(make_folder(1, name="Plans"), max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=folder_id(1)))
        return store

    @pytest.mark.parametrize(
        ("sql", "params"),
        [
            ("UPDATE folders SET name = ? WHERE id = ?", ("\u200b\u202e", folder_id(1))),
            ("UPDATE folders SET name = ? WHERE id = ?", ("x" * 81, folder_id(1))),
            ("UPDATE folders SET name_key = ? WHERE id = ?", ("other", folder_id(1))),
            ("UPDATE folders SET updated_us = ? WHERE id = ?", (_US - 1, folder_id(1))),
        ],
    )
    def test_tampered_folder_get_fails_closed_list_skips_it(
        self,
        db_path: Path,
        stored: FolderStore,
        sql: str,
        params: tuple[object, ...],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        _raw(db_path, sql, params)
        with pytest.raises(ValidationError):
            stored.folders.get(folder_id(1))
        # list() must not go down with one bad row (backlog 6.4 item 1):
        # /api/folders and every item listing that renders `folder` depend on it.
        with caplog.at_level(logging.WARNING):
            assert stored.folders.list() == []
        assert folder_id(1) in caplog.text
        assert "Plans" not in caplog.text  # the name is never logged

    def test_tampered_folder_id_on_an_item_fails_closed(
        self, db_path: Path, stored: FolderStore
    ) -> None:
        # Foreign keys are off on the tampering connection.
        _raw(db_path, "UPDATE items SET folder_id = 'not-a-ulid' WHERE id = ?", (ulid(1),))
        with pytest.raises(ValidationError):
            stored.items.get(ItemId(ulid(1)))

    def test_sanitized_name_is_returned_for_invisible_padding(
        self, db_path: Path, stored: FolderStore
    ) -> None:
        # Like titles: invisible chars in a stored name are removed on read.
        _raw(db_path, "UPDATE folders SET name = ? WHERE id = ?", ("Pl\u200bans", folder_id(1)))
        assert stored.folders.get(folder_id(1)).name == "Plans"


# --- query plans --------------------------------------------------------------------


class TestFolderQueryPlans:
    @pytest.mark.parametrize(
        "sql",
        [
            repository_module._LIST_FOLDER_SQL,
            repository_module._LIST_FOLDER_CURSOR_SQL,
            repository_module._LIST_FOLDER_KIND_SQL,
            repository_module._LIST_FOLDER_KIND_CURSOR_SQL,
        ],
    )
    def test_folder_listings_use_the_folder_index(self, db_path: Path, sql: str) -> None:
        conn = connect(db_path)
        try:
            params = [None] * sql.count("?")
            plan = " ".join(
                str(row[-1]) for row in conn.execute(f"EXPLAIN QUERY PLAN {sql}", params)
            )
        finally:
            conn.close()
        assert "idx_items_folder_order" in plan
        assert "TEMP B-TREE" not in plan  # ordered by the index, no sort step

    def test_emptiness_check_uses_the_folder_index(self, db_path: Path) -> None:
        from preview_dashboard.adapters.sqlite import folders as folders_module

        conn = connect(db_path)
        try:
            plan = " ".join(
                str(row[-1])
                for row in conn.execute(
                    f"EXPLAIN QUERY PLAN {folders_module._FOLDER_IN_USE_SQL}", (folder_id(1),)
                )
            )
        finally:
            conn.close()
        assert "idx_items_folder_order" in plan
