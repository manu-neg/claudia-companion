"""Integration tests for revisions in SQLite: migration 2 and tamper checks (ADR 0019).

Migration 2 must turn every existing item into revision 1 without touching
its files or blobs, and a row whose head copies (`items.kind`,
`items.entry_file`, `items.revision`) disagree with the `revisions` table
must fail closed on read (docs/security.md C24).
"""

from __future__ import annotations

import functools
import hashlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import connection as connection_module
from preview_dashboard.adapters.sqlite import migrations
from preview_dashboard.adapters.sqlite.connection import connect, default_db_path
from preview_dashboard.adapters.sqlite.repository import SqliteItemRepository
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import ItemId
from tests.builders import T0, make_file, make_item, ulid

pytestmark = pytest.mark.integration

_US = 1_767_268_800_000_000  # T0 in epoch microseconds


@pytest.fixture
def v1_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A database created at schema version 1 (before revisions) with one bundle item."""
    db_path = default_db_path(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:1])
        patch.setattr(migrations, "CURRENT_VERSION", 1)
        patch.setattr(connection_module, "CURRENT_VERSION", 1)
        conn = connect(db_path)
        try:
            conn.execute(
                "INSERT INTO items (id, title, description, kind, entry_file, created_us, "
                "updated_us, pinned, state, trashed_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ulid(1), "Old", "", "html", "index.html", _US, _US + 5, 1, "active", None),
            )
            for position, (relpath, blob, media_type) in enumerate(
                [("index.html", 1, "text/html"), ("a.css", 2, "text/css")]
            ):
                conn.execute(
                    "INSERT INTO item_files (item_id, relpath, blob_id, size, sha256, "
                    "media_type, position) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        ulid(1),
                        relpath,
                        ulid(10_000 + blob),
                        len(relpath),
                        hashlib.sha256(relpath.encode()).hexdigest(),
                        media_type,
                        position,
                    ),
                )
            conn.commit()
            assert conn.execute("PRAGMA user_version").fetchone() == (1,)
        finally:
            conn.close()
    yield db_path


def test_migration_2_makes_existing_items_revision_1(v1_db: Path) -> None:
    repo = SqliteItemRepository(functools.partial(connect, v1_db))
    item = repo.get(ItemId(ulid(1)))
    assert item.revision == 1
    assert item.history == ()
    assert item.revision_at == item.created_at == T0
    assert [f.relpath for f in item.files] == ["index.html", "a.css"]
    assert repo.all_blob_ids() == {ulid(10_001), ulid(10_002)}
    conn = connect(v1_db)
    try:
        assert conn.execute("PRAGMA user_version").fetchone() == (migrations.CURRENT_VERSION,)
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        conn.close()


def test_migrated_item_accepts_a_new_revision(v1_db: Path) -> None:
    repo = SqliteItemRepository(functools.partial(connect, v1_db))
    item = repo.get(ItemId(ulid(1)))
    revised, _ = item.with_revision(
        kind="html",
        files=(make_file("index.html", blob=50),),
        entry_file="index.html",
        at=item.next_change_at(T0),
    )
    repo.save(revised, expected_updated_at=item.updated_at)
    assert repo.get(item.id) == revised
    assert repo.usage().total_bytes == revised.stored_size


def test_blob_ids_stay_globally_unique(tmp_path: Path) -> None:
    db_path = default_db_path(tmp_path)
    repo = SqliteItemRepository(functools.partial(connect, db_path))
    repo.add(make_item(1, files=(make_file(blob=7),)))
    with pytest.raises(sqlite3.IntegrityError):
        repo.add(make_item(2, files=(make_file(blob=7),)))


class TestTamperedRevisionRows:
    """The head copies in `items` must agree with `revisions`, else reads fail closed."""

    @pytest.fixture
    def stored(self, tmp_path: Path) -> tuple[Path, SqliteItemRepository, ItemId]:
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(functools.partial(connect, db_path))
        item = make_item(1)
        repo.add(item)
        revised, _ = item.with_revision(
            kind="html",
            files=(make_file("index.html", blob=50),),
            entry_file="index.html",
            at=item.next_change_at(T0),
        )
        repo.save(revised, expected_updated_at=item.updated_at)
        return db_path, repo, item.id

    def _tamper(self, db_path: Path, sql: str, params: tuple[object, ...]) -> None:
        conn = connect(db_path)
        try:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    @pytest.mark.parametrize(
        ("sql", "params"),
        [
            ("UPDATE items SET kind = 'markdown' WHERE id = ?", ()),
            ("UPDATE items SET entry_file = 'other.html' WHERE id = ?", ()),
            ("UPDATE items SET revision = 7 WHERE id = ?", ()),
            ("UPDATE items SET revision = 1 WHERE id = ?", ()),  # head below history
            ("UPDATE revisions SET created_us = 0 WHERE item_id = ? AND number = 2", ()),
            ("DELETE FROM item_files WHERE item_id = ? AND revision = 1", ()),
            ("UPDATE item_files SET relpath = '../x' WHERE item_id = ? AND revision = 1", ()),
        ],
    )
    def test_tampered_revision_rows_raise_on_read(
        self,
        stored: tuple[Path, SqliteItemRepository, ItemId],
        sql: str,
        params: tuple[object, ...],
    ) -> None:
        db_path, repo, item_id = stored
        self._tamper(db_path, sql, (item_id, *params))
        with pytest.raises(ValidationError):
            repo.get(item_id)
