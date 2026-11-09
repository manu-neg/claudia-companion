"""Integration tests for SqliteItemRepository: contract compliance plus adapter specifics.

Covers the shared-group permission model and its refusals, symlink/swap
refusal, migration idempotency, exact pragma values (WAL asserted),
re-validation of tampered rows, snapshot-consistent reads under churn,
`delete_if_purgeable`, compare-and-swap `save` under racing threads,
`compact()` WAL truncation, two-process concurrency
and pagination parity with the in-memory fake — guarantees docs/security.md
C11/C24/C28 require from the real SQLite adapter that the fake can't prove.
"""

from __future__ import annotations

import contextlib
import functools
import multiprocessing
import os
import random
import shutil
import sqlite3
import stat
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from multiprocessing import Queue
from pathlib import Path
from typing import Any

import pytest

from preview_dashboard.adapters.sqlite.connection import (
    DB_DIR_MODE,
    DB_FILE_MODE,
    JOURNAL_SIZE_LIMIT_BYTES,
    SIDECAR_SUFFIXES,
    DatabaseSetupError,
    UnsafeDatabasePathError,
    connect,
    default_db_path,
)
from preview_dashboard.adapters.sqlite.folders import SqliteFolderRepository
from preview_dashboard.adapters.sqlite.migrations import CURRENT_VERSION, migrate
from preview_dashboard.adapters.sqlite.repository import ConnectionFactory, SqliteItemRepository
from preview_dashboard.domain.errors import ConflictError, NotFoundError, ValidationError
from preview_dashboard.domain.models import ItemId, ItemState
from preview_dashboard.domain.query import ItemQuery
from tests.builders import T0, make_file, make_item, ulid
from tests.contracts.item_repository import ItemRepositoryContract
from tests.fakes import InMemoryItemRepository

pytestmark = pytest.mark.integration


def _conn_factory(db_path: Path) -> ConnectionFactory:
    return functools.partial(connect, db_path)


def _all_pages(repo: SqliteItemRepository | InMemoryItemRepository, **filters: object) -> list[str]:
    """Walk every page with a small limit; return the concatenated item ids."""
    ids: list[str] = []
    cursor: str | None = None
    for _ in range(1000):  # hard stop: a broken cursor must not hang the suite
        page = repo.list(ItemQuery(limit=7, cursor=cursor, **filters))  # type: ignore[arg-type]
        ids.extend(item.id for item in page.items)
        cursor = page.next_cursor
        if cursor is None:
            return ids
    raise AssertionError("pagination did not terminate")


class TestSqliteItemRepositoryContract(ItemRepositoryContract):
    """The shared repository contract must pass unchanged against SQLite."""

    @pytest.fixture
    def repo(self, tmp_path: Path) -> SqliteItemRepository:
        return SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))

    @pytest.fixture
    def folders(self, tmp_path: Path, repo: SqliteItemRepository) -> SqliteFolderRepository:
        return SqliteFolderRepository(_conn_factory(default_db_path(tmp_path)))


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


_ROOT = os.geteuid() == 0
_OTHER_ID = 54_321  # a uid/gid no test process runs as


class TestDatabaseCreation:
    """New `db/` and DB file get exact shared-group modes (C24/C28)."""

    def test_db_dir_created_2770_and_file_0660(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()
        assert _mode(db_path.parent) == DB_DIR_MODE == 0o2770
        assert _mode(db_path) == DB_FILE_MODE == 0o660

    def test_modes_are_umask_independent(self, tmp_path: Path) -> None:
        old = os.umask(0o077)
        try:
            db_path = default_db_path(tmp_path)
            connect(db_path).close()
        finally:
            os.umask(old)
        assert _mode(db_path.parent) == 0o2770
        assert _mode(db_path) == 0o660

    def test_sidecars_inherit_file_mode(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        conn = connect(db_path)
        try:
            SqliteItemRepository(_conn_factory(db_path)).add(make_item(1))
            for suffix in SIDECAR_SUFFIXES:
                sidecar = db_path.with_name(db_path.name + suffix)
                assert _mode(sidecar) & 0o007 == 0, suffix
        finally:
            conn.close()

    @pytest.mark.skipif(not _ROOT, reason="chown to a foreign group needs root")
    def test_new_entries_are_handed_to_the_trusted_group(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path, trusted_gid=_OTHER_ID).close()
        assert db_path.parent.stat().st_gid == _OTHER_ID
        assert db_path.stat().st_gid == _OTHER_ID

    @pytest.mark.skipif(_ROOT, reason="root may chown to any group")
    def test_refuses_when_group_cannot_be_set(self, tmp_path: Path) -> None:
        with pytest.raises(UnsafeDatabasePathError):
            connect(default_db_path(tmp_path), trusted_gid=_OTHER_ID)

    def test_missing_data_dir_is_not_created(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            connect(default_db_path(tmp_path / "missing"))

    def test_existing_safe_modes_are_left_untouched(self, tmp_path: Path) -> None:
        # Validation never rewrites existing entries (e.g. a 0600 file from a
        # restored backup stays 0600).
        db_path = default_db_path(tmp_path)
        connect(db_path).close()
        os.chmod(db_path, 0o600)
        os.chmod(db_path.parent, 0o700)
        connect(db_path).close()
        assert _mode(db_path) == 0o600
        assert _mode(db_path.parent) == 0o700


class TestUnsafeLocationRefused:
    """Existing entries outside the shared-group model are refused, not fixed."""

    @pytest.fixture
    def db_path(self, tmp_path: Path) -> Path:
        path = default_db_path(tmp_path)
        connect(path).close()  # last close removes -wal/-shm
        return path

    @pytest.mark.parametrize("mode", [0o644, 0o604, 0o662, 0o666, 0o601])
    def test_db_file_with_any_world_bit(self, db_path: Path, mode: int) -> None:
        os.chmod(db_path, mode)
        with pytest.raises(UnsafeDatabasePathError, match="database file"):
            connect(db_path)

    def test_db_file_group_writable_by_untrusted_group(self, db_path: Path) -> None:
        with pytest.raises(UnsafeDatabasePathError, match="group"):
            connect(db_path, trusted_gid=os.getegid() + 1)

    def test_db_file_group_readable_only_is_fine_for_any_group(self, db_path: Path) -> None:
        os.chmod(db_path, 0o640)
        os.chmod(db_path.parent, 0o2750)  # noqa: S103 - deliberately group-readable
        connect(db_path, trusted_gid=os.getegid() + 1).close()

    @pytest.mark.skipif(not _ROOT, reason="chown to a foreign uid needs root")
    def test_db_file_owned_by_untrusted_uid(self, db_path: Path) -> None:
        os.chown(db_path, _OTHER_ID, -1)
        with pytest.raises(UnsafeDatabasePathError, match="database file is owned"):
            connect(db_path)
        # ...and accepted once that uid is explicitly trusted (viewer setup).
        connect(db_path, trusted_uids={os.geteuid(), _OTHER_ID}).close()

    def test_untrusted_owner_of_the_layout(self, db_path: Path) -> None:
        with pytest.raises(UnsafeDatabasePathError, match="untrusted uid"):
            connect(db_path, trusted_uids={os.geteuid() + 1})

    @pytest.mark.parametrize("mode", [0o2775, 0o2771, 0o777, 0o705])
    def test_db_dir_with_any_world_bit(self, db_path: Path, mode: int) -> None:
        os.chmod(db_path.parent, mode)
        with pytest.raises(UnsafeDatabasePathError, match="db directory"):
            connect(db_path)

    def test_db_dir_group_writable_by_untrusted_group(self, db_path: Path) -> None:
        os.chmod(db_path, 0o600)
        with pytest.raises(UnsafeDatabasePathError, match="db directory"):
            connect(db_path, trusted_gid=os.getegid() + 1)

    def test_db_dir_symlink(self, tmp_path: Path) -> None:
        real = tmp_path / "elsewhere"
        real.mkdir(mode=0o700)
        os.symlink(real, tmp_path / "db")
        with pytest.raises(UnsafeDatabasePathError, match="real directory"):
            connect(default_db_path(tmp_path))

    def test_db_dir_is_a_file(self, tmp_path: Path) -> None:
        (tmp_path / "db").write_bytes(b"")
        with pytest.raises(UnsafeDatabasePathError, match="real directory"):
            connect(default_db_path(tmp_path))

    def test_world_writable_data_dir(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        data.mkdir()
        os.chmod(data, 0o777)  # noqa: S103 - the unsafe mode under test
        with pytest.raises(UnsafeDatabasePathError, match="data directory"):
            connect(default_db_path(data))

    def test_world_readable_data_dir_is_fine(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        data.mkdir()
        os.chmod(data, 0o755)  # noqa: S103 - world-readable data dir is allowed
        connect(default_db_path(data)).close()

    def test_symlinked_db_path_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.sqlite3"
        real.write_bytes(b"")
        link = tmp_path / "link.sqlite3"
        os.symlink(real, link)
        with pytest.raises(UnsafeDatabasePathError, match="symlink"):
            connect(link)

    def test_symlinked_db_path_refused_even_if_target_missing(self, tmp_path: Path) -> None:
        link = tmp_path / "dangling.sqlite3"
        os.symlink(tmp_path / "does-not-exist.sqlite3", link)
        with pytest.raises(UnsafeDatabasePathError):
            connect(link)
        assert not (tmp_path / "does-not-exist.sqlite3").exists()

    def test_fifo_at_db_path_refused(self, tmp_path: Path) -> None:
        os.mkfifo(tmp_path / "fifo.sqlite3", 0o600)
        with pytest.raises(UnsafeDatabasePathError, match="regular file"):
            connect(tmp_path / "fifo.sqlite3")

    @pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
    def test_sidecar_symlink(self, db_path: Path, suffix: str, tmp_path: Path) -> None:
        target = tmp_path / "target"
        target.write_bytes(b"")
        os.symlink(target, db_path.with_name(db_path.name + suffix))
        with pytest.raises(UnsafeDatabasePathError, match=suffix):
            connect(db_path)

    @pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
    def test_sidecar_with_world_bit(self, db_path: Path, suffix: str) -> None:
        sidecar = db_path.with_name(db_path.name + suffix)
        sidecar.write_bytes(b"")
        os.chmod(sidecar, 0o664)
        with pytest.raises(UnsafeDatabasePathError, match=suffix):
            connect(db_path)

    @pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
    def test_sidecar_group_writable_by_untrusted_group(self, db_path: Path, suffix: str) -> None:
        os.chmod(db_path, 0o600)
        os.chmod(db_path.parent, 0o700)
        sidecar = db_path.with_name(db_path.name + suffix)
        sidecar.write_bytes(b"")
        os.chmod(sidecar, 0o660)
        with pytest.raises(UnsafeDatabasePathError, match=suffix):
            connect(db_path, trusted_gid=os.getegid() + 1)

    def test_sidecar_fifo(self, db_path: Path) -> None:
        os.mkfifo(db_path.with_name(db_path.name + "-wal"), 0o600)
        with pytest.raises(UnsafeDatabasePathError, match="regular file"):
            connect(db_path)


class TestSwapDuringConnectRefused:
    """A `db/` or DB file swapped between validation and `sqlite3.connect` is refused."""

    def _patch_connect(
        self, monkeypatch: pytest.MonkeyPatch, before: Callable[[], None]
    ) -> list[sqlite3.Connection]:
        opened: list[sqlite3.Connection] = []
        real_connect = sqlite3.connect

        def swapping_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
            before()
            conn: sqlite3.Connection = real_connect(*args, **kwargs)
            opened.append(conn)
            return conn

        monkeypatch.setattr(sqlite3, "connect", swapping_connect)
        return opened

    def test_db_dir_swapped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()

        def swap() -> None:
            os.rename(db_path.parent, tmp_path / "db.old")
            db_path.parent.mkdir(mode=0o700)
            shutil.copy2(tmp_path / "db.old" / db_path.name, db_path)

        opened = self._patch_connect(monkeypatch, swap)
        with pytest.raises(UnsafeDatabasePathError, match="db directory was replaced"):
            connect(db_path)
        assert len(opened) == 1
        with pytest.raises(sqlite3.ProgrammingError):  # closed on refusal
            opened[0].execute("SELECT 1")

    def test_db_file_swapped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()

        def swap() -> None:
            os.rename(db_path, tmp_path / "old.sqlite3")
            shutil.copy2(tmp_path / "old.sqlite3", db_path)

        self._patch_connect(monkeypatch, swap)
        with pytest.raises(UnsafeDatabasePathError, match="database file was replaced"):
            connect(db_path)


class TestPragmas:
    def test_pragma_values(self, tmp_path: Path) -> None:
        conn = connect(default_db_path(tmp_path))
        try:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
            assert conn.execute("PRAGMA trusted_schema").fetchone()[0] == 0
            assert conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
            limit = conn.execute("PRAGMA journal_size_limit").fetchone()[0]
            assert limit == JOURNAL_SIZE_LIMIT_BYTES == 1024 * 1024
            assert conn.isolation_level is None
        finally:
            conn.close()

    def test_wal_refusal_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        class _NoWal(sqlite3.Connection):
            # Simulates SQLite silently keeping another journal mode.
            def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
                if sql == "PRAGMA journal_mode = WAL":
                    return super().execute("SELECT 'delete'")
                return super().execute(sql, parameters)

        real_connect = sqlite3.connect

        def no_wal_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
            return real_connect(*args, factory=_NoWal, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", no_wal_connect)
        with pytest.raises(DatabaseSetupError, match="WAL"):
            connect(default_db_path(tmp_path))

    def test_foreign_key_cascade_deletes_files(self, tmp_path: Path) -> None:
        repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        item = make_item(1)
        repo.add(item)
        repo.delete(item.id)
        conn = connect(default_db_path(tmp_path))
        try:
            rows = conn.execute("SELECT COUNT(*) FROM item_files").fetchone()
            assert rows[0] == 0
        finally:
            conn.close()


class TestMigrations:
    def test_migrations_set_user_version(self, tmp_path: Path) -> None:
        conn = connect(default_db_path(tmp_path))
        try:
            (version,) = conn.execute("PRAGMA user_version").fetchone()
            assert version == CURRENT_VERSION
        finally:
            conn.close()

    def test_migrate_is_idempotent(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        conn = connect(db_path)  # migrates once
        try:
            migrate(conn)  # no-op: already at CURRENT_VERSION
            migrate(conn)
            (version,) = conn.execute("PRAGMA user_version").fetchone()
            assert version == CURRENT_VERSION
            # Tables still exist exactly once (no duplicate-object errors).
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            assert {"items", "item_files"} <= tables
        finally:
            conn.close()

    def test_reopening_an_already_migrated_db_is_a_noop(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()
        conn = connect(db_path)  # second open: schema already current
        try:
            (version,) = conn.execute("PRAGMA user_version").fetchone()
            assert version == CURRENT_VERSION
        finally:
            conn.close()


class TestNoMigrateMode:
    """`connect(migrate=False)` (viewer, purge): never creates or changes the schema."""

    def test_missing_database_is_refused_and_not_created(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        with pytest.raises(DatabaseSetupError, match="does not exist yet"):
            connect(db_path, migrate=False)
        assert not db_path.parent.exists()
        db_path.parent.mkdir(mode=0o2770)
        with pytest.raises(DatabaseSetupError, match="does not exist yet"):
            connect(db_path, migrate=False)
        assert not db_path.exists()

    def test_current_schema_is_used_as_is(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()
        conn = connect(db_path, migrate=False)
        try:
            assert conn.execute("PRAGMA user_version").fetchone() == (CURRENT_VERSION,)
        finally:
            conn.close()

    @pytest.mark.parametrize("version", [0, CURRENT_VERSION + 1])
    def test_other_schema_versions_are_refused_untouched(
        self, tmp_path: Path, version: int
    ) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()
        raw = sqlite3.connect(db_path)
        raw.execute(f"PRAGMA user_version = {int(version)}")
        raw.close()
        with pytest.raises(DatabaseSetupError, match=f"version {version}"):
            connect(db_path, migrate=False)
        raw = sqlite3.connect(db_path)
        try:
            assert raw.execute("PRAGMA user_version").fetchone() == (version,)
        finally:
            raw.close()


class TestTamperedRows:
    """Rows written outside this module (raw SQL) must fail closed on read.

    `Item`/`ItemFile` are rebuilt through their constructors on every read
    (docs/security.md C24), so a row that bypasses domain validation is
    caught here rather than silently handed back as a usable item.
    """

    def _raw_conn(self, db_path: Path) -> sqlite3.Connection:
        conn = connect(db_path)  # ensures schema exists
        return conn

    def test_tampered_title_made_only_of_bidi_overrides_raises_on_read(
        self, tmp_path: Path
    ) -> None:
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(_conn_factory(db_path))
        item = make_item(1)
        repo.add(item)
        conn = self._raw_conn(db_path)
        try:
            # A title sanitize_title() strips down to nothing (only bidi
            # override characters, no visible content survives cleaning).
            conn.execute(
                "UPDATE items SET title = ? WHERE id = ?",
                (chr(0x202E) * 3, item.id),
            )
            conn.commit()
        finally:
            conn.close()
        with pytest.raises(ValidationError):
            repo.get(item.id)

    def test_tampered_relpath_with_traversal_raises_on_read(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(_conn_factory(db_path))
        item = make_item(1)
        repo.add(item)
        conn = self._raw_conn(db_path)
        try:
            conn.execute(
                "UPDATE item_files SET relpath = ? WHERE item_id = ?", ("../../etc/passwd", item.id)
            )
            conn.commit()
        finally:
            conn.close()
        with pytest.raises(ValidationError):
            repo.get(item.id)

    def test_tampered_active_item_with_trashed_us_raises_on_read(self, tmp_path: Path) -> None:
        # The DB CHECK constraint only constrains `state` and `pinned`
        # individually, not the cross-column invariant "trashed_us is set
        # iff state = 'trashed'" — that's a domain rule, re-checked here by
        # rebuilding through `Item(...)` (docs/security.md C24).
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(_conn_factory(db_path))
        item = make_item(1)
        repo.add(item)
        conn = self._raw_conn(db_path)
        try:
            conn.execute("UPDATE items SET trashed_us = ? WHERE id = ?", (0, item.id))
            conn.commit()
        finally:
            conn.close()
        with pytest.raises(ValidationError):
            repo.get(item.id)

    def test_state_check_constraint_rejects_invalid_state_at_the_db_layer(
        self, tmp_path: Path
    ) -> None:
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(_conn_factory(db_path))
        item = make_item(1)
        repo.add(item)
        conn = self._raw_conn(db_path)
        try:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("UPDATE items SET state = 'bogus' WHERE id = ?", (item.id,))
        finally:
            conn.close()


# --- pagination parity with the fake ----------------------------------------

_KINDS = ("image", "html", "video")


def _seed(repo: SqliteItemRepository | InMemoryItemRepository, rng: random.Random, n: int) -> None:
    for i in range(1, n + 1):
        offset = timedelta(seconds=rng.randint(-5_000, 5_000), microseconds=rng.randint(0, 999))
        created = T0 + offset
        item = make_item(
            i,
            created_at=created,
            updated_at=created,
            pinned=rng.random() < 0.2,
            kind=rng.choice(_KINDS),
        )
        if rng.random() < 0.3:
            item = item.trashed(created + timedelta(seconds=1))
        repo.add(item)


class TestPaginationParityWithFake:
    @pytest.mark.parametrize("seed", [0, 1, 20_260_924])
    def test_list_matches_fake_across_filters_and_pages(self, tmp_path: Path, seed: int) -> None:
        # A seeded PRNG (not used for anything security-sensitive, just
        # deterministic fixture data) driving two independent Random
        # instances from the same seed, so both repos get the same items.
        sql_repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        fake_repo = InMemoryItemRepository()
        _seed(sql_repo, random.Random(seed), 150)  # noqa: S311
        _seed(fake_repo, random.Random(seed), 150)  # noqa: S311

        for kind in (None, *_KINDS):
            for state in (ItemState.ACTIVE, ItemState.TRASHED):
                sql_ids = _all_pages(sql_repo, kind=kind, state=state)
                fake_ids = _all_pages(fake_repo, kind=kind, state=state)
                assert sql_ids == fake_ids, (kind, state)


# --- two-process concurrency -------------------------------------------------


def _mp_write(db_path: Path, start: int, count: int, queue: Queue[str]) -> None:
    try:
        repo = SqliteItemRepository(_conn_factory(db_path))
        for i in range(start, start + count):
            at = T0 + timedelta(microseconds=i)
            repo.add(make_item(i, created_at=at, updated_at=at))
        queue.put("ok")
    except Exception as exc:  # pragma: no cover - reported via the queue instead
        queue.put(f"error: {exc!r}")


def _mp_read(db_path: Path, iterations: int, queue: Queue[str]) -> None:
    try:
        repo = SqliteItemRepository(_conn_factory(db_path))
        for _ in range(iterations):
            repo.list(ItemQuery(limit=200))
        queue.put("ok")
    except Exception as exc:  # pragma: no cover - reported via the queue instead
        queue.put(f"error: {exc!r}")


class TestTwoProcessConcurrency:
    def test_two_writers_and_a_reader_hit_no_locking_errors(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        connect(db_path).close()  # pre-create + migrate before children race on it

        queue: Queue[str] = multiprocessing.Queue()
        procs = [
            multiprocessing.Process(target=_mp_write, args=(db_path, 1, 120, queue)),
            multiprocessing.Process(target=_mp_write, args=(db_path, 100_000, 120, queue)),
            multiprocessing.Process(target=_mp_read, args=(db_path, 40, queue)),
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)

        results = [queue.get(timeout=5) for _ in procs]
        assert results == ["ok"] * len(procs), results
        for p in procs:
            assert p.exitcode == 0

        repo = SqliteItemRepository(_conn_factory(db_path))
        all_ids = _all_pages(repo, state=ItemState.ACTIVE)
        assert len(all_ids) == 240
        assert len(set(all_ids)) == 240


# --- snapshot-consistent reads under concurrent churn ------------------------


def _churn(db_path: Path, seconds: float, queue: Queue[str]) -> None:
    """Add then delete the same trashed items in a tight loop (new blobs each round)."""
    try:
        repo = SqliteItemRepository(_conn_factory(db_path))
        deadline = time.monotonic() + seconds
        blob = 0
        while time.monotonic() < deadline:
            for n in range(1, 6):
                blob += 1
                repo.add(make_item(n, files=(make_file(blob=blob),)).trashed(T0))
            for n in range(1, 6):
                repo.delete(ItemId(ulid(n)))
        queue.put("ok")
    except Exception as exc:  # pragma: no cover - reported via the queue instead
        queue.put(f"error: {exc!r}")


class TestSnapshotReads:
    def test_reads_never_see_an_item_without_its_files(self, tmp_path: Path) -> None:
        # Regression: get/list/list_purgeable used to read the item row and
        # its file rows in separate implicit transactions, so a delete in
        # between surfaced as ValidationError("an item needs at least one file").
        db_path = default_db_path(tmp_path)
        connect(db_path).close()
        queue: Queue[str] = multiprocessing.Queue()
        writer = multiprocessing.Process(target=_churn, args=(db_path, 2.0, queue))
        writer.start()
        repo = SqliteItemRepository(_conn_factory(db_path))
        reads = 0
        try:
            while writer.is_alive():
                repo.list(ItemQuery(state=ItemState.TRASHED))
                repo.list_purgeable(T0 + timedelta(days=30), timedelta(days=1))
                for n in range(1, 6):
                    with contextlib.suppress(NotFoundError):
                        repo.get(ItemId(ulid(n)))
                reads += 1
        finally:
            writer.join(timeout=30)
        assert queue.get(timeout=5) == "ok"
        assert reads > 10


# --- delete_if_purgeable (adapter specifics beyond the contract) ------------


class TestDeleteIfPurgeable:
    def test_tampered_row_fails_closed_and_is_not_deleted(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(_conn_factory(db_path))
        item = make_item(1).trashed(T0)
        repo.add(item)
        conn = connect(db_path)
        try:
            conn.execute("UPDATE item_files SET relpath = ? WHERE item_id = ?", ("../x", item.id))
        finally:
            conn.close()
        with pytest.raises(ValidationError):
            repo.delete_if_purgeable(item.id, T0)
        conn = connect(db_path)
        try:
            assert conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 1
        finally:
            conn.close()

    def test_naive_cutoff_rejected(self, tmp_path: Path) -> None:
        repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        with pytest.raises(ValidationError):
            repo.delete_if_purgeable(ItemId(ulid(1)), datetime(2026, 1, 1))


class TestOptimisticConcurrency:
    """`save` is a compare-and-swap even with real concurrent writers (C11)."""

    def test_racing_writers_on_same_version_exactly_one_wins(self, tmp_path: Path) -> None:
        repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        item = make_item(1)
        repo.add(item)
        writers = 8
        barrier = threading.Barrier(writers)
        wins: list[int] = []
        conflicts: list[int] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def write(n: int) -> None:
            try:
                current = repo.get(item.id)
                barrier.wait(timeout=10)  # everyone holds the same version
                changed = current.with_metadata(now=T0 + timedelta(seconds=n + 1), title=f"w{n}")
                try:
                    repo.save(changed, expected_updated_at=current.updated_at)
                except ConflictError:
                    with lock:
                        conflicts.append(n)
                else:
                    with lock:
                        wins.append(n)
            except BaseException as exc:  # surfaced below, never swallowed
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert errors == []
        assert len(wins) == 1
        assert len(conflicts) == writers - 1
        assert repo.get(item.id).title == f"w{wins[0]}"

    def test_update_sql_is_conditional_on_version(self, tmp_path: Path) -> None:
        # Tamper the stored version directly: a save with the old one must fail.
        db_path = default_db_path(tmp_path)
        repo = SqliteItemRepository(_conn_factory(db_path))
        item = make_item(1)
        repo.add(item)
        conn = connect(db_path)
        try:
            conn.execute("UPDATE items SET updated_us = updated_us + 1 WHERE id = ?", (item.id,))
            conn.commit()
        finally:
            conn.close()
        with pytest.raises(ConflictError):
            repo.save(
                item.with_metadata(now=T0 + timedelta(hours=1), title="x"),
                expected_updated_at=item.updated_at,
            )
        assert repo.get(item.id).title == item.title


class TestPurgeCutoffOverflow:
    def test_cutoff_below_datetime_min_is_a_validation_error(self, tmp_path: Path) -> None:
        repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        with pytest.raises(ValidationError, match="out of range"):
            repo.list_purgeable(datetime.min.replace(tzinfo=UTC), timedelta(days=1))

    def test_cutoff_above_datetime_max_is_a_validation_error(self, tmp_path: Path) -> None:
        repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        with pytest.raises(ValidationError, match="out of range"):
            repo.list_purgeable(datetime.max.replace(tzinfo=UTC), timedelta(days=-1))


# --- compact(): WAL checkpoint + truncate ------------------------------------

_MARKER = "PDASH-DELETED-MARKER-7f3a9c"


class TestCompact:
    def test_deleted_content_is_gone_from_wal_after_compact(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        wal = db_path.with_name(db_path.name + "-wal")
        keeper = connect(db_path)  # idle: keeps -wal from being removed on close
        try:
            repo = SqliteItemRepository(_conn_factory(db_path))
            item = make_item(1, title=f"T {_MARKER}", description=_MARKER)
            repo.add(item)
            repo.delete(item.id)
            assert _MARKER.encode() in wal.read_bytes()  # precondition: residue exists
            assert repo.compact() is True
            assert _MARKER.encode() not in wal.read_bytes()
            assert wal.stat().st_size == 0
            assert _MARKER.encode() not in db_path.read_bytes()  # secure_delete
        finally:
            keeper.close()

    def test_bounded_retry_while_a_reader_holds_an_old_snapshot(self, tmp_path: Path) -> None:
        db_path = default_db_path(tmp_path)
        sleeps: list[float] = []
        repo = SqliteItemRepository(_conn_factory(db_path), sleep=sleeps.append)
        repo.add(make_item(1))
        reader = connect(db_path)
        try:
            reader.execute("BEGIN")
            reader.execute("SELECT COUNT(*) FROM items").fetchone()
            repo.add(make_item(2))
            assert repo.compact(attempts=3, delay_seconds=0.01) is False
            assert len(sleeps) == 2  # no sleep after the last attempt
            reader.rollback()
            assert repo.compact(attempts=3, delay_seconds=0.01) is True
        finally:
            reader.close()

    @pytest.mark.parametrize(("attempts", "delay"), [(0, 0.1), (1, -1.0)])
    def test_invalid_arguments(self, tmp_path: Path, attempts: int, delay: float) -> None:
        repo = SqliteItemRepository(_conn_factory(default_db_path(tmp_path)))
        with pytest.raises(ValueError, match="attempts"):
            repo.compact(attempts=attempts, delay_seconds=delay)
