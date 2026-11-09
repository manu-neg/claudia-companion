"""Integration tests for S-C1 S8: `migrate()` refuses a schema newer than this code.

Old code after a rollback without the backup restore must not run against
(or write to) a newer database. Checked before and under `BEGIN IMMEDIATE`.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import migrations
from preview_dashboard.adapters.sqlite.connection import (
    DatabaseSetupError,
    connect,
    default_db_path,
)

pytestmark = pytest.mark.integration


def _raw(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, isolation_level=None)


def _version(path: Path) -> int:
    raw = _raw(path)
    try:
        (version,) = raw.execute("PRAGMA user_version").fetchone()
    finally:
        raw.close()
    return int(version)


@pytest.fixture
def newer_db(tmp_path: Path) -> Path:
    path = default_db_path(tmp_path)
    connect(path).close()
    raw = _raw(path)
    try:
        raw.execute(f"PRAGMA user_version = {migrations.CURRENT_VERSION + 1}")
    finally:
        raw.close()
    return path


def test_s8_connect_refuses_a_newer_schema(newer_db: Path) -> None:
    with pytest.raises(DatabaseSetupError, match="newer than this code"):
        connect(newer_db)
    assert _version(newer_db) == migrations.CURRENT_VERSION + 1


def test_s8_migrate_refuses_a_newer_schema_directly(newer_db: Path) -> None:
    raw = _raw(newer_db)
    try:
        with pytest.raises(DatabaseSetupError):
            migrations.migrate(raw)
        assert not raw.in_transaction
    finally:
        raw.close()


def test_s8_no_migrate_roles_refuse_it_too(newer_db: Path) -> None:
    with pytest.raises(DatabaseSetupError, match="version"):
        connect(newer_db, migrate=False)


def test_s8_newer_schema_seen_only_under_the_lock_is_refused(tmp_path: Path) -> None:
    # Another process migrates between our first check and BEGIN IMMEDIATE.
    path = default_db_path(tmp_path)
    connect(path).close()
    raw = _raw(path)
    try:
        raw.execute("PRAGMA user_version = 0")
        newer = migrations.CURRENT_VERSION + 1
        reads = iter([0, newer])

        class _Racing:
            """A connection whose two `user_version` reads see 0, then a newer version."""

            def __init__(self, inner: sqlite3.Connection) -> None:
                self.inner = inner

            def execute(self, sql: str) -> object:
                if sql == "PRAGMA user_version":
                    value = next(reads)
                    return _Row((value,))
                return self.inner.execute(sql)

            def commit(self) -> None:
                self.inner.commit()

            def rollback(self) -> None:
                self.inner.rollback()

        with pytest.raises(DatabaseSetupError, match="newer than this code"):
            migrations.migrate(_Racing(raw))  # type: ignore[arg-type]
        assert not raw.in_transaction  # rolled back, nothing applied
    finally:
        raw.close()


class _Row:
    def __init__(self, row: tuple[int]) -> None:
        self._row = row

    def fetchone(self) -> tuple[int]:
        return self._row
