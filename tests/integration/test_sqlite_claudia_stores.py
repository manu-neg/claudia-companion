"""Integration tests for the SQLite owner-message and approval stores (ADR 0031, S-C1 S1).

Runs both port contracts against the admin-only Claudia database, then what
only a real database can show: its own schema 1 (created by the admin role
only, idempotent, all-or-nothing on a crash, purge-role connections refuse a
missing or stale file), the shared item DB no longer holding these tables,
CAS races between threads (first writer wins, C44, C46), the
one-open-request-per-window rule under concurrency, and index use.
"""

from __future__ import annotations

import functools
import sqlite3
import threading
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import claudia_db
from preview_dashboard.adapters.sqlite.approvals import SqliteApprovalStore
from preview_dashboard.adapters.sqlite.claudia_db import (
    CLAUDIA_SCHEMA_VERSION,
    connect_claudia,
    default_claudia_db_path,
)
from preview_dashboard.adapters.sqlite.connection import connect, default_db_path
from preview_dashboard.adapters.sqlite.migrations import DatabaseSetupError
from preview_dashboard.adapters.sqlite.owner_messages import SqliteOwnerMessageStore
from preview_dashboard.adapters.sqlite.repository import ConnectionFactory
from preview_dashboard.domain.approvals import ActionKind, ApprovalState
from preview_dashboard.domain.errors import ConflictError, InvalidStateError
from tests.builders import T0
from tests.contracts.approval_store import (
    ApprovalStoreContract,
    ApprovalStoreHandle,
    consume,
    make_approval,
    wid,
)
from tests.contracts.owner_message_store import (
    MessageStore,
    OwnerMessageStoreContract,
    make_message,
    mid,
)

pytestmark = pytest.mark.integration

# Tamper hooks: a planted code in the inbox, a classifier-only action kind
# (`unknown`, never storable through the domain) in an approval row.
_CORRUPT_MESSAGE_SQL = "UPDATE owner_messages SET text = '123456' WHERE id = ?"
_CORRUPT_APPROVAL_SQL = "UPDATE approval_requests SET action_kind = 'unknown' WHERE id = ?"
_CLAUDIA_OBJECTS = (
    "owner_messages",
    "approval_requests",
    "idx_owner_messages_unhandled",
    "idx_owner_messages_received",
    "idx_approval_requests_open",
    "idx_approval_requests_consumed",
    "idx_approval_requests_expires",
)


def _factory(db_path: Path, *, create: bool = True) -> ConnectionFactory:
    return functools.partial(connect_claudia, db_path, create=create)


def _tamper(db_path: Path, sql: str, params: tuple[object, ...]) -> None:
    conn = connect_claudia(db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = default_claudia_db_path(tmp_path)
    connect_claudia(path).close()  # create + migrate once, like the admin at startup
    return path


class TestSqliteOwnerMessageStoreContract(OwnerMessageStoreContract):
    @pytest.fixture
    def ms(self, db_path: Path) -> MessageStore:
        return MessageStore(
            store=SqliteOwnerMessageStore(_factory(db_path)),
            corrupt=lambda message_id: _tamper(db_path, _CORRUPT_MESSAGE_SQL, (message_id,)),
        )


class TestSqliteApprovalStoreContract(ApprovalStoreContract):
    @pytest.fixture
    def aps(self, db_path: Path) -> ApprovalStoreHandle:
        return ApprovalStoreHandle(
            store=SqliteApprovalStore(_factory(db_path)),
            corrupt=lambda approval_id: _tamper(db_path, _CORRUPT_APPROVAL_SQL, (approval_id,)),
        )


# --- schema ----------------------------------------------------------------------------


def _schema(path: Path) -> list[tuple[str, str]]:
    raw = sqlite3.connect(path)
    try:
        return raw.execute(
            "SELECT name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
        ).fetchall()
    finally:
        raw.close()


def _tables(path: Path) -> set[str]:
    return {name for name, _ in _schema(path)}


def _version(path: Path) -> int:
    raw = sqlite3.connect(path)
    try:
        (version,) = raw.execute("PRAGMA user_version").fetchone()
    finally:
        raw.close()
    return int(version)


def _set_version(path: Path, version: int) -> None:
    raw = sqlite3.connect(path)
    try:
        raw.execute(f"PRAGMA user_version = {int(version)}")
        raw.commit()
    finally:
        raw.close()


class TestClaudiaSchema:
    def test_schema_2_has_every_table_and_index(self, db_path: Path) -> None:
        assert CLAUDIA_SCHEMA_VERSION == 2
        assert _version(db_path) == 2
        assert set(_CLAUDIA_OBJECTS) <= _tables(db_path)
        conn = connect_claudia(db_path)
        try:
            assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert conn.execute("PRAGMA journal_mode").fetchone() == ("wal",)
        finally:
            conn.close()

    def test_rerun_is_a_no_op(self, db_path: Path) -> None:
        before = _schema(db_path)
        conn = connect_claudia(db_path)
        try:
            claudia_db.migrate_claudia(conn)
            claudia_db.migrate_claudia(conn)
        finally:
            conn.close()
        assert _schema(db_path) == before

    def test_failed_migration_rolls_back_and_reruns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def crash_after_1(conn: sqlite3.Connection) -> None:
            claudia_db._claudia_migration_1(conn)
            raise RuntimeError("simulated crash before COMMIT")

        path = default_claudia_db_path(tmp_path)
        with monkeypatch.context() as patch:
            patch.setattr(claudia_db, "_CLAUDIA_MIGRATIONS", ((1, crash_after_1),))
            with pytest.raises(RuntimeError):
                connect_claudia(path)
        assert "owner_messages" not in _tables(path)  # all or nothing
        assert _version(path) == 0
        connect_claudia(path).close()  # the real migration then succeeds
        assert "approval_requests" in _tables(path)

    def test_open_only_role_never_creates_the_database(self, tmp_path: Path) -> None:
        path = default_claudia_db_path(tmp_path)
        with pytest.raises(DatabaseSetupError, match="does not exist"):
            connect_claudia(path, create=False)
        assert not path.parent.exists()
        path.parent.mkdir(mode=0o700)
        with pytest.raises(DatabaseSetupError, match="does not exist"):
            connect_claudia(path, create=False)
        assert not path.exists()

    def test_open_only_role_refuses_an_unmigrated_file(self, tmp_path: Path) -> None:
        path = default_claudia_db_path(tmp_path)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(claudia_db, "migrate_claudia", lambda conn: None)
            connect_claudia(path).close()  # file exists, schema 0
        with pytest.raises(DatabaseSetupError, match="version 0"):
            connect_claudia(path, create=False)

    @pytest.mark.parametrize("create", [True, False])
    def test_newer_schema_is_refused_by_every_role(self, db_path: Path, create: bool) -> None:
        _set_version(db_path, CLAUDIA_SCHEMA_VERSION + 1)
        with pytest.raises(DatabaseSetupError, match="version 3"):
            connect_claudia(db_path, create=create)
        assert _version(db_path) == CLAUDIA_SCHEMA_VERSION + 1  # untouched

    def test_migration_2_keeps_schema_1_rows_as_text(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A v1 file with a stored message (the live layout before C61) ...
        path = default_claudia_db_path(tmp_path)
        with monkeypatch.context() as patch:
            patch.setattr(
                claudia_db, "_CLAUDIA_MIGRATIONS", ((1, claudia_db._claudia_migration_1),)
            )
            patch.setattr(claudia_db, "CLAUDIA_SCHEMA_VERSION", 1)
            conn = connect_claudia(path)
            try:
                conn.execute(
                    "INSERT INTO owner_messages (id, update_id, telegram_message_id, text,"
                    " received_us, is_forwarded, state)"
                    " VALUES (?, 5, 50, 'hello from v1', ?, 0, 'received')",
                    (mid(1), int(T0.timestamp() * 1_000_000)),
                )
                conn.commit()
            finally:
                conn.close()
        assert _version(path) == 1
        # ... migrates additively and the old row loads as a text message.
        connect_claudia(path).close()
        assert _version(path) == 2
        (row,) = SqliteOwnerMessageStore(_factory(path)).list_unhandled(10)
        assert (row.text, row.kind.value, row.media_id, row.media_bytes) == (
            "hello from v1",
            "text",
            None,
            None,
        )

    def test_media_columns_are_checked_by_the_schema(self, db_path: Path) -> None:
        conn = connect_claudia(db_path)
        try:
            for kind, size in (("video", None), ("voice", 0)):
                with pytest.raises(sqlite3.IntegrityError):
                    conn.execute(
                        "INSERT INTO owner_messages (id, update_id, telegram_message_id, text,"
                        " received_us, is_forwarded, state, kind, media_bytes)"
                        " VALUES (?, 6, 60, '', 1, 0, 'received', ?, ?)",
                        (mid(2), kind, size),
                    )
        finally:
            conn.close()

    def test_purge_role_connections_use_the_tables(self, db_path: Path) -> None:
        SqliteOwnerMessageStore(_factory(db_path)).add(make_message(1))
        purge = SqliteOwnerMessageStore(_factory(db_path, create=False))
        assert purge.delete_received_before(T0 + timedelta(days=31)) == 1


class TestSharedDatabaseHasNoClaudiaRows:
    def test_item_db_holds_neither_inbox_nor_approvals(self, tmp_path: Path) -> None:
        path = default_db_path(tmp_path)
        connect(path).close()
        names = _tables(path)
        assert not set(_CLAUDIA_OBJECTS) & names

    def test_item_db_migration_5_keeps_the_outbox_columns(self, tmp_path: Path) -> None:
        path = default_db_path(tmp_path)
        connect(path).close()
        raw = sqlite3.connect(path)
        try:
            tasks = {row[1] for row in raw.execute("PRAGMA table_info(delivery_tasks)")}
            notifications = {row[1] for row in raw.execute("PRAGMA table_info(notifications)")}
        finally:
            raw.close()
        assert "long_form" in tasks
        assert "approval_id" in notifications


# --- races (CAS: first writer wins) -----------------------------------------------------


def _race(n: int, work: Callable[[int], None]) -> list[BaseException | None]:
    """Run `work(i)` in `n` threads released together; return each outcome."""
    barrier = threading.Barrier(n)
    outcomes: list[BaseException | None] = [None] * n

    def run(i: int) -> None:
        barrier.wait()
        try:
            work(i)
        except BaseException as exc:  # recorded and asserted on by the caller
            outcomes[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return outcomes


class TestRaces:
    def test_handled_mark_has_one_winner(self, db_path: Path) -> None:
        store = SqliteOwnerMessageStore(_factory(db_path))
        store.add(make_message(1))

        def mark(_: int) -> None:
            store.mark_handled(mid(1), T0 + timedelta(minutes=1))

        outcomes = _race(8, mark)
        assert outcomes.count(None) == 1
        assert all(isinstance(o, InvalidStateError) for o in outcomes if o is not None)

    def test_redelivered_update_racing_is_stored_once(self, db_path: Path) -> None:
        store = SqliteOwnerMessageStore(_factory(db_path))

        def add(i: int) -> None:
            store.add(make_message(i + 1, update_id=1, telegram_message_id=101))

        outcomes = _race(8, add)
        assert outcomes == [None] * 8
        assert len(store.list_unhandled(100)) == 1

    def test_consume_has_one_winner(self, db_path: Path) -> None:
        store = SqliteApprovalStore(_factory(db_path))
        request = make_approval(1)
        store.add(request)
        tapped, approved, consumed = consume(request)
        store.save(tapped, expected_updated_at=request.updated_at)
        store.save(approved, expected_updated_at=tapped.updated_at)
        outcomes = _race(8, lambda i: store.save(consumed, expected_updated_at=approved.updated_at))
        assert outcomes.count(None) == 1
        assert all(isinstance(o, ConflictError) for o in outcomes if o is not None)
        assert store.get(request.id).state is ApprovalState.CONSUMED

    def test_one_open_request_per_window_under_concurrency(self, db_path: Path) -> None:
        store = SqliteApprovalStore(_factory(db_path))
        outcomes = _race(8, lambda i: store.add(make_approval(i + 1)))
        assert outcomes.count(None) == 1
        assert all(isinstance(o, ConflictError) for o in outcomes if o is not None)
        assert len(store.list_open(wid(1))) == 1

    def test_first_creates_race_on_one_file(self, tmp_path: Path) -> None:
        path = default_claudia_db_path(tmp_path)
        outcomes = _race(8, lambda i: connect_claudia(path).close())
        assert outcomes == [None] * 8
        assert _version(path) == CLAUDIA_SCHEMA_VERSION


# --- query plans ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "params", "index"),
    [
        (
            "SELECT id FROM owner_messages WHERE state = 'received' "
            "ORDER BY received_us, id LIMIT ?",
            (10,),
            "idx_owner_messages_unhandled",
        ),
        (
            "SELECT id FROM approval_requests WHERE state = 'consumed' AND window_id = ? "
            "AND action_kind = ? AND action_target = ? AND resolved_us >= ?",
            (wid(1), ActionKind.PR_MERGE.value, "owner/repo#1", 0),
            "idx_approval_requests_consumed",
        ),
    ],
)
def test_hot_queries_use_their_index(
    db_path: Path, sql: str, params: tuple[object, ...], index: str
) -> None:
    conn = connect_claudia(db_path)
    try:
        plan = " ".join(str(r[-1]) for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))
    finally:
        conn.close()
    assert index in plan
