"""Integration tests for the SQLite question repository + notification outbox (unit N2).

Runs the shared port contracts against SQLite, then what only a real
database can show: migration 3 (from a v2 file, and for no-migrate viewer /
purge connections), all-or-nothing transactions, the compare-and-swap under
racing threads and processes (first answer wins, C34), cascades, index use,
lock-free `pending` reads and fail-closed re-validation of tampered rows (C24).
"""

from __future__ import annotations

import functools
import logging
import multiprocessing
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from datetime import timedelta
from multiprocessing import Queue
from multiprocessing.synchronize import Barrier as ProcessBarrier
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import connection as connection_module
from preview_dashboard.adapters.sqlite import migrations
from preview_dashboard.adapters.sqlite import questions as questions_module
from preview_dashboard.adapters.sqlite.connection import (
    DatabaseSetupError,
    connect,
    default_db_path,
)
from preview_dashboard.adapters.sqlite.questions import (
    SqliteNotificationOutbox,
    SqliteQuestionRepository,
)
from preview_dashboard.adapters.sqlite.repository import ConnectionFactory, SqliteItemRepository
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.application.notify import OutboxService
from preview_dashboard.application.questions import AskCommand, QuestionService
from preview_dashboard.application.ratelimit import SlidingWindowRateLimiter
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.models import ItemId
from preview_dashboard.domain.notifications import DashboardLinks, DeliveryAction, DeliveryState
from preview_dashboard.domain.questions import AnswerResult, QuestionState
from tests.builders import T0, make_item, ulid
from tests.contracts.question_store import (
    NotificationOutboxContract,
    NotifyStore,
    QuestionRepositoryContract,
    add_question,
    resolve_task,
)
from tests.fakes import FakeContentScanner, FakeQuestionEvents, FixedClock
from tests.notify_support import (
    DASHBOARD,
    make_notification,
    make_options,
    make_question,
    make_task,
    qid,
    tid,
)

pytestmark = pytest.mark.integration


def _factory(db_path: Path, *, migrate: bool = True) -> ConnectionFactory:
    return functools.partial(connect, db_path, migrate=migrate)


# Contract hooks: make one row fail re-validation. The task tamper also breaks
# a stored message_ref, so a RESOLVE joined to a tampered SEND fails too.
_T0_US = 1_767_268_800_000_000  # T0 in epoch microseconds

_CORRUPT_TASK_SQL = (
    "UPDATE delivery_tasks SET attempts = 99, "
    "message_ref = CASE WHEN message_ref IS NULL THEN NULL ELSE 'a b' END WHERE id = ?"
)
_CORRUPT_QUESTION_SQL = "UPDATE questions SET prompt = '' WHERE id = ?"


def _store(db_path: Path, *, migrate: bool = True) -> NotifyStore:
    factory = _factory(db_path, migrate=migrate)
    return NotifyStore(
        repo=SqliteQuestionRepository(factory),
        outbox=SqliteNotificationOutbox(factory),
        corrupt_task=lambda task_id: _tamper(db_path, _CORRUPT_TASK_SQL, (task_id,)),
        corrupt_question=lambda question_id: _tamper(
            db_path, _CORRUPT_QUESTION_SQL, (question_id,)
        ),
    )


_COUNT_SQL = {
    "questions": "SELECT COUNT(*) FROM questions",
    "question_options": "SELECT COUNT(*) FROM question_options",
    "notifications": "SELECT COUNT(*) FROM notifications",
    "delivery_tasks": "SELECT COUNT(*) FROM delivery_tasks",
    "delivery_buttons": "SELECT COUNT(*) FROM delivery_buttons",
}


def _counts(db_path: Path) -> dict[str, int]:
    """Row count of every question/outbox table."""
    conn = connect(db_path)
    try:
        return {table: conn.execute(sql).fetchone()[0] for table, sql in _COUNT_SQL.items()}
    finally:
        conn.close()


_EMPTY = dict.fromkeys(_COUNT_SQL, 0)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = default_db_path(tmp_path)
    connect(path).close()  # create + migrate once, like the admin at startup
    return path


class TestSqliteQuestionRepositoryContract(QuestionRepositoryContract):
    @pytest.fixture
    def store(self, db_path: Path) -> NotifyStore:
        return _store(db_path)


class TestSqliteNotificationOutboxContract(NotificationOutboxContract):
    @pytest.fixture
    def store(self, db_path: Path) -> NotifyStore:
        return _store(db_path)


# --- migration 3 and no-migrate roles -----------------------------------------------


@pytest.fixture
def v2_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A database created at schema version 2 (before questions) holding one item."""
    path = default_db_path(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(migrations, "_MIGRATIONS", migrations._MIGRATIONS[:2])
        patch.setattr(migrations, "CURRENT_VERSION", 2)
        patch.setattr(connection_module, "CURRENT_VERSION", 2)
        conn = connect(path)
        try:
            # Raw rows in the v2 shape: today's repository writes later columns.
            item = make_item(1)
            conn.execute(
                "INSERT INTO items (id, title, description, kind, entry_file, created_us, "
                "updated_us, pinned, state, trashed_us, revision) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'active', NULL, 1)",
                (item.id, item.title, "", item.kind, item.entry_file, _T0_US, _T0_US),
            )
            conn.execute(
                "INSERT INTO revisions (item_id, number, kind, entry_file, created_us) "
                "VALUES (?, 1, ?, ?, ?)",
                (item.id, item.kind, item.entry_file, _T0_US),
            )
            (file,) = item.files
            conn.execute(
                "INSERT INTO item_files (item_id, revision, relpath, blob_id, size, sha256, "
                "media_type, position) VALUES (?, 1, ?, ?, ?, ?, ?, 0)",
                (item.id, file.relpath, file.blob_id, file.size, file.sha256, file.media_type),
            )
            conn.commit()
            assert conn.execute("PRAGMA user_version").fetchone() == (2,)
        finally:
            conn.close()
    yield path


class TestMigration3:
    def test_migration_3_is_registered(self) -> None:
        # Later migrations (e.g. 4, folders) build on it; the version only grows.
        assert [v for v, _ in migrations._MIGRATIONS][:3] == [1, 2, 3]
        assert migrations.CURRENT_VERSION >= 3

    def test_v2_database_is_upgraded_keeping_items(self, v2_db: Path) -> None:
        store = _store(v2_db)  # the admin's connect() migrates
        add_question(store)
        assert store.repo.get(qid(1)).state is QuestionState.OPEN
        assert SqliteItemRepository(_factory(v2_db)).get(ItemId(ulid(1))) == make_item(1)
        conn = connect(v2_db)
        try:
            assert conn.execute("PRAGMA user_version").fetchone() == (migrations.CURRENT_VERSION,)
            assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
            assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        finally:
            conn.close()

    def test_no_migrate_roles_refuse_a_v2_database_untouched(self, v2_db: Path) -> None:
        with pytest.raises(DatabaseSetupError, match="version 2"):
            connect(v2_db, migrate=False)
        raw = sqlite3.connect(v2_db)
        try:
            assert raw.execute("PRAGMA user_version").fetchone() == (2,)
            tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master").fetchall()}
            assert "questions" not in tables
        finally:
            raw.close()

    def test_viewer_and_purge_connections_use_the_v3_schema(self, db_path: Path) -> None:
        admin = _store(db_path)
        question, _, _ = add_question(admin)
        admin.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)), expected_updated_at=question.updated_at
        )
        viewer = connect(db_path, migrate=False)
        try:
            assert viewer.execute("PRAGMA user_version").fetchone() == (migrations.CURRENT_VERSION,)
        finally:
            viewer.close()
        # The purge role's housekeeping runs over no-migrate connections.
        purge = _store(db_path, migrate=False)
        assert purge.repo.get(question.id).state is QuestionState.CANCELLED
        later = T0 + timedelta(days=31)
        assert purge.outbox.delete_before(later) == 1
        assert purge.repo.delete_resolved_before(later) == 1
        assert _counts(db_path) == _EMPTY


# --- transactions and cascades -------------------------------------------------------


class TestTransactions:
    def test_failed_add_leaves_no_row_in_any_table(self, db_path: Path) -> None:
        store = _store(db_path)
        question = make_question(1, options=make_options("A", "B", "C"))
        notification = make_notification(1, event_type="question", question_id=question.id)
        # The second SEND on the same channel hits the unique index last.
        tasks = [make_task(1, channel="c0"), make_task(2, channel="c0")]
        with pytest.raises(AlreadyExistsError):
            store.repo.add_with_notification(question, notification, tasks)
        assert _counts(db_path) == _EMPTY

    def test_one_send_per_notification_and_channel(self, db_path: Path) -> None:
        store = _store(db_path)
        with pytest.raises(AlreadyExistsError):
            store.outbox.add(make_notification(1), [make_task(1), make_task(2)])
        assert _counts(db_path) == _EMPTY

    def test_failed_save_keeps_every_row(self, db_path: Path) -> None:
        store = _store(db_path)
        question, _, (send,) = add_question(store)
        before = _counts(db_path)
        cancelled = question.cancelled(T0 + timedelta(seconds=1))
        with pytest.raises(AlreadyExistsError):
            store.repo.save(
                cancelled,
                expected_updated_at=question.updated_at,
                tasks=[resolve_task(3), resolve_task(10)],  # tid(10) is the SEND
            )
        assert _counts(db_path) == before
        assert store.repo.get(question.id) == question
        assert store.outbox.get_task(send.id) == send

    def test_deleting_a_question_cascades_to_everything(self, db_path: Path) -> None:
        store = _store(db_path)
        question, _, _ = add_question(store, channels=("c0", "c1"))
        store.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(3)],
        )
        assert store.repo.delete_resolved_before(T0 + timedelta(days=1)) == 1
        assert _counts(db_path) == _EMPTY

    def test_delete_before_cascades_to_tasks_and_buttons(self, db_path: Path) -> None:
        store = _store(db_path)
        add_question(store)
        assert store.outbox.delete_before(T0 + timedelta(seconds=1)) == 1
        counts = _counts(db_path)
        assert (counts["questions"], counts["question_options"]) == (1, 2)
        assert counts["notifications"] == counts["delivery_tasks"] == 0
        assert counts["delivery_buttons"] == 0


# --- compare-and-swap under real concurrency (C34: first answer wins) ---------------


def _race_save(db_path: Path, n: int, wait: Callable[[], object]) -> str:
    """Read question 1, wait for every racer, then try to answer with option n."""
    store = _store(db_path)
    current = store.repo.get(qid(1))
    wait()
    key = chr(ord("a") + n)
    answered = current.answered(key, "telegram", T0 + timedelta(seconds=1 + n))
    resolve = resolve_task(100 + n, final_state=QuestionState.ANSWERED)
    try:
        store.repo.save(answered, expected_updated_at=current.updated_at, tasks=[resolve])
    except ConflictError:
        return "conflict"
    return f"win:{key}"


def _mp_race(db_path: Path, n: int, barrier: ProcessBarrier, queue: Queue[str]) -> None:
    try:
        queue.put(_race_save(db_path, n, lambda: barrier.wait(timeout=30)))
    except Exception as exc:  # pragma: no cover - reported via the queue instead
        queue.put(f"error: {exc!r}")


def _assert_one_winner(db_path: Path, results: list[str], racers: int) -> None:
    wins = [r for r in results if r.startswith("win:")]
    assert len(wins) == 1, results
    assert results.count("conflict") == racers - 1, results
    store = _store(db_path)
    stored = store.repo.get(qid(1))
    assert stored.state is QuestionState.ANSWERED
    assert f"win:{stored.answer_key}" == wins[0]
    resolves = []
    for n in range(racers):
        try:
            resolves.append(store.outbox.get_task(tid(100 + n)))
        except NotFoundError:
            continue
    assert len(resolves) == 1  # only the winner enqueued its RESOLVE


class TestConcurrentAnswers:
    RACERS = 8

    @pytest.fixture
    def asked(self, db_path: Path) -> Path:
        question = make_question(1, options=make_options(*(f"Option {i}" for i in range(8))))
        add_question(_store(db_path), question=question)
        return db_path

    def test_racing_threads_exactly_one_wins(self, asked: Path) -> None:
        barrier = threading.Barrier(self.RACERS)
        results: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def race(n: int) -> None:
            try:
                outcome = _race_save(asked, n, lambda: barrier.wait(timeout=30))
            except BaseException as exc:  # surfaced below, never swallowed
                with lock:
                    errors.append(exc)
                return
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=race, args=(n,)) for n in range(self.RACERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert errors == []
        _assert_one_winner(asked, results, self.RACERS)

    def test_racing_processes_exactly_one_wins(self, asked: Path) -> None:
        racers = 4
        barrier = multiprocessing.Barrier(racers)
        queue: Queue[str] = multiprocessing.Queue()
        procs = [
            multiprocessing.Process(target=_mp_race, args=(asked, n, barrier, queue))
            for n in range(racers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
        results = [queue.get(timeout=5) for _ in procs]
        assert not [r for r in results if r.startswith("error")], results
        _assert_one_winner(asked, results, racers)

    def test_racing_service_answers_record_once(self, db_path: Path) -> None:
        store = _store(db_path)
        clock = FixedClock(T0)
        service = QuestionService(
            repo=store.repo,
            outbox=store.outbox,
            events=FakeQuestionEvents(),
            clock=clock,
            ids=UlidGenerator(),
            scanner=FakeContentScanner(),
            rate_limiter=SlidingWindowRateLimiter(limit=100, window=timedelta(hours=1)),
            channels=("telegram",),
            links=DashboardLinks(DASHBOARD),
        )
        question = service.ask(
            AskCommand(session_label="s1", prompt="Pick", options=[("a", "A"), ("b", "B")])
        )
        # The alert goes out while the question is open (else it would be stale).
        outbox = OutboxService(outbox=store.outbox, clock=clock)
        (send,) = outbox.pending(20)
        outbox.done(send.id, "chat:42")
        clock.advance(timedelta(seconds=1))
        barrier = threading.Barrier(self.RACERS)
        results: list[AnswerResult] = []
        lock = threading.Lock()

        def answer(n: int) -> None:
            barrier.wait(timeout=30)
            outcome = service.answer(question.id, "ab"[n % 2], "telegram")
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=answer, args=(n,)) for n in range(self.RACERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        assert results.count(AnswerResult.RECORDED) == 1, results
        assert results.count(AnswerResult.ALREADY_ANSWERED) == self.RACERS - 1, results
        # One SEND + exactly one RESOLVE; the RESOLVE edits the SEND's message.
        (resolve,) = outbox.pending(20)
        assert (resolve.action, resolve.message_ref) == (DeliveryAction.RESOLVE, "chat:42")
        assert resolve.payload.final_state is QuestionState.ANSWERED
        assert _counts(db_path)["delivery_tasks"] == 2


# --- query plans and locking ---------------------------------------------------------


class TestQueryPlans:
    @pytest.mark.parametrize(
        ("sql", "params", "index"),
        [
            (questions_module._PENDING_SQL, (0,), "idx_delivery_tasks_due"),
            (questions_module._PENDING_SQL, (0,), "idx_delivery_tasks_send"),
            (questions_module._EXPIRABLE_SQL, (0,), "idx_questions_expirable"),
            (questions_module._DELETE_RESOLVED_SQL, (0,), "idx_questions_resolved"),
            (questions_module._DELETE_NOTIFICATIONS_SQL, (0,), "idx_notifications_created"),
        ],
    )
    def test_hot_queries_use_their_index(
        self, db_path: Path, sql: str, params: tuple[object, ...], index: str
    ) -> None:
        conn = connect(db_path)
        try:
            plan = " ".join(
                str(row[-1]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql, params)
            )
        finally:
            conn.close()
        assert index in plan, plan


class TestPendingTakesNoWriteLock:
    def test_pending_reads_while_another_writer_holds_the_lock(self, db_path: Path) -> None:
        store = _store(db_path)
        store.outbox.add(make_notification(1), [make_task(1)])
        blocker = connect(db_path)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            assert [p.id for p in store.outbox.pending(T0, 10)] == [tid(1)]
            assert time.monotonic() - started < 1.0  # never waited on busy_timeout (5 s)
        finally:
            blocker.rollback()
            blocker.close()


# --- re-validation on read (C24: tampered rows fail closed) -------------------------


def _tamper(db_path: Path, sql: str, params: tuple[object, ...] = ()) -> None:
    conn = connect(db_path)
    try:
        # Bypass the schema's own guards: the domain constructors must still refuse.
        conn.execute("PRAGMA ignore_check_constraints = ON")
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.execute(sql, params)
    finally:
        conn.close()


class TestTamperedRows:
    @pytest.fixture
    def stored(self, db_path: Path) -> NotifyStore:
        store = _store(db_path)
        add_question(store)
        return store

    @pytest.mark.parametrize(
        "sql",
        [
            "UPDATE questions SET prompt = ''",
            "UPDATE questions SET prompt = char(8238)",  # bidi override only
            "UPDATE questions SET state = 'bogus'",
            "UPDATE questions SET state = 'answered', answer_key = 'zz', answer_source = 'x', "
            "resolved_us = updated_us",
            "UPDATE questions SET state = 'open', resolved_us = updated_us",
            "UPDATE questions SET expires_us = created_us",
            "UPDATE questions SET created_us = 9223372036854775807",
            "UPDATE questions SET default_key = 'zz'",
            "UPDATE questions SET item_id = '../../etc'",
            "UPDATE question_options SET label = char(7) WHERE position = 0",
            "UPDATE question_options SET key = 'A:B' WHERE position = 0",
            "DELETE FROM question_options WHERE position = 1",
        ],
    )
    def test_tampered_question_raises_on_read(
        self, stored: NotifyStore, db_path: Path, sql: str
    ) -> None:
        _tamper(db_path, sql)
        with pytest.raises(ValidationError):
            stored.repo.get(qid(1))

    @pytest.mark.parametrize(
        "sql",
        [
            "UPDATE delivery_tasks SET text = ''",
            "UPDATE delivery_tasks SET text = 'a' || char(8238) || 'b'",
            "UPDATE delivery_tasks SET link = 'javascript:alert(1)'",
            "UPDATE delivery_tasks SET attempts = 99",
            "UPDATE delivery_tasks SET action = 'bogus'",
            "UPDATE delivery_tasks SET action = 'resolve'",  # RESOLVE without final_state
            "UPDATE delivery_tasks SET final_state = 'answered'",  # SEND with final_state
            "UPDATE delivery_tasks SET message_ref = 'x'",  # ref on a PENDING task
            "UPDATE delivery_tasks SET channel = 'Tele gram'",
            "UPDATE delivery_tasks SET long_form = 1",  # long form never has buttons
            "UPDATE delivery_tasks SET text = printf('%.301c', 'x')",  # > 300 without long_form
            "UPDATE delivery_buttons SET label = char(10) WHERE position = 0",
            "UPDATE delivery_buttons SET key = 'A:B' WHERE position = 0",
        ],
    )
    def test_tampered_task_raises_on_read(
        self, stored: NotifyStore, db_path: Path, sql: str
    ) -> None:
        _tamper(db_path, sql)
        with pytest.raises(ValidationError):
            stored.outbox.get_task(tid(10))
        # A poison row is failed by id; the call itself goes on (no delivery).
        assert stored.outbox.pending(T0, 10) == []
        assert _state(db_path, tid(10)) == DeliveryState.FAILED.value

    # ZWSP, word joiner, tag char, braille blank, Hangul filler, soft hyphen,
    # CGJ (Copilot review of PR #1, backlog G1).
    @pytest.mark.parametrize("cp", [0x200B, 0x2060, 0xE0041, 0x2800, 0x3164, 0x00AD, 0x034F])
    @pytest.mark.parametrize(
        "sql",
        [
            "UPDATE delivery_tasks SET text = 'a' || char(?) || 'b'",
            "UPDATE delivery_buttons SET label = 'a' || char(?) || 'b' WHERE position = 0",
        ],
    )
    def test_invisible_chars_in_a_task_row_fail_it(
        self, stored: NotifyStore, db_path: Path, sql: str, cp: int
    ) -> None:
        _tamper(db_path, sql, (cp,))
        with pytest.raises(ValidationError):
            stored.outbox.get_task(tid(10))
        assert stored.outbox.pending(T0, 10) == []
        assert _state(db_path, tid(10)) == DeliveryState.FAILED.value

    def test_an_unsanitized_label_row_is_failed_not_cleaned(
        self, stored: NotifyStore, db_path: Path
    ) -> None:
        _tamper(db_path, "UPDATE delivery_buttons SET label = ' Yes ' WHERE position = 0")
        assert stored.outbox.pending(T0, 10) == []
        assert _state(db_path, tid(10)) == DeliveryState.FAILED.value

    def test_poison_row_is_logged_by_id_only(
        self, stored: NotifyStore, db_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        stored.outbox.add(make_notification(2), [make_task(2, notification=2)])
        _tamper(
            db_path,
            "UPDATE delivery_tasks SET text = 'SECRET-ish' || char(8238) WHERE id = ?",
            (tid(10),),
        )
        _tamper(
            db_path, "UPDATE delivery_tasks SET id = 'bad id' || char(10) WHERE id = ?", (tid(2),)
        )
        with caplog.at_level(logging.WARNING, logger=questions_module.__name__):
            assert stored.outbox.pending(T0, 10) == []
        logged = caplog.text
        assert tid(10) in logged and "<malformed id>" in logged
        assert "SECRET-ish" not in logged and "bad id" not in logged
        assert _state(db_path, "bad id\n") == DeliveryState.FAILED.value

    def test_list_expirable_logs_a_poison_question_by_id_only(
        self, stored: NotifyStore, db_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        _tamper(db_path, "UPDATE questions SET prompt = 'leak ' || char(8238), expires_us = 0")
        _tamper(db_path, "UPDATE question_options SET label = '' WHERE position = 0")
        with caplog.at_level(logging.WARNING, logger=questions_module.__name__):
            assert stored.repo.list_expirable(T0 + timedelta(days=2)) == []
        assert qid(1) in caplog.text
        assert "leak" not in caplog.text

    def test_tampered_message_ref_never_reaches_a_channel(
        self, stored: NotifyStore, db_path: Path
    ) -> None:
        stored.outbox.pending(T0, 10)  # SEND handed out while open
        stored.outbox.mark_done(tid(10), "chat:1")
        _tamper(db_path, "UPDATE delivery_tasks SET message_ref = 'a b' WHERE id = ?", (tid(10),))
        with pytest.raises(ValidationError):
            stored.outbox.message_ref_for(qid(1), "c0")
        question = stored.repo.get(qid(1))
        stored.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2)],
        )
        assert stored.outbox.pending(T0, 10) == []  # the RESOLVE would carry the bad ref
        assert _state(db_path, tid(2)) == DeliveryState.FAILED.value

    def test_tampered_notification_raises_on_read(self, stored: NotifyStore, db_path: Path) -> None:
        _tamper(db_path, "UPDATE notifications SET title = ''")
        with pytest.raises(ValidationError):
            stored.outbox.notification_for_question(qid(1))

    def test_tampered_send_state_fails_the_resolve_closed(
        self, stored: NotifyStore, db_path: Path
    ) -> None:
        question = stored.repo.get(qid(1))
        stored.repo.save(
            question.cancelled(T0 + timedelta(seconds=1)),
            expected_updated_at=question.updated_at,
            tasks=[resolve_task(2)],
        )
        stored.outbox.mark_done(tid(10), "chat:1")
        _tamper(db_path, "UPDATE delivery_tasks SET state = 'bogus' WHERE id = ?", (tid(10),))
        assert stored.outbox.pending(T0, 10) == []  # never handed out with a doubtful SEND
        assert _state(db_path, tid(2)) == DeliveryState.FAILED.value


def _state(db_path: Path, task_id: str) -> str:
    conn = connect(db_path)
    try:
        (state,) = conn.execute(
            "SELECT state FROM delivery_tasks WHERE id = ?", (task_id,)
        ).fetchone()
        return str(state)
    finally:
        conn.close()
