"""SqliteQuestionRepository + SqliteNotificationOutbox: the question/outbox ports over SQLite.

Both classes share one store (migration 3): a question, its notification and
its delivery tasks commit in one `BEGIN IMMEDIATE` transaction (transactional
outbox, ADR 0021). Every SQL text is a module-level constant with bound
values (docs/security.md C24); every row read back is rebuilt through its
domain constructor, so a tampered row fails with `ValidationError`. The
batch reads (`pending`, `list_expirable`) isolate such a row instead of
failing the whole call: tasks are marked FAILED, questions skipped.
An approval prompt's text is never taken from this (viewer-writable) store:
`pending` rebuilds it from the admin-only request (C46, storage-totp-1).
"""

from __future__ import annotations

import builtins
import logging
import sqlite3
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum

from preview_dashboard.adapters.sqlite.migrations import DatabaseSetupError
from preview_dashboard.adapters.sqlite.repository import (
    ConnectionFactory,
    _reading,
    _to_us,
    _writing,
)
from preview_dashboard.domain.approvals import (
    ApprovalId,
    ApprovalRequest,
    ApprovalState,
    parse_approval_id,
)
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    NotFoundError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.domain.models import ItemId, ensure_utc, is_ulid
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    DeliveryState,
    DeliveryTask,
    MessageButton,
    MessageContent,
    Notification,
    NotificationId,
    PendingTask,
    TaskId,
    validate_message_ref,
)
from preview_dashboard.domain.query import created_us_to_datetime
from preview_dashboard.domain.questions import Question, QuestionId, QuestionOption, QuestionState
from preview_dashboard.events import APPROVAL_EVENT, RenderContext, default_event_registry
from preview_dashboard.ports.approvals import ApprovalStore

# Mirrors the fake's bound (`OutboxService` caps callers at the same value).
MAX_PENDING_LIMIT = 100
# The stored-only title of a prompt (never shown); equals
# `application.approval_prompts.APPROVAL_TITLE` (a test keeps them equal).
APPROVAL_PROMPT_TITLE = "Approval request"

_log = logging.getLogger(__name__)

# --- questions ------------------------------------------------------------------

_INSERT_QUESTION_SQL = (
    "INSERT INTO questions (id, prompt, default_key, item_id, session_label, created_us, "
    "expires_us, updated_us, state, answer_key, answer_source, resolved_us) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
# Compare-and-swap on updated_us: the first resolution wins (C34).
_UPDATE_QUESTION_SQL = (
    "UPDATE questions SET prompt = ?, default_key = ?, item_id = ?, session_label = ?, "
    "created_us = ?, expires_us = ?, updated_us = ?, state = ?, answer_key = ?, "
    "answer_source = ?, resolved_us = ? WHERE id = ? AND updated_us = ?"
)
_QUESTION_EXISTS_SQL = "SELECT 1 FROM questions WHERE id = ?"
_SELECT_QUESTION_SQL = (
    "SELECT id, prompt, default_key, item_id, session_label, created_us, expires_us, "
    "updated_us, state, answer_key, answer_source, resolved_us FROM questions WHERE id = ?"
)
# The 'open' literal (not a parameter) lets SQLite use the partial index.
_EXPIRABLE_SQL = (
    "SELECT id, prompt, default_key, item_id, session_label, created_us, expires_us, "
    "updated_us, state, answer_key, answer_source, resolved_us FROM questions "
    "WHERE state = 'open' AND expires_us <= ? ORDER BY expires_us, id"
)
# Cascades to options and to the question's notification, tasks and buttons.
_DELETE_RESOLVED_SQL = "DELETE FROM questions WHERE state <> 'open' AND resolved_us < ?"
_INSERT_OPTION_SQL = (
    "INSERT INTO question_options (question_id, position, key, label) VALUES (?, ?, ?, ?)"
)
_DELETE_OPTIONS_SQL = "DELETE FROM question_options WHERE question_id = ?"
_SELECT_OPTIONS_SQL = (
    "SELECT key, label FROM question_options WHERE question_id = ? ORDER BY position"
)

# --- notifications and delivery tasks -----------------------------------------

_INSERT_NOTIFICATION_SQL = (
    "INSERT INTO notifications (id, event_type, title, item_id, question_id, created_us, "
    "approval_id) VALUES (?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_NOTIFICATION_FOR_QUESTION_SQL = (
    "SELECT id, event_type, title, item_id, question_id, created_us, approval_id "
    "FROM notifications WHERE question_id = ?"
)
_NOTIFICATION_QUESTION_SQL = "SELECT question_id FROM notifications WHERE id = ?"
# The admin queues exactly one prompt notification per request; more is forgery.
_COUNT_APPROVAL_PROMPTS_SQL = "SELECT COUNT(*) FROM notifications WHERE approval_id = ?"
# Cascades to the notifications' tasks and their buttons.
_DELETE_NOTIFICATIONS_SQL = "DELETE FROM notifications WHERE created_us < ?"
_INSERT_TASK_SQL = (
    "INSERT INTO delivery_tasks (id, notification_id, channel, action, state, attempts, "
    "next_attempt_us, created_us, message_ref, final_state, text, link, long_form) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_TASK_SQL = (
    "SELECT id, notification_id, channel, action, state, attempts, next_attempt_us, "
    "created_us, message_ref, final_state, text, link, long_form FROM delivery_tasks "
    "WHERE id = ?"
)
# Only a PENDING row changes: finished tasks are immutable (idempotent reports).
_UPDATE_TASK_SQL = (
    "UPDATE delivery_tasks SET state = ?, attempts = ?, next_attempt_us = ?, message_ref = ? "
    "WHERE id = ? AND state = 'pending'"
)
# Due tasks in delivery order, each RESOLVE joined to the SEND whose message
# it edits (at most one: unique index), each task to its question's state
# (a SEND for a resolved question is stale) and carries the prompt's approval
# id; the request itself lives in the admin-only Claudia DB and is looked up
# through the injected `ApprovalStore` (S-C1 S1). Literals keep the partial
# indexes usable.
_PENDING_SQL = (
    "SELECT t.id, t.notification_id, t.channel, t.action, t.state, t.attempts, "
    "t.next_attempt_us, t.created_us, t.message_ref, t.final_state, t.text, t.link, "
    "t.long_form, n.question_id, s.state, s.message_ref, q.state, n.approval_id "
    "FROM delivery_tasks AS t "
    "JOIN notifications AS n ON n.id = t.notification_id "
    "LEFT JOIN delivery_tasks AS s ON t.action = 'resolve' AND s.action = 'send' "
    "AND s.notification_id = t.notification_id AND s.channel = t.channel "
    "LEFT JOIN questions AS q ON q.id = n.question_id "
    "WHERE t.state = 'pending' AND t.next_attempt_us <= ? "
    "ORDER BY t.next_attempt_us, t.created_us, t.id"
)
# Gives up a task whose row fails re-validation (by id: the row can't be parsed).
_POISON_TASK_SQL = "UPDATE delivery_tasks SET state = 'failed' WHERE id = ? AND state = 'pending'"
_SEND_FOR_QUESTION_SQL = (
    "SELECT t.id, t.notification_id, t.channel, t.action, t.state, t.attempts, "
    "t.next_attempt_us, t.created_us, t.message_ref, t.final_state, t.text, t.link, "
    "t.long_form FROM delivery_tasks AS t JOIN notifications AS n ON n.id = t.notification_id "
    "WHERE n.question_id = ? AND t.channel = ? AND t.action = 'send'"
)
_INSERT_BUTTON_SQL = (
    "INSERT INTO delivery_buttons (task_id, position, key, label) VALUES (?, ?, ?, ?)"
)
_SELECT_BUTTONS_SQL = "SELECT key, label FROM delivery_buttons WHERE task_id = ? ORDER BY position"

_QuestionRow = tuple[
    str, str, str | None, str | None, str | None, int, int, int, str, str | None, str | None,
    int | None,
]  # fmt: skip
_NotificationRow = tuple[str, str, str, str | None, str | None, int, str | None]
_TaskRow = tuple[
    str, str, str, str, str, int, int, int, str | None, str | None, str, str | None, int,
]  # fmt: skip
_PendingRow = tuple[
    str, str, str, str, str, int, int, int, str | None, str | None, str, str | None, int,
    str | None, str | None, str | None, str | None, str | None,
]  # fmt: skip


class _HoldPromptError(Exception):
    """The Claudia database can't be read right now: hold the prompt, re-check next poll."""


def _live_request(
    approvals: ApprovalStore | None, approval_id: ApprovalId, at: datetime
) -> ApprovalRequest | None:
    """The prompt's request if it exists, is PENDING and not yet expired at `at`.

    Fail closed: no store wired, an unknown/deleted request or a tampered
    row all mean None, "stale" (no buttons are ever sent for it, C46).

    Raises:
        _HoldPromptError: the Claudia database can't be read right now (the
            prompt is neither sent nor settled).
    """
    if approvals is None:
        return None
    try:
        request = approvals.get(approval_id)
    except (NotFoundError, ValidationError):
        return None
    except (StorageUnavailableError, DatabaseSetupError, sqlite3.Error) as exc:
        # Type only: never let a storage error stall every other alert.
        _log.warning("approval lookup for a prompt failed: %s", type(exc).__name__)
        raise _HoldPromptError from None
    if request.state is not ApprovalState.PENDING or request.is_expired(at):
        return None
    return request


def _log_id(raw: object) -> str:
    """A row id safe to log: the id itself if canonical, else a placeholder (tampered)."""
    return str(raw) if is_ulid(raw) else "<malformed id>"


# --- row <-> domain mapping (shared by both classes) ---------------------------


def _parse_enum[E: StrEnum](cls: type[E], raw: str, what: str) -> E:
    """Convert a stored enum value; a tampered one fails closed."""
    try:
        return cls(raw)
    except ValueError:
        raise ValidationError(f"invalid {what} in stored row") from None


def _optional_us(value: datetime | None) -> int | None:
    return None if value is None else _to_us(value)


def _optional_dt(value: int | None) -> datetime | None:
    return None if value is None else created_us_to_datetime(value)


def _question_values(question: Question) -> tuple[object, ...]:
    """The row values after `id`, in `_INSERT_QUESTION_SQL` / `_UPDATE_QUESTION_SQL` order."""
    return (
        question.prompt,
        question.default_key,
        question.item_id,
        question.session_label,
        _to_us(question.created_at),
        _to_us(question.expires_at),
        _to_us(question.updated_at),
        question.state.value,
        question.answer_key,
        question.answer_source,
        _optional_us(question.resolved_at),
    )


def _insert_options(conn: sqlite3.Connection, question: Question) -> None:
    conn.executemany(
        _INSERT_OPTION_SQL,
        [(question.id, pos, o.key, o.label) for pos, o in enumerate(question.options)],
    )


def _load_question(conn: sqlite3.Connection, row: _QuestionRow) -> Question:
    """Rebuild a `Question` (and its options) from a row, re-validating every field.

    Raises:
        ValidationError: the row or an option fails a domain invariant.
    """
    (
        id_,
        prompt,
        default_key,
        item_id,
        session_label,
        created_us,
        expires_us,
        updated_us,
        state,
        answer_key,
        answer_source,
        resolved_us,
    ) = row
    options = tuple(
        QuestionOption(key=key, label=label)
        for key, label in conn.execute(_SELECT_OPTIONS_SQL, (id_,)).fetchall()
    )
    return Question(
        id=QuestionId(id_),
        prompt=prompt,
        options=options,
        created_at=created_us_to_datetime(created_us),
        expires_at=created_us_to_datetime(expires_us),
        updated_at=created_us_to_datetime(updated_us),
        default_key=default_key,
        item_id=None if item_id is None else ItemId(item_id),
        session_label=session_label,
        state=_parse_enum(QuestionState, state, "question state"),
        answer_key=answer_key,
        answer_source=answer_source,
        resolved_at=_optional_dt(resolved_us),
    )


def _insert_notification(conn: sqlite3.Connection, notification: Notification) -> None:
    try:
        conn.execute(
            _INSERT_NOTIFICATION_SQL,
            (
                notification.id,
                notification.event_type,
                notification.title,
                notification.item_id,
                notification.question_id,
                _to_us(notification.created_at),
                notification.approval_id,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise AlreadyExistsError("notification already exists") from exc


def _load_notification(row: _NotificationRow) -> Notification:
    id_, event_type, title, item_id, question_id, created_us, approval_id = row
    return Notification(
        id=NotificationId(id_),
        event_type=event_type,
        title=title,
        created_at=created_us_to_datetime(created_us),
        item_id=None if item_id is None else ItemId(item_id),
        question_id=None if question_id is None else QuestionId(question_id),
        approval_id=None if approval_id is None else ApprovalId(approval_id),
    )


def _insert_tasks(conn: sqlite3.Connection, tasks: Sequence[DeliveryTask]) -> None:
    """Insert tasks and their buttons (caller holds the write transaction).

    Raises:
        AlreadyExistsError: a task id exists, or a second SEND for the same
            notification and channel (unique index).
    """
    for task in tasks:
        try:
            conn.execute(
                _INSERT_TASK_SQL,
                (
                    task.id,
                    task.notification_id,
                    task.channel,
                    task.action.value,
                    task.state.value,
                    task.attempts,
                    _to_us(task.next_attempt_at),
                    _to_us(task.created_at),
                    task.message_ref,
                    None if task.final_state is None else task.final_state.value,
                    task.content.text,
                    task.content.link,
                    int(task.content.long_form),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise AlreadyExistsError("delivery task already exists") from exc
        conn.executemany(
            _INSERT_BUTTON_SQL,
            [(task.id, pos, b.key, b.label) for pos, b in enumerate(task.content.buttons)],
        )


def _load_task(conn: sqlite3.Connection, row: _TaskRow) -> DeliveryTask:
    """Rebuild a `DeliveryTask` (content and buttons included), re-validating every field.

    Raises:
        ValidationError: the row or a button fails a domain invariant.
    """
    (
        id_,
        notification_id,
        channel,
        action,
        state,
        attempts,
        next_attempt_us,
        created_us,
        message_ref,
        final_state,
        text,
        link,
        long_form,
    ) = row
    # Exactly 0 or 1 (also CHECKed): a tampered value fails closed.
    if long_form not in (0, 1) or isinstance(long_form, bool):
        raise ValidationError("invalid long_form in stored row")
    buttons = tuple(
        MessageButton(key=key, label=label)
        for key, label in conn.execute(_SELECT_BUTTONS_SQL, (id_,)).fetchall()
    )
    return DeliveryTask(
        id=TaskId(id_),
        notification_id=NotificationId(notification_id),
        channel=channel,
        action=_parse_enum(DeliveryAction, action, "delivery action"),
        content=MessageContent(text=text, buttons=buttons, link=link, long_form=long_form == 1),
        created_at=created_us_to_datetime(created_us),
        next_attempt_at=created_us_to_datetime(next_attempt_us),
        state=_parse_enum(DeliveryState, state, "delivery state"),
        attempts=attempts,
        message_ref=message_ref,
        final_state=(
            None if final_state is None else _parse_enum(QuestionState, final_state, "final state")
        ),
    )


def _write_task_state(conn: sqlite3.Connection, task: DeliveryTask) -> None:
    """Persist a transition computed by the domain (done / failed try / dropped)."""
    conn.execute(
        _UPDATE_TASK_SQL,
        (
            task.state.value,
            task.attempts,
            _to_us(task.next_attempt_at),
            task.message_ref,
            task.id,
        ),
    )


def _check_owned(
    tasks: Sequence[DeliveryTask], notification_id: NotificationId, message: str
) -> None:
    if any(t.notification_id != notification_id for t in tasks):
        raise ValidationError(message)


# --- QuestionRepository -------------------------------------------------------------


class SqliteQuestionRepository:
    """`QuestionRepository` over SQLite (see `ports.questions.QuestionRepository`).

    Shares its database with `SqliteNotificationOutbox`. Opens one
    connection per call via `conn_factory` (migrated to schema 3 or later).

    Args:
        conn_factory: see `adapters.sqlite.repository.ConnectionFactory`.
    """

    def __init__(self, conn_factory: ConnectionFactory) -> None:
        self._conn_factory = conn_factory

    def add_with_notification(
        self, question: Question, notification: Notification, tasks: Sequence[DeliveryTask]
    ) -> None:
        """See `QuestionRepository.add_with_notification` (one `BEGIN IMMEDIATE` transaction)."""
        if notification.question_id != question.id:
            raise ValidationError("notification belongs to another question")
        _check_owned(tasks, notification.id, "task belongs to another notification")
        conn = self._conn_factory()
        try:
            with _writing(conn):
                try:
                    conn.execute(_INSERT_QUESTION_SQL, (question.id, *_question_values(question)))
                except sqlite3.IntegrityError as exc:
                    raise AlreadyExistsError("question already exists") from exc
                _insert_options(conn, question)
                _insert_notification(conn, notification)
                _insert_tasks(conn, tasks)
        finally:
            conn.close()

    def get(self, question_id: QuestionId) -> Question:
        """See `QuestionRepository.get`."""
        conn = self._conn_factory()
        try:
            with _reading(conn):
                row = conn.execute(_SELECT_QUESTION_SQL, (question_id,)).fetchone()
                if row is None:
                    raise NotFoundError("question not found")
                return _load_question(conn, row)
        finally:
            conn.close()

    def save(
        self,
        question: Question,
        *,
        expected_updated_at: datetime,
        tasks: Sequence[DeliveryTask] = (),
    ) -> None:
        """See `QuestionRepository.save`.

        One `BEGIN IMMEDIATE` transaction: the conditional `UPDATE ... WHERE
        id = ? AND updated_us = ?` is the compare-and-swap (rowcount 0 → an
        existence check under the same lock tells `NotFoundError` from
        `ConflictError`); the tasks are checked and inserted before COMMIT,
        so only the winning writer enqueues its RESOLVEs.
        """
        expected_us = _to_us(ensure_utc(expected_updated_at, "expected_updated_at"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                cur = conn.execute(
                    _UPDATE_QUESTION_SQL, (*_question_values(question), question.id, expected_us)
                )
                if cur.rowcount == 0:
                    if conn.execute(_QUESTION_EXISTS_SQL, (question.id,)).fetchone() is None:
                        raise NotFoundError("question not found")
                    raise ConflictError("question was changed concurrently")
                for task in tasks:
                    owner = conn.execute(
                        _NOTIFICATION_QUESTION_SQL, (task.notification_id,)
                    ).fetchone()
                    if owner is None or owner[0] != question.id:
                        raise ValidationError(
                            "task does not belong to this question's notification"
                        )
                # Whole-value replace, like the fake: options are rewritten too.
                conn.execute(_DELETE_OPTIONS_SQL, (question.id,))
                _insert_options(conn, question)
                _insert_tasks(conn, tasks)
        finally:
            conn.close()

    def list_expirable(self, now: datetime) -> builtins.list[Question]:
        """See `QuestionRepository.list_expirable`.

        A row failing re-validation is skipped (logged by id only), so one
        tampered question can't stop the others from expiring.
        """
        at_us = _to_us(ensure_utc(now, "now"))
        out: builtins.list[Question] = []
        conn = self._conn_factory()
        try:
            with _reading(conn):
                for row in conn.execute(_EXPIRABLE_SQL, (at_us,)).fetchall():
                    try:
                        out.append(_load_question(conn, row))
                    except ValidationError:
                        _log.warning("skipping invalid question row %s", _log_id(row[0]))
        finally:
            conn.close()
        return out

    def delete_resolved_before(self, cutoff: datetime) -> int:
        """See `QuestionRepository.delete_resolved_before`.

        The cascade also removes each question's notification and tasks
        (normally already gone: purge deletes old notifications first).
        """
        cutoff_us = _to_us(ensure_utc(cutoff, "cutoff"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                cur = conn.execute(_DELETE_RESOLVED_SQL, (cutoff_us,))
            return cur.rowcount
        finally:
            conn.close()


# --- NotificationOutbox ------------------------------------------------------------


class SqliteNotificationOutbox:
    """`NotificationOutbox` over SQLite (see `ports.notify.NotificationOutbox`).

    Shares its database with `SqliteQuestionRepository`. Opens one
    connection per call via `conn_factory` (schema 5 or later).

    Args:
        conn_factory: see `adapters.sqlite.repository.ConnectionFactory`.
        approvals: the admin-only approval store `pending` asks whether an
            approval prompt is still live (C46). None (Claudia off, purge):
            every approval prompt is settled unsent (fail closed).
    """

    def __init__(
        self, conn_factory: ConnectionFactory, *, approvals: ApprovalStore | None = None
    ) -> None:
        self._conn_factory = conn_factory
        self._approvals = approvals
        self._approval_event = default_event_registry().get(APPROVAL_EVENT)

    def add(self, notification: Notification, tasks: Sequence[DeliveryTask]) -> None:
        """See `NotificationOutbox.add` (one `BEGIN IMMEDIATE` transaction)."""
        if notification.question_id is not None:
            raise ValidationError("question notifications are added with their question")
        _check_owned(tasks, notification.id, "task belongs to another notification")
        conn = self._conn_factory()
        try:
            with _writing(conn):
                _insert_notification(conn, notification)
                _insert_tasks(conn, tasks)
        finally:
            conn.close()

    def pending(self, now: datetime, limit: int) -> builtins.list[PendingTask]:
        """See `NotificationOutbox.pending`.

        Reads one snapshot (no write lock on the hot long-poll path), then
        settles, in a short write transaction touching only still-PENDING
        rows, what can never be delivered: a RESOLVE whose SEND is missing,
        FAILED or DONE without a ref → FAILED; a SEND whose question is
        already resolved → DONE unsent (stale); a row failing re-validation
        → FAILED by id (logged by id only). None of these use up `limit`.
        """
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit must be an int")
        if not 1 <= limit <= MAX_PENDING_LIMIT:
            raise ValidationError(f"limit must be 1..{MAX_PENDING_LIMIT}")
        at = ensure_utc(now, "now")
        at_us = _to_us(at)
        out: builtins.list[PendingTask] = []
        settled: builtins.list[DeliveryTask] = []
        poisoned: builtins.list[object] = []
        conn = self._conn_factory()
        try:
            with _reading(conn):
                for row in conn.execute(_PENDING_SQL, (at_us,)):
                    if len(out) >= limit:
                        break
                    try:
                        self._classify(conn, row, out, settled, at)
                    except ValidationError:
                        poisoned.append(row[0])
            if settled or poisoned:
                with _writing(conn):
                    for task in settled:
                        _write_task_state(conn, task)
                    for task_id in poisoned:
                        conn.execute(_POISON_TASK_SQL, (task_id,))
        finally:
            conn.close()
        for task_id in poisoned:
            _log.warning("delivery task row %s is invalid; marked failed", _log_id(task_id))
        return out

    def _classify(
        self,
        conn: sqlite3.Connection,
        row: _PendingRow,
        out: builtins.list[PendingTask],
        settled: builtins.list[DeliveryTask],
        at: datetime,
    ) -> None:
        """Hand a due task out, hold it (RESOLVE waiting for its SEND) or settle it unsent.

        An approval prompt goes out only while its request is PENDING and
        not expired at `at`; otherwise (decided, cancelled, expired,
        deleted or no approval store) it is settled DONE unsent, like a
        resolved question's SEND. Its text is rebuilt from the request's
        stored action text (`approval` event), never read from the task
        row: the viewer can write this database, the request lives in the
        admin-only one (C46, S-C1 S1).

        Raises:
            ValidationError: the row (or a joined value) fails re-validation,
                or an approval prompt is forged: not a SEND, or a second
                prompt notification for the same request.
        """
        task = _load_task(conn, row[:13])
        question_id, send_state, send_ref, question_state = row[13], row[14], row[15], row[16]
        raw_approval_id = row[17]
        content = task.content
        ref: str | None = None
        if (
            task.action is DeliveryAction.SEND
            and question_state is not None
            and _parse_enum(QuestionState, question_state, "question state").is_terminal
        ):
            settled.append(task.done(None))  # stale: the question is already resolved
            return
        approval_id = None if raw_approval_id is None else parse_approval_id(raw_approval_id)
        if approval_id is not None:
            self._check_single_prompt(conn, task, approval_id)
            try:
                request = _live_request(self._approvals, approval_id, at)
            except _HoldPromptError:
                return  # Claudia DB unreadable: hold the prompt, never send it blind
            if request is None:
                # Buttons only for a PENDING, unexpired request (C46); a gone row is stale too.
                settled.append(task.done(None))
                return
            content = self._approval_event.render(
                RenderContext(title=APPROVAL_PROMPT_TITLE, body=request.action_text)
            )
            if content != task.content:
                _log.warning(
                    "approval prompt task %s differs from its request; sending the stored text",
                    _log_id(task.id),
                )
        if task.action is DeliveryAction.RESOLVE:
            state = None if send_state is None else _parse_enum(DeliveryState, send_state, "state")
            if state is DeliveryState.PENDING:
                return  # the message isn't out yet: wait for it
            if state is not DeliveryState.DONE or send_ref is None:
                settled.append(task.dropped())  # nothing to edit, ever
                return
            ref = send_ref
        out.append(
            PendingTask(
                id=task.id,
                channel=task.channel,
                action=task.action,
                payload=DeliveryPayload(
                    content=content,
                    question_id=None if question_id is None else QuestionId(question_id),
                    final_state=task.final_state,
                    approval_id=approval_id,
                    # A long-form SEND is a reply: its audio (if any) waits under this id.
                    voice_id=(
                        NotificationId(row[1])
                        if task.action is DeliveryAction.SEND and content.long_form
                        else None
                    ),
                ),
                message_ref=ref,
            )
        )

    @staticmethod
    def _check_single_prompt(
        conn: sqlite3.Connection, task: DeliveryTask, approval_id: ApprovalId
    ) -> None:
        """Refuse a forged prompt: the admin queues one notification of SENDs per request.

        A second notification (or any RESOLVE) for the same request id can
        only come from a writer other than the admin: all of them fail closed.

        Raises:
            ValidationError: not a SEND, or more than one prompt notification.
        """
        if task.action is not DeliveryAction.SEND:
            raise ValidationError("an approval prompt is only ever a SEND")
        (count,) = conn.execute(_COUNT_APPROVAL_PROMPTS_SQL, (approval_id,)).fetchone()
        if count != 1:
            raise ValidationError("more than one prompt notification for one approval request")

    def get_task(self, task_id: TaskId) -> DeliveryTask:
        """See `NotificationOutbox.get_task`."""
        conn = self._conn_factory()
        try:
            with _reading(conn):
                return self._get_task(conn, task_id)
        finally:
            conn.close()

    def mark_done(self, task_id: TaskId, message_ref: str | None) -> DeliveryTask:
        """See `NotificationOutbox.mark_done` (read-modify-write under the write lock)."""
        if message_ref is not None:
            validate_message_ref(message_ref)
        conn = self._conn_factory()
        try:
            with _writing(conn):
                task = self._get_task(conn, task_id)
                if task.state is not DeliveryState.PENDING:
                    return task
                done = task.done(message_ref)
                _write_task_state(conn, done)
            return done
        finally:
            conn.close()

    def mark_failed(self, task_id: TaskId, *, now: datetime) -> DeliveryTask:
        """See `NotificationOutbox.mark_failed`; the backoff comes from the domain."""
        conn = self._conn_factory()
        try:
            with _writing(conn):
                task = self._get_task(conn, task_id)
                if task.state is not DeliveryState.PENDING:
                    return task
                failed = task.failed_attempt(now)
                _write_task_state(conn, failed)
            return failed
        finally:
            conn.close()

    def notification_for_question(self, question_id: QuestionId) -> Notification | None:
        """See `NotificationOutbox.notification_for_question`."""
        conn = self._conn_factory()
        try:
            row = conn.execute(_SELECT_NOTIFICATION_FOR_QUESTION_SQL, (question_id,)).fetchone()
        finally:
            conn.close()
        return None if row is None else _load_notification(row)

    def message_ref_for(self, question_id: QuestionId, channel: str) -> str | None:
        """See `NotificationOutbox.message_ref_for`."""
        conn = self._conn_factory()
        try:
            with _reading(conn):
                row = conn.execute(_SEND_FOR_QUESTION_SQL, (question_id, channel)).fetchone()
                send = None if row is None else _load_task(conn, row)
        finally:
            conn.close()
        if send is None or send.state is not DeliveryState.DONE:
            return None
        return send.message_ref

    def delete_before(self, cutoff: datetime) -> int:
        """See `NotificationOutbox.delete_before` (tasks and buttons go by cascade)."""
        cutoff_us = _to_us(ensure_utc(cutoff, "cutoff"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                cur = conn.execute(_DELETE_NOTIFICATIONS_SQL, (cutoff_us,))
            return cur.rowcount
        finally:
            conn.close()

    @staticmethod
    def _get_task(conn: sqlite3.Connection, task_id: TaskId) -> DeliveryTask:
        row = conn.execute(_SELECT_TASK_SQL, (task_id,)).fetchone()
        if row is None:
            raise NotFoundError("delivery task not found")
        return _load_task(conn, row)
