"""SqliteOwnerMessageStore: the `OwnerMessageStore` port over SQLite (C44).

Lives in the admin-only Claudia database (`claudia_db`, schema 1), never
in the viewer-writable item DB (S-C1 S1).

Static SQL constants with bound values only (C24); every row is rebuilt
through `OwnerMessage`, so a tampered row fails closed (`get`) or is skipped
(`list_unhandled`, logged by id only: message text is never logged, C29).
Idempotent add rides on UNIQUE (update_id, telegram_message_id) inside one
`BEGIN IMMEDIATE` transaction; `mark_handled` is a conditional UPDATE (CAS).
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
    InvalidStateError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.models import ensure_utc, is_ulid
from preview_dashboard.domain.owner_messages import InboxState, OwnerMessage, OwnerMessageId
from preview_dashboard.domain.query import created_us_to_datetime
from preview_dashboard.ports.owner_messages import MAX_UNHANDLED_LIMIT

_log = logging.getLogger(__name__)

_INSERT_SQL = (
    "INSERT INTO owner_messages (id, update_id, telegram_message_id, text, received_us, "
    "is_forwarded, reply_to_message_id, quote_text, state, handled_us) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_BY_ID_SQL = (
    "SELECT id, update_id, telegram_message_id, text, received_us, is_forwarded, "
    "reply_to_message_id, quote_text, state, handled_us FROM owner_messages WHERE id = ?"
)
_SELECT_BY_UPDATE_SQL = (
    "SELECT id, update_id, telegram_message_id, text, received_us, is_forwarded, "
    "reply_to_message_id, quote_text, state, handled_us FROM owner_messages "
    "WHERE update_id = ? AND telegram_message_id = ?"
)
# The 'received' literal lets SQLite use the partial index.
_SELECT_UNHANDLED_SQL = (
    "SELECT id, update_id, telegram_message_id, text, received_us, is_forwarded, "
    "reply_to_message_id, quote_text, state, handled_us FROM owner_messages "
    "WHERE state = 'received' ORDER BY received_us, id LIMIT ?"
)
# Compare-and-swap: only a RECEIVED row changes, so the first worker wins.
_MARK_HANDLED_SQL = (
    "UPDATE owner_messages SET state = 'handled', handled_us = ? "
    "WHERE id = ? AND state = 'received'"
)
_DELETE_BEFORE_SQL = "DELETE FROM owner_messages WHERE received_us < ?"

_Row = tuple[str, int, int, str, int, int, int | None, str | None, str, int | None]


def _log_id(raw: object) -> str:
    """A row id safe to log: the id itself if canonical, else a placeholder."""
    return str(raw) if is_ulid(raw) else "<malformed id>"


def _load(row: _Row) -> OwnerMessage:
    """Rebuild an `OwnerMessage` from a row, re-validating every field.

    Raises:
        ValidationError: the row fails a domain invariant (tampered).
    """
    (
        id_,
        update_id,
        telegram_message_id,
        text,
        received_us,
        is_forwarded,
        reply_to,
        quote_text,
        state,
        handled_us,
    ) = row
    if is_forwarded not in (0, 1):
        raise ValidationError("invalid forwarded flag in stored row")
    try:
        parsed_state = InboxState(state)
    except ValueError:
        raise ValidationError("invalid inbox state in stored row") from None
    return OwnerMessage(
        id=OwnerMessageId(id_),
        update_id=update_id,
        telegram_message_id=telegram_message_id,
        text=text,
        received_at=created_us_to_datetime(received_us),
        is_forwarded=bool(is_forwarded),
        reply_to_message_id=reply_to,
        quote_text=quote_text,
        state=parsed_state,
        handled_at=None if handled_us is None else created_us_to_datetime(handled_us),
    )


class SqliteOwnerMessageStore:
    """`OwnerMessageStore` over SQLite (see `ports.owner_messages.OwnerMessageStore`).

    Opens one connection per call via `conn_factory`.

    Args:
        conn_factory: zero-argument factory for Claudia-database connections
            (`functools.partial(connect_claudia, path)`).
    """

    def __init__(self, conn_factory: ConnectionFactory) -> None:
        self._conn_factory = conn_factory

    def add(self, message: OwnerMessage) -> OwnerMessage:
        """See `OwnerMessageStore.add` (lookup + insert in one `BEGIN IMMEDIATE`)."""
        if message.state is not InboxState.RECEIVED:
            raise ValidationError("only a received message can be added")
        conn = self._conn_factory()
        try:
            with _writing(conn):
                existing = conn.execute(
                    _SELECT_BY_UPDATE_SQL, (message.update_id, message.telegram_message_id)
                ).fetchone()
                if existing is not None:
                    return _load(existing)  # re-delivered update: stored once
                try:
                    conn.execute(
                        _INSERT_SQL,
                        (
                            message.id,
                            message.update_id,
                            message.telegram_message_id,
                            message.text,
                            _to_us(message.received_at),
                            int(message.is_forwarded),
                            message.reply_to_message_id,
                            message.quote_text,
                            message.state.value,
                            None,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AlreadyExistsError("owner message already exists") from exc
            return message
        finally:
            conn.close()

    def get(self, message_id: OwnerMessageId) -> OwnerMessage:
        """See `OwnerMessageStore.get`."""
        conn = self._conn_factory()
        try:
            row = conn.execute(_SELECT_BY_ID_SQL, (message_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            raise NotFoundError("owner message not found")
        return _load(row)

    def list_unhandled(self, limit: int) -> builtins.list[OwnerMessage]:
        """See `OwnerMessageStore.list_unhandled`; a tampered row is skipped (id logged)."""
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit must be an int")
        if not 1 <= limit <= MAX_UNHANDLED_LIMIT:
            raise ValidationError(f"limit must be 1..{MAX_UNHANDLED_LIMIT}")
        out: builtins.list[OwnerMessage] = []
        conn = self._conn_factory()
        try:
            with _reading(conn):
                rows = conn.execute(_SELECT_UNHANDLED_SQL, (limit,)).fetchall()
        finally:
            conn.close()
        for row in rows:
            try:
                out.append(_load(row))
            except ValidationError:
                _log.warning("skipping invalid owner message row %s", _log_id(row[0]))
        return out

    def mark_handled(self, message_id: OwnerMessageId, at: datetime) -> OwnerMessage:
        """See `OwnerMessageStore.mark_handled` (read, domain transition, CAS write)."""
        at = ensure_utc(at, "at")
        conn = self._conn_factory()
        try:
            with _writing(conn):
                row = conn.execute(_SELECT_BY_ID_SQL, (message_id,)).fetchone()
                if row is None:
                    raise NotFoundError("owner message not found")
                handled = _load(row).handled(at)  # InvalidStateError if already handled
                cur = conn.execute(_MARK_HANDLED_SQL, (_to_us(at), message_id))
                if cur.rowcount != 1:  # pragma: no cover - same write lock as the read
                    raise InvalidStateError("message is already handled")
            return handled
        finally:
            conn.close()

    def delete_received_before(self, cutoff: datetime) -> int:
        """See `OwnerMessageStore.delete_received_before`."""
        cutoff_us = _to_us(ensure_utc(cutoff, "cutoff"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                cur = conn.execute(_DELETE_BEFORE_SQL, (cutoff_us,))
            return cur.rowcount
        finally:
            conn.close()
