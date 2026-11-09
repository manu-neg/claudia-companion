"""SqliteApprovalStore: the `ApprovalStore` port over SQLite (C46, C59).

Lives in the admin-only Claudia database (`claudia_db`, schema 1): the
viewer can't open it, so it can't forge APPROVED/CONSUMED rows (S-C1 S1).

Static SQL constants with bound values only (C24). Every write runs in one
`BEGIN IMMEDIATE` transaction: `add` checks the one-open-request-per-window
rule under the same lock as the insert; `save` re-reads the stored row,
rebuilds it (tampered → `ValidationError`), applies the CAS on `updated_at`
and `domain.approvals.check_successor`, then writes only the mutable
columns, so the bound action text and structured action can never change.
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
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    check_successor,
)
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.models import ensure_utc, is_ulid
from preview_dashboard.domain.owner_messages import OwnerMessageId
from preview_dashboard.domain.query import created_us_to_datetime

_log = logging.getLogger(__name__)

_INSERT_SQL = (
    "INSERT INTO approval_requests (id, window_id, kind, action_kind, action_target, "
    "action_text, message_id, state, created_us, expires_us, updated_us, tapped_us, "
    "approved_us, resolved_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_BY_ID_SQL = (
    "SELECT id, window_id, kind, action_kind, action_target, action_text, message_id, state, "
    "created_us, expires_us, updated_us, tapped_us, approved_us, resolved_us "
    "FROM approval_requests WHERE id = ?"
)
# An open request blocks a new one only while it is not expired (C46).
_OPEN_IN_WINDOW_SQL = (
    "SELECT 1 FROM approval_requests WHERE window_id = ? "
    "AND state IN ('pending', 'tapped', 'approved') AND expires_us > ? LIMIT 1"
)
# Only mutable columns are written; immutable ones are also in the WHERE as a
# backstop to `check_successor` (a mismatch writes nothing).
_UPDATE_SQL = (
    "UPDATE approval_requests SET state = ?, updated_us = ?, tapped_us = ?, approved_us = ?, "
    "resolved_us = ? WHERE id = ? AND updated_us = ? AND action_text = ? AND kind = ? "
    "AND action_kind IS ? AND action_target IS ? AND window_id = ?"
)
_FIND_CONSUMED_SQL = (
    "SELECT id, window_id, kind, action_kind, action_target, action_text, message_id, state, "
    "created_us, expires_us, updated_us, tapped_us, approved_us, resolved_us "
    "FROM approval_requests WHERE state = 'consumed' AND window_id = ? AND action_kind = ? "
    "AND action_target = ? AND resolved_us >= ? AND kind <> 'flagged_message' "
    "ORDER BY resolved_us DESC, id DESC"
)
_LIST_OPEN_ALL_SQL = (
    "SELECT id, window_id, kind, action_kind, action_target, action_text, message_id, state, "
    "created_us, expires_us, updated_us, tapped_us, approved_us, resolved_us "
    "FROM approval_requests WHERE state IN ('pending', 'tapped', 'approved') "
    "ORDER BY created_us, id"
)
_LIST_OPEN_WINDOW_SQL = (
    "SELECT id, window_id, kind, action_kind, action_target, action_text, message_id, state, "
    "created_us, expires_us, updated_us, tapped_us, approved_us, resolved_us "
    "FROM approval_requests WHERE state IN ('pending', 'tapped', 'approved') AND window_id = ? "
    "ORDER BY created_us, id"
)
_LIST_EXPIRABLE_SQL = (
    "SELECT id, window_id, kind, action_kind, action_target, action_text, message_id, state, "
    "created_us, expires_us, updated_us, tapped_us, approved_us, resolved_us "
    "FROM approval_requests WHERE state IN ('pending', 'tapped', 'approved') "
    "AND expires_us <= ? ORDER BY expires_us, id"
)
_DELETE_EXPIRED_BEFORE_SQL = "DELETE FROM approval_requests WHERE expires_us < ?"

_Row = tuple[
    str, str, str, str | None, str | None, str, str | None, str, int, int, int,
    int | None, int | None, int | None,
]  # fmt: skip


def _log_id(raw: object) -> str:
    """A row id safe to log: the id itself if canonical, else a placeholder."""
    return str(raw) if is_ulid(raw) else "<malformed id>"


def _optional_dt(value: int | None) -> datetime | None:
    return None if value is None else created_us_to_datetime(value)


def _optional_us(value: datetime | None) -> int | None:
    return None if value is None else _to_us(value)


def _load(row: _Row) -> ApprovalRequest:
    """Rebuild an `ApprovalRequest` from a row, re-validating every field.

    Raises:
        ValidationError: the row fails a domain invariant (tampered), incl.
            an `action_kind` outside the closed enum (e.g. `unknown`).
    """
    (
        id_,
        window_id,
        kind,
        action_kind,
        action_target,
        action_text,
        message_id,
        state,
        created_us,
        expires_us,
        updated_us,
        tapped_us,
        approved_us,
        resolved_us,
    ) = row
    try:
        parsed_kind = ApprovalKind(kind)
        parsed_state = ApprovalState(state)
        parsed_action = None if action_kind is None else ActionKind(action_kind)
    except ValueError:
        raise ValidationError("invalid enum value in stored approval row") from None
    return ApprovalRequest(
        id=ApprovalId(id_),
        window_id=WindowId(window_id),
        kind=parsed_kind,
        action_kind=parsed_action,
        action_target=action_target,
        action_text=action_text,
        message_id=None if message_id is None else OwnerMessageId(message_id),
        state=parsed_state,
        created_at=created_us_to_datetime(created_us),
        expires_at=created_us_to_datetime(expires_us),
        updated_at=created_us_to_datetime(updated_us),
        tapped_at=_optional_dt(tapped_us),
        approved_at=_optional_dt(approved_us),
        resolved_at=_optional_dt(resolved_us),
    )


def _action_value(request: ApprovalRequest) -> str | None:
    return None if request.action_kind is None else request.action_kind.value


class SqliteApprovalStore:
    """`ApprovalStore` over SQLite (see `ports.approvals.ApprovalStore`).

    Opens one connection per call via `conn_factory`.

    Args:
        conn_factory: zero-argument factory for Claudia-database connections
            (`functools.partial(connect_claudia, path)`).
    """

    def __init__(self, conn_factory: ConnectionFactory) -> None:
        self._conn_factory = conn_factory

    def add(self, request: ApprovalRequest) -> None:
        """See `ApprovalStore.add` (open-window check + insert in one `BEGIN IMMEDIATE`)."""
        # No granted create (C46): only PENDING requests enter the store.
        if request.state is not ApprovalState.PENDING:
            raise ValidationError("approval requests are created only as pending")
        conn = self._conn_factory()
        try:
            with _writing(conn):
                if conn.execute(
                    _OPEN_IN_WINDOW_SQL, (request.window_id, _to_us(request.created_at))
                ).fetchone():
                    raise ConflictError("this window already has an open approval request")
                try:
                    conn.execute(
                        _INSERT_SQL,
                        (
                            request.id,
                            request.window_id,
                            request.kind.value,
                            _action_value(request),
                            request.action_target,
                            request.action_text,
                            request.message_id,
                            request.state.value,
                            _to_us(request.created_at),
                            _to_us(request.expires_at),
                            _to_us(request.updated_at),
                            None,
                            None,
                            None,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise AlreadyExistsError("approval request already exists") from exc
        finally:
            conn.close()

    def get(self, approval_id: ApprovalId) -> ApprovalRequest:
        """See `ApprovalStore.get`."""
        conn = self._conn_factory()
        try:
            row = conn.execute(_SELECT_BY_ID_SQL, (approval_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            raise NotFoundError("approval request not found")
        return _load(row)

    def save(self, request: ApprovalRequest, *, expected_updated_at: datetime) -> None:
        """See `ApprovalStore.save` (read, CAS + successor check, write: one transaction)."""
        expected = ensure_utc(expected_updated_at, "expected_updated_at")
        conn = self._conn_factory()
        try:
            with _writing(conn):
                row = conn.execute(_SELECT_BY_ID_SQL, (request.id,)).fetchone()
                if row is None:
                    raise NotFoundError("approval request not found")
                stored = _load(row)
                if stored.updated_at != expected:
                    raise ConflictError("approval request was changed concurrently")
                check_successor(stored, request)
                cur = conn.execute(
                    _UPDATE_SQL,
                    (
                        request.state.value,
                        _to_us(request.updated_at),
                        _optional_us(request.tapped_at),
                        _optional_us(request.approved_at),
                        _optional_us(request.resolved_at),
                        request.id,
                        _to_us(expected),
                        request.action_text,
                        request.kind.value,
                        _action_value(request),
                        request.action_target,
                        request.window_id,
                    ),
                )
                if cur.rowcount != 1:  # pragma: no cover - same write lock as the read
                    raise ConflictError("approval request was changed concurrently")
        finally:
            conn.close()

    def find_consumed(
        self,
        window_id: WindowId,
        action_kind: ActionKind,
        action_target: str,
        *,
        consumed_since: datetime,
    ) -> ApprovalRequest | None:
        """See `ApprovalStore.find_consumed`; a tampered row never matches (fail closed)."""
        since_us = _to_us(ensure_utc(consumed_since, "consumed_since"))
        if not isinstance(action_kind, ActionKind):
            raise ValidationError("action_kind must be an ActionKind")
        kind_value = action_kind.value
        conn = self._conn_factory()
        try:
            rows = conn.execute(
                _FIND_CONSUMED_SQL, (window_id, kind_value, action_target, since_us)
            ).fetchall()
        finally:
            conn.close()
        for row in rows:
            try:
                request = _load(row)
            except ValidationError:
                _log.warning("skipping invalid approval row %s", _log_id(row[0]))
                continue
            if request.covers(action_kind, action_target):
                return request
        return None

    def list_open(self, window_id: WindowId | None = None) -> builtins.list[ApprovalRequest]:
        """See `ApprovalStore.list_open`; tampered rows are skipped (id logged)."""
        conn = self._conn_factory()
        try:
            with _reading(conn):
                if window_id is None:
                    rows = conn.execute(_LIST_OPEN_ALL_SQL).fetchall()
                else:
                    rows = conn.execute(_LIST_OPEN_WINDOW_SQL, (window_id,)).fetchall()
        finally:
            conn.close()
        return self._load_all(rows)

    def list_expirable(self, now: datetime) -> builtins.list[ApprovalRequest]:
        """See `ApprovalStore.list_expirable`; tampered rows are skipped (id logged)."""
        at_us = _to_us(ensure_utc(now, "now"))
        conn = self._conn_factory()
        try:
            rows = conn.execute(_LIST_EXPIRABLE_SQL, (at_us,)).fetchall()
        finally:
            conn.close()
        return self._load_all(rows)

    def delete_expired_before(self, cutoff: datetime) -> int:
        """See `ApprovalStore.delete_expired_before`."""
        cutoff_us = _to_us(ensure_utc(cutoff, "cutoff"))
        conn = self._conn_factory()
        try:
            with _writing(conn):
                cur = conn.execute(_DELETE_EXPIRED_BEFORE_SQL, (cutoff_us,))
            return cur.rowcount
        finally:
            conn.close()

    @staticmethod
    def _load_all(rows: builtins.list[_Row]) -> builtins.list[ApprovalRequest]:
        out: builtins.list[ApprovalRequest] = []
        for row in rows:
            try:
                out.append(_load(row))
            except ValidationError:
                _log.warning("skipping invalid approval row %s", _log_id(row[0]))
        return out
