"""ApprovalStore port: approval requests bound to one action (ADR 0031, C46, C59).

Contract suite: `tests/contracts/approval_store.py`, run against the fake
and the SQLite adapter.

Security obligations for every implementation (docs/security.md C24, C46):
- **Parameterized queries only**; action text and target round-trip unchanged.
- **Re-validate on read:** rebuild `ApprovalRequest` through its constructor;
  batch reads skip a row that fails (logged by id only).
- **No granted create:** `add` accepts PENDING requests only.
- **`save` is a compare-and-swap** on `updated_at` *and* applies
  `domain.approvals.check_successor` to the stored row under the same
  lock, so the first writer wins, no step is skipped and the bound action
  never changes.
- **At most one open request per window**, checked atomically with the insert.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalRequest,
    WindowId,
)


class ApprovalStore(Protocol):
    """Stores approval requests (whole values; `get` returns what was last stored)."""

    def add(self, request: ApprovalRequest) -> None:
        """Insert a new PENDING request.

        Raises:
            ValidationError: `request` is not PENDING (no granted create).
            AlreadyExistsError: the id exists.
            ConflictError: its window already has an open request that is
                not expired at `request.created_at`.
        """
        ...

    def get(self, approval_id: ApprovalId) -> ApprovalRequest:
        """Return the request with this id, in any state.

        Raises:
            NotFoundError: no such request.
            ValidationError: the stored row fails re-validation.
        """
        ...

    def save(self, request: ApprovalRequest, *, expected_updated_at: datetime) -> None:
        """Replace a stored request with its next state (compare-and-swap).

        Raises:
            NotFoundError: no request with `request.id`.
            ConflictError: the stored `updated_at` != `expected_updated_at`.
            ValidationError / InvalidStateError: `check_successor(stored,
                request)` fails (immutable field changed, illegal step), or
                the stored row fails re-validation.
        """
        ...

    def find_consumed(
        self,
        window_id: WindowId,
        action_kind: ActionKind,
        action_target: str,
        *,
        consumed_since: datetime,
    ) -> ApprovalRequest | None:
        """Return the latest CONSUMED request in `window_id` covering exactly this action.

        Only requests consumed at or after `consumed_since` (the start of
        the run in progress, C59) count; FLAGGED_MESSAGE requests never
        match. Exact, case-sensitive comparison of the normalized target.

        Raises:
            ValidationError: `consumed_since` is naive, or `action_kind` is
                not an `ActionKind` (e.g. the classifier's `unknown`).
        """
        ...

    def list_open(self, window_id: WindowId | None = None) -> list[ApprovalRequest]:
        """Return open (PENDING/TAPPED/APPROVED) requests, oldest first (then id).

        `window_id` None = every window (the viewer's read-only list, C46);
        expired-but-not-yet-marked requests are included.
        """
        ...

    def list_expirable(self, now: datetime) -> list[ApprovalRequest]:
        """Return open requests with `expires_at <= now`, soonest first (then id).

        Raises:
            ValidationError: `now` is naive.
        """
        ...

    def delete_expired_before(self, cutoff: datetime) -> int:
        """Delete requests (any state) with `expires_at < cutoff`; return how many.

        Every request expires at most 24 h after creation (legacy rows
        600 s), so anything that expired before the cutoff is long finished
        (housekeeping).

        Raises:
            ValidationError: `cutoff` is naive.
        """
        ...
