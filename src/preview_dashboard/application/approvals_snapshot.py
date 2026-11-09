"""The admin's pending-approvals snapshot writer (docs/security.md C46 "independent view", M5b).

On every approval change in the admin process (create, tap, approve,
consume, cancel, expiry seen on read) `SnapshotOnChange` asks
`ApprovalsSnapshotWriter` to rewrite one sanitized JSON file the viewer
lists read-only (`application/pending_approvals.py`, unit M8, owns the
format and the reader). Only PENDING and TAPPED (still waiting for the
owner), unexpired requests are written, with
id, action text, action kind, target, state and expiry: never the inbox
message itself or any timestamp besides the expiry. For a flagged-message
request the action text carries a sanitized excerpt of up to 80 characters
of the inbox text (allowed by C46). Expiry only rewrites the file on the
next change, so the reader drops entries past `expires_at` itself
(`application/pending_approvals.py`, tested). More requests than
the reader accepts -> the file is removed (fail closed: no partial list).
Pure core: ports only.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Final

from preview_dashboard.domain.approvals import ApprovalRequest, ApprovalState
from preview_dashboard.ports.approvals import ApprovalStore
from preview_dashboard.ports.approvals_snapshot import ApprovalsSnapshotSink
from preview_dashboard.ports.claudia import ChangeEvents
from preview_dashboard.ports.clock import Clock

_log = logging.getLogger("preview_dashboard.approvals")

# Must equal `application.pending_approvals` (a test keeps them equal).
SNAPSHOT_VERSION: Final = 1
MAX_ENTRIES: Final = 50
_AWAITING_OWNER: Final = frozenset({ApprovalState.PENDING, ApprovalState.TAPPED})


def snapshot_entry(request: ApprovalRequest) -> dict[str, object]:
    """One entry: `id, action_text, kind (action kind | null), target, state, expires_at`."""
    return {
        "id": request.id,
        "action_text": request.action_text,
        "kind": None if request.action_kind is None else request.action_kind.value,
        "target": request.action_target,
        "state": request.state.value,
        "expires_at": request.expires_at.astimezone(UTC).isoformat(),
    }


def build_snapshot(requests: Iterable[ApprovalRequest], now: datetime) -> bytes | None:
    """The snapshot bytes for the open, unexpired `requests` (soonest expiry first).

    Returns:
        UTF-8 JSON, or None when there are more than `MAX_ENTRIES` (the
        reader would refuse it; the caller removes the file instead).
    """
    # Only what still waits for the owner (C46 "independent view"): an APPROVED
    # request (code verified) leaves the panel at once, like a denied one (F-CL3).
    live = sorted(
        (r for r in requests if r.state in _AWAITING_OWNER and not r.is_expired(now)),
        key=lambda r: (r.expires_at, r.id),
    )
    if len(live) > MAX_ENTRIES:
        return None
    body = {"version": SNAPSHOT_VERSION, "approvals": [snapshot_entry(r) for r in live]}
    return json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


class ApprovalsSnapshotWriter:
    """Rewrites the snapshot from the store's open requests (thread-safe, never raises).

    Args:
        store: the approval store (admin-only Claudia DB).
        sink: the snapshot file.
        clock: "now", to leave out requests already past their expiry.
    """

    def __init__(self, *, store: ApprovalStore, sink: ApprovalsSnapshotSink, clock: Clock) -> None:
        self._store = store
        self._sink = sink
        self._clock = clock
        self._lock = threading.Lock()

    def refresh(self) -> bool:
        """Write the current snapshot; False (and the file removed) if that failed."""
        with self._lock:
            try:
                data = build_snapshot(self._store.list_open(), self._clock.now())
                if data is None:
                    _log.warning("approvals snapshot: too many open requests, removed")
                    self._sink.clear()
                    return False
                self._sink.write(data)
                return True
            except Exception as exc:
                # A stale list could vouch for a request that is gone: remove it.
                _log.error("approvals snapshot failed (%s)", type(exc).__name__)
                self._sink.clear()
                return False


class SnapshotOnChange:
    """`ChangeEvents` decorator: wakes the long-polls, then refreshes the snapshot.

    Args:
        inner: the admin's approval change events (long-poll wake-ups).
        writer: the snapshot writer.
    """

    def __init__(self, inner: ChangeEvents, writer: ApprovalsSnapshotWriter) -> None:
        self._inner = inner
        self._writer = writer

    def notify(self) -> None:
        """Wake every waiter first (never delayed by the file), then rewrite; never raises."""
        self._inner.notify()
        self._writer.refresh()

    async def wait(self, timeout: float) -> bool:
        """Delegate to the inner events."""
        return await self._inner.wait(timeout)


__all__ = [
    "MAX_ENTRIES",
    "SNAPSHOT_VERSION",
    "ApprovalsSnapshotWriter",
    "SnapshotOnChange",
    "build_snapshot",
    "snapshot_entry",
]
