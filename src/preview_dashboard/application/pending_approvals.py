"""Pending approvals, read only, for the viewer (security.md §15.1a M2: phone vs dashboard check).

The admin writes a sanitized snapshot of open approvals (M5b); the viewer never
opens the Claudia database (S1). This service validates that snapshot
strictly and keeps only entries that are still open and unexpired. Anything
missing or malformed means "nothing can be confirmed here" (`available` false,
no entries): fail closed, so the owner never sees a request vouched for that
the admin did not write.

Snapshot format v1 (UTF-8 JSON, ≤ 256 KiB):
`{"version": 1, "approvals": [{"id": <ULID>, "action_text": str ≤ 200,
"kind": <ActionKind value> | null, "target": str ≤ 200 | null,
"state": "pending" | "tapped" | "approved", "expires_at": ISO-8601 UTC}]}`
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from preview_dashboard.domain.approvals import (
    ACTION_TARGET_MAX_CHARS,
    ACTION_TEXT_MAX_CHARS,
    ActionKind,
    ApprovalState,
)
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.kb_source import ApprovalsSnapshotSource

SNAPSHOT_VERSION = 1
MAX_ENTRIES = 50
_ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
_OPEN = frozenset({ApprovalState.PENDING, ApprovalState.TAPPED, ApprovalState.APPROVED})
_KINDS = frozenset(kind.value for kind in ActionKind)
_FIELDS = frozenset({"id", "action_text", "kind", "target", "state", "expires_at"})
_TOP_FIELDS = frozenset({"version", "approvals"})


@dataclass(frozen=True, slots=True)
class PendingApproval:
    """One open approval as the admin recorded it (text is untrusted, shown as text)."""

    id: str
    action_text: str
    kind: str | None
    target: str | None
    state: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PendingApprovals:
    """`available` False: no valid snapshot (absent, unsafe or malformed)."""

    available: bool
    approvals: tuple[PendingApproval, ...]


_UNAVAILABLE = PendingApprovals(available=False, approvals=())


def _text(value: object, limit: int) -> str | None:
    """A non-empty string within `limit` characters, free of control characters."""
    if not isinstance(value, str) or not 0 < len(value) <= limit:
        return None
    if any(ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0 for char in value):
        return None
    return value


def _expiry(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo is not None else None


def _entry(raw: object) -> PendingApproval | None:
    """One validated entry, or None (the whole snapshot is then refused)."""
    if not isinstance(raw, dict) or set(raw) != _FIELDS:
        return None
    approval_id, state = raw["id"], raw["state"]
    action_text = _text(raw["action_text"], ACTION_TEXT_MAX_CHARS)
    kind, target = raw["kind"], raw["target"]
    expires_at = _expiry(raw["expires_at"])
    if not isinstance(approval_id, str) or _ULID_RE.fullmatch(approval_id) is None:
        return None
    if not isinstance(state, str) or state not in _OPEN or action_text is None:
        return None
    if kind is not None and (not isinstance(kind, str) or kind not in _KINDS):
        return None
    if target is not None and _text(target, ACTION_TARGET_MAX_CHARS) is None:
        return None
    if expires_at is None:
        return None
    return PendingApproval(
        id=approval_id,
        action_text=action_text,
        kind=kind,
        target=target,
        state=state,
        expires_at=expires_at,
    )


class PendingApprovalsService:
    """Reads and validates the snapshot on every call (no cache: it changes often).

    Args:
        source: the snapshot file, or None when none is configured (always unavailable).
        clock: "now", to drop entries past `expires_at` even if the file is stale.
    """

    def __init__(self, source: ApprovalsSnapshotSource | None, clock: Clock) -> None:
        self._source = source
        self._clock = clock

    def current(self) -> PendingApprovals:
        """The open, unexpired approvals, soonest expiry first; never raises."""
        raw = self._source.read() if self._source is not None else None
        if raw is None:
            return _UNAVAILABLE
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return _UNAVAILABLE
        if not isinstance(data, dict) or set(data) != _TOP_FIELDS:
            return _UNAVAILABLE
        version, entries = data["version"], data["approvals"]
        # `type(...) is int`: JSON `true` would otherwise compare equal to 1.
        if type(version) is not int or version != SNAPSHOT_VERSION:
            return _UNAVAILABLE
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            return _UNAVAILABLE
        parsed = [_entry(entry) for entry in entries]
        # One bad entry spoils the file: a partial list could hide what the phone shows.
        if any(entry is None for entry in parsed):
            return _UNAVAILABLE
        now = self._clock.now()
        open_ones = sorted(
            (entry for entry in parsed if entry is not None and entry.expires_at > now),
            key=lambda entry: (entry.expires_at, entry.id),
        )
        return PendingApprovals(available=True, approvals=tuple(open_ones))
