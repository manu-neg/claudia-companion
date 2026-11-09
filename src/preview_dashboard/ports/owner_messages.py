"""OwnerMessageStore port: the owner-message inbox Claudia's host reads (ADR 0031, C44).

Contract suite: `tests/contracts/owner_message_store.py`, run against the
fake and the SQLite adapter.

Security obligations for every implementation (docs/security.md C24, C29, C44):
- **Parameterized queries only**; message text is untrusted and must
  round-trip unchanged (verbatim, for the screen).
- **Re-validate on read:** rebuild `OwnerMessage` through its constructor,
  so a tampered row (e.g. a planted code) fails with `ValidationError`;
  batch reads skip such a row (logged by id only).
- **Never log message text** (ids and counts only).
- **Idempotent add** on Telegram `update_id` + `telegram_message_id`.
- **`mark_handled` is a compare-and-swap:** each message is handled once.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from preview_dashboard.domain.owner_messages import OwnerMessage, OwnerMessageId

MAX_UNHANDLED_LIMIT = 100


class OwnerMessageStore(Protocol):
    """Stores owner messages (whole values; `get` returns what was last stored)."""

    def add(self, message: OwnerMessage) -> OwnerMessage:
        """Store a new RECEIVED message, or return the one already stored for its update.

        A re-delivered Telegram update (same `update_id` and
        `telegram_message_id`) stores nothing and returns the stored message
        (whose `id` may differ from `message.id`): callers compare ids to
        tell a new message from a duplicate.

        Raises:
            ValidationError: `message` is not RECEIVED.
            AlreadyExistsError: `message.id` exists for another update.
        """
        ...

    def get(self, message_id: OwnerMessageId) -> OwnerMessage:
        """Return the message with this id, in any state.

        Raises:
            NotFoundError: no such message.
            ValidationError: the stored row fails re-validation.
        """
        ...

    def list_unhandled(self, limit: int) -> list[OwnerMessage]:
        """Return up to `limit` (1..100) RECEIVED messages, oldest `received_at` first (then id).

        Raises:
            ValidationError: `limit` out of range.
        """
        ...

    def mark_handled(self, message_id: OwnerMessageId, at: datetime) -> OwnerMessage:
        """Mark a RECEIVED message HANDLED at `at` (compare-and-swap); return it.

        Raises:
            NotFoundError: no such message.
            InvalidStateError: already HANDLED (another worker won).
            ValidationError: `at` is naive or precedes `received_at`.
        """
        ...

    def delete_received_before(self, cutoff: datetime) -> int:
        """Delete messages (any state) with `received_at < cutoff`; return how many.

        Used by the 30-day inbox housekeeping (C44).

        Raises:
            ValidationError: `cutoff` is naive.
        """
        ...
