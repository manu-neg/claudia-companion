"""Ports of the admin's Claudia services: wake-ups and outbound Telegram messages (ADR 0031).

`ChangeEvents` wakes long-polls (inbox, approval state) in-process;
`ApprovalPrompts`, `ApprovalResolutions` and `ReplyOutbox` hand an
approval's Approve/Deny message, its outcome edit (F-CL5) and Claudia's
replies to the notification outbox (the delivery side is
unit M2's). Implementations receive only values the application already
validated and secret-scanned (C35, C46, C56).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from preview_dashboard.domain.approvals import ApprovalRequest
from preview_dashboard.domain.models import ItemId
from preview_dashboard.domain.owner_messages import OwnerMessageId


class ChangeEvents(Protocol):
    """An in-process "something changed" signal for long-polls (advisory: waiters re-read)."""

    def notify(self) -> None:
        """Wake every waiter (thread-safe, never raises)."""
        ...

    async def wait(self, timeout: float) -> bool:
        """Wait up to `timeout` s for `notify()`; True if woken."""
        ...


class ApprovalPrompts(Protocol):
    """Queues the Telegram message showing an approval request with Approve / Deny."""

    def prompt(self, request: ApprovalRequest) -> None:
        """Queue the Approve/Deny message for a new PENDING `request`.

        Raises:
            StorageUnavailableError: delivery is not available (the request
                is then cancelled by the caller: fail closed).
        """
        ...


class ApprovalResolutions(Protocol):
    """Queues the edit of a decided request's Telegram prompt (F-CL5, C46)."""

    def resolve(self, request: ApprovalRequest) -> None:
        """Queue the fixed outcome edit (buttons removed) for a decided `request`.

        Best effort: the caller has already stored the decision and must
        never let this undo or block it.

        Raises:
            ValidationError: `request` is not decided (PENDING / TAPPED).
            StorageUnavailableError: the outbox can't be written right now.
        """
        ...


class ReplyOutbox(Protocol):
    """Queues one of Claudia's `reply` messages (text already validated and scanned)."""

    def queue_reply(
        self,
        text: str,
        *,
        item_id: ItemId | None,
        message_id: OwnerMessageId | None,
        before_visible: Callable[[str], None] | None = None,
    ) -> str:
        """Queue `text` (<= 4096 chars) with an optional dashboard item link; return its id.

        `before_visible(id)` runs once the id exists but before the task is stored
        or the notifier woken (voice: save the audio first, voice-1).

        Raises:
            StorageUnavailableError: delivery is not available.
        """
        ...
