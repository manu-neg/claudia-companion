"""OutboxApprovalPrompts: the `ApprovalPrompts` port over the notification outbox (C46).

One `approval` notification (fixed title, `approval_id` set) plus one SEND
per enabled channel, in one outbox transaction. The message text is the
request's **stored** action text, verbatim (already sanitized and
secret-scanned by `ApprovalService`); the channel adds exactly the fixed
Approve/Deny buttons `p:<id>:ok|no`. Only a PENDING request is prompted,
and the outbox hands the prompt out only while it is still PENDING and
unexpired, re-rendering the text from the stored request at handout (the
outbox row is viewer-writable, storage-totp-1). No channel enabled means
nobody could tap: refused (fail closed). `OutboxApprovalResolutions`
(F-CL5) queues the edit of a decided prompt: one fixed outcome text, no
buttons. Pure core: ports only.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from preview_dashboard.application.notify import new_ulid, send_tasks, validate_channels
from preview_dashboard.domain.approvals import ApprovalRequest, ApprovalState
from preview_dashboard.domain.errors import InvalidStateError, StorageUnavailableError
from preview_dashboard.domain.notifications import (
    Notification,
    NotificationId,
    TaskId,
    approval_outcome_content,
    approval_stored_final_state,
)
from preview_dashboard.events import (
    APPROVAL_EVENT,
    EventRegistry,
    RenderContext,
    default_event_registry,
)
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.notify import ApprovalResolveOutbox, NotificationOutbox, OutboxEvents

# Stored title only (never shown: the prompt's text is the action text).
APPROVAL_TITLE: Final = "Approval request"


class OutboxApprovalPrompts:
    """Queues an approval request's Approve/Deny prompt (implements `ApprovalPrompts`).

    Args:
        outbox: the notification outbox (shared store with the approvals).
        clock: time source for the notification and its tasks.
        ids: ULID source.
        channels: enabled delivery channels (empty: prompts are refused).
        registry: event types (default: the built-ins, incl. `approval`).
        outbox_events: wakes the notifier's long-poll (optional).
    """

    def __init__(
        self,
        *,
        outbox: NotificationOutbox,
        clock: Clock,
        ids: IdGenerator,
        channels: Sequence[str],
        registry: EventRegistry | None = None,
        outbox_events: OutboxEvents | None = None,
    ) -> None:
        self._outbox = outbox
        self._clock = clock
        self._ids = ids
        self._channels = validate_channels(channels)
        self._registry = registry or default_event_registry()
        self._outbox_events = outbox_events

    def prompt(self, request: ApprovalRequest) -> None:
        """Store the prompt notification and its SEND tasks for a PENDING `request`.

        Raises:
            InvalidStateError: `request` is not PENDING (never prompt a decided one).
            StorageUnavailableError: no delivery channel is enabled.
            ValidationError: the rendered message breaks the outgoing policy.
        """
        if request.state is not ApprovalState.PENDING:
            raise InvalidStateError("only a pending approval request is prompted")
        if not self._channels:
            raise StorageUnavailableError("no delivery channel for approval prompts")
        now = self._clock.now()
        kind = self._registry.get(APPROVAL_EVENT)
        notification = Notification(
            id=NotificationId(new_ulid(self._ids)),
            event_type=kind.name,
            title=APPROVAL_TITLE,
            created_at=now,
            approval_id=request.id,
        )
        # The stored text itself (C46: shown verbatim, immutable after create).
        content = kind.render(RenderContext(title=APPROVAL_TITLE, body=request.action_text))
        tasks = send_tasks(
            self._ids,
            notification_id=notification.id,
            channels=self._channels,
            content=content,
            now=now,
        )
        self._outbox.add(notification, tasks)
        if self._outbox_events is not None:
            self._outbox_events.notify()


class OutboxApprovalResolutions:
    """Queues the outcome edit of a decided request's prompt (implements `ApprovalResolutions`).

    One RESOLVE per channel the prompt went out on; the text is the fixed
    text of the outcome (`approval_outcome_content`), and the outbox
    re-derives it from the admin-only request at handout anyway (F-CL5).

    Args:
        outbox: the outbox store that holds the prompt.
        clock: time source for the tasks.
        ids: ULID source.
        outbox_events: wakes the notifier's long-poll (optional; purge has none).
    """

    def __init__(
        self,
        *,
        outbox: ApprovalResolveOutbox,
        clock: Clock,
        ids: IdGenerator,
        outbox_events: OutboxEvents | None = None,
    ) -> None:
        self._outbox = outbox
        self._clock = clock
        self._ids = ids
        self._outbox_events = outbox_events

    def resolve(self, request: ApprovalRequest) -> None:
        """Queue the edit for a decided `request` (no prompt stored: nothing to do).

        Raises:
            ValidationError: `request` is still undecided (PENDING / TAPPED).
            StorageUnavailableError: the outbox can't be written.
        """
        content = approval_outcome_content(request.state)
        added = self._outbox.add_approval_resolves(
            request.id,
            content=content,
            final_state=approval_stored_final_state(request.state),
            now=self._clock.now(),
            new_task_id=lambda: TaskId(new_ulid(self._ids)),
        )
        if added and self._outbox_events is not None:
            self._outbox_events.notify()
