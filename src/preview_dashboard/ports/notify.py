"""Notification ports: the admin-side outbox and the notifier-side plug-ins (ADR 0021).

Admin side: `NotificationOutbox` (persistence of notifications and their
deliveries) and `OutboxEvents` (wakes the notifier's long-poll). Notifier
side, which has no database: `DeliveryQueue` (the admin API as seen by the
notifier), `NotificationChannel` (e.g. Telegram), `AnswerSource` (button
taps). Contract suite for the outbox: `tests/contracts/` (unit N2).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from preview_dashboard.domain.notifications import (
    DeliveryPayload,
    DeliveryTask,
    Notification,
    PendingTask,
    TaskId,
)
from preview_dashboard.domain.questions import AnswerResult, QuestionId

# --- admin side ---------------------------------------------------------------


class NotificationOutbox(Protocol):
    """Transactional outbox of notifications and their per-channel deliveries.

    Shares its store with `QuestionRepository` (question notifications and
    RESOLVE tasks are written through it, atomically with the question).

    Delivery rules (normative; the fake in `tests/fakes.py` is the reference):
    - a task is due when PENDING and `next_attempt_at <= now`;
    - a RESOLVE is handed out only once the SEND of the same notification
      and channel is DONE with a `message_ref`, which `pending` returns as
      the RESOLVE's `message_ref`; while that SEND is PENDING the RESOLVE
      waits; if the SEND is missing, FAILED or DONE without a ref, `pending`
      marks the RESOLVE FAILED (dropped) instead of returning it;
    - `mark_done`/`mark_failed` on a task that is no longer PENDING change
      nothing (idempotent retries from the notifier).
    """

    def add(self, notification: Notification, tasks: Sequence[DeliveryTask]) -> None:
        """Insert a non-question notification and its SEND tasks atomically.

        Raises:
            AlreadyExistsError: the notification or a task id exists.
            ValidationError: `notification.question_id` is set (question
                notifications go through `QuestionRepository.add_with_notification`)
                or a task belongs to another notification.
        """
        ...

    def pending(self, now: datetime, limit: int) -> list[PendingTask]:
        """Return up to `limit` (1..100) due tasks by `(next_attempt_at, created_at, id)`.

        Raises:
            ValidationError: `limit` out of range.
        """
        ...

    def get_task(self, task_id: TaskId) -> DeliveryTask:
        """Return a stored task in any state.

        Raises:
            NotFoundError: no such task.
        """
        ...

    def mark_done(self, task_id: TaskId, message_ref: str | None) -> DeliveryTask:
        """Record a successful delivery (`DeliveryTask.done`); return the stored task.

        Raises:
            NotFoundError: no such task.
            ValidationError: malformed `message_ref`.
        """
        ...

    def mark_failed(self, task_id: TaskId, *, now: datetime) -> DeliveryTask:
        """Record a failed try (`DeliveryTask.failed_attempt(now)`: backoff, FAILED after 8).

        The backoff policy lives in the domain, never in the adapter.

        Raises:
            NotFoundError: no such task.
        """
        ...

    def notification_for_question(self, question_id: QuestionId) -> Notification | None:
        """Return the question's notification, or None (none stored / already purged)."""
        ...

    def message_ref_for(self, question_id: QuestionId, channel: str) -> str | None:
        """Return the `message_ref` of the question's DONE SEND on `channel`, or None."""
        ...

    def delete_before(self, cutoff: datetime) -> int:
        """Delete notifications with `created_at < cutoff` and all their tasks.

        Returns:
            How many notifications were deleted.
        """
        ...


class OutboxEvents(Protocol):
    """In-process wake-up for the notifier's long-poll (`GET /notifier/tasks?wait=`).

    Advisory like `QuestionEvents`: waiters re-read the outbox after waking.
    """

    def notify(self) -> None:
        """Wake every waiter. Call after committing new tasks; thread-safe, never raises."""
        ...

    async def wait(self, timeout: float) -> bool:
        """Wait up to `timeout` seconds for `notify()`; True if notified."""
        ...


# --- notifier side ------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class AnswerEvent:
    """One button tap as reported by an `AnswerSource`.

    `question_id` and `key` are **untrusted** (they come back from the
    channel's callback data) and are validated by the admin, never here.
    The source has already checked who tapped (owner chat id, C34).

    Attributes:
        question_id: raw question id from the callback.
        key: raw option key from the callback.
        actor_ref: who tapped (e.g. Telegram user id), for logs only.
        ack_handle: opaque handle to acknowledge the tap (callback query id).
    """

    question_id: str
    key: str
    actor_ref: str
    ack_handle: str


class NotificationChannel(Protocol):
    """Delivers messages to the owner on one channel (e.g. Telegram).

    Implementations send plain text only (no markup, C35), never log the
    content or their credentials, and raise on failure (any exception makes
    the task retry with backoff).
    """

    name: str

    def send(self, payload: DeliveryPayload) -> str | None:
        """Post a new message; return its channel reference (<= 64 visible ASCII) or None."""
        ...

    def resolve(self, message_ref: str, payload: DeliveryPayload) -> None:
        """Replace message `message_ref` with `payload` (the outcome) and drop its buttons."""
        ...


class AnswerSource(Protocol):
    """Yields the owner's button taps (e.g. Telegram callback queries).

    Must drop anything not from the configured owner before returning it.
    """

    name: str

    def poll(self, timeout: float) -> list[AnswerEvent]:
        """Block up to `timeout` seconds; return the taps received (maybe none)."""
        ...

    def ack(self, handle: str, text: str) -> None:
        """Show `text` to the tapper as the tap's acknowledgement."""
        ...


class DeliveryQueue(Protocol):
    """The admin API as seen by the notifier (scoped notifier token; blocking calls).

    Every method raises on transport/auth errors; the notifier loop backs off.
    """

    def pending(self, wait: float) -> list[PendingTask]:
        """Long-poll up to `wait` seconds for due tasks; return them (maybe none)."""
        ...

    def done(self, task_id: TaskId, message_ref: str | None) -> None:
        """Report a task delivered."""
        ...

    def failed(self, task_id: TaskId) -> None:
        """Report a failed try (the admin applies backoff)."""
        ...

    def submit_answer(
        self, question_id: str, key: str, source: str, actor_ref: str
    ) -> AnswerResult:
        """Submit one tap; the admin validates everything and returns the outcome."""
        ...
