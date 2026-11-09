"""Question ports: `QuestionRepository` (persistence) and `QuestionEvents` (wake-ups).

The repository shares its store with `ports.notify.NotificationOutbox`: a
question, its notification and deliveries are written in one transaction
(transactional outbox, ADR 0021). Contract suite: `tests/contracts/`
(unit N2), run against the fake and the SQLite adapter.

Security obligations for every implementation (docs/security.md C24, C34):
- **Parameterized queries only**; prompt, labels and session label are
  untrusted text and must round-trip unchanged.
- **Re-validate on read:** rebuild `Question`/`QuestionOption` through their
  constructors, so a tampered row fails with `ValidationError`.
- **`save` is a compare-and-swap** on `updated_at`: the first answer wins,
  a concurrent second one gets `ConflictError`, never a silent overwrite.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol

from preview_dashboard.domain.notifications import DeliveryTask, Notification
from preview_dashboard.domain.questions import Question, QuestionId


class QuestionRepository(Protocol):
    """Stores questions (whole values; `get` returns what was last added/saved)."""

    def add_with_notification(
        self, question: Question, notification: Notification, tasks: Sequence[DeliveryTask]
    ) -> None:
        """Insert a new question, its notification and its deliveries atomically.

        All or nothing: either every row is stored or none is.

        Raises:
            AlreadyExistsError: the question, notification or a task id exists.
            ValidationError: `notification.question_id != question.id`, or a
                task's `notification_id != notification.id`.
        """
        ...

    def get(self, question_id: QuestionId) -> Question:
        """Return the question with this id, in any state.

        Raises:
            NotFoundError: no such question.
        """
        ...

    def save(
        self,
        question: Question,
        *,
        expected_updated_at: datetime,
        tasks: Sequence[DeliveryTask] = (),
    ) -> None:
        """Replace a stored question (compare-and-swap) and add `tasks`, in one transaction.

        Writes only if the stored `updated_at` still equals
        `expected_updated_at` (checked and written in one transaction);
        `tasks` (the RESOLVE deliveries of a resolution) are inserted in that
        same transaction, so exactly the winning writer enqueues them.

        Raises:
            NotFoundError: no question with `question.id`.
            ConflictError: the stored question changed since it was read.
            AlreadyExistsError: a task id exists (nothing is written).
            ValidationError: a task's notification is not stored or is not
                this question's notification (nothing is written).
        """
        ...

    def list_expirable(self, now: datetime) -> list[Question]:
        """Return OPEN questions with `expires_at <= now`, soonest `expires_at` first (then id)."""
        ...

    def delete_resolved_before(self, cutoff: datetime) -> int:
        """Delete terminal questions with `resolved_at < cutoff`; return how many.

        Purge calls `NotificationOutbox.delete_before` first, so their
        notifications (created no later than they were resolved) are gone.
        """
        ...


class QuestionEvents(Protocol):
    """In-process wake-ups for long-poll waiters (`GET /questions/{id}?wait=`).

    Advisory only: a waiter must re-read the repository after waking (and
    periodically anyway), since a change made by another process (the
    purge job's expiry) signals nothing here.
    """

    def notify(self, question_id: QuestionId) -> None:
        """Wake every waiter on `question_id`. Call **after** the commit.

        Must be thread-safe (services run in worker threads), never block,
        and never raise, also when no event loop or waiter exists.
        """
        ...

    async def wait(self, question_id: QuestionId, timeout: float) -> bool:
        """Wait up to `timeout` seconds for `notify(question_id)`.

        Returns:
            True if notified, False on timeout.
        """
        ...
