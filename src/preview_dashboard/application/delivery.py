"""DeliveryService: the notifier's work, one round at a time (framework-free).

`run_once_deliveries` fetches due tasks from the admin (`DeliveryQueue`),
hands each to its channel and reports the outcome; `run_once_answers`
polls an `AnswerSource` for taps, submits them and acknowledges each with
the result. The process loop and backoff live in `interfaces/notifier/`.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    PendingTask,
    validate_message_ref,
)
from preview_dashboard.domain.questions import AnswerResult
from preview_dashboard.ports.notify import (
    AnswerEvent,
    AnswerSource,
    DeliveryQueue,
    NotificationChannel,
)

_log = logging.getLogger(__name__)

ACK_TEXTS: dict[AnswerResult, str] = {
    AnswerResult.RECORDED: "Recorded: {key}",
    AnswerResult.ALREADY_ANSWERED: "Already answered",
    AnswerResult.EXPIRED: "Expired",
    AnswerResult.CANCELLED: "Withdrawn",
    AnswerResult.UNKNOWN: "Unknown",
}
ACK_NOT_RECORDED = "Not recorded, try again"


def ack_text(result: AnswerResult, key: str) -> str:
    """The acknowledgement shown to the tapper for `result` (key only when recorded)."""
    text = ACK_TEXTS[result]
    return text.format(key=key) if result is AnswerResult.RECORDED else text


class DeliveryService:
    """Moves deliveries to channels and taps back to the admin.

    Logs carry task ids, channel names and exception **type names** only:
    exception text may hold URLs with a bot token or message content (C36).

    Args:
        queue: the admin API (notifier token).
        channels: enabled channels, routed by `name`.
        answers: where taps come from (None: no answer loop).
        wait_seconds: long-poll wait for due tasks.
        poll_seconds: long-poll wait for taps.

    Raises:
        ValueError: duplicate channel names or non-positive waits.
    """

    def __init__(
        self,
        *,
        queue: DeliveryQueue,
        channels: Sequence[NotificationChannel],
        answers: AnswerSource | None = None,
        wait_seconds: float = 60.0,
        poll_seconds: float = 50.0,
    ) -> None:
        by_name = {c.name: c for c in channels}
        if len(by_name) != len(channels):
            raise ValueError("channel names must be unique")
        if wait_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("waits must be > 0")
        self._queue = queue
        self._channels = by_name
        self._answers = answers
        self._wait = wait_seconds
        self._poll = poll_seconds

    def run_once_deliveries(self) -> int:
        """Fetch due tasks (long-poll) and deliver each; return how many were delivered.

        A channel failure marks just that task failed (retried with backoff
        by the admin); queue errors propagate so the caller can back off.
        """
        delivered = 0
        for task in self._queue.pending(self._wait):
            if self._deliver(task):
                delivered += 1
        return delivered

    def run_once_answers(self) -> int:
        """Poll taps, submit each, acknowledge each; return how many were recorded.

        A submit failure (admin down) is acknowledged "Not recorded, try
        again" so the owner taps again; answers are idempotent (first wins).
        """
        if self._answers is None:
            return 0
        recorded = 0
        for event in self._answers.poll(self._poll):
            result = self._submit(self._answers.name, event)
            if result is AnswerResult.RECORDED:
                recorded += 1
            text = ACK_NOT_RECORDED if result is None else ack_text(result, event.key)
            try:
                self._answers.ack(event.ack_handle, text)
            except Exception as exc:
                # The answer itself is stored; a lost ack only costs the toast.
                _log.warning("answer ack failed (%s)", type(exc).__name__)
        return recorded

    # --- internals -----------------------------------------------------------

    def _deliver(self, task: PendingTask) -> bool:
        channel = self._channels.get(task.channel)
        if channel is None:
            _log.warning("task %s: channel %s is not enabled here", task.id, task.channel)
            self._queue.failed(task.id)
            return False
        try:
            ref = self._run_channel(channel, task)
        except Exception as exc:
            _log.warning("task %s on %s failed (%s)", task.id, task.channel, type(exc).__name__)
            self._queue.failed(task.id)
            return False
        self._queue.done(task.id, ref)
        return True

    @staticmethod
    def _run_channel(channel: NotificationChannel, task: PendingTask) -> str | None:
        if task.action is DeliveryAction.RESOLVE:
            if task.message_ref is None:  # PendingTask forbids this; kept for typing
                raise ValidationError("RESOLVE without message_ref")
            channel.resolve(task.message_ref, task.payload)
            return None
        ref = channel.send(task.payload)
        if ref is None:
            return None
        try:
            return validate_message_ref(ref)
        except ValidationError:
            # Sent, but its id is unusable: record the delivery without it
            # (a later RESOLVE is dropped) rather than send it twice.
            _log.warning("task %s: channel returned an invalid message ref", task.id)
            return None

    def _submit(self, source: str, event: AnswerEvent) -> AnswerResult | None:
        """The admin's verdict on one tap, or None if it could not be asked."""
        try:
            return self._queue.submit_answer(event.question_id, event.key, source, event.actor_ref)
        except Exception as exc:
            _log.warning("answer submit failed (%s)", type(exc).__name__)
            return None
