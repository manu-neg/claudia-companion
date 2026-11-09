"""OwnerUpdateRouter: routes the owner's Telegram updates to the admin (ADR 0031, C44, C46, C47).

Plugs into `DeliveryService` as its `AnswerSource`: each poll reads one
batch from the single `getUpdates` poller and, in update order, passes
answer taps back to the service (unchanged C34 flow), records approval taps
(`/v1/notifier/approvals`, fixed toast; a recorded Approve also gets the
fixed "send your authenticator code" message), hands codes to `/v1/notifier/codes`
and **always** deletes the code message afterwards (a failed delete is
retried with backoff for up to ~47 h, Telegram's delete window; if it never
succeeds the owner gets one fixed "could not be deleted" notice), and
stores owner texts in the inbox (`/v1/notifier/messages`). A code the admin
reports as `duplicate` gets one fixed "code not checked" notice. An owner
text the admin could not take is fetched again (offset rewound, the rest
of the batch with it) after the runner's backoff; the admin stores it once
(idempotent). Logs carry update ids, results and exception type names
only, never text or codes.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

from preview_dashboard.adapters.admin_queue import AdminQueueError
from preview_dashboard.adapters.telegram.answers import ApprovalTap
from preview_dashboard.adapters.telegram.client import TelegramError
from preview_dashboard.adapters.telegram.updates import InboundEvent, OwnerCode, OwnerText
from preview_dashboard.application.delivery import ACK_NOT_RECORDED
from preview_dashboard.ports.notify import AnswerEvent
from preview_dashboard.wire.notifier_messages import (
    TAP_ACK_TEXTS,
    ApprovalTapSubmission,
    CodeResult,
    CodeSubmission,
    MessageResult,
    MessageSubmission,
    OwnerNotice,
    TapResult,
)

# The admin refused the message itself (shape, owner id, length): retrying
# the same update would be refused forever, so it is dropped (logged by id).
# 401/403 (token scope) are configuration errors and are retried.
DROP_STATUSES: Final = frozenset({400, 413, 422})
# A message that keeps failing would hold back every later update (they are
# re-read behind it): give up on it after this many tries (~2 min of runner backoff).
MAX_STORE_ATTEMPTS: Final = 8

# Code-message delete retries (S-C1 S5): a code left in the chat is readable
# by anyone holding the phone, so a failed delete (429, network, 5xx) is
# retried, doubling from 30 s up to 1 h between tries. Telegram lets a bot
# delete private-chat messages for 48 h; the last try is at 47 h.
DELETE_RETRY_FIRST_SECONDS: Final = 30.0
DELETE_RETRY_MAX_SECONDS: Final = 3600.0
DELETE_GIVE_UP_SECONDS: Final = 47 * 3600.0
# Bounded memory; codes arrive at most a few per approval.
MAX_PENDING_DELETES: Final = 64

_log = logging.getLogger(__name__)


class InboundUpdates(Protocol):
    """The update poller (`adapters/telegram/updates.TelegramUpdateSource`)."""

    @property
    def name(self) -> str: ...

    def poll(self, timeout: float) -> list[InboundEvent]:
        """Long-poll; return accepted events in update order."""
        ...

    def rewind(self, update_id: int) -> None:
        """Fetch `update_id` and later updates again on the next poll."""
        ...

    def ack(self, handle: str, text: str) -> None:
        """Show `text` as a tap's toast."""
        ...


class OwnerUpdatesAdmin(Protocol):
    """The admin's owner-update routes (`adapters/admin_queue.AdminDeliveryQueue`)."""

    def submit_message(self, submission: MessageSubmission) -> MessageResult:
        """Store one owner text (idempotent); raise on failure."""
        ...

    def submit_approval_tap(self, submission: ApprovalTapSubmission) -> TapResult:
        """Record one approval tap; raise on failure."""
        ...

    def submit_code(self, submission: CodeSubmission) -> CodeResult:
        """Check one authenticator code; raise on failure."""
        ...


class OwnerChat(Protocol):
    """The fixed chat actions of this path (`TelegramChannel`), owner's chat only."""

    def delete_message(self, message_id: int) -> None:
        """Delete `message_id` (code messages); "not found" counts as deleted; raise on failure."""
        ...

    def send_code_prompt(self) -> None:
        """Send the fixed "send your authenticator code" text; raise on failure."""
        ...

    def send_notice(self, notice: OwnerNotice) -> None:
        """Send one fixed `OwnerNotice` text; raise on failure."""
        ...


class InboxUnavailableError(RuntimeError):
    """An owner message was not stored; it is fetched again after the runner's backoff."""


@dataclass(slots=True)
class _PendingDelete:
    """A code message whose delete failed; times are monotonic seconds."""

    message_id: int
    first_failed: float
    next_try: float
    delay: float


def _retry_after(exc: Exception) -> float:
    after = exc.retry_after if isinstance(exc, TelegramError) else None
    return float(after) if after is not None and after > 0 else 0.0


def _is_permanent(exc: Exception) -> bool:
    # A bad id, or Telegram's 400 ("message can't be deleted"): retrying won't help.
    # "message not found" never gets here: the channel counts it as deleted.
    return isinstance(exc, ValueError) or (isinstance(exc, TelegramError) and exc.status == 400)


class OwnerUpdateRouter:
    """The notifier's `AnswerSource` once owner messages are on.

    Args:
        updates: the single update poller.
        admin: the admin's notifier routes (notifier token).
        chat: deletes code messages, sends the fixed code prompt and notices.
        monotonic: clock for delete retries (injectable for tests).
    """

    def __init__(
        self,
        updates: InboundUpdates,
        admin: OwnerUpdatesAdmin,
        chat: OwnerChat,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._updates = updates
        self._admin = admin
        self._chat = chat
        self._monotonic = monotonic
        self._retry_due = False
        self._failures: tuple[int, int] = (-1, 0)  # (update id, failed tries)
        # In memory only: a notifier restart forgets them (logged when queued).
        self._pending_deletes: list[_PendingDelete] = []
        # The answer source name reported with answers and taps (`telegram`).
        self.name: str = updates.name

    @property
    def pending_deletes(self) -> int:
        """How many code messages are waiting for a delete retry."""
        return len(self._pending_deletes)

    def poll(self, timeout: float) -> list[AnswerEvent]:
        """Retry due code deletes, read one batch, route everything but answer taps.

        Returns the answer taps.

        Raises:
            InboxUnavailableError: an owner message could not be stored (it
                will be re-read), so the runner backs off before the next poll.
            TelegramError: the poll itself failed.
        """
        self._retry_deletes()
        if self._retry_due:
            # A message failed last round but answers had to go out first:
            # back off now, before re-reading it.
            self._retry_due = False
            raise InboxUnavailableError("owner message not stored; retrying")
        answers: list[AnswerEvent] = []
        for event in self._updates.poll(timeout):
            if isinstance(event, AnswerEvent):
                answers.append(event)
            elif isinstance(event, ApprovalTap):
                self._tap(event)
            elif isinstance(event, OwnerCode):
                self._code(event)
            elif not self._store(event):
                # Later updates of this batch come again with it, in order.
                self._updates.rewind(event.update_id)
                if answers:
                    self._retry_due = True
                    return answers
                raise InboxUnavailableError("owner message not stored; retrying")
        return answers

    def ack(self, handle: str, text: str) -> None:
        """Show `text` as an answer tap's toast (delegates to the poller).

        Raises:
            ValueError / TelegramError: see `TelegramUpdateSource.ack`.
        """
        self._updates.ack(handle, text)

    # --- internals ---------------------------------------------------------------

    def _store(self, event: OwnerText) -> bool:
        """True once the inbox has the message (or it is given up for good)."""
        try:
            result = self._admin.submit_message(event.submission)
        except Exception as exc:
            status = exc.status if isinstance(exc, AdminQueueError) else None
            if status in DROP_STATUSES:
                _log.warning("owner message %d refused by the admin; dropped", event.update_id)
                return True
            update_id, tries = self._failures
            tries = tries + 1 if update_id == event.update_id else 1
            self._failures = (event.update_id, tries)
            if tries >= MAX_STORE_ATTEMPTS:
                _log.error(
                    "owner message %d not stored after %d tries (%s); dropped",
                    event.update_id,
                    tries,
                    type(exc).__name__,
                )
                return True
            _log.warning("owner message %d not stored (%s)", event.update_id, type(exc).__name__)
            return False
        _log.info("owner message %d: %s", event.update_id, result)
        return True

    def _tap(self, tap: ApprovalTap) -> None:
        text = ACK_NOT_RECORDED
        result: TapResult | None = None
        try:
            result = self._admin.submit_approval_tap(
                ApprovalTapSubmission(
                    request_id=tap.request_id,
                    decision=tap.decision,
                    source=self.name,
                    actor_ref=tap.actor_ref,
                )
            )
            text = TAP_ACK_TEXTS[result]
        except Exception as exc:
            # Not recorded: the owner taps again (the first tap wins anyway).
            _log.warning("approval tap not recorded (%s)", type(exc).__name__)
        try:
            self._updates.ack(tap.ack_handle, text)
        except Exception as exc:
            _log.warning("approval tap ack failed (%s)", type(exc).__name__)
        if result is TapResult.TAPPED:
            # Toasts vanish after seconds; the code request stays in the chat.
            try:
                self._chat.send_code_prompt()
            except Exception as exc:
                _log.warning("code prompt not sent (%s)", type(exc).__name__)

    def _code(self, event: OwnerCode) -> None:
        # Never retried: a re-sent code could count as a replay; the owner
        # sends a fresh one. The message is deleted whatever happened (C47).
        result: CodeResult | None = None
        try:
            result = self._admin.submit_code(event.submission)
            _log.info("code message %d: %s", event.update_id, result)
        except Exception as exc:
            _log.warning("code message %d not checked (%s)", event.update_id, type(exc).__name__)
        finally:
            self._delete_code(event.submission.message_id, event.update_id)
        if result is CodeResult.DUPLICATE:
            # Otherwise the owner waits for an approval that never comes.
            self._notice(OwnerNotice.CODE_NOT_CHECKED)

    def _delete_code(self, message_id: int, update_id: int) -> None:
        try:
            self._chat.delete_message(message_id)
        except Exception as exc:
            _log.warning("code message %d not deleted (%s)", update_id, type(exc).__name__)
            if _is_permanent(exc):
                self._notice(OwnerNotice.CODE_NOT_DELETED)
            elif len(self._pending_deletes) >= MAX_PENDING_DELETES:
                _log.error("code message %d: delete retry queue full; given up", update_id)
                self._notice(OwnerNotice.CODE_NOT_DELETED)
            else:
                now = self._monotonic()
                delay = max(DELETE_RETRY_FIRST_SECONDS, _retry_after(exc))
                self._pending_deletes.append(
                    _PendingDelete(
                        message_id=message_id,
                        first_failed=now,
                        next_try=now + delay,
                        delay=DELETE_RETRY_FIRST_SECONDS,
                    )
                )

    def _retry_deletes(self) -> None:
        if not self._pending_deletes:
            return
        now = self._monotonic()
        still: list[_PendingDelete] = []
        for entry in self._pending_deletes:
            if now < entry.next_try:
                still.append(entry)
                continue
            try:
                self._chat.delete_message(entry.message_id)
            except Exception as exc:
                deadline = entry.first_failed + DELETE_GIVE_UP_SECONDS
                if _is_permanent(exc) or now >= deadline:
                    _log.error("code message delete given up (%s)", type(exc).__name__)
                    self._notice(OwnerNotice.CODE_NOT_DELETED)
                    continue
                entry.delay = min(entry.delay * 2, DELETE_RETRY_MAX_SECONDS)
                wait = max(entry.delay, _retry_after(exc))
                # One last try at the deadline rather than a wait past it.
                entry.next_try = min(now + wait, deadline)
                still.append(entry)
                _log.warning("code message delete retry failed (%s)", type(exc).__name__)
            else:
                _log.info("code message deleted on retry")
        self._pending_deletes = still

    def _notice(self, notice: OwnerNotice) -> None:
        try:
            self._chat.send_notice(notice)
        except Exception as exc:
            _log.warning("owner notice %s not sent (%s)", notice, type(exc).__name__)
