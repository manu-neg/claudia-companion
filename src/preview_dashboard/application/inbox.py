"""InboxService (owner free-text messages, C44) and ScreenHealthBoard (host health, C45).

The notifier posts the owner's messages; the admin re-checks the sender
against its **own** configured owner chat id (never the notifier's word),
stores the text verbatim apart from the code-run redaction, idempotently on
Telegram `update_id` + `message_id`, and wakes Claudia's long-poll. The
`claudia` token reads unhandled messages and marks them handled (CAS).
Message text is never logged. Pure core: ports only.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from preview_dashboard.application.notify import new_ulid
from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.domain.owner_messages import (
    OwnerMessage,
    OwnerMessageId,
    parse_owner_message_id,
    redact_code_runs,
)
from preview_dashboard.ports.claudia import ChangeEvents
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.owner_messages import OwnerMessageStore

logger = logging.getLogger("preview_dashboard.inbox")


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnerMessageSubmission:
    """One owner message as the notifier reports it (raw values; re-checked here).

    The notifier checked `from.id == chat.id`, the private chat and the
    bot flag; it reports the sender, which the admin compares with its own
    configured owner. `text` and `quote_text` are excluded from `repr` (C29).
    """

    update_id: int
    telegram_message_id: int
    sender_id: int
    text: str = field(repr=False)
    is_forwarded: bool = False
    reply_to_message_id: int | None = None
    quote_text: str | None = field(default=None, repr=False)


class ReceiveResult(StrEnum):
    """`stored` for a new message, `duplicate` for a re-delivered update."""

    STORED = "stored"
    DUPLICATE = "duplicate"


class InboxService:
    """Owner-message inbox behind `/v1/notifier/messages` and `/v1/claudia/messages`.

    Args:
        messages: the inbox store.
        clock: time source.
        ids: ULID source for message ids.
        owner_chat_id: the configured owner (None = notifications off: every
            message refused).
        events: wakes Claudia's long-poll on a new message (optional).
    """

    def __init__(
        self,
        *,
        messages: OwnerMessageStore,
        clock: Clock,
        ids: IdGenerator,
        owner_chat_id: int | None,
        events: ChangeEvents | None = None,
    ) -> None:
        self._messages = messages
        self._clock = clock
        self._ids = ids
        self._owner = owner_chat_id
        self._events = events

    def receive(self, submission: OwnerMessageSubmission) -> tuple[ReceiveResult, OwnerMessage]:
        """Store one owner message (or find the one already stored for this update).

        Raises:
            ValidationError: the sender is not the configured owner (fail
                closed; also when no owner is configured), an authenticator
                code (it belongs on the code route), or any `OwnerMessage`
                invariant.
        """
        sender = submission.sender_id
        is_owner = (
            isinstance(sender, int)
            and not isinstance(sender, bool)
            and self._owner is not None
            and sender == self._owner
        )
        if not is_owner:
            logger.warning("owner message refused: sender is not the configured owner")
            raise ValidationError("message is not from the configured owner")
        # The notifier sends text already redacted (so possibly > 4096 chars):
        # redact again (idempotent) and let the constructor apply the stored bounds.
        text, quote = submission.text, submission.quote_text
        message = OwnerMessage(
            id=OwnerMessageId(new_ulid(self._ids)),
            update_id=submission.update_id,
            telegram_message_id=submission.telegram_message_id,
            text=redact_code_runs(text) if isinstance(text, str) else text,
            received_at=self._clock.now(),
            is_forwarded=submission.is_forwarded,
            reply_to_message_id=submission.reply_to_message_id,
            quote_text=redact_code_runs(quote) if isinstance(quote, str) else quote,
        )
        stored = self._messages.add(message)
        if stored.id != message.id:
            logger.info("owner message duplicate: id=%s", stored.id)
            return ReceiveResult.DUPLICATE, stored
        logger.info("owner message stored: id=%s forwarded=%s", stored.id, stored.is_forwarded)
        if self._events is not None:
            self._events.notify()
        return ReceiveResult.STORED, stored

    def unhandled(self, limit: int) -> list[OwnerMessage]:
        """Up to `limit` (1..100) RECEIVED messages, oldest first.

        Raises:
            ValidationError: `limit` out of range.
        """
        return self._messages.list_unhandled(limit)

    def mark_handled(self, message_id: str) -> OwnerMessage:
        """Mark a message handled (CAS: each message is processed once, C58).

        Raises:
            NotFoundError: malformed or unknown id.
            InvalidStateError: already handled.
        """
        try:
            parsed = parse_owner_message_id(message_id)
        except ValidationError:
            raise NotFoundError("no such owner message") from None
        return self._messages.mark_handled(parsed, self._clock.now())


class ScreenHealth(StrEnum):
    """The host's screening pipeline state (C48): `ok`, `degraded` or `down`."""

    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass(frozen=True, slots=True)
class HealthReport:
    """The latest screen health the host reported, and when."""

    screen: ScreenHealth
    reported_at: datetime


class ScreenHealthBoard:
    """In-memory latest screen-health report from the host (`claudia` token, C45).

    Advisory status only (shown later by `/status` and the viewer); it
    grants nothing, so a restart forgetting it is harmless.
    """

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._latest: HealthReport | None = None

    def report(self, screen: ScreenHealth) -> HealthReport:
        """Record a report now and return it."""
        report = HealthReport(screen=ScreenHealth(screen), reported_at=self._clock.now())
        with self._lock:
            self._latest = report
        if report.screen is not ScreenHealth.OK:
            logger.warning("claudia screen health: %s", report.screen)
        return report

    def latest(self) -> HealthReport | None:
        """The last report, or None if the host never reported."""
        with self._lock:
            return self._latest
