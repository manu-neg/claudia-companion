"""OwnerMediaService: the owner's voice notes and photos for Claudia (docs/security.md C61).

Admin side. The notifier hands over one downloaded file per update; this
service re-checks the sender against the admin's **own** owner id and the
kind's switch, validates the bytes **by content** (Ogg/Opus with the
duration from the stream itself; JPEG structure and size with every
APPn/COM segment stripped), stores the checked bytes in the private media
store and adds an inbox row of kind `voice` / `photo` (idempotent on the
Telegram update, like texts). The `claudia` token then fetches the bytes
by message id and releases them when done. Content is never logged.
Pure core: ports only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from preview_dashboard.application.inbox import ReceiveResult
from preview_dashboard.application.notify import new_ulid
from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.domain.owner_media import (
    MessageKind,
    sanitize_jpeg,
    validate_owner_voice,
)
from preview_dashboard.domain.owner_messages import (
    OwnerMessage,
    OwnerMessageId,
    parse_owner_message_id,
    redact_code_runs,
)
from preview_dashboard.ports.claudia import ChangeEvents
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.owner_media import OwnerMediaStore
from preview_dashboard.ports.owner_messages import OwnerMessageStore

logger = logging.getLogger("preview_dashboard.inbox")


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnerMediaSubmission:
    """One owner voice note or photo as the notifier reports it (raw values; re-checked here).

    `caption` (None = none), `quote_text` and `data` are excluded from `repr` (C29).
    """

    update_id: int
    telegram_message_id: int
    sender_id: int
    kind: MessageKind
    data: bytes = field(repr=False)
    caption: str | None = field(default=None, repr=False)
    is_forwarded: bool = False
    reply_to_message_id: int | None = None
    quote_text: str | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class OwnerMedia:
    """A stored media file for the host: its kind and checked bytes."""

    kind: MessageKind
    data: bytes = field(repr=False)


class OwnerMediaService:
    """Voice/photo intake (`/v1/notifier/media`) and fetch/release (`/v1/claudia/...`).

    Args:
        messages: the inbox store (rows of kind voice/photo).
        media: the private media store (bytes).
        clock / ids: time and ULID sources.
        owner_chat_id: the configured owner (None = every submission refused).
        voice_enabled / photo_enabled: the `claudia_*_input_enabled` switches;
            a kind that is off is refused (fail closed).
        events: wakes Claudia's long-poll on a new message (optional).
    """

    def __init__(
        self,
        *,
        messages: OwnerMessageStore,
        media: OwnerMediaStore,
        clock: Clock,
        ids: IdGenerator,
        owner_chat_id: int | None,
        voice_enabled: bool,
        photo_enabled: bool,
        events: ChangeEvents | None = None,
    ) -> None:
        self._messages = messages
        self._media = media
        self._clock = clock
        self._ids = ids
        self._owner = owner_chat_id
        self._enabled = {
            MessageKind.VOICE: voice_enabled is True,
            MessageKind.PHOTO: photo_enabled is True,
        }
        self._events = events

    def receive(self, submission: OwnerMediaSubmission) -> tuple[ReceiveResult, OwnerMessage]:
        """Check, store and enqueue one voice note / photo (or find the already stored one).

        Raises:
            ValidationError: not the configured owner, a kind that is off or
                unknown, content that fails the C61 checks, or any
                `OwnerMessage` invariant (caption rules as message text).
            LimitExceededError / StorageUnavailableError: the media store is
                full or not writable (the notifier retries).
        """
        sender = submission.sender_id
        if (
            isinstance(sender, bool)
            or not isinstance(sender, int)
            or self._owner is None
            or sender != self._owner
        ):
            logger.warning("owner media refused: sender is not the configured owner")
            raise ValidationError("message is not from the configured owner")
        try:
            kind = MessageKind(submission.kind)
        except ValueError:
            raise ValidationError("unknown media kind") from None
        if not self._enabled.get(kind, False):
            logger.info("owner media refused: %s input is off", kind)
            raise ValidationError(f"{kind} input is off")
        # By content, never by Telegram's claim (C61).
        if kind is MessageKind.VOICE:
            clean = validate_owner_voice(submission.data).data
        else:
            clean = sanitize_jpeg(submission.data).data
        caption, quote = submission.caption, submission.quote_text
        media_id = new_ulid(self._ids)
        message = OwnerMessage(
            id=OwnerMessageId(new_ulid(self._ids)),
            update_id=submission.update_id,
            telegram_message_id=submission.telegram_message_id,
            text="" if caption is None else redact_code_runs(caption),
            received_at=self._clock.now(),
            is_forwarded=submission.is_forwarded,
            reply_to_message_id=submission.reply_to_message_id,
            quote_text=redact_code_runs(quote) if isinstance(quote, str) else quote,
            kind=kind,
            media_id=media_id,
            media_bytes=len(clean),
        )
        self._media.save(media_id, kind, clean)
        try:
            stored = self._messages.add(message)
        except BaseException:
            self._media.discard(media_id, kind)  # no row will ever name it
            raise
        if stored.id != message.id:
            self._media.discard(media_id, kind)  # the first delivery's file stays
            logger.info("owner media duplicate: id=%s", stored.id)
            return ReceiveResult.DUPLICATE, stored
        logger.info("owner media stored: id=%s kind=%s bytes=%d", stored.id, kind, len(clean))
        if self._events is not None:
            self._events.notify()
        return ReceiveResult.STORED, stored

    def fetch(self, message_id: str) -> OwnerMedia:
        """The checked bytes of message `message_id` (any state: the host claims first).

        Raises:
            NotFoundError: malformed or unknown id, a text message, or a file
                already released / purged.
        """
        message, media_id = self._media_message(message_id)
        data = self._media.load(media_id, message.kind)
        if data is None:
            raise NotFoundError("no media waiting for this message")
        return OwnerMedia(kind=message.kind, data=data)

    def release(self, message_id: str) -> None:
        """Delete the file once the host is done with it (idempotent).

        Raises:
            NotFoundError: malformed or unknown id, or a text message.
        """
        message, media_id = self._media_message(message_id)
        self._media.discard(media_id, message.kind)
        logger.info("owner media released: id=%s", message.id)

    def _media_message(self, message_id: str) -> tuple[OwnerMessage, str]:
        """The media row `message_id` and its media id; NotFoundError for anything else."""
        try:
            message = self._messages.get(parse_owner_message_id(message_id))
        except ValidationError:
            raise NotFoundError("no such media message") from None
        if not message.kind.is_media or message.media_id is None:
            raise NotFoundError("no such media message")
        return message, message.media_id
