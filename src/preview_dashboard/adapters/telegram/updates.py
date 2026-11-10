"""TelegramUpdateSource: the single `getUpdates` poller once owner messages are on (C44, C61).

Requests `allowed_updates=["callback_query", "message"]` and turns each
update into one inbound event: an answer tap or approval tap (callback
rules of `answers.py`, C34/C46), an owner text for the inbox, an
authenticator code (C47), or an owner voice note / photo (C61, only with
its switch on; metadata caps checked here, the bytes later). A message
counts only if `from.id == chat.id == owner`, the chat is private and the
sender is not a bot (checked first, for media too); other media,
documents, edits, channel posts, messages sent via a bot or on behalf of
a chat are ignored, logged by update id only (strangers get no
reply, so no existence oracle). Forwarded / external-reply origin and the
quoted / replied-to message are kept as metadata, never folded into the
text. A whole-text ASCII `[0-9]{6}` (spaces removed) is a code, never inbox
text; every other 6-digit run is redacted before it leaves this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Literal

from preview_dashboard.adapters.telegram.answers import (
    MAX_POLL_SECONDS,
    MAX_UPDATE_ID,
    SOURCE_NAME,
    UPDATES_LIMIT,
    ApprovalTap,
    accept_callback,
    answer_callback,
    as_dict,
    as_int,
)
from preview_dashboard.adapters.telegram.client import (
    LONG_POLL_MARGIN,
    TelegramBotClient,
    validate_chat_id,
)
from preview_dashboard.adapters.telegram.files import MediaRefusedError, validate_file_id
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_media import (
    PHOTO_MAX_BYTES,
    PHOTO_MAX_SIDE,
    VOICE_MAX_BYTES,
    VOICE_MAX_SECONDS,
    VOICE_MIME_TYPE,
    MessageKind,
    media_max_bytes,
)
from preview_dashboard.domain.owner_messages import (
    MESSAGE_MAX_CHARS,
    QUOTE_MAX_CHARS,
    STORED_MESSAGE_MAX_CHARS,
    is_code_message,
    is_owner_private_message,
    redact_code_runs,
)
from preview_dashboard.ports.notify import AnswerEvent
from preview_dashboard.wire.notifier_media import MediaSubmission
from preview_dashboard.wire.notifier_messages import (
    CodeSubmission,
    MessageSubmission,
    validate_owner_text,
)

ALLOWED_UPDATES: Final = ("callback_query", "message")
# Any of these makes a message "not plain text" (C44). Text messages never
# carry them; the list fails closed for media with a caption.
_NON_TEXT_KEYS: Final = frozenset(
    {
        "animation",
        "audio",
        "caption",
        "checklist",
        "contact",
        "dice",
        "document",
        "game",
        "giveaway",
        "invoice",
        "location",
        "media_group_id",
        "paid_media",
        "photo",
        "poll",
        "sticker",
        "story",
        "venue",
        "video",
        "video_note",
        "voice",
        "web_app_data",
    }
)
# Owner media that may be taken in (C61); a photo sent as a `document` is not
# (Telegram re-encodes `photo` to JPEG without metadata, documents stay raw).
_MEDIA_KEYS: Final = frozenset({"voice", "photo"})
# Telegram sends a handful of sizes per photo; more is not a real photo.
_MAX_PHOTO_SIZES: Final = 16
# Not the owner typing in the owner's own name: ignored outright.
_NOT_OWNER_TYPED_KEYS: Final = frozenset({"sender_chat", "via_bot", "edit_date"})
# Forwarded content (incl. a reply quoting another chat): kept as the flag.
_FORWARD_KEYS: Final = frozenset(
    {
        "forward_origin",
        "forward_from",
        "forward_from_chat",
        "forward_sender_name",
        "forward_date",
        "external_reply",
    }
)

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class OwnerText:
    """An owner text message ready for `POST /v1/notifier/messages` (already redacted)."""

    update_id: int
    submission: MessageSubmission


@dataclass(frozen=True, slots=True)
class OwnerCode:
    """An authenticator-code message for `POST /v1/notifier/codes` (never inbox text)."""

    update_id: int
    submission: CodeSubmission


@dataclass(frozen=True, slots=True)
class MediaSwitches:
    """Which owner media the notifier takes in (`claudia_*_input_enabled`, C61); off by default."""

    voice: bool = False
    photo: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnerMedia:
    """An owner voice note / photo that passed the metadata caps; to download, then post.

    `file_id` is Telegram's handle (never logged); `max_bytes` the
    download cap for its kind. Caption and quote are already redacted and
    excluded from `repr` (C29).
    """

    update_id: int
    kind: MessageKind
    file_id: str = field(repr=False)
    max_bytes: int
    message_id: int
    sender_id: int
    caption: str | None = field(default=None, repr=False)
    is_forwarded: bool = False
    reply_to_message_id: int | None = None
    quote_text: str | None = field(default=None, repr=False)

    def submission(self, data: bytes) -> MediaSubmission:
        """The `POST /v1/notifier/media` body for the downloaded `data`.

        Raises:
            ValidationError: `data` empty or over the kind's cap.
        """
        return MediaSubmission(
            update_id=self.update_id,
            message_id=self.message_id,
            sender_id=self.sender_id,
            kind=self.kind,
            data=data,
            caption=self.caption,
            is_forwarded=self.is_forwarded,
            reply_to_message_id=self.reply_to_message_id,
            quote_text=self.quote_text,
        )


class MediaSkip(StrEnum):
    """Why an owner voice note / photo was not taken in (each gets one fixed notice, C61)."""

    OFF = "off"  # the kind's switch is off
    REFUSED = "refused"  # over a cap, an album, a bad shape


@dataclass(frozen=True, slots=True)
class MediaSkipped:
    """An owner voice note / photo that is dropped; the router may send a fixed notice."""

    update_id: int
    reason: MediaSkip


InboundEvent = AnswerEvent | ApprovalTap | OwnerText | OwnerCode | OwnerMedia | MediaSkipped
"""One accepted update, in update order."""


def _is_forwarded(message: dict[str, object]) -> bool:
    return bool(_FORWARD_KEYS & message.keys()) or message.get("is_automatic_forward") is True


def accept_message(
    raw: object,
    update_id: int,
    owner_chat_id: int,
    media: MediaSwitches = MediaSwitches(),  # noqa: B008 - frozen, immutable default
) -> OwnerText | OwnerCode | OwnerMedia | MediaSkipped | None:
    """The owner's message `raw` as an inbox text, a code or a voice note / photo, or None.

    Args:
        raw: the update's `message` object (untrusted).
        update_id: the update's id (idempotency key with the message id).
        owner_chat_id: the configured owner chat id.
        media: which media kinds are on (C61); default none.

    The owner check (C44) comes first, for media too: nobody else gets any
    reply. Never raises on untrusted input; anything refused is logged by
    update id only (no text, no sender, no file id).
    """
    message = as_dict(raw)
    sender = as_dict(message.get("from"))
    chat = as_dict(message.get("chat"))
    if not is_owner_private_message(
        from_id=sender.get("id"),
        chat_id=chat.get("id"),
        chat_type=chat.get("type"),
        from_is_bot=sender.get("is_bot"),
        owner_chat_id=owner_chat_id,
    ):
        _log.warning("telegram update %d: message not from the owner's private chat", update_id)
        return None
    if _MEDIA_KEYS & message.keys() and not _NOT_OWNER_TYPED_KEYS & message.keys():
        return _accept_media(message, update_id, owner_chat_id, media)
    text = message.get("text")
    if (
        not isinstance(text, str)
        or _NON_TEXT_KEYS & message.keys()
        or _NOT_OWNER_TYPED_KEYS & message.keys()
    ):
        _log.info("telegram update %d: not a plain owner text message; ignored", update_id)
        return None
    message_id = as_int(message.get("message_id"))
    if message_id is None or len(text) > MESSAGE_MAX_CHARS:
        _log.warning("telegram update %d: malformed text message; ignored", update_id)
        return None
    try:
        if is_code_message(text):
            return OwnerCode(
                update_id,
                CodeSubmission(
                    update_id=update_id,
                    message_id=message_id,
                    sender_id=owner_chat_id,
                    code=text.replace(" ", ""),
                ),
            )
        return OwnerText(
            update_id,
            MessageSubmission(
                update_id=update_id,
                message_id=message_id,
                sender_id=owner_chat_id,
                # The only change to the verbatim text: no code reaches Claudia.
                text=redact_code_runs(text),
                is_forwarded=_is_forwarded(message),
                reply_to_message_id=as_int(
                    as_dict(message.get("reply_to_message")).get("message_id")
                ),
                quote_text=_quote(message, update_id),
            ),
        )
    except ValidationError:
        _log.warning("telegram update %d: text message refused by the inbox rules", update_id)
        return None


def _quote(message: dict[str, object], update_id: int) -> str | None:
    """The quoted part of the replied-to message (redacted), or None."""
    quote = as_dict(message.get("quote")).get("text")
    if not isinstance(quote, str) or not quote.strip():
        return None
    if len(quote) > QUOTE_MAX_CHARS:
        _log.info("telegram update %d: quote over the limit; dropped", update_id)
        return None
    return redact_code_runs(quote)


def _accept_media(
    message: dict[str, object], update_id: int, owner_chat_id: int, media: MediaSwitches
) -> OwnerMedia | MediaSkipped | None:
    """An owner voice note / photo (owner already checked), by Telegram's metadata (C61).

    The switch comes first (off -> skipped, one notice); then the shape:
    exactly one of `voice` / `photo`, an optional caption and nothing else
    of `_NON_TEXT_KEYS` (albums, documents, text are refused), then the caps.
    """
    kind = MessageKind.VOICE if "voice" in message else MessageKind.PHOTO
    if not (media.voice if kind is MessageKind.VOICE else media.photo):
        _log.info("telegram update %d: owner %s while that input is off", update_id, kind)
        return MediaSkipped(update_id, MediaSkip.OFF)
    allowed = frozenset({str(kind), "caption"})
    message_id = as_int(message.get("message_id"))
    if "text" in message or (_NON_TEXT_KEYS - allowed) & message.keys() or message_id is None:
        _log.info("telegram update %d: owner %s of an unsupported shape", update_id, kind)
        return MediaSkipped(update_id, MediaSkip.REFUSED)
    file = _voice_file(message) if kind is MessageKind.VOICE else _photo_file(message)
    caption = _caption(message.get("caption"))
    if file is None or caption is False:
        _log.info("telegram update %d: owner %s over the caps; dropped", update_id, kind)
        return MediaSkipped(update_id, MediaSkip.REFUSED)
    return OwnerMedia(
        update_id=update_id,
        kind=kind,
        file_id=file,
        max_bytes=media_max_bytes(kind),
        message_id=message_id,
        sender_id=owner_chat_id,
        caption=caption,
        is_forwarded=_is_forwarded(message),
        reply_to_message_id=as_int(as_dict(message.get("reply_to_message")).get("message_id")),
        quote_text=_quote(message, update_id),
    )


def _caption(raw: object) -> str | Literal[False] | None:
    """The redacted caption, None if absent/blank, or False if it breaks the text rules."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if not isinstance(raw, str) or len(raw) > MESSAGE_MAX_CHARS:
        return False
    try:
        return validate_owner_text(redact_code_runs(raw), "caption", STORED_MESSAGE_MAX_CHARS)
    except ValidationError:
        return False


def _int_in(raw: object, low: int, high: int) -> int | None:
    value = as_int(raw)
    return value if value is not None and low <= value <= high else None


def _file_id(raw: object) -> str | None:
    try:
        return validate_file_id(raw)
    except MediaRefusedError:
        return None


def _voice_file(message: dict[str, object]) -> str | None:
    """The voice note's file id if its metadata is within the caps, else None."""
    voice = as_dict(message.get("voice"))
    if (
        _int_in(voice.get("duration"), 0, VOICE_MAX_SECONDS) is None
        or _int_in(voice.get("file_size"), 1, VOICE_MAX_BYTES) is None
        or voice.get("mime_type") != VOICE_MIME_TYPE
    ):
        return None
    return _file_id(voice.get("file_id"))


def _photo_file(message: dict[str, object]) -> str | None:
    """File id of the largest `PhotoSize` within the caps (size, both sides), else None.

    Telegram sends a photo re-encoded as JPEG in a few sizes; any size over
    a cap is skipped, never fetched.
    """
    sizes = message.get("photo")
    if not isinstance(sizes, list):
        return None
    best: tuple[int, str] | None = None
    for raw in sizes[:_MAX_PHOTO_SIZES]:
        size = as_dict(raw)
        width = _int_in(size.get("width"), 1, PHOTO_MAX_SIDE)
        height = _int_in(size.get("height"), 1, PHOTO_MAX_SIDE)
        file_id = _file_id(size.get("file_id"))
        if (
            width is None
            or height is None
            or file_id is None
            or _int_in(size.get("file_size"), 1, PHOTO_MAX_BYTES) is None
        ):
            continue
        if best is None or width * height > best[0]:
            best = (width * height, file_id)
    return None if best is None else best[1]


class TelegramUpdateSource:
    """Polls callback queries and owner messages; yields `InboundEvent`s in update order.

    Args:
        client: Bot API client (holds the token).
        owner_chat_id: the owner's chat id from root-owned config (C16, C34, C44).
        media: which owner media kinds are taken in (C61); default none.

    Raises (on construction):
        TelegramConfigError: `owner_chat_id` is not a positive int.
    """

    name = SOURCE_NAME

    def __init__(
        self,
        client: TelegramBotClient,
        owner_chat_id: int,
        *,
        media: MediaSwitches = MediaSwitches(),  # noqa: B008 - frozen, immutable default
    ) -> None:
        self._client = client
        self._owner = validate_chat_id(owner_chat_id)
        self._media = media
        self._offset: int | None = None

    def poll(self, timeout: float) -> list[InboundEvent]:
        """Long-poll up to `timeout` (<= 50) seconds; return the accepted events.

        The offset advances past every update, accepted or not; `rewind`
        moves it back so an update is fetched again.

        Raises:
            TelegramError: the call failed (e.g. 409: another poller is running).
        """
        wait = max(0, min(int(timeout), MAX_POLL_SECONDS))
        params: dict[str, object] = {
            "timeout": wait,
            "limit": UPDATES_LIMIT,
            "allowed_updates": list(ALLOWED_UPDATES),
        }
        if self._offset is not None:
            params["offset"] = self._offset
        result = self._client.call("getUpdates", params, read_timeout=wait + LONG_POLL_MARGIN)
        if not isinstance(result, list):
            _log.warning("getUpdates returned an unexpected shape; ignored")
            return []
        events: list[InboundEvent] = []
        for raw in result[:UPDATES_LIMIT]:
            update = as_dict(raw)
            update_id = as_int(update.get("update_id"))
            if update_id is None or not 0 <= update_id < MAX_UPDATE_ID:
                _log.warning("telegram update without a valid update_id; ignored")
                continue
            self._offset = max(self._offset or 0, update_id + 1)
            event = self._accept(update, update_id)
            if event is not None:
                events.append(event)
        return events

    def rewind(self, update_id: int) -> None:
        """Fetch update `update_id` (and every later one) again on the next poll.

        Telegram confirms updates only when a later `getUpdates` passes a
        higher offset, so moving the offset back before that call re-delivers
        them (the admin stores a message once, C44).
        """
        if self._offset is None or update_id < self._offset:
            self._offset = update_id

    def ack(self, handle: str, text: str) -> None:
        """Show `text` (cut to 200 chars) as a tap's toast.

        Raises:
            ValueError: malformed handle.
            TelegramError: the call failed.
        """
        answer_callback(self._client, handle, text)

    def _accept(self, update: dict[str, object], update_id: int) -> InboundEvent | None:
        if "callback_query" in update:
            return accept_callback(update["callback_query"], self._owner, approvals=True)
        if "message" in update:
            return accept_message(update["message"], update_id, self._owner, self._media)
        # edited_message, channel_post, ... (never requested): ignored.
        _log.info("telegram update %d of an unrequested type; ignored", update_id)
        return None
