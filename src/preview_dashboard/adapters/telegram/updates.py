"""TelegramUpdateSource: the single `getUpdates` poller once owner messages are on (C44).

Requests `allowed_updates=["callback_query", "message"]` and turns each
update into one inbound event: an answer tap or approval tap (callback
rules of `answers.py`, C34/C46), an owner text for the inbox, or an
authenticator code (C47). A message counts only if `from.id == chat.id ==
owner`, the chat is private, the sender is not a bot and it is plain text
(<= 4096 chars); media, edits, channel posts, messages sent via a bot or
on behalf of a chat are ignored, logged by update id only (strangers get no
reply, so no existence oracle). Forwarded / external-reply origin and the
quoted / replied-to message are kept as metadata, never folded into the
text. A whole-text ASCII `[0-9]{6}` (spaces removed) is a code, never inbox
text; every other 6-digit run is redacted before it leaves this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final

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
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_messages import (
    MESSAGE_MAX_CHARS,
    QUOTE_MAX_CHARS,
    is_code_message,
    is_owner_private_message,
    redact_code_runs,
)
from preview_dashboard.ports.notify import AnswerEvent
from preview_dashboard.wire.notifier_messages import CodeSubmission, MessageSubmission

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


InboundEvent = AnswerEvent | ApprovalTap | OwnerText | OwnerCode
"""One accepted update, in update order."""


def _is_forwarded(message: dict[str, object]) -> bool:
    return bool(_FORWARD_KEYS & message.keys()) or message.get("is_automatic_forward") is True


def accept_message(raw: object, update_id: int, owner_chat_id: int) -> OwnerText | OwnerCode | None:
    """The owner's plain text message `raw` as an inbox text or a code, or None (C44).

    Args:
        raw: the update's `message` object (untrusted).
        update_id: the update's id (idempotency key with the message id).
        owner_chat_id: the configured owner chat id.

    Never raises on untrusted input; anything refused is logged by update
    id only (no text, no sender).
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


class TelegramUpdateSource:
    """Polls callback queries and owner messages; yields `InboundEvent`s in update order.

    Args:
        client: Bot API client (holds the token).
        owner_chat_id: the owner's chat id from root-owned config (C16, C34, C44).

    Raises (on construction):
        TelegramConfigError: `owner_chat_id` is not a positive int.
    """

    name = SOURCE_NAME

    def __init__(self, client: TelegramBotClient, owner_chat_id: int) -> None:
        self._client = client
        self._owner = validate_chat_id(owner_chat_id)
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
            return accept_message(update["message"], update_id, self._owner)
        # edited_message, channel_post, ... (never requested): ignored.
        _log.info("telegram update %d of an unrequested type; ignored", update_id)
        return None
