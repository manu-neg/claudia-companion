"""TelegramAnswerSource and the owner-only callback parsing shared with `updates.py`.

`accept_callback` accepts a callback query only if `from.id ==
message.chat.id == owner_chat_id` (C34) and its data is exactly
`a:<ULID>:<option key>` (an answer) or, when approvals are enabled,
`p:<ULID>:(ok|no)` (an approval tap, C46). `TelegramAnswerSource` is the
callback-only poller (`allowed_updates=["callback_query"]`) used while owner
messages are off. Everything else is dropped and logged by reason only,
never content. The update offset lives in memory: re-delivered taps after a
restart are harmless (first answer / first tap wins).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Final

from preview_dashboard.adapters.telegram.client import (
    LONG_POLL_MARGIN,
    TelegramBotClient,
    validate_chat_id,
)
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.ports.notify import AnswerEvent
from preview_dashboard.wire.notifier_messages import ApprovalDecision, parse_approval_callback

SOURCE_NAME: Final = "telegram"
MAX_POLL_SECONDS: Final = 50
UPDATES_LIMIT: Final = 20
MAX_ACK_CHARS: Final = 200  # Bot API limit on answerCallbackQuery text
_CALLBACK_RE = re.compile(r"a:([0-9A-Z]{26}):([a-z0-9_-]{1,16})")
_HANDLE_RE = re.compile(r"[\x21-\x7e]{1,64}")
MAX_UPDATE_ID: Final = 2**53

_log = logging.getLogger(__name__)


def as_int(value: object) -> int | None:
    """`value` if it is a real int (bools are not), else None."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def as_dict(value: object) -> dict[str, object]:
    """`value` if it is a dict, else an empty one (untrusted JSON navigation)."""
    return value if isinstance(value, dict) else {}


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalTap:
    """One owner tap on an approval request's Approve/Deny button (C46).

    `request_id` is a canonical ULID but otherwise untrusted: the admin
    validates it (unknown -> `unknown`, no oracle).

    Attributes:
        request_id: the approval request's id from the callback.
        decision: approve (`ok`) or deny (`no`).
        actor_ref: who tapped (Telegram user id), for logs only.
        ack_handle: the callback query id, to show the toast.
    """

    request_id: str
    decision: ApprovalDecision
    actor_ref: str
    ack_handle: str


def accept_callback(
    raw: object, owner_chat_id: int, *, approvals: bool
) -> AnswerEvent | ApprovalTap | None:
    """The owner's tap in callback query `raw`, or None (logged by reason, no content).

    Args:
        raw: the update's `callback_query` object (untrusted).
        owner_chat_id: the configured owner chat id (C16, C34).
        approvals: also accept `p:<ULID>:(ok|no)` approval taps.
    """
    query = as_dict(raw)
    if not query:
        _log.info("telegram update is not a callback query; ignored")
        return None
    sender = as_int(as_dict(query.get("from")).get("id"))
    chat = as_int(as_dict(as_dict(query.get("message")).get("chat")).get("id"))
    # Both must match: the owner tapping in the owner's private chat (C34).
    if sender != owner_chat_id or chat != owner_chat_id:
        _log.warning("callback query not from the owner's chat; ignored")
        return None
    handle, data = query.get("id"), query.get("data")
    if not isinstance(handle, str) or not _HANDLE_RE.fullmatch(handle):
        _log.warning("callback query with a malformed id; ignored")
        return None
    match = _CALLBACK_RE.fullmatch(data) if isinstance(data, str) else None
    if match is not None and is_ulid(match.group(1)):
        return AnswerEvent(
            question_id=match.group(1),
            key=match.group(2),
            actor_ref=str(sender),
            ack_handle=handle,
        )
    tap = parse_approval_callback(data) if approvals else None
    if tap is not None:
        return ApprovalTap(
            request_id=tap[0], decision=tap[1], actor_ref=str(sender), ack_handle=handle
        )
    _log.warning("callback query with malformed data; ignored")
    return None


def answer_callback(client: TelegramBotClient, handle: str, text: str) -> None:
    """Show `text` (cut to 200 chars) as the toast of callback query `handle`.

    Raises:
        ValueError: malformed handle.
        TelegramError: the call failed.
    """
    if not _HANDLE_RE.fullmatch(handle):
        raise ValueError("malformed callback query id")
    client.call("answerCallbackQuery", {"callback_query_id": handle, "text": text[:MAX_ACK_CHARS]})


class TelegramAnswerSource:
    """Yields the owner's taps on answer buttons (callback queries only).

    Args:
        client: Bot API client (holds the token).
        owner_chat_id: the owner's chat id from root-owned config (C16, C34).

    Raises (on construction):
        TelegramConfigError: `owner_chat_id` is not a positive int.
    """

    name = SOURCE_NAME

    def __init__(self, client: TelegramBotClient, owner_chat_id: int) -> None:
        self._client = client
        self._owner = validate_chat_id(owner_chat_id)
        self._offset: int | None = None

    def poll(self, timeout: float) -> list[AnswerEvent]:
        """Long-poll up to `timeout` (<= 50) seconds; return the owner's valid taps.

        Raises:
            TelegramError: the call failed (e.g. 409: another poller is running).
        """
        wait = max(0, min(int(timeout), MAX_POLL_SECONDS))
        params: dict[str, object] = {
            "timeout": wait,
            "limit": UPDATES_LIMIT,
            "allowed_updates": ["callback_query"],
        }
        if self._offset is not None:
            params["offset"] = self._offset
        result = self._client.call("getUpdates", params, read_timeout=wait + LONG_POLL_MARGIN)
        if not isinstance(result, list):
            _log.warning("getUpdates returned an unexpected shape; ignored")
            return []
        events: list[AnswerEvent] = []
        for update in result[:UPDATES_LIMIT]:
            update_id = as_int(as_dict(update).get("update_id"))
            if update_id is None or not 0 <= update_id < MAX_UPDATE_ID:
                _log.warning("telegram update without a valid update_id; ignored")
                continue
            # Advance past every update, accepted or not, so none is re-read.
            self._offset = max(self._offset or 0, update_id + 1)
            event = accept_callback(
                as_dict(update).get("callback_query"), self._owner, approvals=False
            )
            if isinstance(event, AnswerEvent):
                events.append(event)
        return events

    def ack(self, handle: str, text: str) -> None:
        """Show `text` (cut to 200 chars) as the tap's toast.

        Raises:
            ValueError: malformed handle.
            TelegramError: the call failed.
        """
        answer_callback(self._client, handle, text)
