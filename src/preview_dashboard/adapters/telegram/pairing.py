"""Bot pairing: find the owner's chat id from a `/start <code>` message (`notify pair`).

The operator runs pairing as root with the notifier service stopped; the
printed chat id is then put into root-owned config by hand (C16): the
notifier never learns its owner at runtime. Only a private chat whose
sender is the chat itself and whose text is exactly `/start <code>`
(constant-time compare) matches; every other update is skipped silently.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Callable
from typing import Final

from preview_dashboard.adapters.telegram.client import LONG_POLL_MARGIN, TelegramBotClient

CODE_LENGTH: Final = 8
# Unambiguous uppercase + digits (no 0/O, 1/I/L): easy to type on a phone.
CODE_ALPHABET: Final = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
PAIR_TIMEOUT_SECONDS: Final = 600.0
_POLL_SECONDS: Final = 25
_MAX_TEXT_CHARS: Final = 64
_MAX_ID = 2**53


class PairingTimeoutError(TimeoutError):
    """No matching `/start <code>` arrived before the deadline."""


def new_pairing_code() -> str:
    """A fresh random 8-char code (`secrets`, ~40 bits: unguessable within 10 minutes)."""
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def match_start(update: object, code: str) -> int | None:
    """The chat id if `update` is `/start <code>` from a user in their own private chat."""
    message = _dict(_dict(update).get("message"))
    chat = _dict(message.get("chat"))
    chat_id = _int(chat.get("id"))
    sender = _int(_dict(message.get("from")).get("id"))
    text = message.get("text")
    if chat.get("type") != "private" or chat_id is None or sender != chat_id:
        return None
    if not 0 < chat_id < _MAX_ID or not isinstance(text, str) or len(text) > _MAX_TEXT_CHARS:
        return None
    expected = f"/start {code}".encode()
    return chat_id if hmac.compare_digest(text.strip().encode(), expected) else None


def wait_for_pairing(
    client: TelegramBotClient,
    code: str,
    *,
    timeout: float = PAIR_TIMEOUT_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Long-poll `getUpdates` for `/start <code>`; return the sender's chat id.

    Raises:
        PairingTimeoutError: nothing matched within `timeout` seconds.
        TelegramError: a Bot API call failed (409: the notifier is still running).
    """
    deadline = monotonic() + timeout
    offset: int | None = None
    while (remaining := deadline - monotonic()) > 0:
        wait = max(1, min(_POLL_SECONDS, int(remaining)))
        params: dict[str, object] = {"timeout": wait, "allowed_updates": ["message"]}
        if offset is not None:
            params["offset"] = offset
        result = client.call("getUpdates", params, read_timeout=wait + LONG_POLL_MARGIN)
        for update in result if isinstance(result, list) else []:
            update_id = _int(_dict(update).get("update_id"))
            if update_id is not None and 0 <= update_id < _MAX_ID:
                offset = max(offset or 0, update_id + 1)
            chat_id = match_start(update, code)
            if chat_id is not None:
                if offset is not None:
                    # Confirm the consumed updates so the notifier won't see them.
                    client.call("getUpdates", {"offset": offset, "timeout": 0})
                return chat_id
    raise PairingTimeoutError("no matching /start message before the deadline")
