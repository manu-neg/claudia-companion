"""JSON wire format of `POST /v1/notifier/media` (notifier token, docs/security.md C61).

One owner voice note or photo per request, shared by the notifier
(`adapters/admin_queue.py`) and the admin (`interfaces/admin/notifier_api.py`).
Body: the `/v1/notifier/messages` fields (the caption in place of the text,
`null` = none) plus `kind` and the downloaded file as strict base64 in
`data`; the reply is `{"result": "stored" | "duplicate"}` like texts (same
idempotency key). One JSON body keeps the admin's bounded body reader as
the only size limit: `MAX_MEDIA_BODY_BYTES` covers the base64 of the
largest file plus the worst-case escaped caption and quote. Strict parser
(unknown keys, wrong types, bad base64 -> `ValidationError`, never echoed);
the bytes themselves are checked by the admin (`domain/owner_media.py`).
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_media import MessageKind, media_max_bytes
from preview_dashboard.domain.owner_messages import (
    STORED_MESSAGE_MAX_CHARS,
    STORED_QUOTE_MAX_CHARS,
)
from preview_dashboard.wire.notifier import NOTIFIER_PREFIX
from preview_dashboard.wire.notifier_messages import (
    _object,
    _telegram_id,
    validate_owner_text,
)

MEDIA_PATH: Final = f"{NOTIFIER_PREFIX}/media"
MEDIA_KINDS: Final = frozenset({MessageKind.VOICE, MessageKind.PHOTO})
_MAX_FILE_BYTES: Final = max(media_max_bytes(k) for k in MEDIA_KINDS)
_MAX_BASE64_CHARS: Final = 4 * ((_MAX_FILE_BYTES + 2) // 3)
# JSON escapes a char as at most 12 bytes (a surrogate pair `\\ud83d\\ude00`
# for one astral char counts as one char but 12 bytes): caption + quote,
# plus room for the other fields.
MAX_MEDIA_BODY_BYTES: Final = (
    _MAX_BASE64_CHARS + 12 * (STORED_MESSAGE_MAX_CHARS + STORED_QUOTE_MAX_CHARS) + 4096
)
_REQUIRED: Final = frozenset(
    {"update_id", "message_id", "sender_id", "kind", "data", "caption", "is_forwarded"}
)
_OPTIONAL: Final = frozenset({"reply_to_message_id", "quote_text"})


@dataclass(frozen=True, slots=True, kw_only=True)
class MediaSubmission:
    """One owner voice note / photo for the inbox (`POST /v1/notifier/media`, C61).

    The notifier has checked the sender like for texts (C44), the
    metadata caps and downloaded at most the kind's cap; the admin
    re-checks everything, the bytes by content. `caption`, `quote_text`
    and `data` are excluded from `repr` (C29).

    Invariants (`ValidationError`): ids as `MessageSubmission`; `kind`
    `voice` or `photo`; `data` 1..the kind's cap (2 MiB / 10 MiB);
    `caption` None or redacted text like a message (1..20480 chars),
    `quote_text` None or 1..5120 chars.
    """

    update_id: int
    message_id: int
    sender_id: int
    kind: MessageKind
    data: bytes = field(repr=False)
    caption: str | None = field(default=None, repr=False)
    is_forwarded: bool = False
    reply_to_message_id: int | None = None
    quote_text: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _telegram_id(self.update_id, "update_id", minimum=0)
        _telegram_id(self.message_id, "message_id", minimum=1)
        _telegram_id(self.sender_id, "sender_id", minimum=1)
        if self.reply_to_message_id is not None:
            _telegram_id(self.reply_to_message_id, "reply_to_message_id", minimum=1)
        kind = _kind(self.kind)
        object.__setattr__(self, "kind", kind)
        cap = media_max_bytes(kind)
        if not isinstance(self.data, bytes) or not 1 <= len(self.data) <= cap:
            raise ValidationError(f"{kind} data must be 1..{cap} bytes")
        if self.caption is not None:
            validate_owner_text(self.caption, "caption", STORED_MESSAGE_MAX_CHARS)
        if self.quote_text is not None:
            validate_owner_text(self.quote_text, "quote", STORED_QUOTE_MAX_CHARS)
        if not isinstance(self.is_forwarded, bool):
            raise ValidationError("is_forwarded must be a bool")


def _kind(raw: object) -> MessageKind:
    if not isinstance(raw, str) or raw not in {str(k) for k in MEDIA_KINDS}:
        raise ValidationError("kind must be voice or photo")
    return MessageKind(raw)


def media_request_to_json(submission: MediaSubmission) -> dict[str, object]:
    """Body of `POST /v1/notifier/media` (all nine keys, nulls kept, `data` base64)."""
    return {
        "update_id": submission.update_id,
        "message_id": submission.message_id,
        "sender_id": submission.sender_id,
        "kind": str(submission.kind),
        "data": base64.b64encode(submission.data).decode("ascii"),
        "caption": submission.caption,
        "is_forwarded": submission.is_forwarded,
        "reply_to_message_id": submission.reply_to_message_id,
        "quote_text": submission.quote_text,
    }


def parse_media_request(raw: object) -> MediaSubmission:
    """Parse a submitted voice note / photo (shape, base64 and `MediaSubmission` invariants).

    Raises:
        ValidationError: unknown/missing fields, bad types, bad base64, data
            over the kind's cap, or any other invariant broken.
    """
    fields = _object(raw, "media", _REQUIRED, _OPTIONAL)
    kind = _kind(fields["kind"])
    encoded = fields["data"]
    if not isinstance(encoded, str) or len(encoded) > 4 * ((media_max_bytes(kind) + 2) // 3):
        raise ValidationError(f"{kind} data must be base64 within the cap")
    try:
        data = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValidationError("data must be base64") from None
    forwarded = fields["is_forwarded"]
    if not isinstance(forwarded, bool):
        raise ValidationError("is_forwarded must be a bool")
    caption, reply_to, quote = (
        fields["caption"],
        fields.get("reply_to_message_id"),
        fields.get("quote_text"),
    )
    return MediaSubmission(
        update_id=_telegram_id(fields["update_id"], "update_id", minimum=0),
        message_id=_telegram_id(fields["message_id"], "message_id", minimum=1),
        sender_id=_telegram_id(fields["sender_id"], "sender_id", minimum=1),
        kind=kind,
        data=data,
        caption=None
        if caption is None
        else validate_owner_text(caption, "caption", STORED_MESSAGE_MAX_CHARS),
        is_forwarded=forwarded,
        reply_to_message_id=(
            None if reply_to is None else _telegram_id(reply_to, "reply_to_message_id", minimum=1)
        ),
        quote_text=None
        if quote is None
        else validate_owner_text(quote, "quote", STORED_QUOTE_MAX_CHARS),
    )
