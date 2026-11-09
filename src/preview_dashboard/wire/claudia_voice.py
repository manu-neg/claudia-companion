"""JSON wire format of `POST /v1/claudia/voice` (`claudia` token, C56, unit M10).

Body: the reply text, the Ogg/Opus voice note as strict base64 (<= 1 MiB
decoded) and the optional inbox message / item ids of a reply. Shared by the
admin route and the Claudia host. Framework-free; strict (unknown keys,
wrong types and bad base64 raise `ValidationError`); the audio itself is
checked by `events.voice.validate_voice_audio` on the admin.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.events.voice import VOICE_MAX_BYTES
from preview_dashboard.wire.claudia import CLAUDIA_PREFIX

VOICE_PATH: Final = f"{CLAUDIA_PREFIX}/voice"
# Base64 of the audio cap plus room for the text (<= 4096 chars, JSON-escaped).
MAX_VOICE_BODY_BYTES: Final = (VOICE_MAX_BYTES * 4 // 3) + 4 + 64 * 1024
_REQUIRED: Final = frozenset({"text", "audio"})
_OPTIONAL: Final = frozenset({"message_id", "item_id"})


@dataclass(frozen=True, slots=True, kw_only=True)
class VoiceRequest:
    """Parsed voice body: text, decoded audio bytes and optional ids."""

    text: str
    audio: bytes
    message_id: str | None = None
    item_id: str | None = None


def voice_request_to_json(request: VoiceRequest) -> dict[str, object]:
    """`{"text", "audio" (base64), "message_id", "item_id"}`."""
    return {
        "text": request.text,
        "audio": base64.b64encode(request.audio).decode("ascii"),
        "message_id": request.message_id,
        "item_id": request.item_id,
    }


def _optional_str(raw: object, what: str) -> str | None:
    if raw is not None and not isinstance(raw, str):
        raise ValidationError(f"{what} must be a string")
    return raw


def parse_voice_request(raw: object) -> VoiceRequest:
    """Parse a voice body (shape and base64 only; the admin checks text, audio and budget).

    Raises:
        ValidationError: missing/unknown fields, non-strings, invalid base64
            or decoded audio over the 1 MiB cap.
    """
    if not isinstance(raw, dict) or not all(isinstance(k, str) for k in raw):
        raise ValidationError("voice body must be a JSON object")
    keys = set(raw)
    if not keys >= _REQUIRED or not keys <= _REQUIRED | _OPTIONAL:
        raise ValidationError("voice body has missing or unknown fields")
    text, encoded = raw["text"], raw["audio"]
    if not isinstance(text, str) or not isinstance(encoded, str):
        raise ValidationError("text and audio must be strings")
    if len(encoded) > VOICE_MAX_BYTES * 4 // 3 + 4:
        raise ValidationError("voice audio is too large")
    try:
        audio = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValidationError("audio must be base64") from None
    return VoiceRequest(
        text=text,
        audio=audio,
        message_id=_optional_str(raw.get("message_id"), "message_id"),
        item_id=_optional_str(raw.get("item_id"), "item_id"),
    )


def voice_result_to_json(voice_id: str) -> dict[str, object]:
    """Response of `POST /v1/claudia/voice`: `{"id": <delivery id>}`."""
    return {"id": voice_id}
