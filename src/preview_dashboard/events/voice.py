"""The `voice` event type and the voice-note audio checks (ADR 0031, docs/security.md C56).

A voice reply is always sent as text too, so the event renders exactly like
`reply`. The audio (synthesized locally from that already-scanned text, unit
M10) must pass `validate_voice_audio` before any channel uploads it: one
Ogg/Opus stream, <= 1 MiB, <= 60 s. Pure stdlib: the container is walked
page by page with hard bounds, nothing is decoded.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import REPLY_TEXT_MAX_CHARS, MessageContent
from preview_dashboard.domain.owner_media import check_ogg_opus
from preview_dashboard.events.base import RenderContext
from preview_dashboard.events.reply import render_reply_body

VOICE_EVENT = "voice"
VOICE_MAX_BYTES: Final = 1024 * 1024
VOICE_MAX_SECONDS: Final = 60


@dataclass(frozen=True, slots=True)
class VoiceAudio:
    """A checked voice note: the Ogg/Opus bytes and their duration in seconds."""

    data: bytes
    seconds: float


def validate_voice_audio(data: object) -> VoiceAudio:
    """Check `data` is one well-formed Ogg/Opus stream within the C56 caps.

    Rules: bytes, 1..1 MiB; consecutive Ogg pages (version 0) covering the
    whole buffer, one serial number, a BOS first page whose packet starts
    with `OpusHead`, page sequence numbers counting up from 0, an EOS last
    page; duration = (last granule - pre-skip) / 48000 in 0..60 s.

    Raises:
        ValidationError: anything else (the message never echoes the data).
    """
    if not isinstance(data, bytes):
        raise ValidationError(f"voice audio must be 1..{VOICE_MAX_BYTES} bytes")
    # One walker for outgoing and incoming notes (domain/owner_media.py, C61).
    seconds = check_ogg_opus(
        data, max_bytes=VOICE_MAX_BYTES, max_seconds=VOICE_MAX_SECONDS, what="voice audio"
    )
    return VoiceAudio(data=data, seconds=seconds)


class VoiceEventType:
    """Claudia's voice reply: rendered as its text (always sent too, C56); not actionable.

    `emoji` is unused in the text, as for `reply`.
    """

    name = VOICE_EVENT
    emoji = "🔊"
    actionable = False
    max_chars = REPLY_TEXT_MAX_CHARS  # same text limit as `reply`

    def render(self, ctx: RenderContext) -> MessageContent:
        """The reply text plus the link (the audio travels separately, M10).

        Raises:
            ValidationError: see `events.reply.render_reply_body`.
        """
        return render_reply_body(ctx)
