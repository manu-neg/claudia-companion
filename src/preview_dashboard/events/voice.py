"""The `voice` event type and the voice-note audio checks (ADR 0031, docs/security.md C56).

A voice reply is always sent as text too, so the event renders exactly like
`reply`. The audio (synthesized locally from that already-scanned text, unit
M10) must pass `validate_voice_audio` before any channel uploads it: one
Ogg/Opus stream, <= 1 MiB, <= 60 s. Pure stdlib: the container is walked
page by page with hard bounds, nothing is decoded.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import REPLY_TEXT_MAX_CHARS, MessageContent
from preview_dashboard.events.base import RenderContext
from preview_dashboard.events.reply import render_reply_body

VOICE_EVENT = "voice"
VOICE_MAX_BYTES: Final = 1024 * 1024
VOICE_MAX_SECONDS: Final = 60
# Opus granule positions always count 48 kHz samples (RFC 7845 section 4).
_OPUS_RATE: Final = 48_000
_PAGE_HEADER = struct.Struct("<4sBBqIIIB")  # capture, version, flags, granule, serial, seq, crc, n
_OPUS_HEAD_MIN: Final = 19
_FLAG_BOS: Final = 0x02
_FLAG_EOS: Final = 0x04


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
    if not isinstance(data, bytes) or not 1 <= len(data) <= VOICE_MAX_BYTES:
        raise ValidationError(f"voice audio must be 1..{VOICE_MAX_BYTES} bytes")
    pos, seq, serial, granule, flags, pre_skip = 0, 0, None, 0, 0, 0
    while pos < len(data):
        if len(data) - pos < _PAGE_HEADER.size:
            raise ValidationError("voice audio is not a complete Ogg stream")
        capture, version, flags, granule, page_serial, page_seq, _crc, count = (
            _PAGE_HEADER.unpack_from(data, pos)
        )
        if capture != b"OggS" or version != 0:
            raise ValidationError("voice audio is not an Ogg stream")
        if serial is None:
            serial = page_serial
        if page_serial != serial or page_seq != seq:
            raise ValidationError("voice audio must be one Ogg stream in order")
        table_end = pos + _PAGE_HEADER.size + count
        if table_end > len(data):
            raise ValidationError("voice audio is not a complete Ogg stream")
        body_end = table_end + sum(data[pos + _PAGE_HEADER.size : table_end])
        if body_end > len(data):
            raise ValidationError("voice audio is not a complete Ogg stream")
        if seq == 0:
            pre_skip = _opus_pre_skip(data[table_end:body_end], flags)
        elif flags & _FLAG_BOS:
            raise ValidationError("voice audio must be one Ogg stream in order")
        pos, seq = body_end, seq + 1
    if not flags & _FLAG_EOS:
        raise ValidationError("voice audio must end the Ogg stream")
    seconds = (granule - pre_skip) / _OPUS_RATE
    if not 0 <= seconds <= VOICE_MAX_SECONDS:
        raise ValidationError(f"voice audio must be at most {VOICE_MAX_SECONDS} seconds")
    return VoiceAudio(data=data, seconds=seconds)


def _opus_pre_skip(first_page_body: bytes, flags: int) -> int:
    """The pre-skip of the `OpusHead` packet that must open the stream."""
    if not flags & _FLAG_BOS or len(first_page_body) < _OPUS_HEAD_MIN:
        raise ValidationError("voice audio must start with an OpusHead packet")
    if first_page_body[:8] != b"OpusHead":
        raise ValidationError("voice audio must be Opus")
    pre_skip: int = struct.unpack_from("<H", first_page_body, 10)[0]
    return pre_skip


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
