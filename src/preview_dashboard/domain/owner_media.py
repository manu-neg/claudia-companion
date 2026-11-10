"""Owner voice notes and photos for Claudia (docs/security.md C61): caps and content checks.

Pure stdlib, nothing is decoded: `check_ogg_opus` walks an Ogg container
page by page (one Opus stream, duration from the last granule position),
`sanitize_jpeg` walks JPEG markers and rebuilds the file without any
APPn/COM segment (EXIF, XMP, ICC, comments) and without trailing bytes.
Both check the bytes themselves, never Telegram's claims about them.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from preview_dashboard.domain.errors import ValidationError

_MIB: Final = 1024 * 1024
# Telegram metadata caps, checked again on the content by the admin (C61).
VOICE_MAX_SECONDS: Final = 120
VOICE_MAX_BYTES: Final = 2 * _MIB
VOICE_MIME_TYPE: Final = "audio/ogg"
PHOTO_MAX_BYTES: Final = 10 * _MIB
PHOTO_MAX_SIDE: Final = 4096
VOICE_CONTENT_TYPE: Final = "audio/ogg"
PHOTO_CONTENT_TYPE: Final = "image/jpeg"


class MessageKind(StrEnum):
    """What an inbox message carries: plain text, a voice note or a photo (C44, C61)."""

    TEXT = "text"
    VOICE = "voice"
    PHOTO = "photo"

    @property
    def is_media(self) -> bool:
        """True for a voice note or a photo (bytes stored apart from the row)."""
        return self is not MessageKind.TEXT


def media_max_bytes(kind: MessageKind) -> int:
    """The byte cap of a stored media file of `kind`.

    Raises:
        ValidationError: `kind` is not a media kind.
    """
    if kind is MessageKind.VOICE:
        return VOICE_MAX_BYTES
    if kind is MessageKind.PHOTO:
        return PHOTO_MAX_BYTES
    raise ValidationError("a text message has no media")


def media_content_type(kind: MessageKind) -> str:
    """The content type a stored media file of `kind` is served with.

    Raises:
        ValidationError: `kind` is not a media kind.
    """
    media_max_bytes(kind)
    return VOICE_CONTENT_TYPE if kind is MessageKind.VOICE else PHOTO_CONTENT_TYPE


# --- Ogg/Opus ------------------------------------------------------------------------

# Opus granule positions always count 48 kHz samples (RFC 7845 section 4).
_OPUS_RATE: Final = 48_000
_PAGE_HEADER = struct.Struct("<4sBBqIIIB")  # capture, version, flags, granule, serial, seq, crc, n
_OPUS_HEAD_MIN: Final = 19
_FLAG_BOS: Final = 0x02
_FLAG_EOS: Final = 0x04


def _crc_table() -> tuple[int, ...]:
    table = []
    for byte in range(256):
        crc = byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
            crc &= 0xFFFFFFFF
        table.append(crc)
    return tuple(table)


_CRC_TABLE: Final = _crc_table()
_CRC_OFFSET: Final = 22  # the checksum field inside the page header


def ogg_page_crc(page: bytes) -> int:
    """The Ogg page checksum of `page` (CRC-32, poly 0x04C11DB7, not reflected, init 0).

    The 4 checksum bytes of the page header are taken as zero.
    """
    crc = 0
    for index, byte in enumerate(page):
        if _CRC_OFFSET <= index < _CRC_OFFSET + 4:
            byte = 0
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC_TABLE[((crc >> 24) ^ byte) & 0xFF]
    return crc


def check_ogg_opus(data: object, *, max_bytes: int, max_seconds: float, what: str) -> float:
    """Check `data` is one well-formed Ogg/Opus stream within the caps; return its seconds.

    Rules: bytes, 1..`max_bytes`; consecutive Ogg pages (version 0) covering
    the whole buffer, each with a valid page CRC (so a bad page cannot hide
    another stream in its body), one serial number, a BOS first page whose
    packet starts with `OpusHead`, page sequence numbers counting up from 0,
    an EOS last page; duration = (last granule - pre-skip) / 48000 in
    0..`max_seconds`.

    Raises:
        ValidationError: anything else (`what` names the data; never echoed).
    """
    if not isinstance(data, bytes) or not 1 <= len(data) <= max_bytes:
        raise ValidationError(f"{what} must be 1..{max_bytes} bytes")
    pos, seq, serial, granule, flags, pre_skip = 0, 0, None, 0, 0, 0
    while pos < len(data):
        if len(data) - pos < _PAGE_HEADER.size:
            raise ValidationError(f"{what} is not a complete Ogg stream")
        capture, version, flags, granule, page_serial, page_seq, crc, count = (
            _PAGE_HEADER.unpack_from(data, pos)
        )
        if capture != b"OggS" or version != 0:
            raise ValidationError(f"{what} is not an Ogg stream")
        if serial is None:
            serial = page_serial
        if page_serial != serial or page_seq != seq:
            raise ValidationError(f"{what} must be one Ogg stream in order")
        table_end = pos + _PAGE_HEADER.size + count
        if table_end > len(data):
            raise ValidationError(f"{what} is not a complete Ogg stream")
        body_end = table_end + sum(data[pos + _PAGE_HEADER.size : table_end])
        if body_end > len(data):
            raise ValidationError(f"{what} is not a complete Ogg stream")
        if ogg_page_crc(data[pos:body_end]) != crc:
            raise ValidationError(f"{what} has a corrupt Ogg page")
        if seq == 0:
            pre_skip = _opus_pre_skip(data[table_end:body_end], flags, what)
        elif flags & _FLAG_BOS:
            raise ValidationError(f"{what} must be one Ogg stream in order")
        pos, seq = body_end, seq + 1
    if not flags & _FLAG_EOS:
        raise ValidationError(f"{what} must end the Ogg stream")
    seconds = (granule - pre_skip) / _OPUS_RATE
    if not 0 <= seconds <= max_seconds:
        raise ValidationError(f"{what} must be at most {max_seconds:g} seconds")
    return seconds


def _opus_pre_skip(first_page_body: bytes, flags: int, what: str) -> int:
    """The pre-skip of the `OpusHead` packet that must open the stream."""
    if not flags & _FLAG_BOS or len(first_page_body) < _OPUS_HEAD_MIN:
        raise ValidationError(f"{what} must start with an OpusHead packet")
    if first_page_body[:8] != b"OpusHead":
        raise ValidationError(f"{what} must be Opus")
    pre_skip: int = struct.unpack_from("<H", first_page_body, 10)[0]
    return pre_skip


@dataclass(frozen=True, slots=True)
class OwnerVoiceNote:
    """A checked owner voice note: the Ogg/Opus bytes (stored as received) and its seconds."""

    data: bytes = field(repr=False)
    seconds: float


def validate_owner_voice(data: object) -> OwnerVoiceNote:
    """Check an owner voice note by content: Ogg/Opus, <= 2 MiB, <= 120 s (C61).

    Raises:
        ValidationError: not one Ogg/Opus stream within the caps.
    """
    if not isinstance(data, bytes):
        raise ValidationError("voice note must be bytes")
    seconds = check_ogg_opus(
        data, max_bytes=VOICE_MAX_BYTES, max_seconds=VOICE_MAX_SECONDS, what="voice note"
    )
    return OwnerVoiceNote(data=data, seconds=seconds)


# --- JPEG --------------------------------------------------------------------------------

_SOI: Final = 0xD8
_EOI: Final = 0xD9
_SOS: Final = 0xDA
_COM: Final = 0xFE
_APP_FIRST: Final = 0xE0
_APP_LAST: Final = 0xEF
_RST_FIRST: Final = 0xD0
_RST_LAST: Final = 0xD7
# Start-of-frame markers (every coding process; C4/C8/CC are DHT/JPG/DAC).
_SOF_MARKERS: Final = frozenset({0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD})
_SOF_MARKERS_ALL: Final = _SOF_MARKERS | frozenset({0xCE, 0xCF})
# Table / parameter segments copied as they are: DHT, DAC, DQT, DRI.
_KEPT_TABLES: Final = frozenset({0xC4, 0xCC, 0xDB, 0xDD})
# More than a phone photo ever has; bounds the work on hostile input.
_MAX_SEGMENTS: Final = 4096


@dataclass(frozen=True, slots=True)
class CleanJpeg:
    """A checked owner photo: JPEG bytes without APPn/COM/trailing data, and its size in px."""

    data: bytes = field(repr=False)
    width: int
    height: int


def _segment_end(data: bytes, pos: int) -> int:
    """End offset of the length-prefixed segment whose length field starts at `pos`."""
    if pos + 2 > len(data):
        raise ValidationError("photo is not a complete JPEG")
    length: int = struct.unpack_from(">H", data, pos)[0]
    end = pos + length
    if length < 2 or end > len(data):
        raise ValidationError("photo has a malformed JPEG segment")
    return end


def _frame_size(data: bytes, pos: int, end: int) -> tuple[int, int]:
    """(width, height) of the SOF segment at `pos..end` (after the marker)."""
    if end - pos < 8:
        raise ValidationError("photo has a malformed JPEG frame header")
    height, width = struct.unpack_from(">HH", data, pos + 3)
    if not (1 <= width <= PHOTO_MAX_SIDE and 1 <= height <= PHOTO_MAX_SIDE):
        raise ValidationError(f"photo sides must be 1..{PHOTO_MAX_SIDE} px")
    return width, height


def _scan_end(data: bytes, pos: int) -> int:
    """End of the entropy-coded data starting at `pos`: the next marker other than RSTn.

    Inside a scan, `FF 00` is a stuffed byte and `FF D0..D7` a restart marker.
    """
    while True:
        pos = data.find(b"\xff", pos)
        if pos < 0 or pos + 1 >= len(data):
            raise ValidationError("photo is not a complete JPEG")
        follower = data[pos + 1]
        if follower == 0x00 or _RST_FIRST <= follower <= _RST_LAST:
            pos += 2
        elif follower == 0xFF:
            pos += 1  # fill byte before a marker
        else:
            return pos


def sanitize_jpeg(data: object) -> CleanJpeg:
    """Check an owner photo by content and strip its metadata, byte-wise (C61).

    Walks the markers of a baseline or progressive JPEG: SOI first; exactly
    one SOFn with both sides 1..4096 px before the first scan; DQT, DHT,
    DAC, DRI and every scan copied as they are; every APPn (EXIF, XMP,
    ICC, JFIF) and COM segment dropped; anything after EOI dropped. No
    image library: unknown markers, a missing EOI, truncated segments or
    a second SOI are refused, never repaired.

    Raises:
        ValidationError: not such a JPEG, over 10 MiB or a side over 4096 px.
    """
    if not isinstance(data, bytes) or not 4 <= len(data) <= PHOTO_MAX_BYTES:
        raise ValidationError(f"photo must be 4..{PHOTO_MAX_BYTES} bytes")
    if data[0] != 0xFF or data[1] != _SOI:
        raise ValidationError("photo is not a JPEG")
    out = bytearray(b"\xff\xd8")
    pos = 2
    size: tuple[int, int] | None = None
    scans = 0
    for _ in range(_MAX_SEGMENTS):
        if pos >= len(data) or data[pos] != 0xFF:
            raise ValidationError("photo is not a complete JPEG")
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1  # a marker may be preceded by fill bytes
        if pos >= len(data):
            raise ValidationError("photo is not a complete JPEG")
        marker = data[pos]
        pos += 1
        if marker == _EOI:
            if scans == 0 or size is None:
                raise ValidationError("photo has no image data")
            out += b"\xff\xd9"  # trailing bytes after EOI are dropped
            return CleanJpeg(data=bytes(out), width=size[0], height=size[1])
        end = _segment_end(data, pos)
        if _APP_FIRST <= marker <= _APP_LAST or marker == _COM:
            pos = end  # metadata: never copied
            continue
        if marker in _SOF_MARKERS_ALL:
            if marker not in _SOF_MARKERS or size is not None:
                raise ValidationError("photo must have exactly one supported JPEG frame")
            size = _frame_size(data, pos, end)
        elif marker == _SOS:
            if size is None:
                raise ValidationError("photo has a scan before its frame header")
            scans += 1
            scan_end = _scan_end(data, end)
            out += data[pos - 2 : scan_end]
            pos = scan_end
            continue
        elif marker not in _KEPT_TABLES:
            raise ValidationError("photo has an unsupported JPEG marker")
        out += data[pos - 2 : end]
        pos = end
    raise ValidationError("photo has too many JPEG segments")
