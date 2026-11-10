"""Unit tests for `domain/owner_media.py` and the media fields of `OwnerMessage` (C61).

Covers the Ogg/Opus walker shared with outgoing voice notes, the byte-wise
JPEG sanitizer (metadata and trailer stripped, scans kept, malformed input
refused, never repaired) and the media invariants of inbox rows.
"""

from __future__ import annotations

import struct

import pytest

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_media import (
    PHOTO_MAX_BYTES,
    VOICE_MAX_BYTES,
    MessageKind,
    check_ogg_opus,
    media_content_type,
    media_max_bytes,
    ogg_page_crc,
    sanitize_jpeg,
    validate_owner_voice,
)
from preview_dashboard.domain.owner_messages import OwnerMessage, OwnerMessageId
from tests.fakes import FixedClock
from tests.owner_updates_support import (
    COMMENT_MARKER,
    EXIF_MARKER,
    TRAILER_MARKER,
    jpeg,
    ogg_opus,
    seal_page,
)

MEDIA_ID = "01J00000000000000000000MED"


# --- Ogg/Opus ----------------------------------------------------------------------------


def test_voice_of_120_seconds_passes_and_reports_its_duration() -> None:
    note = validate_owner_voice(ogg_opus(120.0))
    assert note.seconds == pytest.approx(120.0)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(ogg_opus(121.0), id="over-120s-by-granule"),
        pytest.param(ogg_opus(2.0).replace(b"OpusHead", b"VorbisHd"), id="not-opus"),
        pytest.param(b"RIFF" + bytes(100), id="not-ogg"),
        pytest.param(ogg_opus(2.0)[:-10], id="truncated"),
        pytest.param(b"", id="empty"),
        pytest.param(ogg_opus(2.0) + bytes(VOICE_MAX_BYTES), id="over-2-mib"),
    ],
)
def test_voice_refused_by_content(data: bytes) -> None:
    with pytest.raises(ValidationError):
        validate_owner_voice(data)


def _check(data: bytes) -> float:
    return check_ogg_opus(data, max_bytes=VOICE_MAX_BYTES, max_seconds=120, what="voice note")


def test_ogg_crc_matches_a_bitwise_reference() -> None:
    # Spec form (RFC 3533): poly 0x04C11DB7, MSB first, init 0, CRC field as zero.
    page = bytearray(ogg_opus(1.0)[:60])
    page[22:26] = b"\xde\xad\xbe\xef"  # whatever the field holds is ignored
    crc = 0
    for byte in page[:22] + bytes(4) + page[26:]:
        crc ^= byte << 24
        for _ in range(8):
            top = crc & 0x80000000
            crc = (crc << 1) & 0xFFFFFFFF
            if top:
                crc ^= 0x04C11DB7
    assert ogg_page_crc(bytes(page)) == crc != 0


def test_valid_ogg_pages_pass_the_crc_check() -> None:
    assert _check(ogg_opus(2.0)) > 1.9


@pytest.mark.parametrize("page", [0, 1, 2])
def test_flipped_ogg_crc_is_refused_on_any_page(page: int) -> None:
    data = bytearray(ogg_opus(2.0))
    starts = [i for i in range(len(data)) if data[i : i + 4] == b"OggS"]
    data[starts[page] + 22] ^= 0x01
    with pytest.raises(ValidationError, match="corrupt Ogg page"):
        _check(bytes(data))


def test_flipped_body_byte_is_refused() -> None:
    data = bytearray(ogg_opus(2.0))
    data[-1] ^= 0x01
    with pytest.raises(ValidationError, match="corrupt Ogg page"):
        _check(bytes(data))


def test_bad_crc_page_zero_cannot_hide_a_vorbis_page() -> None:
    # Page 0 carries an OpusHead packet and, behind it, a complete Vorbis page
    # (valid CRC of its own): a tolerant demuxer might find that stream.
    hidden = seal_page(
        struct.pack("<4sBBqIIIB", b"OggS", 0, 0x02, 0, 9, 0, 0, 1) + b"\x07" + b"\x01vorbis"
    )
    head = b"OpusHead" + struct.pack("<BBHIhB", 1, 1, 312, 48_000, 0, 0) + hidden
    lacing = [255] * (len(head) // 255) + [len(head) % 255]
    header = struct.pack("<4sBBqIIIB", b"OggS", 0, 0x02, 0, 7, 0, 0, len(lacing))
    page0 = header + bytes(lacing) + head
    rest = ogg_opus(2.0)
    rest = rest[rest.index(b"OggS", 4) :]
    with pytest.raises(ValidationError, match="corrupt Ogg page"):
        _check(page0 + rest)  # page 0 has CRC 0


def test_walker_caps_are_parameters() -> None:
    assert check_ogg_opus(ogg_opus(30.0), max_bytes=4096, max_seconds=30, what="x") > 29
    with pytest.raises(ValidationError, match="x must be at most 10 seconds"):
        check_ogg_opus(ogg_opus(30.0), max_bytes=4096, max_seconds=10, what="x")


def test_voice_bytes_are_kept_as_received_and_not_in_repr() -> None:
    data = ogg_opus(3.0)
    note = validate_owner_voice(data)
    assert note.data == data
    assert "data" not in repr(note)


# --- JPEG -------------------------------------------------------------------------------------


def test_jpeg_metadata_and_trailer_are_stripped_byte_wise() -> None:
    clean = sanitize_jpeg(jpeg(800, 600))
    assert (clean.width, clean.height) == (800, 600)
    for marker in (EXIF_MARKER, COMMENT_MARKER, TRAILER_MARKER, b"JFIF", b"Photoshop"):
        assert marker not in clean.data
    assert clean.data.startswith(b"\xff\xd8") and clean.data.endswith(b"\xff\xd9")
    # No APPn / COM marker survives anywhere before the first scan.
    head = clean.data[: clean.data.index(b"\xff\xda")]
    assert not any(head[i] == 0xFF and 0xE0 <= head[i + 1] <= 0xEF for i in range(len(head) - 1))
    assert b"\xff\xfe" not in head


def test_jpeg_without_metadata_round_trips_exactly() -> None:
    raw = jpeg(metadata=False, trailer=False)
    assert sanitize_jpeg(raw).data == raw


def test_progressive_jpeg_keeps_every_scan() -> None:
    raw = jpeg(scans=3, metadata=False, trailer=False)
    clean = sanitize_jpeg(raw)
    assert clean.data == raw
    assert clean.data.count(b"\xff\xda") == 3


def _with_sof(width: int, height: int) -> bytes:
    return jpeg(width, height)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(_with_sof(4097, 100), id="width-over-4096"),
        pytest.param(_with_sof(100, 4097), id="height-over-4096"),
        pytest.param(_with_sof(0, 100), id="zero-width"),
        pytest.param(b"\x89PNG\r\n\x1a\n" + bytes(64), id="png"),
        pytest.param(jpeg(trailer=False)[:-2], id="no-eoi"),
        pytest.param(jpeg(trailer=False)[:40], id="truncated-segment"),
        pytest.param(b"\xff\xd8\xff\xd9", id="no-frame-no-scan"),
        pytest.param(jpeg().replace(b"\xff\xc0", b"\xff\xc8", 1), id="jpg-extension-marker"),
        pytest.param(jpeg().replace(b"\xff\xdb", b"\xff\xf7", 1), id="jpeg-ls-marker"),
        pytest.param(
            jpeg(trailer=False).replace(b"\xff\xd9", b"\xff\xd8\xff\xd9"), id="second-soi"
        ),
        pytest.param(bytes(PHOTO_MAX_BYTES + 1), id="over-10-mib"),
        pytest.param("not bytes", id="not-bytes"),
    ],
)
def test_jpeg_refused_never_repaired(data: object) -> None:
    with pytest.raises(ValidationError):
        sanitize_jpeg(data)


def test_scan_before_frame_is_refused() -> None:
    raw = jpeg(metadata=False, trailer=False)
    sof_at = raw.index(b"\xff\xc0")
    sof_len = struct.unpack_from(">H", raw, sof_at + 2)[0] + 2
    without_sof = raw[:sof_at] + raw[sof_at + sof_len :]
    with pytest.raises(ValidationError):
        sanitize_jpeg(without_sof)


def test_two_frames_are_refused() -> None:
    raw = jpeg(metadata=False, trailer=False)
    sof_at = raw.index(b"\xff\xc0")
    sof_len = struct.unpack_from(">H", raw, sof_at + 2)[0] + 2
    doubled = raw[: sof_at + sof_len] + raw[sof_at : sof_at + sof_len] + raw[sof_at + sof_len :]
    with pytest.raises(ValidationError, match="exactly one"):
        sanitize_jpeg(doubled)


# --- kinds and inbox rows ------------------------------------------------------------------------


def test_kind_caps_and_content_types() -> None:
    assert media_max_bytes(MessageKind.VOICE) == 2 * 1024 * 1024
    assert media_max_bytes(MessageKind.PHOTO) == 10 * 1024 * 1024
    assert media_content_type(MessageKind.VOICE) == "audio/ogg"
    assert media_content_type(MessageKind.PHOTO) == "image/jpeg"
    with pytest.raises(ValidationError):
        media_max_bytes(MessageKind.TEXT)
    assert not MessageKind.TEXT.is_media
    assert MessageKind.PHOTO.is_media


def _row(**overrides: object) -> OwnerMessage:
    fields: dict[str, object] = {
        "id": OwnerMessageId("01J00000000000000000000MSG"),
        "update_id": 1,
        "telegram_message_id": 2,
        "text": "",
        "received_at": FixedClock().now(),
        "kind": MessageKind.PHOTO,
        "media_id": MEDIA_ID,
        "media_bytes": 1234,
    }
    fields.update(overrides)
    return OwnerMessage(**fields)  # type: ignore[arg-type]


def test_media_row_may_have_no_caption() -> None:
    row = _row()
    assert (row.kind, row.text, row.media_bytes) == (MessageKind.PHOTO, "", 1234)


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"kind": MessageKind.TEXT}, id="text-with-media"),
        pytest.param({"kind": MessageKind.TEXT, "text": ""}, id="empty-text"),
        pytest.param({"media_id": None}, id="no-media-id"),
        pytest.param({"media_id": "../../etc/passwd"}, id="path-as-media-id"),
        pytest.param({"media_bytes": 0}, id="zero-bytes"),
        pytest.param({"media_bytes": True}, id="bool-bytes"),
        pytest.param(
            {"kind": MessageKind.VOICE, "media_bytes": VOICE_MAX_BYTES + 1}, id="voice-cap"
        ),
        pytest.param({"media_bytes": PHOTO_MAX_BYTES + 1}, id="photo-cap"),
        pytest.param({"kind": "video"}, id="unknown-kind"),
        pytest.param({"text": "123456"}, id="caption-is-a-code"),
        pytest.param({"text": "   "}, id="blank-caption"),
    ],
)
def test_media_row_invariants(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _row(**overrides)


def test_text_row_defaults_have_no_media() -> None:
    row = _row(kind=MessageKind.TEXT, text="hi", media_id=None, media_bytes=None)
    assert row.kind is MessageKind.TEXT
    assert row.media_id is None
