"""Test helpers for the notifier's owner-update path (C44, C46, C47, C56) and voice notes.

`Harness` wires `TelegramUpdateSource` + `OwnerUpdateRouter` + a real
`AdminDeliveryQueue` and `TelegramChannel` over the scripted fakes of
`tests/telegram_support.py`; `ogg_opus` builds a minimal Ogg/Opus stream
(valid container, dummy audio) for the voice-cap checks. No network.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.adapters.telegram.files import TelegramMediaFiles
from preview_dashboard.adapters.telegram.updates import MediaSwitches, TelegramUpdateSource
from preview_dashboard.domain.owner_media import ogg_page_crc
from preview_dashboard.interfaces.notifier.owner_updates import OwnerUpdateRouter
from preview_dashboard.wire import notifier_messages as wm
from preview_dashboard.wire.notifier_media import MEDIA_PATH
from tests.telegram_support import (
    FAKE_NOTIFIER_TOKEN,
    OWNER,
    FakeBotApi,
    FakeNotifierAdmin,
    ok,
)

APPROVAL_ID = "01J00000000000000000000AP1"


def result(value: str, status: int = 200) -> httpx.Response:
    """An admin verdict `{"result": value}`."""
    return httpx.Response(status, json={"result": value})


@dataclass
class Harness:
    """The owner-update path over fakes; admin routes answer like a healthy M3 by default.

    `media` switches owner voice/photo intake on (C61); the router always
    has the real `TelegramMediaFiles` downloader over the fake Bot API.
    """

    api: FakeBotApi = field(default_factory=FakeBotApi)
    admin: FakeNotifierAdmin = field(default_factory=FakeNotifierAdmin)
    # The router's monotonic clock (delete retries); tests move it forward.
    now: float = 0.0
    media: MediaSwitches = field(default_factory=MediaSwitches)

    def __post_init__(self) -> None:
        self.admin.route("POST", wm.MESSAGES_PATH, result("stored"))
        self.admin.route("POST", wm.APPROVALS_PATH, result("tapped"))
        self.admin.route("POST", wm.CODES_PATH, result("accepted"))
        self.admin.route("POST", MEDIA_PATH, result("stored"))
        client = self.api.client()
        self.queue = AdminDeliveryQueue(
            Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=self.admin.transport()
        )
        self.source = TelegramUpdateSource(client, OWNER, media=self.media)
        self.channel = TelegramChannel(client, OWNER, dashboard_origin=None)
        self.router = OwnerUpdateRouter(
            self.source,
            self.queue,
            self.channel,
            files=TelegramMediaFiles(client),
            monotonic=lambda: self.now,
        )

    def serve_file(self, data: bytes, path: str = "voice/file_1.oga") -> None:
        """Script one `getFile` + download of `data` at `path`."""
        self.api.script("getFile", ok({"file_id": "F1", "file_path": path, "file_size": len(data)}))
        self.api.script(path.rsplit("/", 1)[-1], httpx.Response(200, content=data))

    def downloads(self) -> list[str]:
        """URLs of every file download (they carry the fake token)."""
        return [c.url for c in self.api.calls if "/file/bot" in c.url]

    def updates(self, *batch: dict[str, Any]) -> None:
        """Script one getUpdates batch."""
        self.api.script("getUpdates", ok(list(batch)))

    def posted(self, path: str) -> list[dict[str, Any]]:
        """Bodies the notifier posted to admin route `path`."""
        return [c.body for c in self.admin.calls if c.url.endswith(path)]

    def deleted(self) -> list[dict[str, Any]]:
        """Bodies of every deleteMessage call."""
        return [c.body for c in self.api.calls if c.method == "deleteMessage"]

    def sent_texts(self) -> list[str]:
        """Texts of every sendMessage call (fixed prompts and notices on this path)."""
        return [str(c.body.get("text")) for c in self.api.calls if c.method == "sendMessage"]


_PAGE = struct.Struct("<4sBBqIIIB")


def _page(body: bytes, *, granule: int, seq: int, flags: int, serial: int = 7) -> bytes:
    lacing = [255] * (len(body) // 255) + [len(body) % 255]
    header = _PAGE.pack(b"OggS", 0, flags, granule, serial, seq, 0, len(lacing))
    page = header + bytes(lacing) + body
    return seal_page(page)


def seal_page(page: bytes) -> bytes:
    """`page` with its Ogg CRC field recomputed (tests that edit a page re-seal it)."""
    return page[:22] + struct.pack("<I", ogg_page_crc(page)) + page[26:]


def ogg_opus(
    seconds: float = 2.0,
    *,
    pre_skip: int = 312,
    audio_bytes: int = 200,
    head_magic: bytes = b"OpusHead",
) -> bytes:
    """A minimal Ogg/Opus stream lasting `seconds` (OpusHead, OpusTags, one audio page).

    `head_magic` replaces the first packet's 8-byte magic (e.g. a Vorbis header).
    """
    head = head_magic + struct.pack("<BBHIhB", 1, 1, pre_skip, 48_000, 0, 0)
    tags = b"OpusTags" + struct.pack("<I", 4) + b"test" + struct.pack("<I", 0)
    granule = pre_skip + int(seconds * 48_000)
    return (
        _page(head, granule=0, seq=0, flags=0x02)
        + _page(tags, granule=0, seq=1, flags=0)
        + _page(b"\x00" * audio_bytes, granule=granule, seq=2, flags=0x04)
    )


EXIF_MARKER = b"Exif\x00\x00GPS-Lat-40.4168-Lon-3.7038"
COMMENT_MARKER = b"secret-comment-from-camera"
TRAILER_MARKER = b"trailing-bytes-after-eoi"


def _segment(marker: int, body: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body


def jpeg(
    width: int = 640,
    height: int = 480,
    *,
    metadata: bool = True,
    trailer: bool = True,
    scans: int = 1,
) -> bytes:
    """A structurally valid JPEG (not decodable): JFIF/EXIF/COM, DQT, SOF0, DHT, scans, EOI.

    Each scan's data holds a stuffed `FF 00` and a restart marker, so the
    walker's in-scan rules are exercised. `metadata` adds APP0/APP1/APP13/COM.
    """
    sof = 0xC2 if scans > 1 else 0xC0
    parts = [b"\xff\xd8"]
    if metadata:
        parts += [
            _segment(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"),
            _segment(0xE1, EXIF_MARKER),
            _segment(0xED, b"Photoshop 3.0\x00IPTC"),
            _segment(0xFE, COMMENT_MARKER),
        ]
    parts += [
        _segment(0xDB, b"\x00" + bytes(range(1, 65))),
        _segment(sof, struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00"),
        _segment(0xC4, b"\x00" + bytes(16) + b""),
    ]
    for _ in range(scans):
        parts += [
            _segment(0xDA, b"\x01\x01\x00\x00\x3f\x00"),
            b"\x12\x34\xff\x00\x56\xff\xd0\x78\x9a",
        ]
    parts.append(b"\xff\xd9")
    if trailer:
        parts.append(TRAILER_MARKER)
    return b"".join(parts)
