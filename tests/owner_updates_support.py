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
from preview_dashboard.adapters.telegram.updates import TelegramUpdateSource
from preview_dashboard.interfaces.notifier.owner_updates import OwnerUpdateRouter
from preview_dashboard.wire import notifier_messages as wm
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
    """The owner-update path over fakes; admin routes answer like a healthy M3 by default."""

    api: FakeBotApi = field(default_factory=FakeBotApi)
    admin: FakeNotifierAdmin = field(default_factory=FakeNotifierAdmin)
    # The router's monotonic clock (delete retries); tests move it forward.
    now: float = 0.0

    def __post_init__(self) -> None:
        self.admin.route("POST", wm.MESSAGES_PATH, result("stored"))
        self.admin.route("POST", wm.APPROVALS_PATH, result("tapped"))
        self.admin.route("POST", wm.CODES_PATH, result("accepted"))
        client = self.api.client()
        self.queue = AdminDeliveryQueue(
            Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=self.admin.transport()
        )
        self.source = TelegramUpdateSource(client, OWNER)
        self.channel = TelegramChannel(client, OWNER, dashboard_origin=None)
        self.router = OwnerUpdateRouter(
            self.source, self.queue, self.channel, monotonic=lambda: self.now
        )

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
    return header + bytes(lacing) + body


def ogg_opus(seconds: float = 2.0, *, pre_skip: int = 312, audio_bytes: int = 200) -> bytes:
    """A minimal Ogg/Opus stream lasting `seconds` (OpusHead, OpusTags, one audio page)."""
    head = b"OpusHead" + struct.pack("<BBHIhB", 1, 1, pre_skip, 48_000, 0, 0)
    tags = b"OpusTags" + struct.pack("<I", 4) + b"test" + struct.pack("<I", 0)
    granule = pre_skip + int(seconds * 48_000)
    return (
        _page(head, granule=0, seq=0, flags=0x02)
        + _page(tags, granule=0, seq=1, flags=0)
        + _page(b"\x00" * audio_bytes, granule=granule, seq=2, flags=0x04)
    )
