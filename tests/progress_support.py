"""Test support for the MCP progress tools (ADR 0029): an in-memory fake admin API.

`FakeProgressAdmin` implements `tools.progress.ProgressApi` with the same
observable behavior as the real admin API for what the tools use (ids,
revision numbers, `expected_revision` conflicts, unknown items, kind hint, get),
and records the uploaded bytes. `tests/unit/test_mcp_progress_tools.py`
runs one contract scenario against it and against the live admin.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.config import DEFAULT_INTAKE_DENIED_PATTERNS
from preview_dashboard.interfaces.mcp.client import (
    AdminConflictError,
    AdminNotFoundError,
    UploadFile,
)
from preview_dashboard.interfaces.mcp.denylist import DenyList
from preview_dashboard.interfaces.mcp.intake import IntakeLimits, IntakePolicy
from preview_dashboard.interfaces.mcp.tools.progress import (
    ProgressApi,
    ProgressStateStore,
    ProgressTools,
)


def read_upload(files: Sequence[UploadFile]) -> dict[str, bytes]:
    """Read every upload's bytes (relpath -> bytes)."""
    out: dict[str, bytes] = {}
    for f in files:
        with f.open_reader() as chunks:
            out[f.relpath] = b"".join(chunks)
    return out


@dataclass
class FakeItem:
    """One item as the fake admin holds it."""

    id: str
    title: str
    kind: str
    pinned: bool
    folder_id: str | None
    revisions: list[dict[str, bytes]] = field(default_factory=list)

    def as_json(self) -> dict[str, object]:
        """The admin API's item JSON (only the fields the tools read)."""
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "pinned": self.pinned,
            "revision": len(self.revisions),
            "folder": {"id": self.folder_id, "name": "F"} if self.folder_id else None,
            "viewer_url": f"https://dash.example.ts.net/#/item/{self.id}",
        }


class FakeProgressAdmin:
    """In-memory `ProgressApi`; `calls` records method names in order."""

    def __init__(self) -> None:
        self.items: dict[str, FakeItem] = {}
        self.calls: list[str] = []
        self._ids = UlidGenerator()

    def publish(
        self,
        files: Sequence[UploadFile],
        *,
        title: str,
        description: str = "",
        kind_hint: str | None = None,
        pinned: bool = False,
        folder_id: str | None = None,
    ) -> dict[str, object]:
        self.calls.append("publish")
        item = FakeItem(
            id=str(self._ids.new_item_id()),
            title=title,
            kind=kind_hint or "file",
            pinned=pinned,
            folder_id=folder_id,
        )
        item.revisions.append(read_upload(files))
        self.items[item.id] = item
        return item.as_json()

    def publish_revision(
        self,
        item_id: str,
        files: Sequence[UploadFile],
        *,
        kind_hint: str | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        self.calls.append("publish_revision")
        item = self._get(item_id)
        if expected_revision is not None and expected_revision != len(item.revisions):
            raise AdminConflictError(
                "admin API 409 conflict: revision changed", status=409, code="conflict"
            )
        item.revisions.append(read_upload(files))
        item.kind = kind_hint or item.kind
        return item.as_json()

    def update_item(
        self,
        item_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        pinned: bool | None = None,
    ) -> dict[str, object]:
        self.calls.append("update_item")
        item = self._get(item_id)
        if title is not None:
            item.title = title
        if pinned is not None:
            item.pinned = pinned
        return item.as_json()

    def move_item(self, item_id: str, folder_id: str | None) -> dict[str, object]:
        self.calls.append("move_item")
        item = self._get(item_id)
        item.folder_id = folder_id
        return item.as_json()

    def get_item(self, item_id: str) -> dict[str, object]:
        self.calls.append("get_item")
        return self._get(item_id).as_json()

    def latest(self, item_id: str) -> bytes:
        """The head revision's `progress.json` bytes."""
        return self._get(item_id).revisions[-1]["progress.json"]

    def _get(self, item_id: str) -> FakeItem:
        try:
            return self.items[item_id]
        except KeyError:
            raise AdminNotFoundError(
                "admin API 404 not_found: item not found", status=404, code="not_found"
            ) from None


NOW = datetime(2026, 9, 30, 9, 15, 0, tzinfo=UTC)
STATUS: dict[str, Any] = {
    "title": "Progress tool",
    "phases": ["Build", "Review"],
    "units": [
        {"id": "P1", "name": "kind + tools", "state": "running"},
        {"id": "P2", "name": "renderer", "state": "waiting", "detail": "after schema"},
    ],
    "timeline": [{"lane": "dev", "bars": [{"unit": "P1", "from": 0, "to": 1}]}],
}


def make_intake(outbox: Path) -> IntakePolicy:
    """The real intake policy over `outbox` with the built-in denylist."""
    return IntakePolicy(
        allowed_roots=(str(outbox),),
        denylist=DenyList(DEFAULT_INTAKE_DENIED_PATTERNS),
        limits=IntakeLimits(max_files=10, max_file_bytes=1 << 20, max_item_bytes=1 << 20),
    )


def make_tools(outbox: Path, admin: ProgressApi) -> ProgressTools:
    """Progress tools over `outbox` with a fixed clock."""
    return ProgressTools(
        intake=make_intake(outbox),
        admin=admin,
        store=ProgressStateStore(str(outbox)),
        clock=lambda: NOW,
    )
