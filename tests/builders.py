"""Test data builders for domain objects (valid by default, override per test).

Shared by unit tests and the port contract suites so every test speaks the
same vocabulary and only spells out the fields it actually cares about.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from preview_dashboard.domain.folders import Folder, FolderId
from preview_dashboard.domain.models import Item, ItemFile, ItemId

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def ulid(n: int) -> str:
    """Deterministic canonical ULID for small integers (digits are valid base32)."""
    return f"{n:026d}"


def make_file(relpath: str = "index.html", *, blob: int = 1, **overrides: Any) -> ItemFile:
    """Build a valid ItemFile; `blob` seeds a unique blob id."""
    data = relpath.encode()
    fields: dict[str, Any] = {
        "relpath": relpath,
        "blob_id": ulid(10_000 + blob),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "media_type": "text/html",
    }
    fields.update(overrides)
    return ItemFile(**fields)


def make_item(n: int = 1, **overrides: Any) -> Item:
    """Build a valid ACTIVE item with id `ulid(n)` and one file (unique blob per n)."""
    fields: dict[str, Any] = {
        "id": ItemId(ulid(n)),
        "title": f"Item {n}",
        "kind": "html",
        "files": (make_file(blob=n),),
        "entry_file": "index.html",
        "created_at": T0,
        "updated_at": T0,
    }
    fields.update(overrides)
    return Item(**fields)


def folder_id(n: int) -> FolderId:
    """Deterministic folder id (kept apart from item/blob ids used in tests)."""
    return FolderId(ulid(50_000 + n))


def make_folder(n: int = 1, **overrides: Any) -> Folder:
    """Build a valid Folder with id `folder_id(n)` named `Folder <n>`."""
    fields: dict[str, Any] = {
        "id": folder_id(n),
        "name": f"Folder {n}",
        "created_at": T0,
        "updated_at": T0,
    }
    fields.update(overrides)
    return Folder(**fields)
