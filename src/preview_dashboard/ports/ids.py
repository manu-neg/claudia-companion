"""IdGenerator port: generates identifiers for items and blobs.

Ids are canonical ULID strings (see ADR 0007); they double as storage keys,
so they must never be derived from user input.
"""

from __future__ import annotations

from typing import Protocol

from preview_dashboard.domain.models import ItemId


class IdGenerator(Protocol):
    """Generator of unique, canonical-ULID identifiers."""

    def new_item_id(self) -> ItemId:
        """Return a new, never-before-returned item id."""
        ...

    def new_blob_id(self) -> str:
        """Return a new, never-before-returned blob id (canonical ULID)."""
        ...
