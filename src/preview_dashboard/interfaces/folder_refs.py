"""Folder references in item JSON, shared by the admin API and the viewer API (ADR 0027).

Resolves the `folder: {"id", "name"} | null` field of item responses with at
most one folder read per request (one `names()` read of the <= 200
folders, no item counts), never one lookup per item; an item whose folder
is not listed renders `null`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Protocol

from preview_dashboard.application.folders import FolderListing
from preview_dashboard.domain.folders import Folder
from preview_dashboard.domain.models import Item, ItemState

FolderNames = Mapping[str, str]
"""Folder id -> folder name, for the folders the items of one response are filed in."""


class FolderLookup(Protocol):
    """Read side of folders: `FolderService` (admin) and `bootstrap.FolderReader` (viewer)."""

    def list(self, *, state: ItemState = ...) -> FolderListing:
        """Every folder in name order with its item count in `state`, plus unfiled."""
        ...

    def get(self, folder_id: str) -> Folder:
        """One folder (ValidationError: bad id; NotFoundError: no such folder)."""
        ...

    def names(self) -> Iterable[Folder]:
        """Every folder, name order, without item counts (cheaper than `list`)."""
        ...


def folder_names(lookup: FolderLookup, items: Iterable[Item]) -> dict[str, str]:
    """Return id -> name for every folder `items` are filed in (one `names()`, or none).

    Uses `names()`, never `list()` (which also runs `counts()`) or `get`
    (which fails closed): a folder row the adapter omits from listings
    (e.g. one that fails re-validation) must render as `null`, not fail
    the whole response. Call it **after** reading the items: a folder
    missing now was deleted since, which needs it empty, so the item is no
    longer filed there and `folder_ref` reports it unfiled — the current
    truth.
    """
    wanted = {item.folder_id for item in items if item.folder_id is not None}
    if not wanted:
        return {}
    return {folder.id: folder.name for folder in lookup.names() if folder.id in wanted}


def folder_ref(item: Item, names: FolderNames) -> dict[str, str] | None:
    """The item's `folder` JSON: `{"id", "name"}`, or None when unfiled (or folder gone)."""
    if item.folder_id is None:
        return None
    name = names.get(item.folder_id)
    return None if name is None else {"id": item.folder_id, "name": name}


def listing_json(listing: FolderListing) -> list[dict[str, object]]:
    """`[{"id", "name", "count"}]` in the listing's (name) order."""
    return [{"id": e.folder.id, "name": e.folder.name, "count": e.count} for e in listing.folders]
