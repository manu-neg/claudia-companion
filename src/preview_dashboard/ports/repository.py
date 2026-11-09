"""ItemRepository port: persistence of Item metadata and state.

Contract is enforced by `tests/contracts/item_repository.py`, run against
both the in-memory fake and every real adapter.

Security obligations for every implementation (docs/security.md C7, C24):
- **Parameterized queries only:** values (titles, descriptions, relpaths,
  ids, cursors) are always bound as parameters, never formatted into SQL
  (or any other query language); titles like `x'); DROP TABLE items;--`
  and relpaths like `it's.txt` must round-trip unchanged.
- **Re-validate on read:** entities are rebuilt through their constructors
  (`Item(...)`, `ItemFile(...)`) when loaded, never via `object.__new__` or
  by bypassing `__post_init__`, so a tampered or corrupted row fails with
  `ValidationError` instead of yielding an unsafe item.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from preview_dashboard.domain.models import Item, ItemId
from preview_dashboard.domain.query import ItemQuery, Page


@dataclass(frozen=True, slots=True, kw_only=True)
class RepositoryUsage:
    """Aggregate storage usage, for the global quotas (docs/security.md C18).

    Attributes:
        item_count: number of items in **any** state (trashed items still
            occupy disk until purged, so they count against `max_items`).
        total_bytes: sum of `ItemFile.size` over every file of every kept
            revision of every item, in any state (old revisions occupy disk
            too, ADR 0019).
    """

    item_count: int
    total_bytes: int


class ItemRepository(Protocol):
    """Stores items (whole aggregates, including their file manifests).

    (`builtins.list` is spelled out below because the `list` method shadows
    the builtin inside the class body.)

    Items are immutable values: `get` returns what was last `add`ed/`save`d,
    equal field by field, **including every kept revision** (`history`,
    `revision`, `revision_at`). Writes are atomic per call; `save` is a
    compare-and-swap on `updated_at` (never a blind last-write-wins) and
    replaces the stored revisions with the item's (pruned ones disappear).
    """

    def add(self, item: Item) -> None:
        """Insert a new item.

        Raises:
            AlreadyExistsError: an item with `item.id` already exists.
        """
        ...

    def get(self, item_id: ItemId) -> Item:
        """Return the item with this id, in any state.

        Raises:
            NotFoundError: no such item.
        """
        ...

    def list(self, query: ItemQuery) -> Page[Item]:
        """Return one page of items matching `query`.

        Order: pinned first, then `created_at` desc, then `id` desc (see
        `domain.query`). `next_cursor` is None on the last page and must be
        accepted back as `ItemQuery.cursor` to fetch the following page.
        Convert the cursor's `created_us` with
        `domain.query.created_us_to_datetime` (or bind it as an integer);
        it is pre-validated to be in range, so no OverflowError can escape.
        """
        ...

    def save(self, item: Item, *, expected_updated_at: datetime) -> None:
        """Replace an existing item (matched by id) with `item`, compare-and-swap style.

        Optimistic concurrency (docs/security.md C11): the admin and viewer
        processes both write items, so a blind "last write wins" could let
        a trash undo a concurrent edit (or vice versa). The replacement
        happens only if the stored row's `updated_at` still equals
        `expected_updated_at` (the value the caller read), checked and
        written in **one** transaction/critical section. Callers must make
        every save strictly increase `updated_at` so it acts as a version.

        Args:
            item: the new state of the item.
            expected_updated_at: tz-aware `updated_at` of the item as read.

        Raises:
            NotFoundError: no item with `item.id` exists.
            ConflictError: the stored item changed since it was read.
        """
        ...

    def delete(self, item_id: ItemId) -> bool:
        """Permanently delete an item; idempotent.

        Returns:
            True if a row was deleted, False if it did not exist.
        """
        ...

    def delete_if_purgeable(self, item_id: ItemId, cutoff: datetime) -> Item | None:
        """Atomically delete an item only if it is still due for purge.

        In **one** transaction/critical section: delete the item iff it
        exists, its state is TRASHED and `trashed_at <= cutoff` (boundary
        inclusive; purge passes `cutoff = now - retention`). This closes the
        race where the owner restores an item (viewer process) between the
        purge job's listing and its delete — a separate `get` + `delete`
        would permanently destroy the just-restored item.

        Args:
            item_id: item to delete.
            cutoff: tz-aware; items trashed at or before it are due.

        Returns:
            The deleted item (the caller then deletes its blobs), or None if
            it does not exist, is ACTIVE, or was trashed after `cutoff`.
        """
        ...

    def list_purgeable(self, now: datetime, retention: timedelta) -> builtins.list[Item]:
        """Return TRASHED items with `now - trashed_at >= retention`, oldest trash first."""
        ...

    def all_blob_ids(self) -> set[str]:
        """Return every blob id referenced by any kept revision of any item, in any state.

        Orphan-sweep protocol (order matters): the sweep first snapshots
        `BlobStore.list_ids(created_before=now - grace)` and only *then*
        calls this method, deleting blobs in the snapshot that are not
        referenced here. Reading references second means any publish whose
        blobs made the snapshot has either committed (and is seen here) or
        has run longer than `grace`, which must exceed the application's
        hard publish timeout — such a publish has already been aborted.
        """
        ...

    def usage(self) -> RepositoryUsage:
        """Return item count and total file bytes over all items, in any state.

        Must be computed from the stored manifests (e.g. `COUNT(*)` over
        items and `SUM(size)` over the files of every kept revision) in one
        consistent read; an empty repository returns zeros.
        """
        ...
