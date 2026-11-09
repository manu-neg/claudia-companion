"""FolderRepository port: persistence of folders and per-folder item counts (ADR 0027).

Contract is enforced by `tests/contracts/folder_repository.py`, run against
both the in-memory fake and every real adapter. A folder repository shares
its store with the `ItemRepository` (items reference folders), so the
referential rules below are checked atomically with the other store's writes.

Security obligations for every implementation (docs/security.md C24, C41):
- **Parameterized queries only**; names like `x'); DROP TABLE folders;--`
  round-trip unchanged.
- **Re-validate on read:** folders are rebuilt through `Folder(...)`, and a
  stored uniqueness key that disagrees with the stored name fails closed —
  `get` raises `ValidationError` for that one folder; `list`/`counts` skip
  the bad row (logged by id only) so the rest of the listing still renders.
- **Referential integrity:** an item never references a missing folder
  (item `add`/`save` into an unknown folder → `NotFoundError`), and a
  folder referenced by any item, in any state, is never deleted.
"""

from __future__ import annotations

import builtins
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from preview_dashboard.domain.folders import Folder, FolderId
from preview_dashboard.domain.models import ItemState


@dataclass(frozen=True, slots=True, kw_only=True)
class FolderCounts:
    """Item counts per folder for one item state.

    Attributes:
        by_folder: every existing folder's id -> its number of items in the
            state (0 for an empty folder).
        unfiled: number of items in the state that are in no folder.
    """

    by_folder: Mapping[FolderId, int]
    unfiled: int


class FolderRepository(Protocol):
    """Stores folders (id, name, timestamps); items reference them by `Item.folder_id`.

    (`builtins.list` is spelled out below because the `list` method shadows
    the builtin inside the class body.)

    Moving an item is **not** a method here: it is an `ItemRepository.save`
    compare-and-swap of the item with a new `folder_id`, which must fail with
    `NotFoundError` if that folder does not exist at commit time.
    """

    def add(self, folder: Folder, *, max_folders: int) -> None:
        """Insert a new folder, atomically enforcing the quota and name uniqueness.

        Raises:
            LimitExceededError: `max_folders` folders already exist.
            AlreadyExistsError: the id exists, or another folder's name has
                the same `name_key` (caseless match).
        """
        ...

    def get(self, folder_id: FolderId) -> Folder:
        """Return the folder with this id.

        Raises:
            NotFoundError: no such folder.
        """
        ...

    def list(self) -> builtins.list[Folder]:
        """Return every existing, valid folder, ordered by `name_key`, then id.

        A row that fails re-validation (tampered `name`/`name_key`) is
        skipped rather than raised: a single bad row must not take down
        `/api/folders` or any item listing that renders a `folder` field
        (`get` still fails closed on that one folder, C39).
        """
        ...

    def rename(self, folder: Folder, *, expected_updated_at: datetime) -> None:
        """Store `folder.name` and `folder.updated_at`, compare-and-swapping on `updated_at`.

        The uniqueness check and the write are one atomic step; renaming a
        folder to a caseless variant of its own name is allowed.

        Raises:
            NotFoundError: no such folder.
            AlreadyExistsError: another folder has the same `name_key`.
            ConflictError: the stored folder's `updated_at` is not
                `expected_updated_at` (changed concurrently).
        """
        ...

    def delete_if_empty(self, folder_id: FolderId) -> None:
        """Delete a folder only if no item, in any state, references it (atomic).

        Raises:
            NotFoundError: no such folder.
            ConflictError: at least one item (active or trashed) is filed in it.
        """
        ...

    def counts(self, state: ItemState) -> FolderCounts:
        """Return per-folder and unfiled item counts for items in `state` (one snapshot)."""
        ...
