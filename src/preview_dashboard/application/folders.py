"""FolderService: create, list (with counts), rename, delete folders and move items (ADR 0027).

Claude organises (admin API + MCP); the viewer only reads (`list`, `get`
through a read-only capability in `bootstrap.py`). Names are sanitized by
the domain and secret-scanned raw and sanitized, like titles (C15, C39);
moving an item is an item compare-and-swap that fails with `NotFoundError`
if the folder is gone at commit time (C41).
"""

from __future__ import annotations

from dataclasses import dataclass

from preview_dashboard.domain.errors import ConflictError
from preview_dashboard.domain.folders import (
    MAX_FOLDERS,
    Folder,
    FolderId,
    parse_folder_id,
)
from preview_dashboard.domain.models import Item, ItemState, parse_item_id
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.folders import FolderRepository
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.repository import ItemRepository
from preview_dashboard.ports.scanner import ContentScanner


@dataclass(frozen=True, slots=True)
class FolderEntry:
    """One folder with the number of items (in the listed state) filed in it."""

    folder: Folder
    count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class FolderListing:
    """Every folder in name order (caseless) with counts, plus the unfiled count."""

    folders: tuple[FolderEntry, ...]
    unfiled_count: int


class FolderService:
    """Folder use cases over the folder and item repositories.

    Idempotency: `rename` to the current name and `move` to the current
    folder are no-ops (no `updated_at` bump). `move` re-reads and retries
    **once** on a conflict, like trash/restore (its intent is absolute);
    `rename` compare-and-swaps on `updated_at` and never retries, like
    `LifecycleService.update` (a new name is a specific intent, not one to
    silently reapply over a concurrent change).

    Args:
        folders / items: repositories over one shared store.
        clock: stamps creations, renames and moves.
        ids: source of new folder ids (canonical ULIDs).
        scanner: secret scan of folder names (raw and sanitized).
        max_folders: folder quota (default `MAX_FOLDERS`, 200).
    """

    def __init__(
        self,
        *,
        folders: FolderRepository,
        items: ItemRepository,
        clock: Clock,
        ids: IdGenerator,
        scanner: ContentScanner,
        max_folders: int = MAX_FOLDERS,
    ) -> None:
        if max_folders < 1:
            raise ValueError("max_folders must be >= 1")
        self._folders = folders
        self._items = items
        self._clock = clock
        self._ids = ids
        self._scanner = scanner
        self._max_folders = max_folders

    def create(self, name: str) -> Folder:
        """Create a folder named `name` (sanitized).

        Raises:
            ValidationError: invalid name (see `domain.folders`).
            SecretDetectedError: the name (raw or sanitized) matches a secret rule.
            AlreadyExistsError: a folder with a caseless-equal name exists.
            LimitExceededError: the folder quota is reached.
        """
        # Any canonical ULID will do; reusing the item-id stream keeps the
        # IdGenerator port unchanged (as `application.notify.new_ulid`).
        folder = Folder.new(id=FolderId(self._ids.new_item_id()), name=name, now=self._clock.now())
        self._scan(name, folder.name)
        self._folders.add(folder, max_folders=self._max_folders)
        return folder

    def get(self, folder_id: str) -> Folder:
        """Return one folder.

        Raises:
            ValidationError: `folder_id` is not a canonical ULID.
            NotFoundError: no such folder.
        """
        return self._folders.get(parse_folder_id(folder_id))

    def list(self, *, state: ItemState = ItemState.ACTIVE) -> FolderListing:
        """Return every folder with its item count in `state`, plus the unfiled count.

        A folder created between the two reads is listed with count 0.
        """
        folders = self._folders.list()
        counts = self._folders.counts(state)
        return FolderListing(
            folders=tuple(FolderEntry(f, counts.by_folder.get(f.id, 0)) for f in folders),
            unfiled_count=counts.unfiled,
        )

    def names(self) -> tuple[Folder, ...]:
        """Return every folder, name order, without item counts.

        Cheaper than `list`: resolving one item's (or a page's) `folder`
        JSON only needs id -> name, never a `counts()` read (`folder_refs`).
        Skips the same tampered rows `list` skips (`FolderRepository.list`).
        """
        return tuple(self._folders.list())

    def rename(self, folder_id: str, name: str) -> Folder:
        """Rename a folder (no-op if the sanitized name is unchanged).

        Never retries on conflict (like `LifecycleService.update`): the new
        name is the caller's specific intent, so silently reapplying it over
        someone else's concurrent rename would be a lost update, not a no-op.

        Raises:
            ValidationError: bad id or invalid name.
            SecretDetectedError: the name (raw or sanitized) matches a secret rule.
            NotFoundError: no such folder.
            AlreadyExistsError: another folder has a caseless-equal name.
            ConflictError: the folder was renamed concurrently; re-read and
                retry.
        """
        current = self._folders.get(parse_folder_id(folder_id))
        renamed = current.renamed(name, at=current.next_change_at(self._clock.now()))
        self._scan(name, renamed.name)
        if renamed.name == current.name:
            return current
        self._folders.rename(renamed, expected_updated_at=current.updated_at)
        return renamed

    def delete(self, folder_id: str) -> None:
        """Delete an empty folder (no item in any state may reference it).

        Raises:
            ValidationError: bad id.
            NotFoundError: no such folder.
            ConflictError: the folder still holds active or trashed items.
        """
        self._folders.delete_if_empty(parse_folder_id(folder_id))

    def move(self, item_id: str, folder_id: str | None) -> Item:
        """File an item into `folder_id` (None = unfiled); works in any item state.

        Raises:
            ValidationError: bad item or folder id.
            NotFoundError: no such item, or no such folder (checked
                atomically with the save).
            ConflictError: the item changed concurrently twice in a row.
        """
        target = None if folder_id is None else parse_folder_id(folder_id)
        parsed = parse_item_id(item_id)
        try:
            return self._move_once(self._items.get(parsed), target)
        except ConflictError:
            # Re-read: the other writer may have moved it already (then no-op).
            return self._move_once(self._items.get(parsed), target)

    # --- internals -----------------------------------------------------------

    def _move_once(self, item: Item, target: FolderId | None) -> Item:
        if item.folder_id == target:
            return item
        moved = item.moved_to(target, at=item.next_change_at(self._clock.now()))
        self._items.save(moved, expected_updated_at=item.updated_at)
        return moved

    def _scan(self, *texts: str) -> None:
        # A folder name is shown like a title and is published metadata (C15).
        session = self._scanner.new_session()
        for text in texts:
            # surrogatepass: raw text may hold lone surrogates; the scan must not crash.
            session.feed(text.encode("utf-8", "surrogatepass") + b"\n")
        session.finish()
