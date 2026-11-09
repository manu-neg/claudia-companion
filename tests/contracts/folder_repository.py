"""Contract test suite for the FolderRepository port (ADR 0027).

Folders and items share one store, so the suite takes a `store` fixture
returning a `FolderStore(items, folders, corrupt_folder)` over the same
empty backend. Subclass `FolderRepositoryContract` and override `store`; it
runs against the in-memory fake and the SQLite adapter, so the two cannot
drift. Referential integrity (docs/security.md C41) is part of the contract;
`corrupt_folder` simulates one tampered row for the re-validation tests
(C39), like `question_store.py`'s `corrupt_task`/`corrupt_question`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

import pytest

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    LimitExceededError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.folders import MAX_FOLDERS, Folder, FolderId
from preview_dashboard.domain.models import ItemState
from preview_dashboard.domain.query import ItemQuery
from preview_dashboard.ports.folders import FolderCounts, FolderRepository
from preview_dashboard.ports.repository import ItemRepository
from tests.builders import T0, folder_id, make_folder, make_item, ulid

# SQL metacharacters in folder names must round-trip as data (C24).
SQL_NAME_PAYLOADS = (
    "Robert'); DROP TABLE folders;--",
    "x' OR '1'='1",
    "%_\\\"'; -- /* */ OR 1=1",
    "'||(SELECT sql FROM sqlite_master)||'",
)


@dataclass(frozen=True)
class FolderStore:
    """An item repository and a folder repository over one shared (empty) store.

    `corrupt_folder` makes one stored folder row fail re-validation on the
    next read (a tampered row), like `question_store.NotifyStore`'s hooks.
    """

    items: ItemRepository
    folders: FolderRepository
    corrupt_folder: Callable[[FolderId], None]


def _renamed(folder: Folder, name: str, minutes: int = 1) -> Folder:
    return folder.renamed(name, at=T0 + timedelta(minutes=minutes))


class FolderRepositoryContract:
    """Behavior every FolderRepository implementation must have."""

    @pytest.fixture
    def store(self) -> FolderStore:
        raise NotImplementedError("override the `store` fixture in the concrete test class")

    # --- add / get / list ----------------------------------------------------

    def test_add_then_get_returns_equal_folder(self, store: FolderStore) -> None:
        folder = make_folder(
            1,
            name="Ünïcode ✓ plans",
            created_at=T0.replace(microsecond=7),
            updated_at=T0 + timedelta(hours=1, microseconds=3),
        )
        store.folders.add(folder, max_folders=MAX_FOLDERS)
        assert store.folders.get(folder.id) == folder

    def test_get_missing_raises_not_found(self, store: FolderStore) -> None:
        with pytest.raises(NotFoundError):
            store.folders.get(folder_id(404))

    def test_duplicate_id_is_refused(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        with pytest.raises(AlreadyExistsError):
            store.folders.add(make_folder(1, name="Other"), max_folders=MAX_FOLDERS)
        assert store.folders.get(folder_id(1)).name == "Folder 1"

    @pytest.mark.parametrize("clash", ["plans", "PLANS", "\uff30\uff4c\uff41\uff4e\uff53"])
    def test_caseless_duplicate_name_is_refused(self, store: FolderStore, clash: str) -> None:
        store.folders.add(make_folder(1, name="Plans"), max_folders=MAX_FOLDERS)
        with pytest.raises(AlreadyExistsError):
            store.folders.add(make_folder(2, name=clash), max_folders=MAX_FOLDERS)
        assert [f.id for f in store.folders.list()] == [folder_id(1)]

    def test_accented_name_is_a_different_folder(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1, name="Plans"), max_folders=MAX_FOLDERS)
        store.folders.add(make_folder(2, name="Pl\u00e1ns"), max_folders=MAX_FOLDERS)
        assert len(store.folders.list()) == 2

    def test_sharp_s_and_ss_clash(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1, name="Straße"), max_folders=MAX_FOLDERS)
        with pytest.raises(AlreadyExistsError):
            store.folders.add(make_folder(2, name="STRASSE"), max_folders=MAX_FOLDERS)

    def test_quota_is_enforced_atomically_with_the_insert(self, store: FolderStore) -> None:
        for n in range(1, 4):
            store.folders.add(make_folder(n), max_folders=3)
        with pytest.raises(LimitExceededError):
            store.folders.add(make_folder(4), max_folders=3)
        assert len(store.folders.list()) == 3

    def test_list_is_ordered_by_caseless_name_then_id(self, store: FolderStore) -> None:
        for n, name in ((1, "beta"), (2, "Alpha"), (3, "gamma"), (4, "Ärger"), (5, "alpha 2")):
            store.folders.add(make_folder(n, name=name), max_folders=MAX_FOLDERS)
        names = [f.name for f in store.folders.list()]
        # Caseless keys in code-point order: 'Ärger' decomposes to 'a' + U+0308,
        # which sorts after 'alpha 2' ('l' < U+0308) and before 'beta'.
        assert names == ["Alpha", "alpha 2", "Ärger", "beta", "gamma"]

    def test_list_empty(self, store: FolderStore) -> None:
        assert store.folders.list() == []

    @pytest.mark.parametrize("name", SQL_NAME_PAYLOADS)
    def test_sql_metacharacters_round_trip(self, store: FolderStore, name: str) -> None:
        folder = make_folder(1, name=name)
        store.folders.add(folder, max_folders=MAX_FOLDERS)
        store.folders.add(make_folder(2), max_folders=MAX_FOLDERS)
        assert store.folders.get(folder.id) == folder
        assert len(store.folders.list()) == 2

    # --- tampered rows (item 1: fail closed on get, skip on list) -----------------

    def test_list_skips_a_tampered_row_get_still_fails_closed(self, store: FolderStore) -> None:
        good = make_folder(1, name="Good")
        bad = make_folder(2, name="Bad")
        store.folders.add(good, max_folders=MAX_FOLDERS)
        store.folders.add(bad, max_folders=MAX_FOLDERS)
        store.corrupt_folder(bad.id)
        assert store.folders.list() == [good]
        with pytest.raises(ValidationError):
            store.folders.get(bad.id)

    def test_counts_are_unaffected_by_a_tampered_row(self, store: FolderStore) -> None:
        # counts() never rebuilds a Folder, so it does not fail closed on a
        # tampered name; the folder is simply absent from the (skipping) listing.
        bad = make_folder(1, name="Bad")
        store.folders.add(bad, max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=bad.id))
        store.corrupt_folder(bad.id)
        counts = store.folders.counts(ItemState.ACTIVE)
        assert counts.by_folder[bad.id] == 1

    # --- rename ------------------------------------------------------------------

    def test_rename_stores_name_and_time(self, store: FolderStore) -> None:
        folder = make_folder(1)
        store.folders.add(folder, max_folders=MAX_FOLDERS)
        renamed = _renamed(folder, "Renamed")
        store.folders.rename(renamed, expected_updated_at=folder.updated_at)
        assert store.folders.get(folder.id) == renamed

    def test_rename_to_own_caseless_variant_is_allowed(self, store: FolderStore) -> None:
        folder = make_folder(1, name="plans")
        store.folders.add(folder, max_folders=MAX_FOLDERS)
        store.folders.rename(_renamed(folder, "PLANS"), expected_updated_at=folder.updated_at)
        assert store.folders.get(folder.id).name == "PLANS"

    def test_rename_to_taken_name_is_refused(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1, name="Plans"), max_folders=MAX_FOLDERS)
        second = make_folder(2, name="Other")
        store.folders.add(second, max_folders=MAX_FOLDERS)
        with pytest.raises(AlreadyExistsError):
            store.folders.rename(_renamed(second, "plans"), expected_updated_at=second.updated_at)
        assert store.folders.get(second.id) == second

    def test_rename_missing_raises_not_found(self, store: FolderStore) -> None:
        missing = make_folder(9)
        with pytest.raises(NotFoundError):
            store.folders.rename(_renamed(missing, "New"), expected_updated_at=missing.updated_at)

    def test_renamed_name_frees_the_old_one(self, store: FolderStore) -> None:
        first = make_folder(1, name="Plans")
        store.folders.add(first, max_folders=MAX_FOLDERS)
        store.folders.rename(_renamed(first, "Archive"), expected_updated_at=first.updated_at)
        store.folders.add(make_folder(2, name="plans"), max_folders=MAX_FOLDERS)
        assert [f.name for f in store.folders.list()] == ["Archive", "plans"]

    # --- rename compare-and-swap (item 2) -----------------------------------------

    def test_rename_with_stale_expected_time_is_a_conflict(self, store: FolderStore) -> None:
        folder = make_folder(1)
        store.folders.add(folder, max_folders=MAX_FOLDERS)
        store.folders.rename(_renamed(folder, "First"), expected_updated_at=folder.updated_at)
        with pytest.raises(ConflictError):
            # Stale expected_updated_at: as if two renames raced from the same read.
            store.folders.rename(
                _renamed(folder, "Second", minutes=2), expected_updated_at=folder.updated_at
            )
        # The winning rename ("First") is untouched by the loser.
        assert store.folders.get(folder.id).name == "First"

    def test_rename_conflict_does_not_free_or_take_the_name(self, store: FolderStore) -> None:
        folder = make_folder(1, name="Plans")
        store.folders.add(folder, max_folders=MAX_FOLDERS)
        winner = _renamed(folder, "Archive")
        store.folders.rename(winner, expected_updated_at=folder.updated_at)
        with pytest.raises(ConflictError):
            store.folders.rename(
                _renamed(folder, "Projects", minutes=2), expected_updated_at=folder.updated_at
            )
        # Both names are free again: the failed rename touched nothing.
        store.folders.add(make_folder(2, name="Plans"), max_folders=MAX_FOLDERS)
        store.folders.add(make_folder(3, name="Projects"), max_folders=MAX_FOLDERS)

    # --- delete_if_empty (C41) ---------------------------------------------------

    def test_delete_empty_folder(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        store.folders.delete_if_empty(folder_id(1))
        with pytest.raises(NotFoundError):
            store.folders.get(folder_id(1))
        # The name is free again.
        store.folders.add(make_folder(2, name="Folder 1"), max_folders=MAX_FOLDERS)

    def test_delete_missing_raises_not_found(self, store: FolderStore) -> None:
        with pytest.raises(NotFoundError):
            store.folders.delete_if_empty(folder_id(404))

    def test_delete_refused_while_an_active_item_is_filed(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=folder_id(1)))
        with pytest.raises(ConflictError):
            store.folders.delete_if_empty(folder_id(1))
        assert store.folders.get(folder_id(1)) == make_folder(1)

    def test_delete_refused_while_a_trashed_item_is_filed(self, store: FolderStore) -> None:
        # A trashed item keeps its folder: restore must be able to put it back.
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=folder_id(1)).trashed(T0))
        with pytest.raises(ConflictError):
            store.folders.delete_if_empty(folder_id(1))

    def test_delete_allowed_once_the_item_moved_out(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        item = make_item(1, folder_id=folder_id(1))
        store.items.add(item)
        store.items.save(
            item.moved_to(None, at=T0 + timedelta(seconds=1)), expected_updated_at=item.updated_at
        )
        store.folders.delete_if_empty(folder_id(1))
        assert store.folders.list() == []

    def test_delete_allowed_once_the_item_was_purged(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        item = make_item(1, folder_id=folder_id(1)).trashed(T0)
        store.items.add(item)
        assert store.items.delete_if_purgeable(item.id, T0 + timedelta(days=30)) == item
        store.folders.delete_if_empty(folder_id(1))

    # --- items referencing folders (C41) -------------------------------------

    def test_item_add_into_missing_folder_is_not_found(self, store: FolderStore) -> None:
        with pytest.raises(NotFoundError):
            store.items.add(make_item(1, folder_id=folder_id(404)))
        with pytest.raises(NotFoundError):
            store.items.get(make_item(1).id)
        assert store.items.all_blob_ids() == set()

    def test_item_move_into_missing_folder_is_not_found(self, store: FolderStore) -> None:
        item = make_item(1)
        store.items.add(item)
        with pytest.raises(NotFoundError):
            store.items.save(
                item.moved_to(folder_id(404), at=T0 + timedelta(seconds=1)),
                expected_updated_at=item.updated_at,
            )
        assert store.items.get(item.id) == item

    def test_item_move_into_deleted_folder_is_not_found(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        item = make_item(1)
        store.items.add(item)
        moved = item.moved_to(folder_id(1), at=T0 + timedelta(seconds=1))
        store.folders.delete_if_empty(folder_id(1))  # deleted between read and save
        with pytest.raises(NotFoundError):
            store.items.save(moved, expected_updated_at=item.updated_at)
        assert store.items.get(item.id).folder_id is None

    # --- counts ------------------------------------------------------------------

    def test_counts_empty(self, store: FolderStore) -> None:
        assert store.folders.counts(ItemState.ACTIVE) == FolderCounts(by_folder={}, unfiled=0)

    def test_counts_per_state_include_empty_folders(self, store: FolderStore) -> None:
        for n in (1, 2, 3):
            store.folders.add(make_folder(n), max_folders=MAX_FOLDERS)
        store.items.add(make_item(1, folder_id=folder_id(1)))
        store.items.add(make_item(2, folder_id=folder_id(1)))
        store.items.add(make_item(3, folder_id=folder_id(1)).trashed(T0))
        store.items.add(make_item(4, folder_id=folder_id(2)).trashed(T0))
        store.items.add(make_item(5))
        store.items.add(make_item(6))
        store.items.add(make_item(7).trashed(T0))
        active = store.folders.counts(ItemState.ACTIVE)
        assert dict(active.by_folder) == {folder_id(1): 2, folder_id(2): 0, folder_id(3): 0}
        assert active.unfiled == 2
        trashed = store.folders.counts(ItemState.TRASHED)
        assert dict(trashed.by_folder) == {folder_id(1): 1, folder_id(2): 1, folder_id(3): 0}
        assert trashed.unfiled == 1

    def test_counts_match_the_filtered_listing(self, store: FolderStore) -> None:
        store.folders.add(make_folder(1), max_folders=MAX_FOLDERS)
        for n in range(1, 6):
            store.items.add(make_item(n, folder_id=folder_id(1) if n % 2 else None))
        counts = store.folders.counts(ItemState.ACTIVE)
        listed = store.items.list(ItemQuery(folder=folder_id(1), limit=200)).items
        assert counts.by_folder[folder_id(1)] == len(listed) == 3
        assert counts.unfiled == 2
        assert {i.id for i in listed} == {ulid(1), ulid(3), ulid(5)}
