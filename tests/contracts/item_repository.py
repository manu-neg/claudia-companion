"""Contract test suite for the ItemRepository port.

Subclass `ItemRepositoryContract` in a `test_*.py` module and override the
`repo` fixture to return a fresh, empty repository, and `folders` to return
the `FolderRepository` sharing its store (items reference folders, ADR 0027).
The same suite runs against the in-memory fake and the SQLite adapter, so
they cannot drift.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, timedelta, timezone

import pytest

from preview_dashboard.domain.errors import AlreadyExistsError, ConflictError, NotFoundError
from preview_dashboard.domain.folders import MAX_FOLDERS, UNFILED
from preview_dashboard.domain.models import Item, ItemId, ItemState
from preview_dashboard.domain.query import ItemQuery, item_sort_key
from preview_dashboard.ports.folders import FolderRepository
from preview_dashboard.ports.repository import ItemRepository, RepositoryUsage
from tests.builders import T0, folder_id, make_file, make_folder, make_item, ulid

RETENTION = timedelta(days=14)


def _all_pages(repo: ItemRepository, **filters: object) -> list[Item]:
    """Walk every page with a small limit and return the concatenation."""
    items: list[Item] = []
    cursor: str | None = None
    for _ in range(100):  # hard stop: a broken cursor must not hang the suite
        page = repo.list(ItemQuery(limit=2, cursor=cursor, **filters))  # type: ignore[arg-type]
        items.extend(page.items)
        cursor = page.next_cursor
        if cursor is None:
            return items
    raise AssertionError("pagination did not terminate")


class ItemRepositoryContract:
    """Behavior every ItemRepository implementation must have."""

    @pytest.fixture
    def repo(self) -> ItemRepository:
        raise NotImplementedError("override the `repo` fixture in the concrete test class")

    @pytest.fixture
    def folders(self, repo: ItemRepository) -> FolderRepository:
        raise NotImplementedError("override the `folders` fixture in the concrete test class")

    # --- add / get ---------------------------------------------------------

    def test_add_then_get_returns_equal_item(self, repo: ItemRepository) -> None:
        item = make_item(
            1,
            title="Ünïcode ✓ title",
            description="line 1\nline 2",
            kind="markdown",
            files=(
                make_file("index.html", blob=1),
                make_file("assets/app.js", blob=2, media_type="text/javascript"),
                make_file("empty.txt", blob=3, size=0, media_type="text/plain"),
            ),
            created_at=T0.replace(microsecond=123456),
            updated_at=T0 + timedelta(hours=1, microseconds=7),
            pinned=True,
        )
        repo.add(item)
        got = repo.get(item.id)
        assert got == item
        assert got.files == item.files  # order preserved
        assert got.created_at.tzinfo is not None
        assert got.created_at.utcoffset() == timedelta(0)

    def test_sql_metacharacters_round_trip(self, repo: ItemRepository) -> None:
        # Values must be bound as parameters, never spliced into SQL (C24).
        item = make_item(
            1,
            title="Robert'); DROP TABLE items;--",
            description="%_\\\"'; -- /* */ OR 1=1",
            files=(
                make_file("it's.txt", blob=1, media_type="text/plain"),
                make_file("100_pct'--/x.txt", blob=3, media_type="text/plain"),
            ),
            entry_file="it's.txt",
        )
        repo.add(item)
        repo.add(make_item(2))
        assert repo.get(item.id) == item
        assert {i.id for i in repo.list(ItemQuery()).items} == {ulid(1), ulid(2)}
        assert repo.all_blob_ids() == {ulid(10_001), ulid(10_002), ulid(10_003)}
        saved = item.with_metadata(now=T0, title="a' OR '1'='1", description="%")
        repo.save(saved, expected_updated_at=item.updated_at)
        assert repo.get(item.id) == saved
        assert repo.get(ItemId(ulid(2))).title == "Item 2"

    def test_trashed_item_round_trips(self, repo: ItemRepository) -> None:
        item = make_item(1).trashed(T0 + timedelta(minutes=5))
        repo.add(item)
        assert repo.get(item.id) == item

    def test_non_utc_input_round_trips_as_same_instant(self, repo: ItemRepository) -> None:
        tz = timezone(timedelta(hours=-5))
        item = make_item(1, created_at=T0.astimezone(tz), updated_at=T0.astimezone(tz))
        repo.add(item)
        got = repo.get(item.id)
        assert got.created_at == T0
        assert got.created_at.tzinfo == UTC

    def test_get_missing_raises_not_found(self, repo: ItemRepository) -> None:
        with pytest.raises(NotFoundError):
            repo.get(ItemId(ulid(999)))

    def test_add_duplicate_id_raises_already_exists(self, repo: ItemRepository) -> None:
        repo.add(make_item(1))
        with pytest.raises(AlreadyExistsError):
            repo.add(make_item(1, title="other"))
        assert repo.get(ItemId(ulid(1))).title == "Item 1"

    # --- save / delete -----------------------------------------------------

    def test_save_replaces_existing_item(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        updated = item.with_metadata(now=T0 + timedelta(hours=1), title="New", pinned=True)
        repo.save(updated, expected_updated_at=item.updated_at)
        assert repo.get(item.id) == updated

    def test_save_can_replace_files(self, repo: ItemRepository) -> None:
        import dataclasses

        item = make_item(1)
        repo.add(item)
        updated = dataclasses.replace(
            item,
            files=(make_file("main.html", blob=50), make_file("x/y.css", blob=51)),
            entry_file="main.html",
        )
        repo.save(updated, expected_updated_at=item.updated_at)
        assert repo.get(item.id) == updated
        assert repo.all_blob_ids() == {ulid(10_050), ulid(10_051)}

    def test_save_state_transition_persists(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        repo.save(item.trashed(T0 + timedelta(days=1)), expected_updated_at=item.updated_at)
        trashed = repo.get(item.id)
        assert trashed.state is ItemState.TRASHED
        repo.save(trashed.restored(T0 + timedelta(days=2)), expected_updated_at=trashed.updated_at)
        got = repo.get(item.id)
        assert got.state is ItemState.ACTIVE
        assert got.trashed_at is None

    def test_save_missing_raises_not_found(self, repo: ItemRepository) -> None:
        item = make_item(1)
        with pytest.raises(NotFoundError):
            repo.save(item, expected_updated_at=item.updated_at)

    # --- save: optimistic concurrency (docs/security.md C11) -----------------

    def test_concurrent_update_raises_conflict_and_keeps_first_write(
        self, repo: ItemRepository
    ) -> None:
        item = make_item(1)
        repo.add(item)
        # Two writers read the same version...
        first = item.with_metadata(now=T0 + timedelta(minutes=1), title="first")
        second = item.trashed(T0 + timedelta(minutes=2))
        repo.save(first, expected_updated_at=item.updated_at)
        # ...the second one's compare-and-swap must fail, not overwrite.
        with pytest.raises(ConflictError):
            repo.save(second, expected_updated_at=item.updated_at)
        assert repo.get(item.id) == first

    def test_conflict_leaves_files_untouched(self, repo: ItemRepository) -> None:
        import dataclasses

        item = make_item(1, files=(make_file(blob=1),))
        repo.add(item)
        stale = dataclasses.replace(item, files=(make_file(blob=2),))
        with pytest.raises(ConflictError):
            repo.save(stale, expected_updated_at=item.updated_at + timedelta(microseconds=1))
        assert repo.get(item.id) == item
        assert repo.all_blob_ids() == {ulid(10_001)}

    def test_save_after_reread_succeeds(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        first = item.with_metadata(now=T0 + timedelta(minutes=1), pinned=True)
        repo.save(first, expected_updated_at=item.updated_at)
        current = repo.get(item.id)
        second = current.trashed(T0 + timedelta(minutes=2))
        repo.save(second, expected_updated_at=current.updated_at)
        assert repo.get(item.id) == second

    def test_expected_version_compares_instants_not_offsets(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        tz = timezone(timedelta(hours=3))
        updated = item.with_metadata(now=T0 + timedelta(hours=1), title="New")
        repo.save(updated, expected_updated_at=item.updated_at.astimezone(tz))
        assert repo.get(item.id) == updated

    def test_expected_version_is_microsecond_exact(self, repo: ItemRepository) -> None:
        item = make_item(1, updated_at=T0 + timedelta(microseconds=5))
        repo.add(item)
        updated = item.with_metadata(now=T0 + timedelta(hours=1), title="New")
        with pytest.raises(ConflictError):
            repo.save(updated, expected_updated_at=T0 + timedelta(microseconds=4))

    def test_missing_row_is_not_found_even_with_stale_version(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        repo.delete(item.id)
        with pytest.raises(NotFoundError):
            repo.save(item.with_metadata(now=T0, pinned=True), expected_updated_at=T0)

    def test_delete_is_idempotent(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        assert repo.delete(item.id) is True
        assert repo.delete(item.id) is False
        with pytest.raises(NotFoundError):
            repo.get(item.id)

    def test_delete_leaves_other_items(self, repo: ItemRepository) -> None:
        repo.add(make_item(1))
        repo.add(make_item(2))
        repo.delete(ItemId(ulid(1)))
        assert repo.get(ItemId(ulid(2))).id == ulid(2)

    # --- list: ordering, filters, paging -----------------------------------

    def test_list_empty(self, repo: ItemRepository) -> None:
        page = repo.list(ItemQuery())
        assert page.items == ()
        assert page.next_cursor is None

    def test_list_orders_pinned_then_created_desc_then_id_desc(self, repo: ItemRepository) -> None:
        h = timedelta(hours=1)
        items = [
            make_item(1, created_at=T0, updated_at=T0),
            make_item(2, created_at=T0 + h, updated_at=T0 + h),
            make_item(3, created_at=T0 + h, updated_at=T0 + h),  # ties with 2 -> id desc
            make_item(4, created_at=T0 - h, updated_at=T0 - h, pinned=True),
            make_item(5, created_at=T0 + 2 * h, updated_at=T0 + 2 * h),
            make_item(6, created_at=T0 - 2 * h, updated_at=T0 - 2 * h, pinned=True),
        ]
        for item in items:
            repo.add(item)
        ids = [i.id for i in repo.list(ItemQuery()).items]
        assert ids == [ulid(4), ulid(6), ulid(5), ulid(3), ulid(2), ulid(1)]

    def test_list_orders_by_microseconds(self, repo: ItemRepository) -> None:
        us = timedelta(microseconds=1)
        repo.add(make_item(1, created_at=T0 + us, updated_at=T0 + us))
        repo.add(make_item(2, created_at=T0, updated_at=T0))
        assert [i.id for i in repo.list(ItemQuery()).items] == [ulid(1), ulid(2)]

    def test_list_filters_by_state(self, repo: ItemRepository) -> None:
        repo.add(make_item(1))
        repo.add(make_item(2).trashed(T0 + timedelta(minutes=1)))
        active = repo.list(ItemQuery(state=ItemState.ACTIVE)).items
        trashed = repo.list(ItemQuery(state=ItemState.TRASHED)).items
        assert [i.id for i in active] == [ulid(1)]
        assert [i.id for i in trashed] == [ulid(2)]

    def test_list_filters_by_kind(self, repo: ItemRepository) -> None:
        repo.add(make_item(1, kind="image"))
        repo.add(make_item(2, kind="html"))
        repo.add(make_item(3, kind="image"))
        page = repo.list(ItemQuery(kind="image"))
        assert [i.id for i in page.items] == [ulid(3), ulid(1)]

    def test_list_filters_by_several_kinds(self, repo: ItemRepository) -> None:
        repo.add(make_item(1, kind="html"))
        repo.add(make_item(2, kind="progress"))
        repo.add(make_item(3, kind="image"))
        repo.add(make_item(4, kind="html").trashed(T0 + timedelta(minutes=1)))
        page = repo.list(ItemQuery(kinds=("html", "progress")))
        assert [i.id for i in page.items] == [ulid(2), ulid(1)]
        assert page.next_cursor is None
        # One kind via `kinds` is the same filter as `kind`.
        assert (
            repo.list(ItemQuery(kinds=("image",))).items == repo.list(ItemQuery(kind="image")).items
        )
        trashed = repo.list(ItemQuery(kinds=("html", "image"), state=ItemState.TRASHED))
        assert [i.id for i in trashed.items] == [ulid(4)]

    def test_list_several_kinds_up_to_the_maximum(self, repo: ItemRepository) -> None:
        names = ("audio", "code", "csv", "diff", "html", "image", "json", "pdf")
        for n, name in enumerate(names, start=1):
            repo.add(make_item(n, kind=name))
        repo.add(make_item(9, kind="video"))
        page = repo.list(ItemQuery(kinds=names, limit=200))
        assert {i.id for i in page.items} == {ulid(n) for n in range(1, 9)}
        # Every padding length (1..8 distinct kinds) returns exactly its kinds.
        for count in range(1, len(names) + 1):
            got = repo.list(ItemQuery(kinds=names[:count], limit=200)).items
            assert {i.kind for i in got} == set(names[:count])
            assert len(got) == count

    @pytest.mark.parametrize("use_folder", [False, True])
    def test_multi_kind_paging_keeps_order_without_gaps(
        self, repo: ItemRepository, folders: FolderRepository, use_folder: bool
    ) -> None:
        self._with_folders(folders, 1)
        kinds = ("html", "progress", "image")
        for n in range(1, 13):
            at = T0 + timedelta(minutes=n % 3)  # many created_at ties
            repo.add(
                make_item(
                    n,
                    kind=kinds[n % 3],
                    created_at=at,
                    updated_at=at,
                    pinned=n in (2, 7),
                    folder_id=folder_id(1) if use_folder and n % 4 else None,
                )
            )
        folder = folder_id(1) if use_folder else None
        wanted = ("html", "progress")
        walked = _all_pages(repo, kinds=wanted, folder=folder)
        full = repo.list(ItemQuery(limit=200, kinds=wanted, folder=folder)).items
        assert [i.id for i in walked] == [i.id for i in full]
        assert len({i.id for i in walked}) == len(walked)
        assert {i.kind for i in walked} == set(wanted)
        keys = [item_sort_key(i) for i in walked]
        assert keys == sorted(keys, reverse=True)
        expected = sum(
            1 for n in range(1, 13) if kinds[n % 3] in wanted and (not use_folder or n % 4)
        )
        assert len(walked) == expected

    def test_list_respects_limit_and_paginates_without_gaps(self, repo: ItemRepository) -> None:
        for n in range(1, 8):
            at = T0 + timedelta(minutes=n % 3)  # many created_at ties
            repo.add(make_item(n, created_at=at, updated_at=at, pinned=n in (2, 5)))
        first = repo.list(ItemQuery(limit=2))
        assert len(first.items) == 2
        assert first.next_cursor is not None
        walked = _all_pages(repo)
        full = repo.list(ItemQuery(limit=200)).items
        assert [i.id for i in walked] == [i.id for i in full]
        assert len({i.id for i in walked}) == 7
        keys = [item_sort_key(i) for i in walked]
        assert keys == sorted(keys, reverse=True)

    def test_list_last_page_has_no_cursor_when_exactly_full(self, repo: ItemRepository) -> None:
        repo.add(make_item(1))
        repo.add(make_item(2))
        page = repo.list(ItemQuery(limit=2))
        assert len(page.items) == 2
        assert page.next_cursor is None

    def test_list_paging_combines_with_filters(self, repo: ItemRepository) -> None:
        for n in range(1, 7):
            item = make_item(n, kind="image" if n % 2 else "html")
            repo.add(item.trashed(T0 + timedelta(minutes=1)) if n > 4 else item)
        walked = _all_pages(repo, kind="image", state=ItemState.ACTIVE)
        assert [i.id for i in walked] == [ulid(3), ulid(1)]

    # --- purge support -----------------------------------------------------

    def test_list_purgeable_boundary_and_order(self, repo: ItemRepository) -> None:
        now = T0 + timedelta(days=30)
        repo.add(make_item(1))  # active: never purgeable
        repo.add(make_item(2).trashed(now - RETENTION))  # exactly at boundary
        repo.add(make_item(3).trashed(now - RETENTION + timedelta(microseconds=1)))
        repo.add(make_item(4).trashed(now - RETENTION - timedelta(days=1)))  # oldest
        due = repo.list_purgeable(now, RETENTION)
        assert [i.id for i in due] == [ulid(4), ulid(2)]

    def test_delete_if_purgeable_deletes_due_item_boundary_inclusive(
        self, repo: ItemRepository
    ) -> None:
        item = make_item(1).trashed(T0 + timedelta(minutes=5))
        repo.add(item)
        assert repo.delete_if_purgeable(item.id, T0 + timedelta(minutes=5)) == item
        with pytest.raises(NotFoundError):
            repo.get(item.id)
        assert repo.all_blob_ids() == set()

    def test_delete_if_purgeable_keeps_item_trashed_after_cutoff(
        self, repo: ItemRepository
    ) -> None:
        item = make_item(1).trashed(T0 + timedelta(minutes=5))
        repo.add(item)
        cutoff = T0 + timedelta(minutes=5) - timedelta(microseconds=1)
        assert repo.delete_if_purgeable(item.id, cutoff) is None
        assert repo.get(item.id) == item

    def test_delete_if_purgeable_keeps_restored_item(self, repo: ItemRepository) -> None:
        # Restored between the purge job's listing and its delete: must survive.
        trashed = make_item(1).trashed(T0)
        repo.add(trashed)
        restored = trashed.restored(T0 + timedelta(days=20))
        repo.save(restored, expected_updated_at=trashed.updated_at)
        assert repo.delete_if_purgeable(trashed.id, T0 + timedelta(days=30)) is None
        assert repo.get(trashed.id) == restored

    def test_delete_if_purgeable_missing_returns_none(self, repo: ItemRepository) -> None:
        assert repo.delete_if_purgeable(ItemId(ulid(404)), T0) is None

    def test_delete_if_purgeable_non_utc_cutoff(self, repo: ItemRepository) -> None:
        item = make_item(1).trashed(T0)
        repo.add(item)
        tz = timezone(timedelta(hours=9))
        assert repo.delete_if_purgeable(item.id, T0.astimezone(tz)) == item

    def test_delete_if_purgeable_leaves_other_items(self, repo: ItemRepository) -> None:
        repo.add(make_item(1).trashed(T0))
        repo.add(make_item(2).trashed(T0))
        repo.delete_if_purgeable(ItemId(ulid(1)), T0)
        assert repo.get(ItemId(ulid(2))).id == ulid(2)
        assert repo.all_blob_ids() == {ulid(10_002)}

    def test_list_purgeable_empty(self, repo: ItemRepository) -> None:
        assert repo.list_purgeable(T0, RETENTION) == []

    def test_all_blob_ids_covers_every_state(self, repo: ItemRepository) -> None:
        repo.add(make_item(1, files=(make_file(blob=1), make_file("a.css", blob=2))))
        repo.add(make_item(2, files=(make_file(blob=3),)).trashed(T0))
        assert repo.all_blob_ids() == {ulid(10_001), ulid(10_002), ulid(10_003)}
        repo.delete(ItemId(ulid(1)))
        assert repo.all_blob_ids() == {ulid(10_003)}

    def test_all_blob_ids_empty(self, repo: ItemRepository) -> None:
        assert repo.all_blob_ids() == set()

    # --- usage (global quotas, docs/security.md C18) -------------------------

    def test_usage_empty(self, repo: ItemRepository) -> None:
        assert repo.usage() == RepositoryUsage(item_count=0, total_bytes=0)

    def test_usage_counts_every_state_and_file(self, repo: ItemRepository) -> None:
        repo.add(
            make_item(
                1,
                files=(
                    make_file("index.html", blob=1, size=100),
                    make_file("a.css", blob=2, size=23),
                    make_file("empty.txt", blob=3, size=0, media_type="text/plain"),
                ),
            )
        )
        repo.add(make_item(2, files=(make_file(blob=4, size=2**40),)).trashed(T0))
        assert repo.usage() == RepositoryUsage(item_count=2, total_bytes=123 + 2**40)

    def test_usage_follows_save_and_delete(self, repo: ItemRepository) -> None:
        import dataclasses

        item = make_item(1, files=(make_file(blob=1, size=10),))
        repo.add(item)
        repo.save(
            dataclasses.replace(item, files=(make_file(blob=2, size=7),)),
            expected_updated_at=item.updated_at,
        )
        assert repo.usage() == RepositoryUsage(item_count=1, total_bytes=7)
        repo.delete(item.id)
        assert repo.usage() == RepositoryUsage(item_count=0, total_bytes=0)

    # --- revisions (ADR 0019) ------------------------------------------------

    @staticmethod
    def _revised(item: Item, n: int) -> Item:
        return item.with_revision(
            kind="markdown",
            files=(
                make_file("notes.md", blob=100 + 2 * n, media_type="text/markdown"),
                make_file("sub/b.md", blob=101 + 2 * n, media_type="text/markdown"),
            ),
            entry_file="notes.md",
            at=item.next_change_at(T0 + timedelta(hours=n)),
        )[0]

    def test_revisions_round_trip(self, repo: ItemRepository) -> None:
        item = make_item(1, pinned=True)
        repo.add(item)
        revised = self._revised(item, 2)
        repo.save(revised, expected_updated_at=item.updated_at)
        got = repo.get(item.id)
        assert got == revised
        assert got.revision == 2
        assert got.history == (item.head,)
        assert got.revision_at == revised.revision_at
        assert [i.revision for i in repo.list(ItemQuery()).items] == [2]
        # The kind filter follows the head.
        assert [i.id for i in repo.list(ItemQuery(kind="markdown")).items] == [item.id]
        assert repo.list(ItemQuery(kind="html")).items == ()

    def test_revised_item_can_be_added_whole(self, repo: ItemRepository) -> None:
        item = self._revised(self._revised(make_item(1), 2), 3)
        repo.add(item)
        assert repo.get(item.id) == item

    def test_blob_ids_and_usage_cover_every_revision(self, repo: ItemRepository) -> None:
        item = make_item(1, files=(make_file(blob=1, size=10),))
        repo.add(item)
        revised = self._revised(item, 2)
        repo.save(revised, expected_updated_at=item.updated_at)
        assert repo.all_blob_ids() == {f.blob_id for f in revised.all_files}
        assert len(repo.all_blob_ids()) == 3
        assert repo.usage() == RepositoryUsage(item_count=1, total_bytes=revised.stored_size)

    def test_save_drops_pruned_revisions(self, repo: ItemRepository) -> None:
        from preview_dashboard.domain.models import MAX_REVISIONS

        item = make_item(1)
        repo.add(item)
        pruned_blobs: set[str] = set()
        for n in range(2, MAX_REVISIONS + 3):
            current = repo.get(item.id)
            revised, pruned = current.with_revision(
                kind="html",
                files=(make_file("index.html", blob=500 + n),),
                entry_file="index.html",
                at=current.next_change_at(T0 + timedelta(hours=n)),
            )
            pruned_blobs |= {f.blob_id for r in pruned for f in r.files}
            repo.save(revised, expected_updated_at=current.updated_at)
        got = repo.get(item.id)
        assert len(got.revisions) == MAX_REVISIONS
        assert got.revisions[0].number == 3
        assert len(pruned_blobs) == 2
        assert not pruned_blobs & repo.all_blob_ids()

    def test_delete_removes_every_revision(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        revised = self._revised(item, 2)
        repo.save(revised, expected_updated_at=item.updated_at)
        trashed = revised.trashed(revised.next_change_at(T0 + timedelta(days=1)))
        repo.save(trashed, expected_updated_at=revised.updated_at)
        assert repo.delete_if_purgeable(item.id, T0 + timedelta(days=30)) == trashed
        assert repo.all_blob_ids() == set()
        assert repo.usage() == RepositoryUsage(item_count=0, total_bytes=0)

    def test_conflicting_revision_save_changes_nothing(self, repo: ItemRepository) -> None:
        item = make_item(1)
        repo.add(item)
        with pytest.raises(ConflictError):
            repo.save(
                self._revised(item, 2),
                expected_updated_at=item.updated_at + timedelta(microseconds=1),
            )
        assert repo.get(item.id) == item
        assert repo.all_blob_ids() == {ulid(10_001)}

    # --- folders (ADR 0027) --------------------------------------------------

    @staticmethod
    def _with_folders(folders: FolderRepository, *numbers: int) -> None:
        for n in numbers:
            folders.add(make_folder(n), max_folders=MAX_FOLDERS)

    def test_folder_id_round_trips(self, repo: ItemRepository, folders: FolderRepository) -> None:
        self._with_folders(folders, 1)
        item = make_item(1, folder_id=folder_id(1))
        repo.add(item)
        assert repo.get(item.id) == item
        assert repo.get(item.id).folder_id == folder_id(1)
        repo.add(make_item(2))
        assert repo.get(ItemId(ulid(2))).folder_id is None

    def test_move_is_a_compare_and_swap(
        self, repo: ItemRepository, folders: FolderRepository
    ) -> None:
        self._with_folders(folders, 1, 2)
        item = make_item(1)
        repo.add(item)
        first = item.moved_to(folder_id(1), at=T0 + timedelta(seconds=1))
        second = item.moved_to(folder_id(2), at=T0 + timedelta(seconds=2))
        repo.save(first, expected_updated_at=item.updated_at)
        with pytest.raises(ConflictError):
            repo.save(second, expected_updated_at=item.updated_at)
        assert repo.get(item.id) == first

    def test_folder_survives_trash_restore_pin_and_revision(
        self, repo: ItemRepository, folders: FolderRepository
    ) -> None:
        self._with_folders(folders, 1)
        item = make_item(1, folder_id=folder_id(1))
        repo.add(item)
        steps: list[Callable[[Item], Item]] = [
            lambda i: i.with_metadata(now=i.next_change_at(T0), pinned=True, title="t"),
            lambda i: self._revised(i, 2),
            lambda i: i.trashed(i.next_change_at(T0)),
            lambda i: i.restored(i.next_change_at(T0)),
        ]
        for step in steps:
            current = repo.get(item.id)
            changed = step(current)
            repo.save(changed, expected_updated_at=current.updated_at)
            assert repo.get(item.id).folder_id == folder_id(1)

    def test_list_filters_by_folder_and_unfiled(
        self, repo: ItemRepository, folders: FolderRepository
    ) -> None:
        self._with_folders(folders, 1, 2)
        repo.add(make_item(1, folder_id=folder_id(1)))
        repo.add(make_item(2, folder_id=folder_id(2)))
        repo.add(make_item(3, folder_id=folder_id(1)))
        repo.add(make_item(4))
        repo.add(make_item(5, folder_id=folder_id(1)).trashed(T0))

        def ids(**filters: object) -> list[str]:
            return [i.id for i in repo.list(ItemQuery(**filters)).items]  # type: ignore[arg-type]

        assert ids(folder=folder_id(1)) == [ulid(3), ulid(1)]
        assert ids(folder=folder_id(2)) == [ulid(2)]
        assert ids(folder=UNFILED) == [ulid(4)]
        assert ids(folder=folder_id(1), state=ItemState.TRASHED) == [ulid(5)]
        assert ids(folder=UNFILED, state=ItemState.TRASHED) == []
        assert ids(folder=folder_id(99)) == []  # unknown folder: empty, not an error
        assert len(ids()) == 4

    def test_folder_filter_combines_with_kind(
        self, repo: ItemRepository, folders: FolderRepository
    ) -> None:
        self._with_folders(folders, 1)
        repo.add(make_item(1, kind="image", folder_id=folder_id(1)))
        repo.add(make_item(2, kind="html", folder_id=folder_id(1)))
        repo.add(make_item(3, kind="image"))
        assert [i.id for i in repo.list(ItemQuery(kind="image", folder=folder_id(1))).items] == [
            ulid(1)
        ]
        assert [i.id for i in repo.list(ItemQuery(kind="image", folder=UNFILED)).items] == [ulid(3)]

    @pytest.mark.parametrize("kind", [None, "image"])
    def test_folder_filtered_paging_keeps_order_without_gaps(
        self, repo: ItemRepository, folders: FolderRepository, kind: str | None
    ) -> None:
        self._with_folders(folders, 1)
        for n in range(1, 12):
            at = T0 + timedelta(minutes=n % 3)  # many created_at ties
            repo.add(
                make_item(
                    n,
                    kind="image",
                    created_at=at,
                    updated_at=at,
                    pinned=n in (2, 7),
                    folder_id=folder_id(1) if n % 4 else None,
                )
            )
        for folder in (folder_id(1), UNFILED):
            walked = _all_pages(repo, folder=folder, kind=kind)
            full = repo.list(ItemQuery(limit=200, folder=folder, kind=kind)).items
            assert [i.id for i in walked] == [i.id for i in full]
            keys = [item_sort_key(i) for i in walked]
            assert keys == sorted(keys, reverse=True)
        in_folder = {i.id for i in _all_pages(repo, folder=folder_id(1))}
        unfiled = {i.id for i in _all_pages(repo, folder=UNFILED)}
        assert len(in_folder) == 9
        assert len(unfiled) == 2
        assert not in_folder & unfiled
