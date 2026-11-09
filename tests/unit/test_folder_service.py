"""Unit tests for FolderService and PublishService's `folder_id` (ADR 0027), over fakes.

Covers create/list/get/rename/delete/move happy paths, idempotency, errors,
the move compare-and-swap retry, and publishing straight into a folder.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from preview_dashboard.application import FolderService
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    LimitExceededError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.folders import UNFILED
from preview_dashboard.domain.models import Item, ItemState
from preview_dashboard.domain.query import ItemQuery
from preview_dashboard.ports.folders import FolderCounts
from tests.app_support import command, incoming, make_publish
from tests.builders import T0, folder_id, make_item, ulid
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryFolderRepository,
    InMemoryItemRepository,
    SequentialIdGenerator,
)

pytestmark = pytest.mark.unit


class Harness:
    """A FolderService over one shared fake store."""

    def __init__(self, *, max_folders: int = 200) -> None:
        self.items = InMemoryItemRepository()
        self.folders = InMemoryFolderRepository(self.items)
        self.clock = FixedClock()
        self.scanner = FakeContentScanner()
        self.service = FolderService(
            folders=self.folders,
            items=self.items,
            clock=self.clock,
            ids=SequentialIdGenerator(start=90_000),
            scanner=self.scanner,
            max_folders=max_folders,
        )


@pytest.fixture
def h() -> Harness:
    return Harness()


class TestCreateAndList:
    def test_create_returns_the_stored_folder(self, h: Harness) -> None:
        folder = h.service.create("  Plans ")
        assert folder.name == "Plans"
        assert folder.created_at == folder.updated_at == T0
        assert h.service.get(folder.id) == folder

    def test_list_orders_by_name_with_counts(self, h: Harness) -> None:
        beta = h.service.create("beta")
        alpha = h.service.create("Alpha")
        h.items.add(make_item(1, folder_id=beta.id))
        h.items.add(make_item(2, folder_id=beta.id).trashed(T0))
        h.items.add(make_item(3))
        listing = h.service.list()
        assert [(e.folder.name, e.count) for e in listing.folders] == [("Alpha", 0), ("beta", 1)]
        assert listing.unfiled_count == 1
        trash = h.service.list(state=ItemState.TRASHED)
        assert [(e.folder.id, e.count) for e in trash.folders] == [(alpha.id, 0), (beta.id, 1)]
        assert trash.unfiled_count == 0

    def test_list_empty(self, h: Harness) -> None:
        listing = h.service.list()
        assert listing.folders == ()
        assert listing.unfiled_count == 0

    def test_names_orders_by_name_without_reading_counts(self) -> None:
        # `names()` backs `folder_refs.folder_names` (item `folder` JSON): it
        # must never pay for a `counts()` read (S-F2 review, item 4).
        class _NoCounts(InMemoryFolderRepository):
            def counts(self, state: ItemState) -> FolderCounts:
                raise AssertionError("names() must not read item counts")

        items = InMemoryItemRepository()
        folders = _NoCounts(items)
        service = FolderService(
            folders=folders,
            items=items,
            clock=FixedClock(),
            ids=SequentialIdGenerator(start=90_000),
            scanner=FakeContentScanner(),
        )
        service.create("beta")
        service.create("Alpha")
        assert [f.name for f in service.names()] == ["Alpha", "beta"]

    def test_names_skips_a_tampered_row(self, h: Harness) -> None:
        # Same skip-invalid-row behaviour as `list` (C39).
        keep = h.service.create("Plans")
        bad = h.service.create("Bad")
        h.folders.corrupt_folder(bad.id)
        assert [f.id for f in h.service.names()] == [keep.id]

    def test_duplicate_name_is_refused(self, h: Harness) -> None:
        h.service.create("Plans")
        with pytest.raises(AlreadyExistsError):
            h.service.create("PLANS")

    def test_quota(self) -> None:
        h = Harness(max_folders=2)
        h.service.create("a")
        h.service.create("b")
        with pytest.raises(LimitExceededError):
            h.service.create("c")

    def test_invalid_quota_setting(self, h: Harness) -> None:
        with pytest.raises(ValueError, match="max_folders"):
            FolderService(
                folders=h.folders,
                items=h.items,
                clock=h.clock,
                ids=SequentialIdGenerator(),
                scanner=h.scanner,
                max_folders=0,
            )

    @pytest.mark.parametrize("bad", ["x", "01arz3ndektsv4rrffq69g5fav", "unfiled"])
    def test_get_validates_the_id(self, h: Harness, bad: str) -> None:
        with pytest.raises(ValidationError):
            h.service.get(bad)

    def test_get_missing(self, h: Harness) -> None:
        with pytest.raises(NotFoundError):
            h.service.get(folder_id(404))


class TestRename:
    def test_rename(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.clock.advance(timedelta(minutes=5))
        renamed = h.service.rename(folder.id, "Archive")
        assert renamed.name == "Archive"
        assert renamed.updated_at == T0 + timedelta(minutes=5)
        assert h.service.get(folder.id) == renamed

    def test_same_name_is_a_no_op(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.clock.advance(timedelta(minutes=5))
        assert h.service.rename(folder.id, " Plans\u200b ") == folder
        assert h.service.get(folder.id).updated_at == T0

    def test_case_change_is_a_rename(self, h: Harness) -> None:
        folder = h.service.create("plans")
        assert h.service.rename(folder.id, "Plans").name == "Plans"

    def test_clock_step_back_still_moves_the_version(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.clock.advance(timedelta(hours=-1))
        assert h.service.rename(folder.id, "New").updated_at > folder.updated_at

    def test_rename_to_taken_name(self, h: Harness) -> None:
        h.service.create("Plans")
        other = h.service.create("Other")
        with pytest.raises(AlreadyExistsError):
            h.service.rename(other.id, "plans")

    def test_rename_missing(self, h: Harness) -> None:
        with pytest.raises(NotFoundError):
            h.service.rename(folder_id(404), "x")

    def test_rename_conflict_is_not_retried(
        self, h: Harness, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Unlike move/trash/restore, rename does not retry: the caller asked
        # for a specific new name, not "whatever it ends up being."
        folder = h.service.create("Plans")
        attempts = 0
        real_rename = h.folders.rename

        def flaky_rename(candidate: object, **kwargs: object) -> None:
            nonlocal attempts
            attempts += 1
            raise ConflictError("changed concurrently")

        monkeypatch.setattr(h.folders, "rename", flaky_rename)
        with pytest.raises(ConflictError):
            h.service.rename(folder.id, "Archive")
        assert attempts == 1
        monkeypatch.setattr(h.folders, "rename", real_rename)
        assert h.service.get(folder.id) == folder


class TestDelete:
    def test_delete_empty(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.service.delete(folder.id)
        assert h.service.list().folders == ()

    def test_delete_refused_with_trashed_items(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.items.add(make_item(1, folder_id=folder.id).trashed(T0))
        with pytest.raises(ConflictError):
            h.service.delete(folder.id)

    def test_delete_missing_and_bad_id(self, h: Harness) -> None:
        with pytest.raises(NotFoundError):
            h.service.delete(folder_id(404))
        with pytest.raises(ValidationError):
            h.service.delete("../x")


class TestMove:
    def test_move_in_and_out(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.items.add(make_item(1))
        h.clock.advance(timedelta(seconds=3))
        moved = h.service.move(ulid(1), folder.id)
        assert moved.folder_id == folder.id
        assert moved.updated_at == T0 + timedelta(seconds=3)
        assert h.items.list(ItemQuery(folder=folder.id)).items == (moved,)
        back = h.service.move(ulid(1), None)
        assert back.folder_id is None
        assert h.items.list(ItemQuery(folder=UNFILED)).items == (back,)

    def test_move_to_current_folder_is_a_no_op(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        item = make_item(1, folder_id=folder.id)
        h.items.add(item)
        h.clock.advance(timedelta(seconds=3))
        assert h.service.move(ulid(1), folder.id) == item
        assert h.items.get(item.id).updated_at == T0

    def test_unfiled_to_unfiled_is_a_no_op(self, h: Harness) -> None:
        item = make_item(1)
        h.items.add(item)
        assert h.service.move(ulid(1), None) == item

    def test_move_of_a_trashed_item_keeps_it_trashed(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.items.add(make_item(1).trashed(T0))
        moved = h.service.move(ulid(1), folder.id)
        assert moved.state is ItemState.TRASHED
        assert moved.trashed_at == T0

    def test_move_to_missing_folder(self, h: Harness) -> None:
        item = make_item(1)
        h.items.add(item)
        with pytest.raises(NotFoundError):
            h.service.move(ulid(1), folder_id(404))
        assert h.items.get(item.id) == item

    def test_move_missing_item(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        with pytest.raises(NotFoundError):
            h.service.move(ulid(9), folder.id)

    @pytest.mark.parametrize(("item_id", "target"), [("x", None), (ulid(1), "unfiled")])
    def test_move_validates_ids(self, h: Harness, item_id: str, target: str | None) -> None:
        h.items.add(make_item(1))
        with pytest.raises(ValidationError):
            h.service.move(item_id, target)

    def test_conflict_is_retried_once(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.items.add(make_item(1))
        real_save = h.items.save
        calls: list[Item] = []

        def racing_save(item: Item, *, expected_updated_at: object) -> None:
            if not calls:
                # Another writer (e.g. the viewer pinning) lands first.
                current = h.items.get(item.id)
                real_save(
                    current.with_metadata(now=T0 + timedelta(seconds=1), pinned=True),
                    expected_updated_at=current.updated_at,
                )
            calls.append(item)
            real_save(item, expected_updated_at=expected_updated_at)  # type: ignore[arg-type]

        h.items.save = racing_save  # type: ignore[method-assign]
        moved = h.service.move(ulid(1), folder.id)
        assert len(calls) == 2
        assert moved.pinned is True  # the retry started from the re-read item
        assert h.items.get(moved.id) == moved

    def test_second_conflict_propagates(self, h: Harness) -> None:
        folder = h.service.create("Plans")
        h.items.add(make_item(1))

        def always_conflict(item: Item, *, expected_updated_at: object) -> None:
            raise ConflictError("changed")

        h.items.save = always_conflict  # type: ignore[method-assign]
        with pytest.raises(ConflictError):
            h.service.move(ulid(1), folder.id)


class TestPublishIntoFolder:
    def test_publish_files_the_item(self) -> None:
        p = make_publish()
        folder = FolderService(
            folders=p.folders,
            items=p.repo,
            clock=p.clock,
            ids=SequentialIdGenerator(start=90_000),
            scanner=FakeContentScanner(),
        ).create("Plans")
        item = p.service.publish(command(incoming("a.txt"), folder_id=folder.id))
        assert item.folder_id == folder.id
        assert p.repo.get(item.id).folder_id == folder.id

    def test_publish_unfiled_by_default(self) -> None:
        p = make_publish()
        assert p.service.publish(command(incoming("a.txt"))).folder_id is None

    def test_missing_folder_fails_before_any_byte_moves(self) -> None:
        p = make_publish()
        with pytest.raises(NotFoundError):
            p.service.publish(command(incoming("a.txt"), folder_id=folder_id(404)))
        assert p.blobs.list_ids() == set()
        assert p.repo.count() == 0

    @pytest.mark.parametrize("bad", ["unfiled", "x", "01arz3ndektsv4rrffq69g5fav"])
    def test_bad_folder_id_is_a_validation_error(self, bad: str) -> None:
        p = make_publish()
        with pytest.raises(ValidationError):
            p.service.publish(command(incoming("a.txt"), folder_id=bad))
        assert p.blobs.list_ids() == set()

    def test_revisions_keep_the_folder(self) -> None:
        from preview_dashboard.application import RevisionCommand

        p = make_publish()
        folder = FolderService(
            folders=p.folders,
            items=p.repo,
            clock=p.clock,
            ids=SequentialIdGenerator(start=90_000),
            scanner=FakeContentScanner(),
        ).create("Plans")
        item = p.service.publish(command(incoming("a.txt"), folder_id=folder.id))
        revised = p.service.publish_revision(
            RevisionCommand(item_id=item.id, files=[incoming("b.txt")])
        )
        assert revised.folder_id == folder.id
