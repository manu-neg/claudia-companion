"""Security tests for folders (ADR 0027): C39 names, C40 viewer read-only, C41 integrity.

- C39: folder names are untrusted display text: sanitized with the title
  rules (control, bidi, invisible chars removed; 1..80 chars; a visible
  char required), secret-scanned raw **and** sanitized, unique under
  compatibility caseless matching, and capped at 200 folders.
- C40: the viewer core can only read folders (`FolderReader`).
- C41: no item ever references a missing folder, and a folder referenced by
  any item (active or trashed) is never deleted; purge leaves folders alone.
"""

from __future__ import annotations

import inspect
from datetime import timedelta

import pytest

from preview_dashboard.application import FolderService, PurgeService
from preview_dashboard.bootstrap import FolderReader
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    LimitExceededError,
    NotFoundError,
    SecretDetectedError,
    ValidationError,
)
from preview_dashboard.domain.folders import MAX_FOLDERS, Folder, sanitize_folder_name
from preview_dashboard.domain.models import ItemState
from tests.app_support import command, incoming, make_publish
from tests.builders import T0, folder_id, make_folder, make_item, ulid
from tests.fakes import (
    FAKE_SECRET,
    FakeContentScanner,
    FixedClock,
    InMemoryBlobStore,
    InMemoryFolderRepository,
    SequentialIdGenerator,
)

pytestmark = pytest.mark.security


def _service(folders: InMemoryFolderRepository | None = None) -> FolderService:
    folders = folders or InMemoryFolderRepository()
    return FolderService(
        folders=folders,
        items=folders.items,
        clock=FixedClock(),
        ids=SequentialIdGenerator(start=90_000),
        scanner=FakeContentScanner(),
    )


# --- C39: name sanitising, scan, uniqueness, quota ----------------------------------


class TestNameSanitising:
    @pytest.mark.parametrize(
        ("raw", "stored"),
        [
            ("Plans\u202e.txt", "Plans.txt"),  # bidi override
            ("Pl\u200bans", "Plans"),  # zero-width space
            ("Pl\u00adans", "Plans"),  # soft hyphen
            ("A\x00B\x1bC", "ABC"),  # control chars
            ("line\nbreak\ttab", "line break tab"),  # single line
            ("\ufeffPlans\u2066", "Plans"),  # BOM, isolate
            ("  padded  ", "padded"),
            ("Cafe\u0301", "Caf\u00e9"),  # NFC
            ("\U000e0041tag", "tag"),  # tag character (hidden data)
        ],
    )
    def test_invisible_and_control_chars_are_removed(self, raw: str, stored: str) -> None:
        assert sanitize_folder_name(raw) == stored
        assert _service().create(raw).name == stored

    @pytest.mark.parametrize(
        "raw",
        ["", "   ", "\u200b\u202e", "\u3164", "\x00\x01", "x" * 81, "x" * 400],
    )
    def test_empty_invisible_or_long_names_are_refused(self, raw: str) -> None:
        service = _service()
        with pytest.raises(ValidationError):
            service.create(raw)
        assert service.list().folders == ()

    @pytest.mark.parametrize("raw", [None, 5, b"bytes", ["x"]])
    def test_non_strings_are_refused(self, raw: object) -> None:
        with pytest.raises(ValidationError):
            _service().create(raw)  # type: ignore[arg-type]

    def test_stored_names_are_revalidated(self) -> None:
        # A Folder cannot hold an unsanitized name, even via replace().
        import dataclasses

        folder = make_folder(1)
        assert dataclasses.replace(folder, name="a\u202eb").name == "ab"
        with pytest.raises(ValidationError):
            Folder(id=folder_id(1), name="\u200b", created_at=T0, updated_at=T0)


class TestNameSecretScan:
    def test_secret_in_name_is_refused(self) -> None:
        service = _service()
        with pytest.raises(SecretDetectedError):
            service.create("keys " + FAKE_SECRET.decode())
        assert service.list().folders == ()

    def test_secret_hidden_by_invisible_chars_is_caught_after_sanitizing(self) -> None:
        # Raw text doesn't match; the stored (sanitized) text would.
        hidden = FAKE_SECRET.decode().replace("-", "-\u200b", 1)
        assert FAKE_SECRET.decode() not in hidden
        service = _service()
        with pytest.raises(SecretDetectedError):
            service.create(hidden)
        assert service.list().folders == ()

    def test_rename_is_scanned_too(self) -> None:
        service = _service()
        folder = service.create("Plans")
        with pytest.raises(SecretDetectedError):
            service.rename(folder.id, FAKE_SECRET.decode())
        assert service.get(folder.id).name == "Plans"


class TestNameUniquenessAndQuota:
    @pytest.mark.parametrize(
        "clash",
        ["plans", "PLANS", "\uff30\uff4c\uff41\uff4e\uff53", "Pla\u200bns", " Plans "],
    )
    def test_look_alike_names_are_refused(self, clash: str) -> None:
        service = _service()
        service.create("Plans")
        with pytest.raises(AlreadyExistsError):
            service.create(clash)

    def test_quota_default_is_200(self) -> None:
        assert MAX_FOLDERS == 200
        service = _service()
        for n in range(MAX_FOLDERS):
            service.create(f"f{n}")
        with pytest.raises(LimitExceededError):
            service.create("one too many")
        assert len(service.list().folders) == MAX_FOLDERS


# --- C40: viewer folders are read-only -----------------------------------------------


class TestViewerReadOnly:
    def test_folder_reader_exposes_reads_only(self) -> None:
        public = {name for name, _ in inspect.getmembers(FolderReader) if not name.startswith("_")}
        assert public == {"list", "get", "names"}

    def test_folder_reader_reads(self) -> None:
        folders = InMemoryFolderRepository()
        service = _service(folders)
        created = service.create("Plans")
        folders.items.add(make_item(1, folder_id=created.id))
        reader = FolderReader(service)
        assert reader.get(created.id) == created
        listing = reader.list()
        assert [(e.folder.id, e.count) for e in listing.folders] == [(created.id, 1)]
        assert [f.id for f in reader.names()] == [created.id]


# --- C41: referential integrity -----------------------------------------------------------


class TestReferentialIntegrity:
    def test_folder_with_only_trashed_items_cannot_be_deleted(self) -> None:
        folders = InMemoryFolderRepository()
        service = _service(folders)
        folder = service.create("Plans")
        folders.items.add(make_item(1, folder_id=folder.id).trashed(T0))
        with pytest.raises(ConflictError):
            service.delete(folder.id)
        # Restoring puts the item back into its (still existing) folder.
        restored = folders.items.get(make_item(1).id)
        assert restored.folder_id == folder.id

    def test_move_into_missing_folder_changes_nothing(self) -> None:
        folders = InMemoryFolderRepository()
        item = make_item(1)
        folders.items.add(item)
        with pytest.raises(NotFoundError):
            _service(folders).move(item.id, folder_id(404))
        assert folders.items.get(item.id) == item

    def test_publish_into_a_folder_deleted_mid_publish_rolls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        p = make_publish()
        # The up-front check passes (folder "exists"), but it is gone at commit.
        monkeypatch.setattr(p.folders, "get", lambda _id: make_folder(1))
        with pytest.raises(NotFoundError):
            p.service.publish(command(incoming("a.txt", b"data"), folder_id=folder_id(1)))
        assert p.repo.count() == 0
        assert p.blobs.list_ids() == set()  # no orphaned blobs

    def test_purge_leaves_folders_alone(self) -> None:
        folders = InMemoryFolderRepository()
        service = _service(folders)
        folder = service.create("Plans")
        folders.items.add(make_item(1, folder_id=folder.id).trashed(T0))
        clock = FixedClock(T0 + timedelta(days=60))
        report = PurgeService(
            repo=folders.items,
            blobs=InMemoryBlobStore(clock=clock),
            clock=clock,
            retention=timedelta(days=14),
            orphan_grace=timedelta(hours=1),
        ).run()
        assert report.items_purged == 1
        assert service.get(folder.id) == folder
        assert service.list(state=ItemState.TRASHED).folders[0].count == 0
        service.delete(folder.id)  # now empty: deletable
        with pytest.raises(NotFoundError):
            service.get(folder.id)

    def test_ids_are_validated_before_any_lookup(self) -> None:
        service = _service()
        for bad in ("../etc", "unfiled", ulid(1) + "/x", "'; DROP TABLE folders;--"):
            with pytest.raises(ValidationError):
                service.get(bad)
            with pytest.raises(ValidationError):
                service.delete(bad)
            with pytest.raises(ValidationError):
                service.move(ulid(1), bad)


# --- backlog 6.4 item 1: one tampered folder row must not break every listing -------


class TestTamperedRowFailsClosedOnlyWhereItMust:
    """A tampered folder must not take `/api/folders` (or any item listing that
    renders `folder`) down with it: `get`/`FolderService.get` still fail closed
    on that one folder, but `list`/`FolderService.list` skip it (C39)."""

    def test_folder_reader_list_survives_a_tampered_folder(self) -> None:
        folders = InMemoryFolderRepository()
        service = _service(folders)
        good = service.create("Good")
        bad = service.create("Bad")
        folders.items.add(make_item(1, folder_id=good.id))
        folders.corrupt_folder(bad.id)
        listing = FolderReader(service).list()
        assert [e.folder.id for e in listing.folders] == [good.id]
        with pytest.raises(ValidationError):
            FolderReader(service).get(bad.id)


# --- backlog 6.4 item 2: rename has no compare-and-swap -----------------------------


class TestRenameCompareAndSwap:
    """Renaming a stale folder must not silently overwrite a concurrent rename."""

    def test_racing_renames_the_second_gets_a_conflict(self) -> None:
        folders = InMemoryFolderRepository()
        service = _service(folders)
        folder = service.create("Plans")
        # Two admins read the same folder, then both try to rename it.
        stale = folders.get(folder.id)
        service.rename(folder.id, "Archive")
        with pytest.raises(ConflictError):
            folders.rename(
                stale.renamed("Projects", at=stale.updated_at),
                expected_updated_at=stale.updated_at,
            )
        assert service.get(folder.id).name == "Archive"
