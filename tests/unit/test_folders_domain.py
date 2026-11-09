"""Unit tests for the folder domain (ADR 0027): Folder, ids, Item.folder_id, ItemQuery.folder.

Pure domain: no fakes needed. Name sanitising itself is proven in
`tests/security/test_folders.py` (C39); this file covers invariants,
transitions and the listing filter.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta, timezone

import pytest

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.folders import (
    FOLDER_NAME_MAX_CHARS,
    UNFILED,
    Folder,
    FolderId,
    Unfiled,
    folder_name_key,
    parse_folder_filter,
    parse_folder_id,
)
from preview_dashboard.domain.models import Item, ItemState
from preview_dashboard.domain.query import ItemQuery, paginate
from tests.builders import T0, folder_id, make_file, make_folder, make_item, ulid

pytestmark = pytest.mark.unit


class TestFolderIds:
    def test_parse_accepts_canonical_ulids(self) -> None:
        assert parse_folder_id(ulid(7)) == ulid(7)

    @pytest.mark.parametrize(
        "raw",
        ["", "unfiled", "01arz3ndektsv4rrffq69g5fav", ulid(7) + "0", "8" + ulid(7)[1:], None, 7],
    )
    def test_parse_rejects_anything_else(self, raw: object) -> None:
        with pytest.raises(ValidationError, match="folder id"):
            parse_folder_id(raw)

    def test_filter_parses_unfiled_and_ids(self) -> None:
        assert parse_folder_filter("unfiled") is UNFILED
        assert parse_folder_filter(ulid(3)) == FolderId(ulid(3))

    @pytest.mark.parametrize("raw", ["Unfiled", "UNFILED", " unfiled", "none", "", "null"])
    def test_filter_rejects_other_spellings(self, raw: str) -> None:
        with pytest.raises(ValidationError):
            parse_folder_filter(raw)


class TestFolder:
    def test_new_sets_both_times(self) -> None:
        folder = Folder.new(id=folder_id(1), name="  Plans  ", now=T0)
        assert folder.name == "Plans"
        assert folder.created_at == folder.updated_at == T0

    def test_times_are_normalized_to_utc(self) -> None:
        tz = timezone(timedelta(hours=2))
        folder = make_folder(1, created_at=T0.astimezone(tz), updated_at=T0.astimezone(tz))
        assert folder.created_at.utcoffset() == timedelta(0)

    def test_naive_time_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_folder(1, created_at=T0.replace(tzinfo=None))

    def test_updated_before_created_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_folder(1, updated_at=T0 - timedelta(microseconds=1))

    def test_bad_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_folder(1, id="x")

    def test_name_limit_is_80_chars(self) -> None:
        assert make_folder(1, name="x" * FOLDER_NAME_MAX_CHARS).name == "x" * 80
        with pytest.raises(ValidationError, match="folder name"):
            make_folder(1, name="x" * 81)

    def test_replace_revalidates(self) -> None:
        with pytest.raises(ValidationError):
            dataclasses.replace(make_folder(1), name="")

    def test_renamed_moves_updated_at(self) -> None:
        folder = make_folder(1)
        renamed = folder.renamed(" New ", at=T0 + timedelta(minutes=1))
        assert renamed.name == "New"
        assert renamed.updated_at == T0 + timedelta(minutes=1)
        assert renamed.created_at == folder.created_at
        assert renamed.id == folder.id

    def test_renamed_rejects_time_running_backwards(self) -> None:
        folder = make_folder(1, updated_at=T0 + timedelta(hours=1))
        with pytest.raises(ValidationError):
            folder.renamed("New", at=T0)

    def test_next_change_at_is_strictly_later(self) -> None:
        folder = make_folder(1, updated_at=T0 + timedelta(hours=1))
        assert folder.next_change_at(T0) == T0 + timedelta(hours=1, microseconds=1)
        assert folder.next_change_at(T0 + timedelta(hours=2)) == T0 + timedelta(hours=2)

    def test_name_key_is_caseless(self) -> None:
        assert make_folder(1, name="Plans").name_key == make_folder(2, name="PLANS").name_key
        assert folder_name_key("Straße") == folder_name_key("STRASSE")
        assert folder_name_key("Plans") != folder_name_key("Pláns")


class TestItemFolder:
    def test_default_is_unfiled(self) -> None:
        assert make_item(1).folder_id is None

    def test_new_accepts_a_folder(self) -> None:
        item = Item.new(
            id=make_item(1).id,
            title="t",
            kind="html",
            files=(make_file(),),
            entry_file="index.html",
            now=T0,
            folder_id=folder_id(1),
        )
        assert item.folder_id == folder_id(1)

    @pytest.mark.parametrize("bad", ["", "unfiled", "01arz3ndektsv4rrffq69g5fav", "x" * 26])
    def test_bad_folder_id_is_rejected(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="folder id"):
            make_item(1, folder_id=bad)

    def test_moved_to_changes_folder_and_version(self) -> None:
        item = make_item(1)
        moved = item.moved_to(folder_id(1), at=T0 + timedelta(seconds=1))
        assert moved.folder_id == folder_id(1)
        assert moved.updated_at == T0 + timedelta(seconds=1)
        back = moved.moved_to(None, at=T0 + timedelta(seconds=2))
        assert back.folder_id is None

    def test_moved_to_works_in_the_trash(self) -> None:
        trashed = make_item(1).trashed(T0)
        moved = trashed.moved_to(folder_id(1), at=T0 + timedelta(seconds=1))
        assert moved.state is ItemState.TRASHED
        assert moved.trashed_at == T0  # retention is not extended
        assert moved.folder_id == folder_id(1)

    def test_moved_to_rejects_time_running_backwards(self) -> None:
        item = make_item(1, updated_at=T0 + timedelta(hours=1))
        with pytest.raises(ValidationError):
            item.moved_to(folder_id(1), at=T0)

    def test_moved_to_validates_the_id(self) -> None:
        with pytest.raises(ValidationError):
            make_item(1).moved_to(FolderId("nope"), at=T0)

    def test_every_transition_keeps_the_folder(self) -> None:
        item = make_item(1, folder_id=folder_id(1))
        edited = item.with_metadata(now=T0, title="x", pinned=True)
        revised, _ = edited.with_revision(
            kind="html", files=(make_file(blob=9),), entry_file="index.html", at=T0
        )
        trashed = revised.trashed(T0 + timedelta(seconds=1))
        restored = trashed.restored(T0 + timedelta(seconds=2))
        assert {i.folder_id for i in (edited, revised, trashed, restored)} == {folder_id(1)}

    def test_trashed_items_still_refuse_edits(self) -> None:
        # Moving is allowed in the trash; metadata edits still are not.
        with pytest.raises(InvalidStateError):
            make_item(1, folder_id=folder_id(1)).trashed(T0).with_metadata(now=T0, title="x")


class TestItemQueryFolder:
    def test_default_is_no_filter(self) -> None:
        assert ItemQuery().folder is None
        assert ItemQuery().folder_id is None

    def test_accepts_an_id_or_unfiled(self) -> None:
        assert ItemQuery(folder=folder_id(1)).folder_id == folder_id(1)
        query = ItemQuery(folder=UNFILED)
        assert isinstance(query.folder, Unfiled)
        assert query.folder_id is None

    @pytest.mark.parametrize("bad", ["", "unfiled", "UNFILED", "01arz3ndektsv4rrffq69g5fav", 5])
    def test_rejects_anything_else(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="folder"):
            ItemQuery(folder=bad)  # type: ignore[arg-type]

    def test_matches_and_paginate_honour_the_filter(self) -> None:
        items = [
            make_item(1, folder_id=folder_id(1)),
            make_item(2, folder_id=folder_id(2)),
            make_item(3),
            make_item(4, folder_id=folder_id(1), pinned=True),
            make_item(5, folder_id=folder_id(1)).trashed(T0),
        ]
        in_one = paginate(items, ItemQuery(folder=folder_id(1)))
        assert [i.id for i in in_one.items] == [ulid(4), ulid(1)]
        unfiled = paginate(items, ItemQuery(folder=UNFILED))
        assert [i.id for i in unfiled.items] == [ulid(3)]
        everything = paginate(items, ItemQuery())
        assert len(everything.items) == 4

    def test_cursor_paging_within_a_folder(self) -> None:
        items = [make_item(n, folder_id=folder_id(1) if n % 2 else None) for n in range(1, 10)]
        first = paginate(items, ItemQuery(folder=folder_id(1), limit=2))
        assert first.next_cursor is not None
        second = paginate(items, ItemQuery(folder=folder_id(1), limit=2, cursor=first.next_cursor))
        ids = [i.id for i in (*first.items, *second.items)]
        assert ids == [ulid(9), ulid(7), ulid(5), ulid(3)]
