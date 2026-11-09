"""Unit tests for domain models: ids, BlobRef, ItemFile, Item invariants and transitions."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta, timezone

import pytest

from preview_dashboard.domain.errors import InvalidPathError, InvalidStateError, ValidationError
from preview_dashboard.domain.models import (
    BlobRef,
    Item,
    ItemFile,
    ItemId,
    ItemState,
    ensure_utc,
    is_ulid,
    parse_item_id,
    validate_blob_id,
    validate_kind,
)
from tests.builders import T0, make_file, make_item, ulid

pytestmark = pytest.mark.unit

RETENTION = timedelta(days=14)
SHA = "a" * 64


# --- ids / helpers -------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["01ARZ3NDEKTSV4RRFFQ69G5FAV", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "0" * 26]
)
def test_valid_ulids(value: str) -> None:
    assert is_ulid(value)
    assert parse_item_id(value) == value
    assert validate_blob_id(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        "01arz3ndektsv4rrffq69g5fav",  # lowercase: not canonical
        "81ARZ3NDEKTSV4RRFFQ69G5FAV",  # > 128 bits
        "01ARZ3NDEKTSV4RRFFQ69G5FA",  # 25 chars
        "01ARZ3NDEKTSV4RRFFQ69G5FAVX",
        "01ARZ3NDEKTSV4RRFFQ69G5FAI",  # I is not Crockford
        "../../../../../../etc/pass",
        "01ARZ3NDEKTSV4RRFFQ69G5FA\n",
    ],
)
def test_invalid_ulids(value: str) -> None:
    assert not is_ulid(value)
    with pytest.raises(ValidationError):
        parse_item_id(value)
    with pytest.raises(ValidationError):
        validate_blob_id(value)


def test_is_ulid_rejects_non_strings() -> None:
    assert not is_ulid(None)
    assert not is_ulid(12345)


@pytest.mark.parametrize("kind", ["html", "image", "code-diff", "a", "a" * 32])
def test_valid_kinds(kind: str) -> None:
    assert validate_kind(kind) == kind


@pytest.mark.parametrize("kind", ["", "HTML", "1html", "-x", "a_b", "a" * 33, "html "])
def test_invalid_kinds(kind: str) -> None:
    with pytest.raises(ValidationError):
        validate_kind(kind)


def test_ensure_utc_converts_and_rejects_naive() -> None:
    est = T0.astimezone(timezone(timedelta(hours=-5)))
    assert ensure_utc(est).tzinfo == UTC
    assert ensure_utc(est) == T0
    with pytest.raises(ValidationError):
        ensure_utc(datetime(2026, 1, 1))


# --- BlobRef / ItemFile ----------------------------------------------------------


def test_blob_ref_validation() -> None:
    assert BlobRef(blob_id=ulid(1), size=0, sha256=SHA).size == 0
    with pytest.raises(ValidationError):
        BlobRef(blob_id="bad", size=0, sha256=SHA)
    with pytest.raises(ValidationError):
        BlobRef(blob_id=ulid(1), size=-1, sha256=SHA)
    with pytest.raises(ValidationError):
        BlobRef(blob_id=ulid(1), size=True, sha256=SHA)
    with pytest.raises(ValidationError):
        BlobRef(blob_id=ulid(1), size=1, sha256="A" * 64)


def test_item_file_from_blob() -> None:
    ref = BlobRef(blob_id=ulid(5), size=3, sha256=SHA)
    f = ItemFile.from_blob("a/b.txt", ref, "text/plain")
    assert (f.relpath, f.blob_id, f.size, f.sha256, f.media_type) == (
        "a/b.txt",
        ulid(5),
        3,
        SHA,
        "text/plain",
    )


def test_item_file_rejects_unsafe_relpath() -> None:
    with pytest.raises(InvalidPathError):
        make_file("../x")


@pytest.mark.parametrize("media_type", ["text/html", "image/svg+xml", "application/vnd.ms-excel"])
def test_item_file_accepts_media_types(media_type: str) -> None:
    assert make_file(media_type=media_type).media_type == media_type


@pytest.mark.parametrize(
    "media_type", ["", "text", "Text/HTML", "text/html; charset=utf-8", "text/html\n", "*/*x/"]
)
def test_item_file_rejects_media_types(media_type: str) -> None:
    with pytest.raises(ValidationError):
        make_file(media_type=media_type)


def test_item_file_is_frozen() -> None:
    f = make_file()
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.relpath = "x"  # type: ignore[misc]


# --- Item invariants -------------------------------------------------------------


def test_item_new_defaults() -> None:
    item = Item.new(
        id=ItemId(ulid(1)),
        title="  Hello  ",
        kind="html",
        files=[make_file()],
        entry_file="index.html",
        now=T0,
    )
    assert item.title == "Hello"
    assert item.description == ""
    assert item.created_at == item.updated_at == T0
    assert item.state is ItemState.ACTIVE
    assert item.trashed_at is None
    assert item.pinned is False
    assert isinstance(item.files, tuple)


def test_item_converts_file_list_to_tuple() -> None:
    item = make_item(files=[make_file()])
    assert isinstance(item.files, tuple)
    hash(item)  # hashable because every field is immutable


def test_item_rejects_bad_id() -> None:
    with pytest.raises(ValidationError):
        make_item(id=ItemId("nope"))


@pytest.mark.parametrize("title", ["", "   ", "\u202e\u200b", "x" * 201])
def test_item_rejects_bad_titles(title: str) -> None:
    with pytest.raises(ValidationError):
        make_item(title=title)


def test_item_title_length_boundary() -> None:
    assert len(make_item(title="x" * 200).title) == 200


def test_item_title_and_description_are_sanitized() -> None:
    item = make_item(title="a\u202eb\nc", description="  x\r\ny\x00  ")
    assert item.title == "ab c"
    assert item.description == "x\ny"


def test_item_description_length_boundary() -> None:
    assert len(make_item(description="d" * 5000).description) == 5000
    with pytest.raises(ValidationError):
        make_item(description="d" * 5001)


def test_item_needs_a_file() -> None:
    with pytest.raises(ValidationError, match="at least one"):
        make_item(files=())


def test_item_rejects_non_itemfile_entries() -> None:
    with pytest.raises(ValidationError):
        make_item(files=("index.html",))


@pytest.mark.parametrize(
    "paths",
    [
        ("index.html", "index.html"),
        ("A.html", "a.html"),  # collide on case-insensitive filesystems
        ("index.html", "docs", "docs/x.md"),  # 'docs' is both file and dir
        ("index.html", "Docs", "docs/sub/x.md"),
    ],
)
def test_item_rejects_conflicting_paths(paths: tuple[str, ...]) -> None:
    files = tuple(make_file(p, blob=i) for i, p in enumerate(paths))
    with pytest.raises(ValidationError):
        make_item(files=files)


def test_item_allows_distinct_nested_paths() -> None:
    files = (
        make_file("index.html", blob=1),
        make_file("docs/a.md", blob=2),
        make_file("docs.md", blob=3),
    )
    assert len(make_item(files=files).files) == 3


def test_item_entry_file_must_be_listed() -> None:
    with pytest.raises(ValidationError, match="entry_file"):
        make_item(entry_file="other.html")


def test_item_rejects_naive_datetimes() -> None:
    naive = datetime(2026, 1, 1)
    with pytest.raises(ValidationError):
        make_item(created_at=naive, updated_at=naive)


def test_item_normalizes_datetimes_to_utc() -> None:
    est = T0.astimezone(timezone(timedelta(hours=-5)))
    item = make_item(created_at=est, updated_at=est)
    assert item.created_at.tzinfo == UTC
    assert item.created_at == T0


def test_item_updated_before_created_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_item(updated_at=T0 - timedelta(seconds=1))


def test_trashed_at_iff_trashed() -> None:
    with pytest.raises(ValidationError):
        make_item(state=ItemState.TRASHED)
    with pytest.raises(ValidationError):
        make_item(trashed_at=T0)
    assert make_item(state=ItemState.TRASHED, trashed_at=T0).trashed_at == T0


def test_item_rejects_bad_state_and_pinned() -> None:
    with pytest.raises(ValidationError):
        make_item(state="deleted")
    with pytest.raises(ValidationError):
        make_item(pinned=1)


def test_item_accepts_state_string() -> None:
    assert make_item(state="active").state is ItemState.ACTIVE


def test_total_size_and_file_lookup() -> None:
    files = (
        make_file("index.html", blob=1, size=10),
        make_file("a.css", blob=2, size=5, media_type="text/css"),
    )
    item = make_item(files=files)
    assert item.total_size == 15
    assert item.file("a.css") == files[1]
    assert item.file("A.css") is None
    assert item.file("missing") is None


# --- transitions -----------------------------------------------------------------


def test_trash_and_restore_round_trip() -> None:
    item = make_item()
    at = T0 + timedelta(hours=1)
    trashed = item.trashed(at)
    assert item.state is ItemState.ACTIVE  # original untouched
    assert trashed.state is ItemState.TRASHED
    assert trashed.trashed_at == at
    assert trashed.updated_at == at
    later = at + timedelta(hours=1)
    restored = trashed.restored(later)
    assert restored.state is ItemState.ACTIVE
    assert restored.trashed_at is None
    assert restored.updated_at == later


def test_trash_twice_is_invalid() -> None:
    with pytest.raises(InvalidStateError):
        make_item().trashed(T0).trashed(T0)


def test_restore_active_is_invalid() -> None:
    with pytest.raises(InvalidStateError):
        make_item().restored(T0)


def test_trash_before_creation_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_item().trashed(T0 - timedelta(seconds=1))


def test_with_metadata_updates_only_given_fields() -> None:
    item = make_item(description="keep")
    now = T0 + timedelta(minutes=1)
    updated = item.with_metadata(now=now, title=" New ", pinned=True)
    assert updated.title == "New"
    assert updated.description == "keep"
    assert updated.pinned is True
    assert updated.updated_at == now
    assert updated.created_at == item.created_at
    cleared = updated.with_metadata(now=now, description="")
    assert cleared.description == ""
    assert cleared.title == "New"


def test_with_metadata_validates() -> None:
    with pytest.raises(ValidationError):
        make_item().with_metadata(now=T0, title="  ")


def test_with_metadata_on_trashed_item_is_invalid() -> None:
    with pytest.raises(InvalidStateError):
        make_item().trashed(T0).with_metadata(now=T0, pinned=True)


def test_is_purgeable_boundary() -> None:
    trashed = make_item().trashed(T0)
    assert not trashed.is_purgeable(T0 + RETENTION - timedelta(microseconds=1), RETENTION)
    assert trashed.is_purgeable(T0 + RETENTION, RETENTION)
    assert trashed.is_purgeable(T0 + RETENTION + timedelta(days=1), RETENTION)


def test_active_item_is_never_purgeable() -> None:
    item = make_item()
    assert not item.is_purgeable(T0 + timedelta(days=365), RETENTION)
    with pytest.raises(InvalidStateError):
        item.ensure_purgeable(T0 + timedelta(days=365), RETENTION)


def test_ensure_purgeable() -> None:
    trashed = make_item().trashed(T0)
    trashed.ensure_purgeable(T0 + RETENTION, RETENTION)
    with pytest.raises(InvalidStateError):
        trashed.ensure_purgeable(T0 + timedelta(days=1), RETENTION)


def test_is_purgeable_rejects_naive_now() -> None:
    with pytest.raises(ValidationError):
        make_item().trashed(T0).is_purgeable(datetime(2027, 1, 1), RETENTION)


# --- unit 2 hardening: caseless collisions, bounds, transition ordering ---------


@pytest.mark.parametrize(
    "paths",
    [
        ("Straße.txt", "STRASSE.txt"),
        ("İ.txt", "i̇.txt"),  # 'İ' vs 'i' + combining dot above
        ("ᾼ.txt", "ᾳ.txt"),  # Greek capital/small alpha with iota
        ("Σ.txt", "ς.txt"),  # Sigma vs final sigma
        ("Å/a.txt", "å"),  # file/dir clash under caseless match
        ("dir/İ", "DIR/i̇"),
    ],
)
def test_item_rejects_caseless_equivalent_paths(paths: tuple[str, ...]) -> None:
    files = tuple(make_file(p, blob=i) for i, p in enumerate(paths))
    with pytest.raises(ValidationError):
        make_item(files=files, entry_file=paths[0])


@pytest.mark.parametrize("size", [2**63, 2**64, 10**30])
def test_sizes_beyond_int64_are_rejected(size: int) -> None:
    with pytest.raises(ValidationError):
        BlobRef(blob_id=ulid(1), size=size, sha256=SHA)
    with pytest.raises(ValidationError):
        make_file(size=size)


def test_max_int64_size_is_accepted() -> None:
    assert BlobRef(blob_id=ulid(1), size=2**63 - 1, sha256=SHA).size == 2**63 - 1


@pytest.mark.parametrize(
    "value",
    [
        datetime.min.replace(tzinfo=timezone(timedelta(hours=5))),
        datetime.max.replace(tzinfo=timezone(timedelta(hours=-5))),
    ],
)
def test_unrepresentable_utc_datetimes_raise_validation_error(value: datetime) -> None:
    with pytest.raises(ValidationError, match="out of range"):
        ensure_utc(value)
    with pytest.raises(ValidationError):
        make_item(created_at=value, updated_at=value)


def test_trashed_before_updated_at_is_rejected() -> None:
    item = make_item(updated_at=T0 + timedelta(hours=1))
    with pytest.raises(ValidationError, match="updated_at"):
        item.trashed(T0 + timedelta(minutes=30))
    assert item.trashed(T0 + timedelta(hours=1)).trashed_at == T0 + timedelta(hours=1)


def test_restored_before_trashed_at_is_rejected() -> None:
    trashed = make_item().trashed(T0 + timedelta(hours=1))
    with pytest.raises(ValidationError, match="trashed_at"):
        trashed.restored(T0 + timedelta(minutes=59))
    assert trashed.restored(T0 + timedelta(hours=1)).state is ItemState.ACTIVE


def test_transitions_reject_naive_times() -> None:
    with pytest.raises(ValidationError):
        make_item().trashed(datetime(2027, 1, 1))
    with pytest.raises(ValidationError):
        make_item().trashed(T0).restored(datetime(2027, 1, 1))


def test_constructed_trashed_at_must_not_precede_created_at() -> None:
    with pytest.raises(ValidationError, match="trashed_at"):
        make_item(state=ItemState.TRASHED, trashed_at=T0 - timedelta(microseconds=1))
