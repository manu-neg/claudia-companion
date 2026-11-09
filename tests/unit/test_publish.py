"""Unit tests for PublishService: happy paths, kind/media-type assignment, validation, rollback.

Limits/quotas/deadline live in `tests/security/test_publish_limits.py`
(C18/C11) and the secret scan in `tests/security/test_secret_scan.py` (C15).
"""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest

from preview_dashboard.application import IncomingFile, PublishLimits
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    InvalidPathError,
    LimitExceededError,
    SecretDetectedError,
    UnsupportedContentError,
    ValidationError,
)
from preview_dashboard.domain.models import BlobRef, Item, ItemId, ItemState
from preview_dashboard.domain.query import ItemQuery
from preview_dashboard.kinds import default_registry
from tests.app_support import (
    DEFAULT_LIMITS,
    TrackingIterable,
    command,
    incoming,
    make_publish,
)
from tests.fakes import FAKE_SECRET, InMemoryBlobStore, InMemoryItemRepository

pytestmark = pytest.mark.unit

REGISTRY = default_registry()


def _read(h: Any, blob_id: str) -> bytes:
    with h.blobs.open(blob_id) as f:
        data: bytes = f.read()
        return data


# --- happy paths -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("relpaths", "kind"),
    [
        (["photo.png"], "image"),
        (["a.jpg", "b.webp"], "image"),
        (["logo.svg"], "svg"),
        (["page.html"], "html"),
        (["index.html", "style.css", "app.js", "img/logo.png", "data.xml"], "html"),
        (["clip.mp4"], "video"),
        (["song.mp3"], "audio"),
        (["doc.pdf"], "pdf"),
        (["README.md"], "markdown"),
        (["main.py"], "code"),
        (["data.json"], "json"),
        (["t.csv"], "csv"),
        (["notes.txt"], "text"),
        (["change.diff"], "diff"),
        (["blob.bin"], "file"),
        (["a.html", "b.html"], "file"),  # no index.html -> not an html bundle
        (["a.svg", "b.png"], "file"),  # mixed kinds -> fallback
    ],
)
def test_publish_detects_kind_and_types_every_file_from_that_kind(
    relpaths: list[str], kind: str
) -> None:
    h = make_publish()
    item = h.service.publish(command(*(incoming(p, p.encode()) for p in relpaths)))
    assert item.kind == kind
    item_kind = REGISTRY.get(kind)
    assert [f.relpath for f in item.files] == relpaths
    for f in item.files:
        # C8: the item's own kind decides, never a per-file registry lookup.
        assert f.media_type == item_kind.media_type(f.relpath)
    assert item.entry_file == item_kind.entry_file(relpaths)
    assert h.repo.get(item.id) == item


def test_file_kind_members_are_all_octet_stream() -> None:
    h = make_publish()
    item = h.service.publish(command(incoming("a.html"), incoming("b.html"), incoming("c.js")))
    assert item.kind == "file"
    assert {f.media_type for f in item.files} == {"application/octet-stream"}


def test_mixed_svg_bundle_never_stores_svg_media_type() -> None:
    h = make_publish()
    item = h.service.publish(command(incoming("a.svg"), incoming("b.png")))
    assert item.kind == "file"
    assert all(f.media_type != "image/svg+xml" for f in item.files)


def test_html_bundle_uses_html_closed_asset_map() -> None:
    h = make_publish()
    item = h.service.publish(
        command(
            incoming("index.html"),
            incoming("app.js"),
            incoming("style.css"),
            incoming("x.xml"),
            incoming("m.wasm"),
            incoming("main.py"),
        )
    )
    types = {f.relpath: f.media_type for f in item.files}
    assert types == {
        "index.html": "text/html",
        "app.js": "text/javascript",
        "style.css": "text/css",
        "x.xml": "application/octet-stream",
        "m.wasm": "application/octet-stream",
        "main.py": "application/octet-stream",
    }
    assert item.entry_file == "index.html"


def test_standalone_js_is_inert_text() -> None:
    h = make_publish()
    item = h.service.publish(command(incoming("app.js")))
    assert item.kind == "code"
    assert item.files[0].media_type == "text/plain"


def test_publish_stores_exact_bytes_size_and_digest() -> None:
    h = make_publish()
    data = bytes(range(256)) * 3
    item = h.service.publish(command(incoming("a.bin", data, chunk=7)))
    f = item.files[0]
    assert f.size == len(data)
    assert f.sha256 == hashlib.sha256(data).hexdigest()
    assert _read(h, f.blob_id) == data


def test_publish_sets_metadata_and_times() -> None:
    h = make_publish()
    item = h.service.publish(
        command(incoming("a.txt"), title="  Hello\u202e  ", description="desc", pinned=True)
    )
    assert item.title == "Hello"  # sanitized by the domain
    assert item.description == "desc"
    assert item.pinned is True
    assert item.state is ItemState.ACTIVE
    assert item.created_at == item.updated_at == h.clock.now()


def test_empty_file_is_allowed() -> None:
    h = make_publish()
    item = h.service.publish(command(incoming("empty.txt", b"")))
    assert item.files[0].size == 0


def test_empty_chunks_are_skipped() -> None:
    h = make_publish()
    item = h.service.publish(command(IncomingFile("a.txt", [b"", b"ab", b"", b"c"])))
    assert _read(h, item.files[0].blob_id) == b"abc"


# --- kind hints ----------------------------------------------------------------------


def test_compatible_hint_is_used() -> None:
    h = make_publish()
    item = h.service.publish(command(incoming("a.txt"), kind_hint="file"))
    assert item.kind == "file"
    assert item.files[0].media_type == "application/octet-stream"


def test_incompatible_hint_rejected_before_any_byte() -> None:
    h = make_publish()
    chunks = TrackingIterable([b"x"])

    with pytest.raises(UnsupportedContentError):
        h.service.publish(command(IncomingFile("a.txt", chunks), kind_hint="image"))
    assert not chunks.consumed
    assert h.blobs.list_ids() == set()


@pytest.mark.parametrize("hint", ["IMAGE", "x" * 5000, "image/../..", "", "im age"])
def test_malformed_hint_is_rejected_and_not_echoed(hint: str) -> None:
    h = make_publish()
    with pytest.raises(ValidationError) as info:
        h.service.publish(command(incoming("a.png"), kind_hint=hint))
    if hint:
        assert hint not in str(info.value)


def test_unknown_but_wellformed_hint_rejected() -> None:
    h = make_publish()
    with pytest.raises(UnsupportedContentError):
        h.service.publish(command(incoming("a.png"), kind_hint="nosuchkind"))


# --- validation up front ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("relpaths", "error"),
    [
        (["../etc/passwd"], InvalidPathError),
        (["/abs.txt"], InvalidPathError),
        (["a\\b.txt"], InvalidPathError),
        (["ok.txt", "OK.TXT"], ValidationError),  # caseless duplicate
        (["a", "a/b.txt"], ValidationError),  # file doubles as directory
        (["index.html", "sub/index.html"], None),  # fine: root index exists
    ],
)
def test_manifest_problems_fail_before_streaming(
    relpaths: list[str], error: type[Exception] | None
) -> None:
    h = make_publish()

    trackers = [TrackingIterable([b"data"]) for _ in relpaths]
    cmd = command(*(IncomingFile(p, t) for p, t in zip(relpaths, trackers, strict=True)))
    if error is None:
        h.service.publish(cmd)
        return
    with pytest.raises(error):
        h.service.publish(cmd)
    assert not any(t.consumed for t in trackers)
    assert h.blobs.list_ids() == set()
    assert h.repo.count() == 0


def test_no_files_rejected() -> None:
    h = make_publish()
    with pytest.raises((ValidationError, UnsupportedContentError)):
        h.service.publish(command())


@pytest.mark.parametrize("title", ["", "   ", "\u200b\u202e", "x" * 201])
def test_bad_title_rejected_before_streaming(title: str) -> None:
    h = make_publish()
    tracker = TrackingIterable([b"data"])

    with pytest.raises(ValidationError):
        h.service.publish(command(IncomingFile("a.txt", tracker), title=title))
    assert not tracker.consumed


def test_limits_value_object_validates() -> None:
    with pytest.raises(ValueError, match="max_files"):
        PublishLimits(**{**DEFAULT_LIMITS, "max_files": 0})
    with pytest.raises(ValueError, match="timeout"):
        PublishLimits(**{**DEFAULT_LIMITS, "timeout": timedelta(0)})
    with pytest.raises(ValueError, match="max_file_bytes"):
        PublishLimits(**{**DEFAULT_LIMITS, "max_file_bytes": 5_000})


# --- rollback on every failure point ---------------------------------------------------


class _BoomError(Exception):
    pass


def _chunks_then(exc: BaseException) -> Iterator[bytes]:
    yield b"partial"
    raise exc


class _AddFailsRepo(InMemoryItemRepository):
    def add(self, item: Item) -> None:
        raise AlreadyExistsError("item already exists")


class _DeleteFailsStore(InMemoryBlobStore):
    def __init__(self) -> None:
        super().__init__()
        self.delete_attempts: list[str] = []

    def delete(self, blob_id: str) -> None:
        self.delete_attempts.append(blob_id)
        raise OSError("disk on fire")


class _PutFailsOnSecond(InMemoryBlobStore):
    def __init__(self) -> None:
        super().__init__()
        self.puts = 0

    def put(self, chunks: Any, max_bytes: int) -> BlobRef:
        self.puts += 1
        if self.puts == 2:
            list(chunks)
            raise _BoomError("storage exploded")
        return super().put(chunks, max_bytes)


@pytest.mark.parametrize(
    "failure",
    [
        "second_file_too_big",
        "secret_in_second_file",
        "chunks_raise",
        "keyboard_interrupt",
        "repo_add_fails",
        "put_raises",
    ],
)
def test_any_failure_deletes_all_blobs_of_the_publish(failure: str) -> None:

    repo = _AddFailsRepo() if failure == "repo_add_fails" else None
    blobs = _PutFailsOnSecond() if failure == "put_raises" else None
    h = make_publish(repo=repo, blobs=blobs)
    first = incoming("a.txt", b"first file")
    second: IncomingFile
    expected: type[BaseException]
    if failure == "second_file_too_big":
        second, expected = incoming("b.txt", b"y" * 1_001), LimitExceededError
    elif failure == "secret_in_second_file":
        second, expected = incoming("b.txt", b"xx" + FAKE_SECRET), SecretDetectedError
    elif failure == "chunks_raise":
        second, expected = IncomingFile("b.txt", _chunks_then(_BoomError())), _BoomError
    elif failure == "keyboard_interrupt":
        second, expected = (
            IncomingFile("b.txt", _chunks_then(KeyboardInterrupt())),
            KeyboardInterrupt,
        )
    elif failure == "repo_add_fails":
        second, expected = incoming("b.txt"), AlreadyExistsError
    else:
        second, expected = incoming("b.txt"), _BoomError
    with pytest.raises(expected):
        h.service.publish(command(first, second))
    assert h.blobs.list_ids() == set()
    assert h.repo.count() == 0


def test_rollback_keeps_going_when_delete_fails() -> None:
    blobs = _DeleteFailsStore()
    h = make_publish(blobs=blobs)
    with pytest.raises(LimitExceededError):
        h.service.publish(
            command(incoming("a.txt"), incoming("b.txt"), incoming("c.txt", b"z" * 1_001))
        )
    assert len(blobs.delete_attempts) == 2  # both stored blobs were attempted


class _CommitThenRaiseRepo(InMemoryItemRepository):
    """`add` commits, then fails (e.g. the connection dies before COMMIT is acked)."""

    def add(self, item: Item) -> None:
        super().add(item)
        raise _BoomError("connection lost after commit")


class _AddAndGetFailRepo(InMemoryItemRepository):
    """`add` fails and the follow-up `get` can't tell whether it committed."""

    def add(self, item: Item) -> None:
        raise _BoomError("unknown outcome")

    def get(self, item_id: ItemId) -> Item:
        raise _BoomError("database unavailable")


class _CollidingAddRepo(InMemoryItemRepository):
    """`add` finds another item already stored under the new id."""

    def add(self, item: Item) -> None:
        super().add(
            dataclasses.replace(item, files=(item.files[0],), entry_file=item.files[0].relpath)
        )
        raise AlreadyExistsError("item already exists")


def test_rollback_keeps_blobs_of_an_item_that_did_commit() -> None:
    # L1: once `repo.add` was entered, blobs are only deleted when the row
    # provably did not commit; deleting here would leave a dangling row.
    repo = _CommitThenRaiseRepo()
    h = make_publish(repo=repo)
    with pytest.raises(_BoomError):
        h.service.publish(command(incoming("a.txt", b"a"), incoming("b.txt", b"b")))
    assert repo.count() == 1
    (stored,) = repo.list(ItemQuery()).items
    assert h.blobs.list_ids() == {f.blob_id for f in stored.files}
    for f in stored.files:
        assert h.blobs.open(f.blob_id).read() in (b"a", b"b")


def test_rollback_keeps_blobs_when_commit_state_is_unknown() -> None:
    h = make_publish(repo=_AddAndGetFailRepo())
    with pytest.raises(_BoomError, match="unknown outcome"):
        h.service.publish(command(incoming("a.txt"), incoming("b.txt")))
    assert len(h.blobs.list_ids()) == 2  # left for the orphan sweep


def test_rollback_deletes_only_blobs_the_stored_row_does_not_reference() -> None:
    h = make_publish(repo=_CollidingAddRepo())
    with pytest.raises(AlreadyExistsError):
        h.service.publish(command(incoming("a.txt"), incoming("b.txt")))
    (stored,) = h.repo.list(ItemQuery()).items
    assert h.blobs.list_ids() == {stored.files[0].blob_id}


def test_other_items_blobs_survive_a_failed_publish() -> None:
    h = make_publish()
    ok = h.service.publish(command(incoming("keep.txt", b"keep")))
    with pytest.raises(LimitExceededError):
        h.service.publish(command(incoming("a.txt"), incoming("b.txt", b"y" * 1_001)))
    assert h.blobs.list_ids() == {ok.files[0].blob_id}


# --- quota reservation ---------------------------------------------------------------


def test_reservations_are_released_after_success_and_failure() -> None:
    h = make_publish(max_items=2)
    with pytest.raises(LimitExceededError):
        h.service.publish(command(incoming("a.txt", b"y" * 1_001)))
    h.service.publish(command(incoming("a.txt")))
    h.service.publish(command(incoming("b.txt")))
    with pytest.raises(LimitExceededError, match="item quota"):
        h.service.publish(command(incoming("c.txt")))


def test_in_flight_publish_counts_against_item_quota() -> None:
    h = make_publish(max_items=1)
    nested: list[BaseException] = []

    def chunks() -> Iterator[bytes]:
        yield b"a"
        try:
            h.service.publish(command(incoming("n.txt")))
        except LimitExceededError as exc:
            nested.append(exc)
        yield b"b"

    h.service.publish(command(IncomingFile("outer.txt", chunks())))
    assert len(nested) == 1
    assert "item quota" in str(nested[0])


def test_in_flight_publish_reserves_bytes() -> None:
    # Outer reserves max_item_bytes (3000) of the 4000 total: 1000 left.
    h = make_publish(max_total_bytes=4_000)
    results: list[object] = []

    def chunks() -> Iterator[bytes]:
        yield b"a"
        try:
            results.append(h.service.publish(command(incoming("n.txt", b"n" * 999))))
            h.service.publish(command(incoming("m.txt", b"m" * 2)))
        except LimitExceededError as exc:
            results.append(exc)
        yield b"b"

    h.service.publish(command(IncomingFile("outer.txt", chunks())))
    assert isinstance(results[0], Item)
    assert isinstance(results[1], LimitExceededError)
