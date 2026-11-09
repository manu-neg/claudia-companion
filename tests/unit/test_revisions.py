"""Unit tests for item revisions: the domain model and `PublishService.publish_revision`.

Covers the ADR 0019 contract: stable id, new head per update, last
`MAX_REVISIONS` kept (pruned automatically, blobs deleted after commit),
bytes of every revision counted in the quota, the publish checks (secret
scan, limits, rate limit, deadline) reused, rollback and compare-and-swap.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest

from preview_dashboard.application import RevisionCommand
from preview_dashboard.domain.errors import (
    ConflictError,
    InvalidStateError,
    LimitExceededError,
    NotFoundError,
    RateLimitedError,
    SecretDetectedError,
    ValidationError,
)
from preview_dashboard.domain.models import (
    MAX_REVISIONS,
    Item,
    ItemId,
    ItemState,
    Revision,
)
from tests.app_support import command, incoming, make_publish
from tests.builders import T0, make_file, make_item, ulid
from tests.fakes import FAKE_SECRET, InMemoryItemRepository

pytestmark = pytest.mark.unit

H = timedelta(hours=1)


def _revise(
    item: Item, n: int, *, at_hours: int | None = None
) -> tuple[Item, tuple[Revision, ...]]:
    at = T0 + (at_hours if at_hours is not None else n) * H
    return item.with_revision(
        kind="html",
        files=(make_file("index.html", blob=1000 + n),),
        entry_file="index.html",
        at=at,
    )


# --- domain -------------------------------------------------------------------------------


def test_new_item_is_revision_one_with_no_history() -> None:
    item = make_item(1)
    assert item.revision == 1
    assert item.revision_at == item.created_at
    assert item.history == ()
    assert [r.number for r in item.revisions] == [1]
    assert item.head.files == item.files
    assert item.stored_size == item.total_size


def test_with_revision_keeps_identity_and_metadata() -> None:
    item = make_item(1, title="T", description="D", pinned=True)
    updated, pruned = item.with_revision(
        kind="markdown",
        files=(make_file("notes.md", blob=50, media_type="text/markdown"),),
        entry_file="notes.md",
        at=T0 + H,
    )
    assert pruned == ()
    assert (updated.id, updated.title, updated.description, updated.pinned) == (
        item.id,
        "T",
        "D",
        True,
    )
    assert updated.revision == 2
    assert updated.kind == "markdown"
    assert updated.revision_at == updated.updated_at == T0 + H
    assert updated.history == (item.head,)
    assert updated.revision_by_number(1) == item.head
    assert updated.revision_by_number(None) == updated.head
    assert updated.revision_by_number(3) is None
    assert updated.stored_size == item.total_size + updated.total_size
    assert {f.blob_id for f in updated.all_files} == {ulid(10_001), ulid(10_050)}


def test_revisions_are_pruned_to_the_last_twenty() -> None:
    item = make_item(1)
    all_pruned: list[Revision] = []
    for n in range(2, MAX_REVISIONS + 3):
        item, pruned = _revise(item, n)
        all_pruned.extend(pruned)
    assert len(item.revisions) == MAX_REVISIONS
    assert [r.number for r in item.revisions] == list(range(3, MAX_REVISIONS + 3))
    assert [r.number for r in all_pruned] == [1, 2]
    assert item.revision_by_number(1) is None


def test_trashed_item_cannot_get_a_revision() -> None:
    trashed = make_item(1).trashed(T0 + H)
    with pytest.raises(InvalidStateError):
        _revise(trashed, 2, at_hours=2)


def test_revision_time_must_not_run_backwards() -> None:
    item = make_item(1, updated_at=T0 + 2 * H)
    with pytest.raises(ValidationError):
        _revise(item, 2, at_hours=1)


def test_next_change_at_is_strictly_after_updated_at() -> None:
    item = make_item(1, updated_at=T0 + H)
    assert item.next_change_at(T0) == T0 + H + timedelta(microseconds=1)
    assert item.next_change_at(T0 + 2 * H) == T0 + 2 * H


@pytest.mark.parametrize(
    "overrides",
    [
        {"revision": 0},
        {"revision": True},
        {"revision": 2**31},
        {"revision_at": T0 - H},  # before created_at
        {"revision_at": T0 + 2 * H},  # after updated_at
    ],
)
def test_item_rejects_bad_head_revision(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_item(1, updated_at=T0 + H, **overrides)


def _rev(number: int, blob: int, at: timedelta = timedelta(0)) -> Revision:
    return Revision(
        number=number,
        kind="html",
        files=(make_file("index.html", blob=blob),),
        entry_file="index.html",
        created_at=T0 + at,
    )


@pytest.mark.parametrize(
    "history",
    [
        (_rev(3, 50),),  # not below the head (3)
        (_rev(2, 50), _rev(1, 51)),  # decreasing
        (_rev(1, 50), _rev(1, 51)),  # duplicate number
        (_rev(1, 50, 2 * H), _rev(2, 51, H)),  # time runs backwards
        (_rev(1, 1),),  # shares the head's blob
        tuple(_rev(n, 100 + n) for n in range(1, MAX_REVISIONS + 1)),  # 21 in total
    ],
)
def test_item_rejects_inconsistent_history(history: tuple[Revision, ...]) -> None:
    number = max(3, len(history) + 1)
    with pytest.raises(ValidationError):
        make_item(
            1, revision=number, updated_at=T0 + 3 * H, revision_at=T0 + 3 * H, history=history
        )


def test_revision_validates_its_manifest() -> None:
    with pytest.raises(ValidationError):
        Revision(number=1, kind="html", files=(), entry_file="x", created_at=T0)
    with pytest.raises(ValidationError):
        Revision(
            number=1,
            kind="html",
            files=(make_file("a.html", blob=1), make_file("A.html", blob=2)),
            entry_file="a.html",
            created_at=T0,
        )


# --- application: publish_revision ------------------------------------------------------


class _BoomError(Exception):
    pass


def _published(**kwargs: Any) -> tuple[Any, Item]:
    harness = make_publish(**kwargs)
    item = harness.service.publish(command(incoming("index.html", b"<p>v1</p>")))
    return harness, item


def _revision(item_id: str, *files: Any, **kwargs: Any) -> RevisionCommand:
    return RevisionCommand(item_id=item_id, files=list(files), **kwargs)


def test_publish_revision_adds_a_new_head_with_the_same_id() -> None:
    harness, item = _published()
    harness.clock.advance(H)
    updated = harness.service.publish_revision(
        _revision(item.id, incoming("index.html", b"<p>v2</p>"), incoming("a.css", b"p{}"))
    )
    assert updated.id == item.id
    assert updated.revision == 2
    assert [f.relpath for f in updated.files] == ["index.html", "a.css"]
    assert updated.history[0].files == item.files
    assert harness.repo.get(item.id) == updated
    stored = {f.blob_id: harness.blobs.open(f.blob_id).read() for f in updated.all_files}
    assert sorted(stored.values()) == [b"<p>v1</p>", b"<p>v2</p>", b"p{}"]


def test_publish_revision_may_change_kind_and_types_come_from_the_new_kind() -> None:
    harness, item = _published()
    updated = harness.service.publish_revision(_revision(item.id, incoming("notes.md", b"# hi")))
    assert updated.kind == "markdown"
    assert updated.files[0].media_type == "text/markdown"
    assert updated.history[0].kind == "html"


def test_publish_revision_prunes_and_deletes_old_blobs() -> None:
    harness, item = _published()
    first_blob = item.files[0].blob_id
    for n in range(2, MAX_REVISIONS + 2):
        harness.clock.advance(H)
        item = harness.service.publish_revision(
            _revision(item.id, incoming("index.html", f"v{n}".encode()))
        )
    assert item.revision == MAX_REVISIONS + 1
    assert len(item.revisions) == MAX_REVISIONS
    with pytest.raises(NotFoundError):
        harness.blobs.open(first_blob)
    assert harness.blobs.list_ids() == {f.blob_id for f in item.all_files}


def test_publish_revision_of_trashed_item_is_refused_without_storing() -> None:
    harness, item = _published()
    harness.repo.save(item.trashed(T0 + H), expected_updated_at=item.updated_at)
    before = harness.blobs.list_ids()
    with pytest.raises(InvalidStateError):
        harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v2")))
    assert harness.blobs.list_ids() == before


def test_publish_revision_of_missing_item() -> None:
    harness, _ = _published()
    with pytest.raises(NotFoundError):
        harness.service.publish_revision(_revision(ulid(999), incoming("a.txt")))
    with pytest.raises(ValidationError):
        harness.service.publish_revision(_revision("not-an-id", incoming("a.txt")))


def test_publish_revision_secret_in_content_rolls_back() -> None:
    harness, item = _published()
    before = harness.blobs.list_ids()
    with pytest.raises(SecretDetectedError) as info:
        harness.service.publish_revision(
            _revision(item.id, incoming("ok.txt", b"fine"), incoming("b.txt", b"x" + FAKE_SECRET))
        )
    assert info.value.relpath == "b.txt"
    assert harness.blobs.list_ids() == before
    assert harness.repo.get(item.id) == item


def test_publish_revision_secret_in_relpath_is_refused_before_any_byte() -> None:
    harness, item = _published()
    name = FAKE_SECRET.decode() + ".txt"
    with pytest.raises(SecretDetectedError):
        harness.service.publish_revision(_revision(item.id, incoming(name, b"x")))
    assert harness.repo.get(item.id) == item


def test_publish_revision_expected_revision_mismatch_is_a_conflict() -> None:
    harness, item = _published()
    with pytest.raises(ConflictError):
        harness.service.publish_revision(
            _revision(item.id, incoming("index.html", b"v2"), expected_revision=2)
        )
    ok = harness.service.publish_revision(
        _revision(item.id, incoming("index.html", b"v2"), expected_revision=1)
    )
    assert ok.revision == 2
    with pytest.raises(ValidationError):
        harness.service.publish_revision(
            _revision(item.id, incoming("index.html", b"v3"), expected_revision=0)
        )


class _ConflictOnce(InMemoryItemRepository):
    """Applies a concurrent edit right before the first `save` (a racing writer)."""

    def __init__(self, edit: Any) -> None:
        super().__init__()
        self._edit = edit
        self.raced = False

    def save(self, item: Item, *, expected_updated_at: Any) -> None:
        if not self.raced:
            self.raced = True
            current = self.get(item.id)
            super().save(self._edit(current), expected_updated_at=current.updated_at)
        super().save(item, expected_updated_at=expected_updated_at)


class _SaveCommitsThenRaisesRepo(InMemoryItemRepository):
    """`save` commits, then fails (e.g. the connection dies before COMMIT is acked)."""

    def save(self, item: Item, *, expected_updated_at: Any) -> None:
        super().save(item, expected_updated_at=expected_updated_at)
        raise _BoomError("connection lost after commit")


def test_publish_revision_rollback_keeps_the_new_head_when_save_commits_then_raises() -> None:
    # M1: `save` raising must not be read as "definitely did not commit" —
    # the previous `committing`-flag logic did, and deleted the new head's
    # blobs even though the row (and its reference to them) had committed.
    repo = _SaveCommitsThenRaisesRepo()
    harness, item = _published(repo=repo)
    with pytest.raises(_BoomError):
        harness.service.publish_revision(_revision(item.id, incoming("index.html", b"<p>v2</p>")))
    stored = repo.get(item.id)
    assert stored.revision == 2
    assert harness.blobs.list_ids() == {f.blob_id for f in stored.all_files}


def test_publish_revision_retries_once_after_a_concurrent_edit() -> None:
    repo = _ConflictOnce(lambda i: i.with_metadata(now=i.next_change_at(T0), title="Edited"))
    harness, item = _published(repo=repo)
    updated = harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v2")))
    assert updated.title == "Edited"  # the concurrent edit survives
    assert updated.revision == 2
    assert repo.get(item.id) == updated


def test_publish_revision_concurrent_trash_wins_and_rolls_back() -> None:
    repo = _ConflictOnce(lambda i: i.trashed(i.next_change_at(T0)))
    harness, item = _published(repo=repo)
    before = harness.blobs.list_ids()
    with pytest.raises(InvalidStateError):
        harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v2")))
    assert harness.blobs.list_ids() == before
    assert repo.get(item.id).state is ItemState.TRASHED


def test_publish_revision_concurrent_revision_with_expected_revision_conflicts() -> None:
    def other_revision(i: Item) -> Item:
        return i.with_revision(
            kind="html",
            files=(make_file("index.html", blob=900),),
            entry_file="index.html",
            at=i.next_change_at(T0),
        )[0]

    repo = _ConflictOnce(other_revision)
    harness, item = _published(repo=repo)
    with pytest.raises(ConflictError):
        harness.service.publish_revision(
            _revision(item.id, incoming("index.html", b"v2"), expected_revision=1)
        )


def test_every_revision_counts_against_the_byte_quota() -> None:
    harness, item = _published(max_file_bytes=1_000, max_item_bytes=1_000, max_total_bytes=1_500)
    item = harness.service.publish_revision(_revision(item.id, incoming("index.html", b"x" * 900)))
    assert harness.repo.usage().total_bytes == item.stored_size
    with pytest.raises(LimitExceededError):
        harness.service.publish_revision(_revision(item.id, incoming("index.html", b"y" * 1_000)))
    assert harness.repo.get(item.id) == item


def test_revisions_do_not_take_item_slots() -> None:
    harness, item = _published(max_items=1)
    updated = harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v2")))
    assert updated.revision == 2
    with pytest.raises(LimitExceededError):
        harness.service.publish(command(incoming("b.txt")))


def test_publish_revision_counts_against_the_rate_limit() -> None:
    harness, item = _published(rate=2)
    harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v2")))
    with pytest.raises(RateLimitedError):
        harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v3")))


def test_publish_revision_past_the_deadline_never_commits() -> None:
    harness, item = _published()

    def slow() -> Iterator[bytes]:
        yield b"a"
        harness.mono.advance(3_600)
        yield b"b"

    with pytest.raises(LimitExceededError, match="timed out"):
        harness.service.publish_revision(
            RevisionCommand(
                item_id=item.id, files=[dataclasses.replace(incoming("a.txt"), chunks=slow())]
            )
        )
    assert harness.repo.get(item.id) == item
    assert harness.blobs.list_ids() == {item.files[0].blob_id}


def test_publish_revision_validates_manifest_before_reading() -> None:
    harness, item = _published()
    with pytest.raises(ValidationError):
        harness.service.publish_revision(_revision(item.id, incoming("a.txt"), incoming("A.txt")))
    with pytest.raises(LimitExceededError):
        harness.service.publish_revision(
            _revision(item.id, *(incoming(f"f{n}.txt") for n in range(20)))
        )


def test_purge_deletes_the_blobs_of_every_revision() -> None:
    from preview_dashboard.application import PurgeService

    harness, item = _published()
    harness.clock.advance(H)
    item = harness.service.publish_revision(_revision(item.id, incoming("index.html", b"v2")))
    harness.repo.save(
        item.trashed(item.next_change_at(harness.clock.now())), expected_updated_at=item.updated_at
    )
    purge = PurgeService(
        repo=harness.repo,
        blobs=harness.blobs,
        clock=harness.clock,
        retention=timedelta(days=14),
        orphan_grace=timedelta(hours=2),
    )
    report = purge.run(harness.clock.now() + timedelta(days=15))
    assert report.items_purged == 1
    assert report.blobs_deleted == 2
    assert harness.blobs.list_ids() == set()
    with pytest.raises(NotFoundError):
        harness.repo.get(ItemId(item.id))
