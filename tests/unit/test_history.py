"""Tests for pruning old revisions (ADR 0030): `Item.without_history` and `HistoryService`.

Domain bounds/head/trashed rules, and the service over fakes: commit before
blob deletes, CAS retry, idempotency, failed deletes swept later (C43).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from preview_dashboard.application import HistoryService, PurgeService
from preview_dashboard.domain.errors import (
    ConflictError,
    InvalidStateError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.models import (
    MAX_REVISIONS,
    Item,
    ItemFile,
    validate_keep_revisions,
)
from tests.builders import T0, make_item, ulid
from tests.fakes import FixedClock, InMemoryBlobStore, InMemoryItemRepository

pytestmark = pytest.mark.unit

H = timedelta(hours=1)


def _store_file(blobs: InMemoryBlobStore, data: bytes) -> ItemFile:
    ref = blobs.put([data], max_bytes=1024)
    return ItemFile.from_blob("index.html", ref, "text/html")


def _with_revisions(count: int, blobs: InMemoryBlobStore, n: int = 1) -> Item:
    """An active item with `count` revisions whose blobs really exist in `blobs`."""
    item = make_item(n, files=(_store_file(blobs, b"v1"),))
    for number in range(2, count + 1):
        item, _ = item.with_revision(
            kind="html",
            files=(_store_file(blobs, f"v{number}".encode()),),
            entry_file="index.html",
            at=T0 + number * H,
        )
    return item


# --- domain ---------------------------------------------------------------------------


@pytest.mark.parametrize("keep", [0, -1, MAX_REVISIONS + 1, True, 1.0, "1", None])
def test_keep_is_bounded(keep: object) -> None:
    with pytest.raises(ValidationError):
        validate_keep_revisions(keep)
    item = _with_revisions(3, InMemoryBlobStore())
    with pytest.raises(ValidationError):
        item.without_history(keep, at=T0 + 10 * H)  # type: ignore[arg-type]


def test_keep_one_drops_every_older_revision_oldest_first() -> None:
    item = _with_revisions(4, InMemoryBlobStore())
    pruned, dropped = item.without_history(1, at=T0 + 10 * H)
    assert [r.number for r in dropped] == [1, 2, 3]
    assert pruned.history == ()
    assert pruned.head == item.head  # the head is never dropped
    assert pruned.revision == 4
    assert pruned.updated_at == T0 + 10 * H
    assert (pruned.id, pruned.title, pruned.pinned) == (item.id, item.title, item.pinned)
    assert pruned.stored_size == item.total_size


def test_keep_counts_the_head() -> None:
    item = _with_revisions(5, InMemoryBlobStore())
    pruned, dropped = item.without_history(3, at=T0 + 10 * H)
    assert [r.number for r in dropped] == [1, 2]
    assert [r.number for r in pruned.revisions] == [3, 4, 5]


@pytest.mark.parametrize("keep", [3, 4, MAX_REVISIONS])
def test_nothing_to_drop_returns_the_item_unchanged(keep: int) -> None:
    item = _with_revisions(3, InMemoryBlobStore())
    same, dropped = item.without_history(keep, at=T0 + 10 * H)
    assert dropped == ()
    assert same is item  # no new updated_at: no write needed


def test_trashed_item_is_refused_even_with_nothing_to_drop() -> None:
    item = make_item(1).trashed(T0 + H)
    with pytest.raises(InvalidStateError):
        item.without_history(1, at=T0 + 2 * H)


def test_prune_time_must_not_run_backwards() -> None:
    item = _with_revisions(3, InMemoryBlobStore())
    with pytest.raises(ValidationError):
        item.without_history(1, at=item.updated_at - timedelta(microseconds=1))


# --- service --------------------------------------------------------------------------


class _Blobs(InMemoryBlobStore):
    """Records deletes; can fail them; checks the row was saved first (C11)."""

    def __init__(self, *, fail: bool = False) -> None:
        super().__init__()
        self.fail = fail
        self.deleted: list[str] = []
        self.repo: InMemoryItemRepository | None = None

    def delete(self, blob_id: str) -> None:
        if self.repo is not None:
            assert blob_id not in self.repo.all_blob_ids(), "blob deleted before the commit"
        if self.fail:
            raise OSError("disk says no")
        self.deleted.append(blob_id)
        super().delete(blob_id)


class _Env:
    def __init__(self, *, fail: bool = False, repo: InMemoryItemRepository | None = None) -> None:
        self.clock = FixedClock(T0 + 100 * H)
        self.repo = repo or InMemoryItemRepository()
        self.blobs = _Blobs(fail=fail)
        self.blobs.repo = self.repo
        self.service = HistoryService(repo=self.repo, blobs=self.blobs, clock=self.clock)

    def add(self, count: int, n: int = 1) -> Item:
        item = _with_revisions(count, self.blobs, n)
        self.repo.add(item)
        return item


def test_prune_commits_then_deletes_only_the_dropped_blobs() -> None:
    env = _Env()
    item = env.add(4)
    other = env.add(3, n=2)
    result = env.service.prune_revisions(item.id)
    assert result.revisions_removed == 3
    dropped_blobs = {f.blob_id for r in item.history for f in r.files}
    assert set(env.blobs.deleted) == dropped_blobs
    assert result.bytes_freed == sum(r.total_size for r in item.history)
    stored = env.repo.get(item.id)
    assert stored == result.item
    assert [r.number for r in stored.revisions] == [4]
    assert stored.updated_at == env.clock.now()
    # The head's blob and every other item's blobs are intact.
    assert env.blobs.open(item.files[0].blob_id).read() == b"v4"
    assert env.repo.get(other.id) == other
    assert {f.blob_id for f in other.all_files} <= env.blobs.list_ids()


def test_prune_is_idempotent() -> None:
    env = _Env()
    item = env.add(3)
    env.service.prune_revisions(item.id, keep=2)
    stamped = env.repo.get(item.id)
    again = env.service.prune_revisions(item.id, keep=2)
    assert (again.revisions_removed, again.bytes_freed) == (0, 0)
    assert again.item == stamped
    assert env.repo.get(item.id).updated_at == stamped.updated_at  # no write


def test_single_revision_item_is_a_no_op() -> None:
    env = _Env()
    item = env.add(1)
    result = env.service.prune_revisions(item.id)
    assert (result.item, result.revisions_removed, result.bytes_freed) == (item, 0, 0)
    assert env.blobs.deleted == []


def test_trashed_item_is_refused_and_nothing_deleted() -> None:
    env = _Env()
    item = env.add(3)
    env.repo.save(item.trashed(item.updated_at), expected_updated_at=item.updated_at)
    with pytest.raises(InvalidStateError):
        env.service.prune_revisions(item.id)
    assert env.blobs.deleted == []
    assert len(env.repo.get(item.id).revisions) == 3


def test_expected_revision_must_be_the_head() -> None:
    env = _Env()
    item = env.add(3)
    with pytest.raises(ConflictError):
        env.service.prune_revisions(item.id, expected_revision=2)
    assert env.repo.get(item.id) == item
    assert env.service.prune_revisions(item.id, expected_revision=3).revisions_removed == 2


@pytest.mark.parametrize(
    ("item_id", "keep", "expected", "error"),
    [
        ("nope", 1, None, ValidationError),
        (ulid(1), 0, None, ValidationError),
        (ulid(1), 21, None, ValidationError),
        (ulid(1), 1, 0, ValidationError),
        (ulid(99), 1, None, NotFoundError),
    ],
)
def test_bad_input(item_id: str, keep: int, expected: int | None, error: type[Exception]) -> None:
    env = _Env()
    env.add(2)
    with pytest.raises(error):
        env.service.prune_revisions(item_id, keep=keep, expected_revision=expected)
    assert env.blobs.deleted == []


class _ConcurrentRevision(InMemoryItemRepository):
    """The first save loses the race to a revision published meanwhile."""

    def __init__(self, blobs: InMemoryBlobStore) -> None:
        super().__init__()
        self.blobs = blobs
        self.raced = False

    def save(self, item: Item, *, expected_updated_at: datetime) -> None:
        if not self.raced:
            self.raced = True
            current = self.get(item.id)
            newer, _ = current.with_revision(
                kind="html",
                files=(_store_file(self.blobs, b"racing"),),
                entry_file="index.html",
                at=current.next_change_at(current.updated_at),
            )
            super().save(newer, expected_updated_at=current.updated_at)
        super().save(item, expected_updated_at=expected_updated_at)


def test_cas_conflict_is_reread_and_the_new_revision_is_kept() -> None:
    env = _Env()
    env.repo = repo = _ConcurrentRevision(env.blobs)
    env.blobs.repo = repo
    env.service = HistoryService(repo=repo, blobs=env.blobs, clock=env.clock)
    item = env.add(3)
    result = env.service.prune_revisions(item.id)
    stored = repo.get(item.id)
    # The racing revision 4 became the head and survived; 1..3 are gone.
    assert [r.number for r in stored.revisions] == [4]
    assert env.blobs.open(stored.files[0].blob_id).read() == b"racing"
    assert result.revisions_removed == 3


def test_cas_conflict_with_expected_revision_is_refused() -> None:
    env = _Env()
    env.repo = repo = _ConcurrentRevision(env.blobs)
    env.blobs.repo = repo
    env.service = HistoryService(repo=repo, blobs=env.blobs, clock=env.clock)
    item = env.add(3)
    with pytest.raises(ConflictError):
        env.service.prune_revisions(item.id, expected_revision=3)
    assert env.blobs.deleted == []
    assert len(repo.get(item.id).revisions) == 4


class _AlwaysConflict(InMemoryItemRepository):
    def save(self, item: Item, *, expected_updated_at: datetime) -> None:
        raise ConflictError("item was changed concurrently")


def test_second_conflict_propagates() -> None:
    blobs = _Blobs()
    repo = _AlwaysConflict()
    item = _with_revisions(3, blobs)
    repo.add(item)
    service = HistoryService(repo=repo, blobs=blobs, clock=FixedClock(T0 + 100 * H))
    with pytest.raises(ConflictError):
        service.prune_revisions(item.id)
    assert blobs.deleted == []


def test_post_commit_hook_runs_after_a_prune_only(caplog: pytest.LogCaptureFixture) -> None:
    calls: list[str] = []

    def boom() -> None:
        raise RuntimeError("secret text")

    env = _Env()
    env.service = HistoryService(
        repo=env.repo,
        blobs=env.blobs,
        clock=env.clock,
        post_commit=[boom, lambda: calls.append("compact")],
    )
    single = env.add(1)
    env.service.prune_revisions(single.id)  # nothing to prune: no compaction
    assert calls == []
    item = env.add(3, n=2)
    result = env.service.prune_revisions(item.id)  # a raising hook never fails the prune
    assert result.revisions_removed == 2
    assert calls == ["compact"]
    assert "RuntimeError" in caplog.text and "secret text" not in caplog.text


def test_blob_delete_failure_stays_committed_and_is_swept_later(
    caplog: pytest.LogCaptureFixture,
) -> None:
    env = _Env(fail=True)
    item = env.add(3)
    dropped_blobs = {f.blob_id for r in item.history for f in r.files}
    result = env.service.prune_revisions(item.id)
    assert result.revisions_removed == 2
    assert [r.number for r in env.repo.get(item.id).revisions] == [3]
    assert dropped_blobs <= env.blobs.list_ids()  # still on "disk"
    assert "could not delete blob" in caplog.text
    env.blobs.fail = False
    report = PurgeService(
        repo=env.repo,
        blobs=env.blobs,
        clock=env.clock,
        retention=timedelta(days=14),
        orphan_grace=H,
    ).run()
    assert report.orphans_deleted == len(dropped_blobs)
    assert not dropped_blobs & env.blobs.list_ids()
    assert env.blobs.open(item.files[0].blob_id).read() == b"v3"
