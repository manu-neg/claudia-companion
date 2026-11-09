"""Unit tests for PurgeService: retention boundary, row-before-blob order, orphan sweep.

The sweep's snapshot-then-references order and the grace period are what
keep it from racing an in-flight publish (docs/security.md C11).
"""

from __future__ import annotations

import builtins
from datetime import datetime, timedelta

import pytest

from preview_dashboard.application import PurgeReport, PurgeService
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import Item, ItemId
from tests.builders import T0, make_file, make_item, ulid
from tests.fakes import FixedClock, InMemoryBlobStore, InMemoryItemRepository

pytestmark = pytest.mark.unit

RETENTION = timedelta(days=14)
GRACE = timedelta(hours=1)


class _Log:
    def __init__(self) -> None:
        self.calls: list[str] = []


class RecordingRepo(InMemoryItemRepository):
    def __init__(self, log: _Log) -> None:
        super().__init__()
        self._log = log

    def delete(self, item_id: ItemId) -> bool:
        self._log.calls.append(f"repo.delete:{item_id}")
        return super().delete(item_id)

    def delete_if_purgeable(self, item_id: ItemId, cutoff: datetime) -> Item | None:
        self._log.calls.append(f"repo.delete:{item_id}")
        return super().delete_if_purgeable(item_id, cutoff)

    def all_blob_ids(self) -> set[str]:
        self._log.calls.append("repo.all_blob_ids")
        return super().all_blob_ids()

    def list_purgeable(self, now: datetime, retention: timedelta) -> builtins.list[Item]:
        self._log.calls.append("repo.list_purgeable")
        return super().list_purgeable(now, retention)


class RecordingBlobs(InMemoryBlobStore):
    def __init__(self, log: _Log, clock: FixedClock) -> None:
        super().__init__(clock=clock)
        self._log = log

    def delete(self, blob_id: str) -> None:
        self._log.calls.append(f"blobs.delete:{blob_id}")
        super().delete(blob_id)

    def list_ids(self, created_before: datetime | None = None) -> set[str]:
        self._log.calls.append("blobs.list_ids")
        return super().list_ids(created_before)


class Env:
    def __init__(self, **kwargs: object) -> None:
        self.log = _Log()
        self.clock = FixedClock(T0)
        self.repo = RecordingRepo(self.log)
        self.blobs = RecordingBlobs(self.log, self.clock)
        self.service = PurgeService(
            repo=self.repo,
            blobs=self.blobs,
            clock=self.clock,
            retention=RETENTION,
            orphan_grace=GRACE,
            **kwargs,  # type: ignore[arg-type]
        )

    def stored_item(self, n: int, *, files: int = 1, trashed_at: datetime | None = None) -> Item:
        refs = [self.blobs.put([f"{n}-{k}".encode()], max_bytes=100) for k in range(files)]
        item = make_item(
            n,
            files=tuple(
                make_file(f"f{k}.txt", blob_id=r.blob_id, size=r.size, sha256=r.sha256)
                for k, r in enumerate(refs)
            ),
            entry_file="f0.txt",
        )
        if trashed_at is not None:
            item = item.trashed(trashed_at)
        self.repo.add(item)
        return item


@pytest.fixture
def env() -> Env:
    return Env()


def test_purges_only_expired_trash_boundary_inclusive(env: Env) -> None:
    active = env.stored_item(1)
    due = env.stored_item(2, files=2, trashed_at=T0)
    young = env.stored_item(3, trashed_at=T0 + timedelta(microseconds=1))
    report = env.service.run(now=T0 + RETENTION)
    assert report == PurgeReport(items_purged=1, blobs_deleted=2, orphans_deleted=0)
    assert env.repo.all_blob_ids() == {f.blob_id for i in (active, young) for f in i.files}
    assert env.blobs.list_ids() == env.repo.all_blob_ids()
    assert due.id not in {i.id for i in env.repo._items.values()}


def test_row_is_deleted_before_its_blobs(env: Env) -> None:
    item = env.stored_item(1, files=2, trashed_at=T0)
    env.service.run(now=T0 + RETENTION)
    row = env.log.calls.index(f"repo.delete:{item.id}")
    for f in item.files:
        assert row < env.log.calls.index(f"blobs.delete:{f.blob_id}")


def test_sweep_snapshots_blobs_before_reading_references(env: Env) -> None:
    env.service.run(now=T0 + timedelta(days=1))
    calls = [c for c in env.log.calls if c in ("blobs.list_ids", "repo.all_blob_ids")]
    assert calls == ["blobs.list_ids", "repo.all_blob_ids"]


def test_uncommitted_blob_within_grace_is_kept(env: Env) -> None:
    # A publish has stored its blob but not committed the row yet.
    ref = env.blobs.put([b"in flight"], max_bytes=100)
    env.clock.advance(GRACE - timedelta(seconds=1))
    assert env.service.run().orphans_deleted == 0
    assert ref.blob_id in env.blobs.list_ids()


def test_orphan_older_than_grace_is_deleted(env: Env) -> None:
    ref = env.blobs.put([b"orphan"], max_bytes=100)
    kept = env.stored_item(1)
    env.clock.advance(GRACE + timedelta(seconds=1))
    report = env.service.run()
    assert report.orphans_deleted == 1
    assert env.blobs.list_ids() == {kept.files[0].blob_id}
    assert ref.blob_id not in env.blobs.list_ids()


def test_referenced_old_blobs_are_never_swept(env: Env) -> None:
    a = env.stored_item(1)
    b = env.stored_item(2, trashed_at=T0)
    env.clock.advance(timedelta(days=13))
    report = env.service.run()
    assert report.orphans_deleted == 0
    assert env.blobs.list_ids() == {a.files[0].blob_id, b.files[0].blob_id}


def test_commit_racing_the_sweep_is_safe(env: Env) -> None:
    # Publish commits between the snapshot and the reference read: the
    # blob is in the snapshot but also referenced -> kept.
    ref = env.blobs.put([b"late commit"], max_bytes=100)
    env.clock.advance(GRACE * 2)
    original_list_ids = env.blobs.list_ids

    def list_then_commit(created_before: datetime | None = None) -> set[str]:
        snapshot = original_list_ids(created_before)
        env.repo.add(
            make_item(7, files=(make_file(blob_id=ref.blob_id, size=ref.size, sha256=ref.sha256),))
        )
        return snapshot

    env.blobs.list_ids = list_then_commit  # type: ignore[method-assign]
    assert env.service.run().orphans_deleted == 0
    assert ref.blob_id in original_list_ids()


def test_restore_between_listing_and_delete_is_not_purged(env: Env) -> None:
    item = env.stored_item(1, trashed_at=T0)
    original = env.repo.list_purgeable

    def list_then_restore(now: datetime, retention: timedelta) -> list[Item]:
        due = original(now, retention)
        current = env.repo.get(item.id)
        env.repo.save(current.restored(now), expected_updated_at=current.updated_at)
        return due

    env.repo.list_purgeable = list_then_restore  # type: ignore[method-assign]
    report = env.service.run(now=T0 + RETENTION)
    assert report.items_purged == 0
    assert env.repo.get(item.id).trashed_at is None
    assert item.files[0].blob_id in env.blobs.list_ids()


def test_shared_blob_still_referenced_is_kept(env: Env) -> None:
    item = env.stored_item(1, trashed_at=T0)
    shared = item.files[0]
    env.repo.add(make_item(2, files=(shared,), entry_file=shared.relpath))
    report = env.service.run(now=T0 + RETENTION)
    assert report.items_purged == 1
    assert report.blobs_deleted == 0
    assert shared.blob_id in env.blobs.list_ids()


def test_run_is_idempotent(env: Env) -> None:
    env.stored_item(1, trashed_at=T0)
    env.blobs.put([b"orphan"], max_bytes=100)
    now = T0 + RETENTION + GRACE * 2
    first = env.service.run(now=now)
    assert (first.items_purged, first.orphans_deleted) == (1, 1)
    assert env.service.run(now=now) == PurgeReport(
        items_purged=0, blobs_deleted=0, orphans_deleted=0
    )


def test_crash_between_row_and_blob_delete_is_recovered_by_sweep(env: Env) -> None:
    item = env.stored_item(1, trashed_at=T0)
    env.repo.delete(item.id)  # "crashed" right after the row delete
    report = env.service.run(now=T0 + GRACE * 2)
    assert report.orphans_deleted == 1
    assert env.blobs.list_ids() == set()


def test_defaults_now_to_clock(env: Env) -> None:
    env.stored_item(1, trashed_at=T0)
    env.clock.advance(RETENTION)
    assert env.service.run().items_purged == 1


def test_maintenance_hooks_run_and_are_reported() -> None:
    calls: list[str] = []

    def staging() -> int:
        calls.append("staging")
        return 3

    e = Env(maintenance={"staging": staging})
    report = e.service.run()
    assert calls == ["staging"]
    assert report.maintenance == {"staging": 3}


def test_voice_2_a_failing_maintenance_hook_does_not_stop_the_run() -> None:
    def bad() -> int:
        raise PermissionError("unreadable")

    e = Env(maintenance={"bad": bad, "ok": lambda: 3})
    report = e.service.run()  # must not raise
    assert report.maintenance == {"bad": 0, "ok": 3}
    assert report.inbox_failed is False and report.questions_failed is False


@pytest.mark.parametrize("field", ["retention", "orphan_grace"])
def test_invalid_durations_rejected(field: str) -> None:
    durations = {"retention": RETENTION, "orphan_grace": GRACE, field: timedelta(0)}
    with pytest.raises(ValueError):
        PurgeService(
            repo=InMemoryItemRepository(),
            blobs=InMemoryBlobStore(),
            clock=FixedClock(),
            retention=durations["retention"],
            orphan_grace=durations["orphan_grace"],
        )


def test_item_ids_used_for_deletes_only_come_from_the_repo(env: Env) -> None:
    # Purge deletes by DB ids only (C25): nothing else is ever deleted.
    env.stored_item(1, trashed_at=T0)
    env.service.run(now=T0 + RETENTION)
    deleted = [c.split(":", 1)[1] for c in env.log.calls if c.startswith("repo.delete:")]
    assert deleted == [ulid(1)]


def test_post_purge_hooks_only_run_when_items_were_purged() -> None:
    calls: list[str] = []
    e = Env(post_purge=[lambda: calls.append("compact")])
    e.stored_item(1, trashed_at=T0)
    e.service.run(now=T0 + RETENTION - timedelta(seconds=1))  # nothing due
    assert calls == []
    e.blobs.put([b"orphan"], max_bytes=100)
    e.clock.advance(GRACE * 2)
    e.service.run(now=T0 + GRACE * 2)  # orphans only: still no compaction
    assert calls == []
    e.service.run(now=T0 + RETENTION)
    assert calls == ["compact"]


def test_post_purge_runs_after_rows_and_blobs_are_gone() -> None:
    seen: list[tuple[int, int]] = []
    e = Env()
    e.stored_item(1, trashed_at=T0)
    service = PurgeService(
        repo=e.repo,
        blobs=e.blobs,
        clock=e.clock,
        retention=RETENTION,
        orphan_grace=GRACE,
        post_purge=[lambda: seen.append((e.repo.count(), len(e.blobs.list_ids())))],
    )
    service.run(now=T0 + RETENTION)
    assert seen == [(0, 0)]


def test_post_purge_hook_return_value_is_ignored() -> None:
    # SqliteItemRepository.compact() returns a bool; the hook type accepts it.
    def compact() -> bool:
        return False

    e = Env(post_purge=[compact])
    e.stored_item(1, trashed_at=T0)
    assert e.service.run(now=T0 + RETENTION).items_purged == 1


@pytest.mark.parametrize("field", ["retention", "orphan_grace"])
def test_cutoff_overflow_is_a_validation_error(field: str) -> None:
    e = Env()
    huge = timedelta(days=999_999_999)
    service = PurgeService(
        repo=e.repo,
        blobs=e.blobs,
        clock=e.clock,
        retention=huge if field == "retention" else RETENTION,
        orphan_grace=huge if field == "orphan_grace" else GRACE,
    )
    item = e.stored_item(1, trashed_at=T0)
    with pytest.raises(ValidationError, match="out of range"):
        service.run(now=T0 + RETENTION)
    assert e.repo.get(item.id) == item  # fails closed: nothing deleted
    assert not [c for c in e.log.calls if "delete" in c]
