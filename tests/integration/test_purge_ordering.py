"""Integration tests: PurgeService against the real FsBlobStore (docs/security.md C11, C25).

Proves the purge/sweep protocol with real filesystem timestamps: expired
trash loses its row and blobs, a fresh unreferenced blob (in-flight
publish) survives the grace period, and the staging sweep runs as an
injected maintenance hook without the core knowing about staging files.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.application import PurgeService
from preview_dashboard.domain.models import Item
from tests.builders import make_file, make_item
from tests.fakes import InMemoryItemRepository

pytestmark = pytest.mark.integration

RETENTION = timedelta(days=14)
GRACE = timedelta(hours=1)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[FsBlobStore]:
    with FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock()) as s:
        yield s


def _service(repo: InMemoryItemRepository, store: FsBlobStore) -> PurgeService:
    return PurgeService(
        repo=repo,
        blobs=store,
        clock=SystemClock(),
        retention=RETENTION,
        orphan_grace=GRACE,
        maintenance={"staging": lambda: store.sweep_staging(older_than=GRACE)},
    )


def _stored_item(repo: InMemoryItemRepository, store: FsBlobStore, n: int) -> Item:
    ref = store.put([b"content %d" % n], max_bytes=100)
    item = make_item(
        n,
        files=(make_file("a.txt", blob_id=ref.blob_id, size=ref.size, sha256=ref.sha256),),
        entry_file="a.txt",
    )
    repo.add(item)
    return item


def test_expired_trash_row_and_blob_removed(store: FsBlobStore, tmp_path: Path) -> None:
    repo = InMemoryItemRepository()
    now = SystemClock().now()
    keep = _stored_item(repo, store, 1)
    doomed = _stored_item(repo, store, 2)
    repo.save(doomed.trashed(max(now, doomed.updated_at)), expected_updated_at=doomed.updated_at)
    report = _service(repo, store).run(now=now + RETENTION + timedelta(seconds=1))
    assert (report.items_purged, report.blobs_deleted) == (1, 1)
    assert store.list_ids() == {keep.files[0].blob_id}


def test_fresh_unreferenced_blob_survives_grace_then_goes(store: FsBlobStore) -> None:
    repo = InMemoryItemRepository()
    in_flight = store.put([b"not committed yet"], max_bytes=100)
    now = SystemClock().now()
    service = _service(repo, store)
    assert service.run(now=now).orphans_deleted == 0
    assert in_flight.blob_id in store.list_ids()
    assert service.run(now=now + GRACE + timedelta(seconds=5)).orphans_deleted == 1
    assert store.list_ids() == set()


def test_staging_sweep_runs_as_maintenance_hook(store: FsBlobStore, tmp_path: Path) -> None:
    staging = tmp_path / "data" / "staging"
    leftover = staging / f"{UlidGenerator().new_blob_id()}.part"
    leftover.write_bytes(b"crashed mid-write")
    old = SystemClock().now().timestamp() - GRACE.total_seconds() - 60
    os.utime(leftover, (old, old))
    report = _service(InMemoryItemRepository(), store).run()
    assert report.maintenance == {"staging": 1}
    assert not leftover.exists()
