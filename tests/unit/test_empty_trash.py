"""Tests for `PurgeService.empty_trash` (ADR 0030, docs/security.md C43).

All trash goes now, active items never; rows before blobs; a mid-run restore
survives; failed blob deletes are left to the sweep.
"""

from __future__ import annotations

import builtins
from datetime import timedelta

import pytest

from preview_dashboard.application import PurgeReport
from preview_dashboard.domain.models import Item, ItemFile, ItemId
from preview_dashboard.domain.query import ItemQuery, Page
from tests.builders import T0
from tests.unit.test_purge import Env

pytestmark = pytest.mark.unit

H = timedelta(hours=1)


def test_empties_every_trashed_item_regardless_of_retention() -> None:
    env = Env()
    active = env.stored_item(1)
    fresh = env.stored_item(2, files=2, trashed_at=T0)
    old = env.stored_item(3, trashed_at=T0)
    report = env.service.empty_trash()
    assert report == PurgeReport(items_purged=2, blobs_deleted=3, orphans_deleted=0)
    assert [i.id for i in env.repo.snapshot()] == [active.id]
    assert env.blobs.list_ids() == {f.blob_id for f in active.files}
    for gone in (fresh, old):
        assert gone.id not in {i.id for i in env.repo.snapshot()}


def test_rows_go_before_their_blobs() -> None:
    env = Env()
    item = env.stored_item(1, files=2, trashed_at=T0)
    env.service.empty_trash()
    row = env.log.calls.index(f"repo.delete:{item.id}")
    for f in item.files:
        assert row < env.log.calls.index(f"blobs.delete:{f.blob_id}")


def test_every_revision_of_a_trashed_item_is_deleted() -> None:
    env = Env()
    item = env.stored_item(1)
    ref = env.blobs.put([b"v2"], max_bytes=10)
    revised, _ = item.with_revision(
        kind="html",
        files=(ItemFile.from_blob("index.html", ref, "text/html"),),
        entry_file="index.html",
        at=T0 + H,
    )
    env.repo.save(revised.trashed(T0 + 2 * H), expected_updated_at=item.updated_at)
    report = env.service.empty_trash()
    assert (report.items_purged, report.blobs_deleted) == (1, 2)
    assert env.blobs.list_ids() == set()


def test_empty_trash_is_idempotent_and_no_op_without_trash() -> None:
    hooks: list[str] = []
    env = Env(post_purge=[lambda: hooks.append("compact")])
    env.stored_item(1)
    assert env.service.empty_trash() == PurgeReport(
        items_purged=0, blobs_deleted=0, orphans_deleted=0
    )
    assert hooks == []
    env.stored_item(2, trashed_at=T0)
    assert env.service.empty_trash().items_purged == 1
    assert hooks == ["compact"]
    assert env.service.empty_trash().items_purged == 0
    assert hooks == ["compact"]


class _RestoreRace(Env):
    """The owner restores (or restores + re-trashes) an item right after the listing."""

    def __init__(self, *, retrash: bool) -> None:
        super().__init__()
        self.retrash = retrash
        self.victim: ItemId | None = None
        original = self.repo.list

        def racing_list(query: ItemQuery) -> Page[Item]:
            page = original(query)
            if self.victim is not None:
                current = self.repo.get(self.victim)
                restored = current.restored(current.next_change_at(T0 + H))
                if self.retrash:
                    restored = restored.trashed(restored.next_change_at(T0 + 2 * H))
                self.repo.save(restored, expected_updated_at=current.updated_at)
                self.victim = None
            return page

        self.repo.list = racing_list  # type: ignore[method-assign]


@pytest.mark.parametrize("retrash", [False, True])
def test_item_restored_mid_run_is_not_deleted(retrash: bool) -> None:
    env = _RestoreRace(retrash=retrash)
    kept = env.stored_item(1, trashed_at=T0)
    gone = env.stored_item(2, trashed_at=T0)
    env.victim = kept.id
    report = env.service.empty_trash()
    assert report.items_purged == 1
    survivor = env.repo.get(kept.id)
    assert survivor.state.value == ("trashed" if retrash else "active")
    assert {f.blob_id for f in survivor.files} <= env.blobs.list_ids()
    assert gone.id not in {i.id for i in env.repo.snapshot()}


def test_blob_still_referenced_elsewhere_is_kept() -> None:
    env = Env()
    item = env.stored_item(1, trashed_at=T0)
    original = env.repo.all_blob_ids

    def also_referenced() -> set[str]:
        return original() | {item.files[0].blob_id}

    env.repo.all_blob_ids = also_referenced  # type: ignore[method-assign]
    report = env.service.empty_trash()
    assert (report.items_purged, report.blobs_deleted) == (1, 0)
    assert item.files[0].blob_id in env.blobs.list_ids()


def test_blob_delete_failure_is_logged_and_left_to_the_sweep(
    caplog: pytest.LogCaptureFixture,
) -> None:
    env = Env()
    item = env.stored_item(1, files=2, trashed_at=T0)
    original = env.blobs.delete
    calls: builtins.list[str] = []

    def failing(blob_id: str) -> None:
        calls.append(blob_id)
        raise OSError("disk says no")

    env.blobs.delete = failing  # type: ignore[method-assign]
    report = env.service.empty_trash()
    assert (report.items_purged, report.blobs_deleted) == (1, 0)
    assert len(calls) == 2
    assert "could not delete blob" in caplog.text
    env.blobs.delete = original  # type: ignore[method-assign]
    swept = env.service.run(now=T0 + 2 * H)
    assert swept.orphans_deleted == 2
    assert not {f.blob_id for f in item.files} & env.blobs.list_ids()


def test_reads_every_page_of_trash() -> None:
    env = Env()
    for n in range(1, 206):
        env.stored_item(n, trashed_at=T0 + timedelta(seconds=n))
    seen: builtins.list[str | None] = []
    original = env.repo.list

    def recording(query: ItemQuery) -> Page[Item]:
        seen.append(query.cursor)
        return original(query)

    env.repo.list = recording  # type: ignore[method-assign]
    assert env.service.empty_trash().items_purged == 205
    assert len(seen) == 2 and seen[0] is None
    assert env.repo.snapshot() == []


def test_never_touches_questions_or_maintenance() -> None:
    ran: builtins.list[str] = []

    def staging() -> int:
        ran.append("staging")
        return 0

    env = Env(maintenance={"staging": staging})
    env.stored_item(1, trashed_at=T0)
    report = env.service.empty_trash()
    assert ran == []
    assert report.maintenance == {}


def test_raising_post_purge_hook_is_contained(caplog: pytest.LogCaptureFixture) -> None:
    ran: builtins.list[str] = []

    def boom() -> None:
        raise RuntimeError("secret text")

    env = Env(post_purge=[boom, lambda: ran.append("second")])
    env.stored_item(1, trashed_at=T0)
    assert env.service.empty_trash().items_purged == 1
    assert ran == ["second"]  # a failing hook doesn't stop the next one
    assert "RuntimeError" in caplog.text and "secret text" not in caplog.text


def test_raising_post_purge_hook_does_not_fail_the_timed_run() -> None:
    def boom() -> None:
        raise OSError("busy")

    env = Env(post_purge=[boom])
    env.stored_item(1, trashed_at=T0)
    assert env.service.run(now=T0 + timedelta(days=30)).items_purged == 1
