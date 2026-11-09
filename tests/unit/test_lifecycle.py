"""Unit tests for LifecycleService: update, pin/unpin, trash/restore transitions and idempotency."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta

import pytest

from preview_dashboard.application import LifecycleService
from preview_dashboard.domain.errors import (
    ConflictError,
    InvalidStateError,
    NotFoundError,
    SecretDetectedError,
    ValidationError,
)
from preview_dashboard.domain.models import Item, ItemId, ItemState
from tests.builders import T0, make_item, ulid
from tests.fakes import FAKE_SECRET, FakeContentScanner, FixedClock, InMemoryItemRepository

pytestmark = pytest.mark.unit

US = timedelta(microseconds=1)


Env = tuple[LifecycleService, InMemoryItemRepository, FixedClock]


@pytest.fixture
def env() -> Env:
    repo = InMemoryItemRepository()
    clock = FixedClock(T0 + timedelta(hours=1))
    service = LifecycleService(repo=repo, clock=clock, scanner=FakeContentScanner())
    repo.add(make_item(1))
    return service, repo, clock


def test_update_changes_fields_and_timestamp(env: Env) -> None:
    service, repo, clock = env
    updated = service.update(ulid(1), title="New", description="D", pinned=True)
    assert (updated.title, updated.description, updated.pinned) == ("New", "D", True)
    assert updated.updated_at == clock.now()
    assert repo.get(updated.id) == updated


def test_update_partial_keeps_other_fields(env: Env) -> None:
    service, _, _ = env
    updated = service.update(ulid(1), pinned=True)
    assert updated.title == "Item 1"
    assert updated.pinned


def test_update_with_nothing_is_noop(env: Env) -> None:
    service, repo, _ = env
    before = repo.get(ItemId(ulid(1)))
    assert service.update(ulid(1)) == before


def test_update_trashed_item_rejected(env: Env) -> None:
    service, _, _ = env
    service.trash(ulid(1))
    with pytest.raises(InvalidStateError):
        service.update(ulid(1), title="x")


def test_update_invalid_title_rejected(env: Env) -> None:
    service, _, _ = env
    with pytest.raises(ValidationError):
        service.update(ulid(1), title="   ")


def test_update_secret_rejected(env: Env) -> None:
    service, repo, _ = env
    with pytest.raises(SecretDetectedError):
        service.update(ulid(1), title="x " + FAKE_SECRET.decode())
    assert repo.get(ItemId(ulid(1))).title == "Item 1"


def test_trash_then_restore(env: Env) -> None:
    service, repo, clock = env
    trashed = service.trash(ulid(1))
    assert trashed.state is ItemState.TRASHED
    assert trashed.trashed_at == clock.now()
    clock.advance(timedelta(days=1))
    restored = service.restore(ulid(1))
    assert restored.state is ItemState.ACTIVE
    assert restored.trashed_at is None
    assert restored.updated_at == clock.now()
    assert repo.get(restored.id) == restored


def test_trash_is_idempotent(env: Env) -> None:
    service, repo, clock = env
    first = service.trash(ulid(1))
    clock.advance(timedelta(hours=1))
    again = service.trash(ulid(1))
    assert again == first  # trashed_at not bumped: retention isn't extended
    assert repo.get(first.id) == first


def test_restore_active_is_idempotent(env: Env) -> None:
    service, repo, _ = env
    before = repo.get(ItemId(ulid(1)))
    assert service.restore(ulid(1)) == before


def test_clock_behind_is_clamped(env: Env) -> None:
    service, _, clock = env
    clock.set(T0 - timedelta(days=5))  # NTP step back
    trashed = service.trash(ulid(1))
    # Never at or before the item's last change: updated_at is the version.
    assert trashed.trashed_at == T0 + US
    restored = service.restore(ulid(1))
    assert restored.updated_at == T0 + 2 * US


def test_every_transition_strictly_increases_updated_at(env: Env) -> None:
    service, _, clock = env
    clock.set(T0)  # frozen at the item's own timestamp
    stamps = [
        service.update(ulid(1), title="a").updated_at,
        service.update(ulid(1), pinned=True).updated_at,
        service.trash(ulid(1)).updated_at,
        service.restore(ulid(1)).updated_at,
    ]
    assert stamps == sorted(set(stamps))
    assert stamps[0] > T0


# --- optimistic concurrency (docs/security.md C11) -------------------------------------


class _RacingRepo(InMemoryItemRepository):
    """Runs `interleave` after the n-th `get`, as if another process wrote meanwhile."""

    def __init__(self) -> None:
        super().__init__()
        self.interleave: dict[int, Callable[[], None]] = {}
        self.gets = 0

    def get(self, item_id: ItemId) -> Item:
        item = super().get(item_id)
        self.gets += 1
        action = self.interleave.pop(self.gets, None)
        if action is not None:
            action()
        return item


def _racing_env() -> tuple[LifecycleService, _RacingRepo]:
    repo = _RacingRepo()
    repo.add(make_item(1))
    clock = FixedClock(T0 + timedelta(hours=1))
    return LifecycleService(repo=repo, clock=clock, scanner=FakeContentScanner()), repo


def _other_write(repo: _RacingRepo, change: Callable[[Item], Item]) -> Callable[[], None]:
    """A write by "another process" (bypasses the interleaving hook)."""

    def run() -> None:
        current = InMemoryItemRepository.get(repo, ItemId(ulid(1)))
        repo.save(change(current), expected_updated_at=current.updated_at)

    return run


def test_update_conflict_raises_and_keeps_other_write() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(
        repo, lambda i: i.with_metadata(now=i.updated_at + US, title="theirs")
    )
    with pytest.raises(ConflictError):
        service.update(ulid(1), title="mine")
    assert repo.get(ItemId(ulid(1))).title == "theirs"


def test_trash_retries_once_after_concurrent_edit() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(
        repo, lambda i: i.with_metadata(now=i.updated_at + US, title="theirs")
    )
    trashed = service.trash(ulid(1))
    assert trashed.state is ItemState.TRASHED
    assert trashed.title == "theirs"  # the concurrent edit is not lost
    assert repo.get(trashed.id) == trashed


def test_trash_retry_is_noop_when_other_writer_already_trashed() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(repo, lambda i: i.trashed(i.updated_at + US))
    trashed = service.trash(ulid(1))
    # The other writer's trash stands; trashed_at is not re-stamped.
    assert trashed == repo.get(ItemId(ulid(1)))
    assert trashed.trashed_at == T0 + US


def test_restore_retries_once_after_concurrent_change() -> None:
    service, repo = _racing_env()
    item = InMemoryItemRepository.get(repo, ItemId(ulid(1)))
    trashed = item.trashed(item.updated_at + US)
    repo.save(trashed, expected_updated_at=item.updated_at)
    # Another writer edits the trashed item's state between our read and save.
    repo.interleave[1] = _other_write(repo, lambda i: i.restored(i.updated_at + US))
    restored = service.restore(ulid(1))
    assert restored.state is ItemState.ACTIVE
    assert repo.get(restored.id) == restored


def test_second_conflict_propagates() -> None:
    service, repo = _racing_env()
    bump = _other_write(repo, lambda i: i.with_metadata(now=i.updated_at + US, pinned=True))
    bump2 = _other_write(repo, lambda i: i.with_metadata(now=i.updated_at + US, pinned=False))
    repo.interleave[1] = bump
    repo.interleave[2] = bump2
    with pytest.raises(ConflictError):
        service.trash(ulid(1))
    assert repo.get(ItemId(ulid(1))).state is ItemState.ACTIVE


def test_restore_of_item_purged_meanwhile_is_not_found() -> None:
    service, repo = _racing_env()
    item = InMemoryItemRepository.get(repo, ItemId(ulid(1)))
    repo.save(item.trashed(item.updated_at + US), expected_updated_at=item.updated_at)

    def purge() -> None:
        repo.delete(ItemId(ulid(1)))

    repo.interleave[1] = purge
    with pytest.raises(NotFoundError):
        service.restore(ulid(1))


@pytest.mark.parametrize("op", ["trash", "restore", "update"])
def test_unknown_and_malformed_ids(env: Env, op: str) -> None:
    service, _, _ = env
    with pytest.raises(NotFoundError):
        getattr(service, op)(ulid(42))
    with pytest.raises(ValidationError):
        getattr(service, op)("../../etc")


# --- set_pinned (the viewer's pin/unpin, backlog R2) ----------------------------------


def test_set_pinned_pins_and_unpins(env: Env) -> None:
    service, repo, clock = env
    pinned = service.set_pinned(ulid(1), pinned=True)
    assert pinned.pinned
    assert pinned.updated_at == clock.now()
    assert repo.get(pinned.id) == pinned
    clock.advance(timedelta(seconds=1))
    unpinned = service.set_pinned(ulid(1), pinned=False)
    assert not unpinned.pinned
    assert unpinned.updated_at > pinned.updated_at
    assert (unpinned.title, unpinned.description) == (pinned.title, pinned.description)
    assert repo.get(unpinned.id) == unpinned


@pytest.mark.parametrize("pinned", [True, False])
def test_set_pinned_is_idempotent_without_a_write(env: Env, pinned: bool) -> None:
    service, repo, clock = env
    first = service.set_pinned(ulid(1), pinned=pinned)
    clock.advance(timedelta(seconds=1))
    # A repeat returns the stored item unchanged: no updated_at bump (the
    # feed's ETag stays stable for polling clients).
    assert service.set_pinned(ulid(1), pinned=pinned) == first
    assert repo.get(first.id) == first


@pytest.mark.parametrize("stored_pin", [True, False])
@pytest.mark.parametrize("pinned", [True, False])
def test_set_pinned_refuses_trashed_items(stored_pin: bool, pinned: bool) -> None:
    repo = InMemoryItemRepository()
    clock = FixedClock(T0 + timedelta(hours=1))
    service = LifecycleService(repo=repo, clock=clock, scanner=FakeContentScanner())
    item = make_item(1)
    if stored_pin:
        item = item.with_metadata(now=item.updated_at + US, pinned=True)
    trashed = item.trashed(item.updated_at + US)
    repo.add(trashed)
    # Refused whatever the stored flag: the answer never depends on it.
    with pytest.raises(InvalidStateError):
        service.set_pinned(ulid(1), pinned=pinned)
    assert repo.get(trashed.id) == trashed


def test_set_pinned_retries_once_after_concurrent_edit() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(
        repo, lambda i: i.with_metadata(now=i.updated_at + US, title="theirs")
    )
    pinned = service.set_pinned(ulid(1), pinned=True)
    assert pinned.pinned
    assert pinned.title == "theirs"  # the concurrent edit is not lost
    assert repo.get(pinned.id) == pinned


def test_set_pinned_retry_is_noop_when_other_writer_already_pinned() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(
        repo, lambda i: i.with_metadata(now=i.updated_at + US, pinned=True)
    )
    pinned = service.set_pinned(ulid(1), pinned=True)
    assert pinned == repo.get(ItemId(ulid(1)))
    assert pinned.updated_at == T0 + US  # not re-stamped


def test_set_pinned_after_concurrent_trash_is_invalid_state() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(repo, lambda i: i.trashed(i.updated_at + US))
    with pytest.raises(InvalidStateError):
        service.set_pinned(ulid(1), pinned=True)
    stored = repo.get(ItemId(ulid(1)))
    assert stored.state is ItemState.TRASHED
    assert not stored.pinned


def test_set_pinned_second_conflict_propagates() -> None:
    service, repo = _racing_env()
    repo.interleave[1] = _other_write(
        repo, lambda i: i.with_metadata(now=i.updated_at + US, title="a")
    )
    repo.interleave[2] = _other_write(
        repo, lambda i: i.with_metadata(now=i.updated_at + US, title="b")
    )
    with pytest.raises(ConflictError):
        service.set_pinned(ulid(1), pinned=True)
    assert not repo.get(ItemId(ulid(1))).pinned


@pytest.mark.parametrize("pinned", [True, False])
def test_set_pinned_unknown_and_malformed_ids(env: Env, pinned: bool) -> None:
    service, _, _ = env
    with pytest.raises(NotFoundError):
        service.set_pinned(ulid(42), pinned=pinned)
    with pytest.raises(ValidationError):
        service.set_pinned("../../etc", pinned=pinned)
