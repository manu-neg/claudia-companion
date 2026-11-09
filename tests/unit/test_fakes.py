"""Unit tests for fake-only behavior (clock control, id sequence, capacity).

Port behavior shared with real adapters is covered by the contract suites
in `tests/unit/test_fake_contracts.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from preview_dashboard.domain.errors import LimitExceededError, ValidationError
from preview_dashboard.domain.models import ItemState, is_ulid
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.repository import ItemRepository
from tests.builders import T0, make_item
from tests.fakes import (
    DEFAULT_START,
    FixedClock,
    InMemoryBlobStore,
    InMemoryItemRepository,
    SequentialIdGenerator,
)

pytestmark = pytest.mark.unit


def test_fakes_satisfy_ports_statically() -> None:
    # Assignments are checked by mypy against the Protocols.
    clock: Clock = FixedClock()
    ids: IdGenerator = SequentialIdGenerator()
    repo: ItemRepository = InMemoryItemRepository()
    store: BlobStore = InMemoryBlobStore(clock=clock, ids=ids)
    del clock, ids, repo, store


def test_fixed_clock_advance_and_set() -> None:
    clock = FixedClock()
    assert clock.now() == DEFAULT_START
    assert clock.now().tzinfo == UTC
    assert clock.advance(timedelta(days=1)) == DEFAULT_START + timedelta(days=1)
    target = datetime(2030, 5, 5, tzinfo=UTC)
    clock.set(target)
    assert clock.now() == target
    with pytest.raises(ValidationError):
        clock.set(datetime(2030, 5, 5))


def test_sequential_ids_are_unique_ulids() -> None:
    ids = SequentialIdGenerator()
    generated = [ids.new_item_id(), ids.new_blob_id(), ids.new_item_id()]
    assert generated == ["0" * 25 + "1", "0" * 25 + "2", "0" * 25 + "3"]
    assert all(is_ulid(i) for i in generated)


def test_blob_store_uses_injected_clock_and_capacity() -> None:
    clock = FixedClock(T0)
    store = InMemoryBlobStore(capacity_bytes=10, clock=clock)
    old = store.put([b"abcd"], max_bytes=10)
    clock.advance(timedelta(hours=1))
    new = store.put([b"ef"], max_bytes=10)
    assert store.list_ids(created_before=T0 + timedelta(minutes=30)) == {old.blob_id}
    assert store.list_ids() == {old.blob_id, new.blob_id}
    assert store.free_bytes() == 4


def test_blob_store_capacity_is_enforced() -> None:
    store = InMemoryBlobStore(capacity_bytes=3)
    store.put([b"abc"], max_bytes=3)
    assert store.free_bytes() == 0
    with pytest.raises(LimitExceededError, match="full"):
        store.put([b"d"], max_bytes=1)
    assert store.put([], max_bytes=0).size == 0  # empty blobs still fit


def test_repository_count_helper() -> None:
    repo = InMemoryItemRepository()
    repo.add(make_item(1))
    repo.add(make_item(2).trashed(T0))
    assert repo.count() == 2
    assert repo.count(ItemState.TRASHED) == 1
