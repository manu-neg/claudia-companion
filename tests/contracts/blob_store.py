"""Contract test suite for the BlobStore port.

Subclass `BlobStoreContract` in a `test_*.py` module and override the
`store` fixture to return a fresh, empty store. Runs unchanged against the
in-memory fake and the filesystem adapter.

Optional fixture hooks (default: the dependent tests are skipped):
- `outside_sentinel` -> `Path`: a file *outside* the store's root (the
  store under test must be the one from `store`). Traversal-shaped ids must
  never open or delete it. Name it like a canonical ULID to also catch
  adapters that join an id onto the wrong base directory.
- `store_with_capacity` -> `Callable[[int], BlobStore]`: builds a fresh store
  that can hold at most N bytes in total (simulated disk full / ENOSPC).
"""

from __future__ import annotations

import hashlib
import itertools
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from preview_dashboard.domain.errors import LimitExceededError, NotFoundError
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.ports.blobstore import BlobStore

FAR_PAST = datetime(2000, 1, 1, tzinfo=UTC)
FAR_FUTURE = datetime(2100, 1, 1, tzinfo=UTC)
MALFORMED_IDS = [
    "",
    ".",
    "..",
    "../x",
    "../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "/abs/path",
    "a/b",
    "01arz3ndektsv4rrffq69g5fav",  # lowercase ULID
    "01ARZ3NDEKTSV4RRFFQ69G5FAV0",  # overlong
    "01ARZ3NDEKTSV4RRFFQ69G5FA",  # short
    "81ARZ3NDEKTSV4RRFFQ69G5FAV",  # > 128 bits
    "01ARZ3NDEKTSV4RRFFQ69G5FAV\n",
    "\uff10" * 26,  # fullwidth digits
    "X" * 26,
    "\x00" * 26,
]
CAPACITY = 1024


class _BoomError(Exception):
    pass


class BlobStoreContract:
    """Behavior every BlobStore implementation must have."""

    @pytest.fixture
    def store(self) -> BlobStore:
        raise NotImplementedError("override the `store` fixture in the concrete test class")

    @pytest.fixture
    def outside_sentinel(self) -> Path:
        pytest.skip("store has no filesystem root (override `outside_sentinel` to enable)")

    @pytest.fixture
    def store_with_capacity(self) -> Callable[[int], BlobStore]:
        pytest.skip("no disk-full simulation (override `store_with_capacity` to enable)")

    # --- put / open ----------------------------------------------------------

    def test_put_then_open_round_trips(self, store: BlobStore) -> None:
        ref = store.put([b"hello ", b"", b"world"], max_bytes=100)
        assert is_ulid(ref.blob_id)
        assert ref.size == 11
        assert ref.sha256 == hashlib.sha256(b"hello world").hexdigest()
        with store.open(ref.blob_id) as f:
            assert f.read() == b"hello world"

    def test_empty_blob(self, store: BlobStore) -> None:
        ref = store.put([], max_bytes=0)
        assert ref.size == 0
        assert ref.sha256 == hashlib.sha256(b"").hexdigest()
        with store.open(ref.blob_id) as f:
            assert f.read() == b""

    def test_open_stream_is_seekable(self, store: BlobStore) -> None:
        ref = store.put([b"0123456789"], max_bytes=10)
        with store.open(ref.blob_id) as f:
            assert f.seekable()
            f.seek(4)
            assert f.read(3) == b"456"

    def test_each_put_gets_a_new_id(self, store: BlobStore) -> None:
        a = store.put([b"same"], max_bytes=10)
        b = store.put([b"same"], max_bytes=10)
        assert a.blob_id != b.blob_id
        assert store.list_ids() == {a.blob_id, b.blob_id}

    def test_binary_content_is_preserved(self, store: BlobStore) -> None:
        data = bytes(range(256)) * 50
        ref = store.put([data[:1000], data[1000:]], max_bytes=len(data))
        with store.open(ref.blob_id) as f:
            assert f.read() == data

    # --- limits and atomicity ------------------------------------------------

    def test_put_exactly_max_bytes_is_allowed(self, store: BlobStore) -> None:
        assert store.put([b"12345"], max_bytes=5).size == 5

    def test_put_over_max_bytes_raises_and_leaves_nothing(self, store: BlobStore) -> None:
        with pytest.raises(LimitExceededError):
            store.put([b"123", b"456"], max_bytes=5)
        assert store.list_ids() == set()

    def test_put_stops_reading_once_limit_is_crossed(self, store: BlobStore) -> None:
        # An endless stream must not be buffered: the limit ends the read.
        with pytest.raises(LimitExceededError):
            store.put(itertools.repeat(b"x" * 1024), max_bytes=10 * 1024)
        assert store.list_ids() == set()

    def test_failing_source_propagates_and_leaves_nothing(self, store: BlobStore) -> None:
        def chunks() -> Iterator[bytes]:
            yield b"partial"
            raise _BoomError

        with pytest.raises(_BoomError):
            store.put(chunks(), max_bytes=100)
        assert store.list_ids() == set()

    def test_negative_max_bytes_is_rejected(self, store: BlobStore) -> None:
        with pytest.raises(ValueError, match="max_bytes"):
            store.put([b""], max_bytes=-1)

    # --- not found / delete --------------------------------------------------

    def test_open_unknown_id_raises_not_found(self, store: BlobStore) -> None:
        with pytest.raises(NotFoundError):
            store.open("0" * 26)

    @pytest.mark.parametrize("blob_id", MALFORMED_IDS)
    def test_open_malformed_id_raises_not_found(self, store: BlobStore, blob_id: str) -> None:
        with pytest.raises(NotFoundError):
            store.open(blob_id)

    def test_delete_is_idempotent(self, store: BlobStore) -> None:
        ref = store.put([b"x"], max_bytes=1)
        store.delete(ref.blob_id)
        store.delete(ref.blob_id)
        with pytest.raises(NotFoundError):
            store.open(ref.blob_id)
        assert store.list_ids() == set()

    @pytest.mark.parametrize("blob_id", MALFORMED_IDS)
    def test_delete_malformed_id_is_a_noop(self, store: BlobStore, blob_id: str) -> None:
        ref = store.put([b"x"], max_bytes=1)
        store.delete(blob_id)
        assert store.list_ids() == {ref.blob_id}

    def test_delete_leaves_other_blobs(self, store: BlobStore) -> None:
        a = store.put([b"a"], max_bytes=1)
        b = store.put([b"b"], max_bytes=1)
        store.delete(a.blob_id)
        assert store.list_ids() == {b.blob_id}

    # --- listing / capacity --------------------------------------------------

    def test_list_ids_created_before(self, store: BlobStore) -> None:
        ref = store.put([b"x"], max_bytes=1)
        assert store.list_ids(created_before=FAR_FUTURE) == {ref.blob_id}
        assert store.list_ids(created_before=FAR_PAST) == set()

    def test_free_bytes_is_non_negative_int(self, store: BlobStore) -> None:
        free = store.free_bytes()
        assert isinstance(free, int)
        assert free >= 0

    def test_list_ids_returns_only_canonical_ulids(self, store: BlobStore) -> None:
        store.put([b"x"], max_bytes=1)
        assert all(is_ulid(i) for i in store.list_ids())

    # --- confinement (optional: filesystem-backed stores) ----------------------

    def test_malformed_ids_never_reach_files_outside_the_store(
        self, store: BlobStore, outside_sentinel: Path
    ) -> None:
        original = outside_sentinel.read_bytes()
        name = outside_sentinel.name
        ids = [
            *MALFORMED_IDS,
            str(outside_sentinel),
            f"/{name}",
            *(("../" * depth) + name for depth in range(1, 8)),
            *(("..\\" * depth) + name for depth in range(1, 4)),
            *(("..%2f" * depth) + name for depth in range(1, 4)),
            *(("%2e%2e/" * depth) + name for depth in range(1, 4)),
        ]
        kept = store.put([b"keep"], max_bytes=4)
        for blob_id in ids:
            store.delete(blob_id)
            with pytest.raises(NotFoundError):
                store.open(blob_id)
        if is_ulid(name):
            # A valid-looking id still only resolves inside the store.
            with pytest.raises(NotFoundError):
                store.open(name)
            store.delete(name)
        assert outside_sentinel.read_bytes() == original
        assert store.list_ids() == {kept.blob_id}

    # --- disk full (optional: stores with a capacity hook) ---------------------

    def test_disk_full_raises_limit_exceeded_and_leaves_nothing(
        self, store_with_capacity: Callable[[int], BlobStore]
    ) -> None:
        store = store_with_capacity(CAPACITY)
        kept = store.put([b"k" * 100], max_bytes=100)
        with pytest.raises(LimitExceededError):
            # max_bytes is generous: only the storage capacity can stop this.
            store.put(itertools.repeat(b"x" * 64, 1000), max_bytes=10 * CAPACITY)
        assert store.list_ids() == {kept.blob_id}
        with store.open(kept.blob_id) as f:
            assert f.read() == b"k" * 100
        # The failed put left nothing behind, so the space is still usable.
        again = store.put([b"a" * 100], max_bytes=100)
        assert store.list_ids() == {kept.blob_id, again.blob_id}
