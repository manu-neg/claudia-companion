"""Integration tests for FsBlobStore: contract compliance plus adapter specifics.

Covers atomicity, permissions, symlink refusal, disk-full handling and
staging cleanup — guarantees docs/security.md C7/C11 require from the real
filesystem adapter that the in-memory fake (tests/fakes.py) can't prove.
"""

from __future__ import annotations

import errno
import itertools
import os
import stat
from array import array
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore, UnsafeStorageLayoutError
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.domain.errors import LimitExceededError, NotFoundError
from tests.builders import ulid
from tests.contracts.blob_store import BlobStoreContract
from tests.fakes import FixedClock, SequentialIdGenerator

pytestmark = pytest.mark.integration


class _BoomError(Exception):
    pass


class TestFsBlobStoreContract(BlobStoreContract):
    """The shared BlobStore contract must pass unchanged against the real adapter."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> Iterator[FsBlobStore]:
        with FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock()) as store:
            yield store

    @pytest.fixture
    def outside_sentinel(self, tmp_path: Path) -> Path:
        """A file outside the store's root, for contract tests proving malformed
        or adversarial blob ids never escape the root (docs/security.md I2/C7).
        Also exercised directly by TestFsBlobStoreMalformedIds below.
        """
        sentinel = tmp_path / "outside-sentinel.txt"
        sentinel.write_text("must never be read, written or deleted by the store")
        return sentinel

    @pytest.fixture
    def store_with_capacity(self, tmp_path: Path) -> Callable[[int], FsBlobStore]:
        """Disk-full hook for the contract: free space = capacity - bytes under the root."""

        def make(capacity: int) -> FsBlobStore:
            root = tmp_path / "capped"

            def free() -> int:
                used = sum(p.stat().st_size for p in root.rglob("*") if p.is_file())
                return max(0, capacity - used)

            return FsBlobStore(
                root, ids=UlidGenerator(), clock=SystemClock(), free_bytes_provider=free
            )

        return make


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestFsBlobStorePermissions:
    def test_directories_get_restrictive_mode(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock(), dir_mode=0o750)
        assert _mode(root) == 0o750
        assert _mode(root / "blobs") == 0o750
        assert _mode(root / "staging") == 0o750

    def test_blob_file_gets_restrictive_mode(self, tmp_path: Path) -> None:
        store = FsBlobStore(
            tmp_path / "data", ids=UlidGenerator(), clock=SystemClock(), file_mode=0o640
        )
        ref = store.put([b"hi"], max_bytes=10)
        blob_path = tmp_path / "data" / "blobs" / ref.blob_id[-2:] / ref.blob_id
        assert _mode(blob_path) == 0o640

    def test_custom_modes_are_honored(self, tmp_path: Path) -> None:
        store = FsBlobStore(
            tmp_path / "data",
            ids=UlidGenerator(),
            clock=SystemClock(),
            file_mode=0o600,
            dir_mode=0o700,
        )
        ref = store.put([b"hi"], max_bytes=10)
        assert _mode(tmp_path / "data" / "blobs") == 0o700
        blob_path = tmp_path / "data" / "blobs" / ref.blob_id[-2:] / ref.blob_id
        assert _mode(blob_path) == 0o600


def _all_blob_files(root: Path) -> list[Path]:
    blobs_dir = root / "blobs"
    if not blobs_dir.is_dir():
        return []
    return [p for p in blobs_dir.rglob("*") if p.is_file()]


class TestFsBlobStoreAtomicity:
    def test_exception_mid_stream_leaves_no_staging_or_blob_files(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())

        def chunks() -> Iterator[bytes]:
            yield b"partial"
            raise _BoomError

        with pytest.raises(_BoomError):
            store.put(chunks(), max_bytes=100)

        assert list((tmp_path / "data" / "staging").iterdir()) == []
        assert store.list_ids() == set()
        assert _all_blob_files(tmp_path / "data") == []

    def test_limit_exceeded_mid_stream_leaves_nothing(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())

        with pytest.raises(LimitExceededError):
            store.put(itertools.repeat(b"x" * 1024), max_bytes=10 * 1024)

        assert list((tmp_path / "data" / "staging").iterdir()) == []
        assert store.list_ids() == set()

    def test_successful_put_leaves_no_staging_file(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())
        store.put([b"ok"], max_bytes=10)
        assert list((tmp_path / "data" / "staging").iterdir()) == []


class TestFsBlobStoreDiskFull:
    def test_simulated_disk_full_raises_limit_exceeded_and_leaves_nothing(
        self, tmp_path: Path
    ) -> None:
        store = FsBlobStore(
            tmp_path / "data",
            ids=UlidGenerator(),
            clock=SystemClock(),
            free_bytes_provider=lambda: 0,
        )

        with pytest.raises(LimitExceededError):
            store.put([b"more than zero free bytes"], max_bytes=1000)

        assert list((tmp_path / "data" / "staging").iterdir()) == []
        assert store.list_ids() == set()

    def test_disk_full_partway_through_a_stream_leaves_nothing(self, tmp_path: Path) -> None:
        free = {"bytes": 5}
        store = FsBlobStore(
            tmp_path / "data",
            ids=UlidGenerator(),
            clock=SystemClock(),
            free_bytes_provider=lambda: free["bytes"],
        )

        def chunks() -> Iterator[bytes]:
            yield b"abc"
            free["bytes"] = 0
            yield b"def"

        with pytest.raises(LimitExceededError):
            store.put(chunks(), max_bytes=100)

        assert list((tmp_path / "data" / "staging").iterdir()) == []
        assert store.list_ids() == set()

    def test_empty_blob_succeeds_even_with_no_free_space(self, tmp_path: Path) -> None:
        # An empty write needs no space; a real filesystem allows it too.
        store = FsBlobStore(
            tmp_path / "data",
            ids=UlidGenerator(),
            clock=SystemClock(),
            free_bytes_provider=lambda: 0,
        )
        ref = store.put([], max_bytes=0)
        assert ref.size == 0

    def test_free_bytes_uses_the_injected_provider(self, tmp_path: Path) -> None:
        store = FsBlobStore(
            tmp_path / "data",
            ids=UlidGenerator(),
            clock=SystemClock(),
            free_bytes_provider=lambda: 12345,
        )
        assert store.free_bytes() == 12345

    def test_free_bytes_defaults_to_real_disk_usage(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())
        free = store.free_bytes()
        assert isinstance(free, int)
        assert free > 0


class TestFsBlobStoreSymlinkRefusal:
    def test_symlinked_blobs_dir_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        root.mkdir(mode=0o750)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (root / "blobs").symlink_to(elsewhere)

        with pytest.raises(UnsafeStorageLayoutError):
            FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

    def test_symlinked_staging_dir_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        root.mkdir(mode=0o750)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (root / "staging").symlink_to(elsewhere)

        with pytest.raises(UnsafeStorageLayoutError):
            FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

    def test_symlinked_root_is_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        root = tmp_path / "data"
        root.symlink_to(real)

        with pytest.raises(UnsafeStorageLayoutError):
            FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

    def test_planted_symlink_at_blob_path_is_refused_on_open(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=SequentialIdGenerator(), clock=SystemClock())
        blob_id = ulid(1)
        shard_dir = root / "blobs" / blob_id[-2:]
        shard_dir.mkdir(parents=True, exist_ok=True)
        secret = tmp_path / "secret.txt"
        secret.write_text("outside the store")
        (shard_dir / blob_id).symlink_to(secret)

        with pytest.raises(NotFoundError):
            store.open(blob_id)


class TestFsBlobStoreSharding:
    def test_blob_is_placed_under_its_last_two_chars(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        ref = store.put([b"data"], max_bytes=10)
        expected = root / "blobs" / ref.blob_id[-2:] / ref.blob_id
        assert expected.is_file()

    def test_many_blobs_spread_across_shard_directories(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        for _ in range(40):
            store.put([b"x"], max_bytes=10)
        shard_dirs = list((root / "blobs").iterdir())
        # 40 fresh random ULIDs landing in a single shard would be a fluke.
        assert len(shard_dirs) > 1


class TestFsBlobStoreStagingSweep:
    def test_sweep_removes_stale_staging_files_only(self, tmp_path: Path) -> None:
        clock = FixedClock()
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=clock)
        staging = tmp_path / "data" / "staging"

        stale = staging / f"{ulid(1)}.part"
        stale.write_bytes(b"leftover")
        fresh = staging / f"{ulid(2)}.part"
        fresh.write_bytes(b"leftover")
        not_staging = staging / "not-a-staging-file.txt"
        not_staging.write_bytes(b"ignore me")

        old_time = (clock.now() - timedelta(hours=2)).timestamp()
        os.utime(stale, (old_time, old_time))

        removed = store.sweep_staging(older_than=timedelta(hours=1))

        assert removed == 1
        assert not stale.exists()
        assert fresh.exists()
        assert not_staging.exists()

    def test_sweep_ignores_names_that_are_not_valid_staging_files(self, tmp_path: Path) -> None:
        clock = FixedClock()
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=clock)
        staging = tmp_path / "data" / "staging"
        junk = staging / "not-a-ulid.part"
        junk.write_bytes(b"junk")
        old_time = (clock.now() - timedelta(days=1)).timestamp()
        os.utime(junk, (old_time, old_time))

        removed = store.sweep_staging(older_than=timedelta(hours=1))

        assert removed == 0
        assert junk.exists()

    def test_sweep_does_not_remove_staging_files_newer_than_the_cutoff(
        self, tmp_path: Path
    ) -> None:
        clock = FixedClock()
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=clock)
        staging = tmp_path / "data" / "staging"
        fresh = staging / f"{ulid(1)}.part"
        fresh.write_bytes(b"leftover")

        removed = store.sweep_staging(older_than=timedelta(hours=1))

        assert removed == 0
        assert fresh.exists()


_ADVERSARIAL_IDS = [
    "../x",
    "../../sentinel",
    "/etc/passwd",
    "..%2f",
    ".",
    "",
    "01arz3ndektsv4rrffq69g5fav",  # lowercase ULID: not canonical
    "0" * 27,  # overlong
]


class TestFsBlobStoreMalformedIds:
    """Blob ids are validated before any path is built (docs/security.md C7).

    See also tests/security/test_fs_confinement_blobstore.py for the
    dedicated security-control version of this invariant.
    """

    @pytest.mark.parametrize("blob_id", _ADVERSARIAL_IDS)
    def test_open_never_touches_filesystem_outside_root(self, tmp_path: Path, blob_id: str) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        before = _snapshot(tmp_path)

        with pytest.raises(NotFoundError):
            store.open(blob_id)

        assert _snapshot(tmp_path) == before

    @pytest.mark.parametrize("blob_id", _ADVERSARIAL_IDS)
    def test_delete_never_touches_filesystem_outside_root(
        self, tmp_path: Path, blob_id: str
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        before = _snapshot(tmp_path)

        store.delete(blob_id)  # must be a silent no-op

        assert _snapshot(tmp_path) == before


def _snapshot(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def _staging_names(root: Path) -> list[str]:
    return sorted(p.name for p in (root / "staging").iterdir())


class _FixedIds(SequentialIdGenerator):
    """Id generator that hands out one fixed (possibly bogus) blob id."""

    def __init__(self, blob_id: str) -> None:
        super().__init__()
        self._blob_id = blob_id

    def new_blob_id(self) -> str:
        return self._blob_id


class TestFsBlobStoreLifecycle:
    def test_context_manager_closes_and_closed_store_refuses_use(self, tmp_path: Path) -> None:
        with FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock()) as store:
            ref = store.put([b"x"], max_bytes=1)
        for call in (
            lambda: store.put([b"x"], max_bytes=1),
            lambda: store.open(ref.blob_id),
            lambda: store.delete(ref.blob_id),
            lambda: store.list_ids(),
            lambda: store.free_bytes(),
            lambda: store.sweep_staging(timedelta(0)),
        ):
            with pytest.raises(RuntimeError, match="closed"):
                call()

    def test_close_is_idempotent(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())
        store.close()
        store.close()

    def test_group_writable_modes_are_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="writable"):
            FsBlobStore(tmp_path / "d", ids=UlidGenerator(), clock=SystemClock(), dir_mode=0o770)
        with pytest.raises(ValueError, match="writable"):
            FsBlobStore(tmp_path / "d", ids=UlidGenerator(), clock=SystemClock(), file_mode=0o666)

    def test_negative_reserve_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="reserve"):
            FsBlobStore(tmp_path / "d", ids=UlidGenerator(), clock=SystemClock(), reserve_bytes=-1)

    def test_opened_blob_stream_is_blocking(self, tmp_path: Path) -> None:
        # O_NONBLOCK is only for the open itself (FIFO safety); reads block normally.
        with FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock()) as store:
            ref = store.put([b"abc"], max_bytes=3)
            with store.open(ref.blob_id) as f:
                assert os.get_blocking(f.fileno())


class TestFsBlobStoreDurability:
    def test_new_layout_and_shard_dirs_fsync_their_parent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        synced: list[int] = []
        real_fsync = os.fsync

        def spy(fd: int) -> None:
            synced.append(os.fstat(fd).st_ino)
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", spy)
        root = tmp_path / "data"
        with FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock()) as store:
            assert root.stat().st_ino in synced  # after creating blobs/ and staging/
            assert tmp_path.stat().st_ino in synced  # after creating root itself
            synced.clear()
            store.put([b"x"], max_bytes=1)
            assert (root / "blobs").stat().st_ino in synced  # after creating the shard

    def test_new_shard_dir_gets_exact_mode_despite_umask(self, tmp_path: Path) -> None:
        old = os.umask(0o077)
        try:
            with FsBlobStore(
                tmp_path / "data", ids=UlidGenerator(), clock=SystemClock(), dir_mode=0o750
            ) as store:
                ref = store.put([b"x"], max_bytes=1)
        finally:
            os.umask(old)
        assert _mode(tmp_path / "data" / "blobs" / ref.blob_id[-2:]) == 0o750

    def test_concurrent_shard_creation_is_tolerated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=SequentialIdGenerator(), clock=SystemClock())
        real_mkdir = os.mkdir

        def racing_mkdir(name: Any, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
            # Another process creates the shard first; ours then loses the race.
            real_mkdir(name, 0o750, dir_fd=dir_fd)
            raise FileExistsError(errno.EEXIST, "exists")

        monkeypatch.setattr(os, "mkdir", racing_mkdir)
        ref = store.put([b"x"], max_bytes=1)
        monkeypatch.undo()
        with store.open(ref.blob_id) as f:
            assert f.read() == b"x"


class TestFsBlobStoreOutOfSpace:
    """ENOSPC/EDQUOT anywhere in put -> LimitExceededError, nothing left (C11)."""

    @pytest.mark.parametrize("err", [errno.ENOSPC, errno.EDQUOT])
    @pytest.mark.parametrize("func", ["write", "fsync", "link", "mkdir", "open"])
    def test_out_of_space_is_limit_exceeded_and_leaves_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, func: str, err: int
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

        def fail(*args: object, **kwargs: object) -> None:
            raise OSError(err, os.strerror(err))

        monkeypatch.setattr(os, func, fail)
        with pytest.raises(LimitExceededError):
            store.put([b"data"], max_bytes=10)
        monkeypatch.undo()
        assert _staging_names(root) == []
        assert store.list_ids() == set()
        assert _all_blob_files(root) == []

    def test_other_os_errors_propagate_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

        def fail(*args: object, **kwargs: object) -> None:
            raise OSError(errno.EIO, "I/O error")

        monkeypatch.setattr(os, "write", fail)
        with pytest.raises(OSError) as info:
            store.put([b"data"], max_bytes=10)
        assert info.value.errno == errno.EIO
        monkeypatch.undo()
        assert _staging_names(root) == []

    def test_failing_unlink_after_link_removes_the_published_blob(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        real_unlink = os.unlink
        calls = {"n": 0}

        def flaky_unlink(name: Any, *, dir_fd: int | None = None) -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError(errno.EIO, "I/O error")
            real_unlink(name, dir_fd=dir_fd)

        monkeypatch.setattr(os, "unlink", flaky_unlink)
        with pytest.raises(OSError):
            store.put([b"data"], max_bytes=10)
        monkeypatch.undo()
        assert _staging_names(root) == []
        assert _all_blob_files(root) == []

    def test_failing_fchmod_closes_and_removes_the_staging_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

        def fail(*args: object, **kwargs: object) -> None:
            raise _BoomError

        monkeypatch.setattr(os, "fchmod", fail)
        with pytest.raises(_BoomError):
            store.put([b"data"], max_bytes=10)
        monkeypatch.undo()
        assert _staging_names(root) == []


class TestFsBlobStoreReserveAndChunks:
    def test_chunk_that_would_cross_the_reserve_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(
            root,
            ids=UlidGenerator(),
            clock=SystemClock(),
            free_bytes_provider=lambda: 1000,
            reserve_bytes=900,
        )
        assert store.put([b"x" * 100], max_bytes=1000).size == 100  # leaves exactly 900
        with pytest.raises(LimitExceededError):
            store.put([b"x" * 101], max_bytes=1000)
        assert _staging_names(root) == []

    def test_limit_exceeded_closes_the_chunk_iterator(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())
        closed = {"flag": False}

        def chunks() -> Iterator[bytes]:
            try:
                while True:
                    yield b"x" * 10
            finally:
                closed["flag"] = True

        with pytest.raises(LimitExceededError):
            store.put(chunks(), max_bytes=25)
        assert closed["flag"]

    def test_size_counts_bytes_not_buffer_items(self, tmp_path: Path) -> None:
        store = FsBlobStore(tmp_path / "data", ids=UlidGenerator(), clock=SystemClock())
        wide = array("I", [1, 2, 3])  # len 3, but 3 * itemsize bytes
        with pytest.raises(LimitExceededError):
            store.put([wide], max_bytes=3)  # type: ignore[list-item]
        ref = store.put([wide, bytearray(b"z")], max_bytes=100)  # type: ignore[list-item]
        assert ref.size == wide.itemsize * 3 + 1

    def test_non_buffer_chunk_is_rejected_and_leaves_nothing(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        with pytest.raises(TypeError):
            store.put([b"ok", "text"], max_bytes=100)  # type: ignore[list-item]
        assert _staging_names(root) == []
        assert store.list_ids() == set()


class TestFsBlobStoreGeneratedIds:
    @pytest.mark.parametrize("bad_id", ["../escaped", "", "01arz3ndektsv4rrffq69g5fav"])
    def test_non_canonical_generated_id_is_refused_before_any_fs_call(
        self, tmp_path: Path, bad_id: str
    ) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=_FixedIds(bad_id), clock=SystemClock())
        before = _snapshot(tmp_path)
        with pytest.raises(RuntimeError, match="non-canonical"):
            store.put([b"x"], max_bytes=1)
        assert _snapshot(tmp_path) == before

    def test_id_collision_raises_and_keeps_the_existing_blob(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=_FixedIds(ulid(7)), clock=SystemClock())
        store.put([b"first"], max_bytes=10)
        with pytest.raises(RuntimeError, match="collision"):
            store.put([b"second"], max_bytes=10)
        with store.open(ulid(7)) as f:
            assert f.read() == b"first"
        assert _staging_names(root) == []


class TestFsBlobStoreListing:
    def test_blob_in_the_wrong_shard_is_not_listed(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        ref = store.put([b"x"], max_bytes=1)
        stray = ulid(5)  # ends in "05"
        wrong_shard = root / "blobs" / "ZZ"
        wrong_shard.mkdir(mode=0o750)
        (wrong_shard / stray).write_bytes(b"misplaced")
        assert store.list_ids() == {ref.blob_id}
