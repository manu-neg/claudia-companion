"""Security test: FsBlobStore can never touch anything outside its data dir.

Proves docs/security.md I2 ("can never read or list anything outside its
own data directory") and C7 ("paths are only ever built from validated
ids") at the blob-storage layer, including against a local attacker who
tampers with the layout *after* the store started (dirfd confinement:
symlinked shard, swapped `blobs/`, planted FIFO / hardlink) and against
untrusted (shared-writable / foreign-owned) directories. Complements tests/security/test_paths.py,
which covers the equivalent invariant for bundle-relative paths.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore, UnsafeStorageLayoutError
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.domain.errors import NotFoundError
from tests.builders import ulid
from tests.fakes import SequentialIdGenerator

pytestmark = pytest.mark.security

# Ids an attacker who controlled the DB manifest (or a malformed request)
# might supply; none of these are canonical ULIDs, so none must ever reach
# a filesystem call.
ADVERSARIAL_BLOB_IDS = [
    "../x",
    "../../etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%2f",
    "",
    ".",
    "..",
    "01arz3ndektsv4rrffq69g5fav",  # lowercase ULID: not canonical (ADR 0007)
    "\x00" * 26,
    "a/b",
    "0" * 27,  # one char too long
]


def _snapshot(path: Path) -> set[str]:
    return {str(p.relative_to(path)) for p in path.rglob("*")}


class TestBlobIdConfinement:
    @pytest.mark.parametrize("blob_id", ADVERSARIAL_BLOB_IDS)
    def test_open_with_adversarial_id_raises_not_found_and_touches_nothing(
        self, tmp_path: Path, blob_id: str
    ) -> None:
        canary = tmp_path / "canary.txt"
        canary.write_text("must never be read or moved")
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        before = _snapshot(tmp_path)

        with pytest.raises(NotFoundError):
            store.open(blob_id)

        assert _snapshot(tmp_path) == before
        assert canary.read_text() == "must never be read or moved"

    @pytest.mark.parametrize("blob_id", ADVERSARIAL_BLOB_IDS)
    def test_delete_with_adversarial_id_is_a_silent_noop(
        self, tmp_path: Path, blob_id: str
    ) -> None:
        canary = tmp_path / "canary.txt"
        canary.write_text("must never be deleted")
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())
        before = _snapshot(tmp_path)

        store.delete(blob_id)

        assert _snapshot(tmp_path) == before
        assert canary.exists()


class TestPlantedSymlinkConfinement:
    def test_open_refuses_a_symlink_planted_at_a_valid_blob_path(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=SequentialIdGenerator(), clock=SystemClock())
        blob_id = ulid(1)
        shard_dir = root / "blobs" / blob_id[-2:]
        shard_dir.mkdir(parents=True, exist_ok=True)
        secret = tmp_path / "outside-the-store.txt"
        secret.write_text("sensitive")
        (shard_dir / blob_id).symlink_to(secret)

        with pytest.raises(NotFoundError):
            store.open(blob_id)

        # The symlink target itself must be untouched: proves it was never
        # dereferenced, not just that the read failed for some other reason.
        assert secret.read_text() == "sensitive"

    def test_delete_removes_only_the_symlink_not_its_target(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = FsBlobStore(root, ids=SequentialIdGenerator(), clock=SystemClock())
        blob_id = ulid(1)
        shard_dir = root / "blobs" / blob_id[-2:]
        shard_dir.mkdir(parents=True, exist_ok=True)
        secret = tmp_path / "outside-the-store.txt"
        secret.write_text("sensitive")
        (shard_dir / blob_id).symlink_to(secret)

        store.delete(blob_id)

        assert not (shard_dir / blob_id).exists()
        assert secret.read_text() == "sensitive"


class TestRootLayoutConfinement:
    def test_symlinked_blobs_dir_refuses_to_start(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        root.mkdir(mode=0o750)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (root / "blobs").symlink_to(elsewhere)

        with pytest.raises(UnsafeStorageLayoutError):
            FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

    def test_symlinked_staging_dir_refuses_to_start(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        root.mkdir(mode=0o750)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (root / "staging").symlink_to(elsewhere)

        with pytest.raises(UnsafeStorageLayoutError):
            FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())

    def test_symlinked_root_refuses_to_start(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        root = tmp_path / "data"
        root.symlink_to(real)

        with pytest.raises(UnsafeStorageLayoutError):
            FsBlobStore(root, ids=UlidGenerator(), clock=SystemClock())


def _store(root: Path, **kwargs: object) -> FsBlobStore:
    return FsBlobStore(root, ids=SequentialIdGenerator(), clock=SystemClock(), **kwargs)  # type: ignore[arg-type]


class TestPostInitTamperingConfinement:
    """Layout swapped under a running store must never redirect it outside."""

    def test_symlinked_shard_planted_after_init_is_never_followed(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = _store(root)
        blob_id = ulid(1)  # the id the store's next put() will use
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / blob_id).write_text("outside the store")
        (root / "blobs" / blob_id[-2:]).symlink_to(outside)
        before = _snapshot(outside)

        with pytest.raises(NotFoundError):
            store.open(blob_id)
        store.delete(blob_id)
        assert store.list_ids() == set()
        with pytest.raises(UnsafeStorageLayoutError):
            store.put([b"attacker wants this outside"], max_bytes=100)

        assert (outside / blob_id).read_text() == "outside the store"
        assert _snapshot(outside) == before
        assert list((root / "staging").iterdir()) == []

    def test_blobs_dir_swapped_for_symlink_after_init_is_never_followed(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "data"
        store = _store(root)
        kept = store.put([b"kept"], max_bytes=10)
        victim_id = ulid(99)
        outside = tmp_path / "outside"
        (outside / victim_id[-2:]).mkdir(parents=True)
        (outside / victim_id[-2:] / victim_id).write_text("outside the store")
        os.rename(root / "blobs", root / "blobs-moved")
        (root / "blobs").symlink_to(outside)
        before = _snapshot(outside)

        with pytest.raises(NotFoundError):
            store.open(victim_id)
        store.delete(victim_id)
        assert store.list_ids() == {kept.blob_id}
        new = store.put([b"new"], max_bytes=10)

        # The store keeps using the directory it opened at start-up.
        assert (root / "blobs-moved" / new.blob_id[-2:] / new.blob_id).is_file()
        assert _snapshot(outside) == before
        assert (outside / victim_id[-2:] / victim_id).read_text() == "outside the store"

    def test_fifo_planted_at_blob_path_does_not_hang_open(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = _store(root)
        blob_id = ulid(1)
        shard = root / "blobs" / blob_id[-2:]
        shard.mkdir(mode=0o750)
        os.mkfifo(shard / blob_id)
        outcome: list[BaseException | None] = []

        def attempt() -> None:
            try:
                store.open(blob_id).close()
                outcome.append(None)
            except BaseException as exc:  # recorded for the assert below
                outcome.append(exc)

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive(), "open() blocked on a FIFO"
        assert len(outcome) == 1
        assert isinstance(outcome[0], NotFoundError)

    def test_hardlink_planted_at_blob_path_is_not_served_or_damaged(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = _store(root)
        blob_id = ulid(1)
        secret = tmp_path / "secret.txt"
        secret.write_text("sensitive")
        shard = root / "blobs" / blob_id[-2:]
        shard.mkdir(mode=0o750)
        os.link(secret, shard / blob_id)

        with pytest.raises(NotFoundError):
            store.open(blob_id)
        store.delete(blob_id)

        assert secret.read_text() == "sensitive"
        assert secret.stat().st_nlink == 1


class TestUntrustedDirectoryRefusal:
    @pytest.mark.parametrize("subdir", ["", "blobs", "staging"])
    @pytest.mark.parametrize("mode", [0o770, 0o757, 0o777])
    def test_shared_writable_layout_dir_refuses_to_start(
        self, tmp_path: Path, subdir: str, mode: int
    ) -> None:
        root = tmp_path / "data"
        _store(root).close()
        os.chmod(root / subdir if subdir else root, mode)

        with pytest.raises(UnsafeStorageLayoutError):
            _store(root)

    @pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
    @pytest.mark.parametrize("subdir", ["", "blobs", "staging"])
    def test_foreign_owned_layout_dir_refuses_to_start(self, tmp_path: Path, subdir: str) -> None:
        root = tmp_path / "data"
        _store(root).close()
        os.chown(root / subdir if subdir else root, 54321, -1)

        with pytest.raises(UnsafeStorageLayoutError):
            _store(root)

    @pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
    def test_explicitly_trusted_owner_is_accepted(self, tmp_path: Path) -> None:
        # The viewer runs as a different user than the writer and trusts it.
        root = tmp_path / "data"
        _store(root).close()
        for path in (root, root / "blobs", root / "staging"):
            os.chown(path, 54321, -1)

        _store(root, trusted_owner_uids={0, 54321}).close()

    def test_shared_writable_shard_is_refused_for_every_operation(self, tmp_path: Path) -> None:
        root = tmp_path / "data"
        store = _store(root)
        blob_id = ulid(1)
        shard = root / "blobs" / blob_id[-2:]
        shard.mkdir()
        os.chmod(shard, 0o777)  # noqa: S103 - deliberately unsafe layout under test
        (shard / blob_id).write_text("planted")
        os.chmod(shard / blob_id, 0o640)

        with pytest.raises(NotFoundError):
            store.open(blob_id)
        store.delete(blob_id)
        assert store.list_ids() == set()
        with pytest.raises(UnsafeStorageLayoutError):
            store.put([b"x"], max_bytes=1)

        assert (shard / blob_id).read_text() == "planted"
        assert list((root / "staging").iterdir()) == []
