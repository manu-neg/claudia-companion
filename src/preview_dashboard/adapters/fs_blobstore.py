"""FsBlobStore: filesystem-backed BlobStore adapter (docs/security.md I2, C7, C11, C20).

Blobs are written to a staging file, fsynced, then atomically published into
a sharded, ULID-keyed layout under `root/blobs/`. Confinement is enforced
with directory file descriptors: `root`, `blobs/` and `staging/` are opened
once (never through a symlink) and every later operation is relative to
those fds, so swapping a directory for a symlink after start-up can't
redirect any read, write, listing or delete outside the store.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
from collections.abc import Callable, Collection, Iterable, Iterator
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Self

from preview_dashboard.domain.errors import LimitExceededError, NotFoundError
from preview_dashboard.domain.models import BlobRef, ensure_utc, is_ulid
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator

# Staging files are named "<ulid>.part"; only names of this exact shape are
# ever treated as staging files (matches what `sweep_staging` may remove).
_STAGING_SUFFIX = ".part"
# Shard directory names are the *last* two chars of a canonical ULID.
_SHARD_NAME_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{2}")
# Every directory is opened without following a symlink in its last
# component; combined with dir_fd-relative lookups, no component is ever
# resolved through a symlink after the root itself.
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK: opening a FIFO planted at a blob path must not hang the reader.
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
_STAGING_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# Out-of-space and out-of-quota are the same condition for the caller.
_OUT_OF_SPACE = frozenset({errno.ENOSPC, errno.EDQUOT})
# Errors meaning "something that is not a real directory is at this name".
_NOT_A_REAL_DIR = frozenset({errno.ELOOP, errno.ENOTDIR})
# Group/other write bits: a directory anyone else can write into can't be trusted.
_FOREIGN_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH


class UnsafeStorageLayoutError(RuntimeError):
    """The store's on-disk layout can't be trusted.

    Raised when `root`, `blobs/`, `staging/` or a shard directory is a
    symlink or non-directory, is group/world-writable, or is owned by an
    untrusted uid. Raised at construction (the service fails to start) and
    by `put` (a publish is refused); `open`/`delete`/`list_ids` treat an
    untrusted shard as absent instead, so they fail closed without raising.
    """


def _is_out_of_space(exc: OSError) -> bool:
    return exc.errno in _OUT_OF_SPACE


def _close_quietly(fd: int) -> None:
    # Used only on error paths: never let a close error mask the original one.
    with suppress(OSError):
        os.close(fd)


def _write_all(fd: int, view: memoryview) -> None:
    """Unbuffered write loop: nothing is buffered, so nothing flushes on close."""
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _close_iterator(*candidates: object) -> None:
    """Close the chunk source so its producer stops (e.g. a generator's finally runs)."""
    for candidate in candidates:
        close = getattr(candidate, "close", None)
        if callable(close):
            # The limit error is what the caller needs to see; a failing
            # close() of the producer must not replace it.
            with suppress(Exception):
                close()
            return


class FsBlobStore:
    """BlobStore backed by a local (or same-host-mounted) filesystem.

    On-disk layout under `root`, all on the same filesystem (required so the
    link+unlink publish step below is atomic):

        root/blobs/<AB>/<ULID>    Final, immutable blobs, sharded by the
                                    id's *last* two Crockford-base32 chars
                                    (the random suffix; 32² = 1024 shards).
                                    The *first* chars of a ULID are a
                                    timestamp, so a burst of ids would
                                    otherwise collide on one or two shards.
        root/staging/<ULID>.part  In-progress writes. Never exposed via
                                    `open`/`list_ids`; cleaned up on any
                                    error and by `sweep_staging`.

    Confinement (docs/security.md I2): the constructor opens `root`,
    `blobs/` and `staging/` with `O_DIRECTORY|O_NOFOLLOW` and keeps the fds.
    All later operations are relative to them (`dir_fd=`); shard dirs are
    opened `O_DIRECTORY|O_NOFOLLOW` from the `blobs/` fd. Every directory
    must be a real directory owned by a trusted uid and not group/world
    writable (`UnsafeStorageLayoutError` otherwise). `open` additionally
    requires a regular file with exactly one link (a planted hardlink to an
    outside file is "not found").

    Lifecycle: the store holds three directory fds from construction until
    `close()` (idempotent; also via `with FsBlobStore(...) as store:`).
    Using a closed store raises `RuntimeError`. Not safe to `close()`
    concurrently with other calls; all other methods are thread-safe.

    Args:
        root: data directory (created, with its parent existing, if missing).
        ids: blob-id generator; its output is validated before use.
        clock: time source for `sweep_staging`.
        file_mode / dir_mode: exact modes for created files/dirs; must not
            grant group/other write (`ValueError`).
        free_bytes_provider: replaces the real free-space query (tests use
            it to simulate a full disk); defaults to `fstatvfs` on `root`.
        reserve_bytes: free-disk floor; a chunk that would leave less than
            this free is refused with `LimitExceededError` (bootstrap wires
            it to `min_free_disk_bytes`).
        trusted_owner_uids: uids allowed to own existing layout dirs;
            defaults to the process's effective uid. A reader running as a
            different service user (the viewer) passes the writer's uid.
    """

    def __init__(
        self,
        root: Path,
        *,
        ids: IdGenerator,
        clock: Clock,
        file_mode: int = 0o640,
        dir_mode: int = 0o750,
        free_bytes_provider: Callable[[], int] | None = None,
        reserve_bytes: int = 0,
        trusted_owner_uids: Collection[int] | None = None,
    ) -> None:
        if file_mode & _FOREIGN_WRITE_BITS or dir_mode & _FOREIGN_WRITE_BITS:
            raise ValueError("file_mode/dir_mode must not be group- or world-writable")
        if reserve_bytes < 0:
            raise ValueError("reserve_bytes must be >= 0")
        self._ids = ids
        self._clock = clock
        self._file_mode = file_mode
        self._dir_mode = dir_mode
        self._reserve_bytes = reserve_bytes
        self._trusted_uids = frozenset(
            trusted_owner_uids if trusted_owner_uids is not None else (os.geteuid(),)
        )
        self._free_bytes_provider = free_bytes_provider or self._disk_free_bytes
        self._closed = True  # until every fd below is open
        self._root_fd = self._open_root(Path(root))
        try:
            self._blobs_fd = self._open_layout_dir("blobs")
            try:
                self._staging_fd = self._open_layout_dir("staging")
            except BaseException:
                os.close(self._blobs_fd)
                raise
        except BaseException:
            os.close(self._root_fd)
            raise
        self._closed = False

    # --- lifecycle -------------------------------------------------------------

    def close(self) -> None:
        """Release the directory fds; idempotent. The store is unusable afterwards."""
        if self._closed:
            return
        self._closed = True
        for fd in (self._staging_fd, self._blobs_fd, self._root_fd):
            _close_quietly(fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        # Safety net only; callers should close() explicitly. getattr: the
        # constructor may have failed before `_closed` existed.
        # suppress: may run during interpreter shutdown, when `os` is half torn down.
        if not getattr(self, "_closed", True):
            with suppress(Exception):
                self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("FsBlobStore is closed")

    # --- directory handling ------------------------------------------------------

    def _verify_dir_fd(self, fd: int, what: str) -> None:
        """Refuse a directory that isn't a real, trusted-owner, non-shared-writable dir."""
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise UnsafeStorageLayoutError(f"{what} must be a directory")
        if st.st_uid not in self._trusted_uids:
            raise UnsafeStorageLayoutError(f"{what} is owned by an untrusted uid")
        if st.st_mode & _FOREIGN_WRITE_BITS:
            raise UnsafeStorageLayoutError(f"{what} must not be group- or world-writable")

    def _open_dir(self, name: str, parent_fd: int | None, *, create: bool) -> int | None:
        """Open (optionally creating) directory `name` relative to `parent_fd`.

        Returns None if it is missing and `create` is False. A newly created
        directory gets exactly `dir_mode` and its parent is fsynced so the
        entry survives a crash. Raises `UnsafeStorageLayoutError` for a
        symlink / non-directory / untrusted directory; other `OSError`s
        (e.g. ENOSPC from mkdir) propagate unchanged.
        """
        created = False
        try:
            try:
                fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    return None
                try:
                    os.mkdir(name, self._dir_mode, dir_fd=parent_fd)
                    created = True
                except FileExistsError:
                    pass  # a concurrent creator won; verify what's there below
                fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in _NOT_A_REAL_DIR:
                raise UnsafeStorageLayoutError(
                    f"{name} must be a real directory, not a symlink"
                ) from None
            raise
        try:
            if created:
                os.fchmod(fd, self._dir_mode)  # mkdir's mode is filtered by umask
            self._verify_dir_fd(fd, name)
            if created and parent_fd is not None:
                os.fsync(parent_fd)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _open_root(self, root: Path) -> int:
        existed = os.path.lexists(root)
        fd = self._open_dir(os.fspath(root), None, create=True)
        if fd is None:  # pragma: no cover - create=True never returns None
            raise UnsafeStorageLayoutError("could not open the store root")
        if not existed:
            # The root has no parent fd of ours; fsync its parent by path once.
            parent_fd = os.open(os.fspath(root.parent), os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        return fd

    def _open_layout_dir(self, name: str) -> int:
        fd = self._open_dir(name, self._root_fd, create=True)
        if fd is None:  # pragma: no cover - create=True never returns None
            raise UnsafeStorageLayoutError(f"could not open {name}")
        return fd

    def _open_shard_for_read(self, shard: str) -> int | None:
        """Open an existing shard, or None if it is missing or untrusted (fail closed)."""
        try:
            return self._open_dir(shard, self._blobs_fd, create=False)
        except UnsafeStorageLayoutError:
            return None

    def _reopen(self, dir_fd: int) -> int:
        # A fresh open file description, so concurrent scandir calls never
        # share (and race on) the long-lived fd's directory offset.
        return os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=dir_fd)

    def _disk_free_bytes(self) -> int:
        st = os.fstatvfs(self._blobs_fd)
        return st.f_bavail * st.f_frsize

    # --- BlobStore port --------------------------------------------------------

    def put(self, chunks: Iterable[bytes], max_bytes: int) -> BlobRef:
        """Store `chunks` as a new blob; see `ports.blobstore.BlobStore.put`.

        Each chunk may be any bytes-like object; its size is counted as
        `memoryview(chunk).nbytes` (not `len`), so a typed buffer can't
        smuggle more bytes past `max_bytes`. Non-buffers raise `TypeError`.

        Raises:
            LimitExceededError: over `max_bytes`, below the free-disk
                reserve, or ENOSPC/EDQUOT anywhere in the write/publish.
            UnsafeStorageLayoutError: the target shard dir is untrusted.
            RuntimeError: the id generator returned a non-canonical id or
                a colliding one (programming errors), or the store is closed.
        """
        self._require_open()
        if max_bytes < 0:
            raise ValueError("max_bytes must be >= 0")
        blob_id = self._ids.new_blob_id()
        # Defense in depth: the id becomes a filename, so never trust the
        # generator blindly (a bad id must not reach any filesystem call).
        if not is_ulid(blob_id):
            raise RuntimeError("id generator returned a non-canonical blob id")
        staging_name = f"{blob_id}{_STAGING_SUFFIX}"
        iterator = iter(chunks)
        fd = -1
        shard_fd = -1
        staged = False
        published = False
        try:
            try:
                fd = os.open(staging_name, _STAGING_FLAGS, self._file_mode, dir_fd=self._staging_fd)
                staged = True
                os.fchmod(fd, self._file_mode)  # os.open's mode is filtered by umask
                size, sha256 = self._copy(iterator, fd, max_bytes)
                os.fsync(fd)
                closing, fd = fd, -1
                os.close(closing)
                shard_fd = self._open_shard_for_write(blob_id[-2:])
                try:
                    # link+unlink (not rename): a crash between the two
                    # leaves a complete blob plus a stale staging file,
                    # never a half-written blob (ADR 0004).
                    os.link(
                        staging_name,
                        blob_id,
                        src_dir_fd=self._staging_fd,
                        dst_dir_fd=shard_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    # A fresh id collided with an existing blob: a generator
                    # bug, never something to overwrite or swallow.
                    raise RuntimeError(f"blob id collision on put: {blob_id!r}") from None
                published = True
                os.unlink(staging_name, dir_fd=self._staging_fd)
                staged = False
                os.fsync(shard_fd)
            except OSError as exc:
                if _is_out_of_space(exc):
                    raise LimitExceededError("not enough disk space for this blob") from exc
                raise
        except BaseException as exc:
            # Never leave a partial blob or staging file behind.
            if isinstance(exc, LimitExceededError):
                _close_iterator(iterator, chunks)
            if fd >= 0:
                _close_quietly(fd)
            if published and shard_fd >= 0:
                with suppress(OSError):
                    os.unlink(blob_id, dir_fd=shard_fd)
            if staged:
                with suppress(OSError):
                    os.unlink(staging_name, dir_fd=self._staging_fd)
            raise
        finally:
            if shard_fd >= 0:
                _close_quietly(shard_fd)
        return BlobRef(blob_id=blob_id, size=size, sha256=sha256)

    def _open_shard_for_write(self, shard: str) -> int:
        fd = self._open_dir(shard, self._blobs_fd, create=True)
        if fd is None:  # pragma: no cover - create=True never returns None
            raise UnsafeStorageLayoutError(f"could not open shard {shard}")
        return fd

    def _copy(self, chunks: Iterator[bytes], fd: int, max_bytes: int) -> tuple[int, str]:
        """Stream `chunks` into `fd`, enforcing the size limit and disk reserve."""
        digest = hashlib.sha256()
        total = 0
        for chunk in chunks:
            view = memoryview(chunk).cast("B")
            nbytes = view.nbytes
            if total + nbytes > max_bytes:
                # Fail fast: stop pulling and never write past the limit (C18).
                raise LimitExceededError("blob exceeds the size limit")
            if nbytes and self._free_bytes_provider() - nbytes < self._reserve_bytes:
                # Refuse before the disk actually fills (free-disk floor).
                raise LimitExceededError("not enough free disk space for this blob")
            _write_all(fd, view)
            digest.update(view)
            total += nbytes
        return total, digest.hexdigest()

    def open(self, blob_id: str) -> BinaryIO:
        """Open a blob for reading; see `ports.blobstore.BlobStore.open`.

        Anything but a regular, single-link file reached without symlinks
        through a trusted shard is `NotFoundError` (FIFOs return at once).
        """
        self._require_open()
        if not is_ulid(blob_id):
            raise NotFoundError("blob not found")
        shard_fd = self._open_shard_for_read(blob_id[-2:])
        if shard_fd is None:
            raise NotFoundError("blob not found")
        try:
            fd = os.open(blob_id, _READ_FLAGS, dir_fd=shard_fd)
        except OSError:
            raise NotFoundError("blob not found") from None
        finally:
            os.close(shard_fd)
        try:
            st = os.fstat(fd)
            # st_nlink == 1: a hardlink planted to a file outside the store
            # would otherwise be served (same check as intake, C27).
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise NotFoundError("blob not found")
            os.set_blocking(fd, True)
            return os.fdopen(fd, "rb")
        except BaseException:
            _close_quietly(fd)
            raise

    def delete(self, blob_id: str) -> None:
        """Delete a blob; see `ports.blobstore.BlobStore.delete` (idempotent, fail-safe).

        `unlink` removes only a directory entry inside a trusted shard; it
        never dereferences a symlink or reaches a symlinked/untrusted shard.
        """
        self._require_open()
        if not is_ulid(blob_id):
            return
        shard_fd = self._open_shard_for_read(blob_id[-2:])
        if shard_fd is None:
            return
        try:
            with suppress(FileNotFoundError, IsADirectoryError):
                os.unlink(blob_id, dir_fd=shard_fd)
        finally:
            os.close(shard_fd)

    def list_ids(self, created_before: datetime | None = None) -> set[str]:
        """List complete blob ids; see `ports.blobstore.BlobStore.list_ids`.

        Only regular files whose name is a canonical ULID *and* whose last
        two chars match their shard are listed; untrusted shards are skipped.
        `created_before` is compared against the file's mtime, set when the
        staging write completes (before the atomic publish).
        """
        self._require_open()
        cutoff = (
            ensure_utc(created_before, "created_before") if created_before is not None else None
        )
        ids: set[str] = set()
        listing_fd = self._reopen(self._blobs_fd)
        try:
            with os.scandir(listing_fd) as shards:
                for shard in shards:
                    if not _SHARD_NAME_RE.fullmatch(shard.name):
                        continue
                    if not shard.is_dir(follow_symlinks=False):
                        continue
                    shard_fd = self._open_shard_for_read(shard.name)
                    if shard_fd is None:
                        continue
                    try:
                        ids.update(self._list_shard(shard_fd, shard.name, cutoff))
                    finally:
                        os.close(shard_fd)
        finally:
            os.close(listing_fd)
        return ids

    def _list_shard(self, shard_fd: int, shard: str, cutoff: datetime | None) -> set[str]:
        found: set[str] = set()
        with os.scandir(shard_fd) as entries:
            for entry in entries:
                name = entry.name
                if not is_ulid(name) or name[-2:] != shard:
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if cutoff is not None:
                    mtime = datetime.fromtimestamp(
                        entry.stat(follow_symlinks=False).st_mtime, tz=UTC
                    )
                    if mtime >= cutoff:
                        continue
                found.add(name)
        return found

    def free_bytes(self) -> int:
        """Return free disk space (real, or from `free_bytes_provider` if injected)."""
        self._require_open()
        return max(0, self._free_bytes_provider())

    # --- adapter-specific maintenance (not part of the BlobStore port) -------

    def sweep_staging(self, older_than: timedelta) -> int:
        """Remove stale staging files (an interrupted `put` that never cleaned up).

        Not on the `BlobStore` port: "staging files" are an artifact of this
        adapter's atomic-write strategy, not a concept every backend has
        (e.g. an S3 adapter would sweep abandoned multipart uploads
        instead). Called periodically by the purge job (docs/operations.md).

        Returns:
            The number of staging files removed.
        """
        self._require_open()
        cutoff = self._clock.now() - older_than
        removed = 0
        listing_fd = self._reopen(self._staging_fd)
        try:
            with os.scandir(listing_fd) as entries:
                for entry in entries:
                    if not entry.name.endswith(_STAGING_SUFFIX):
                        continue
                    stem = entry.name[: -len(_STAGING_SUFFIX)]
                    if not is_ulid(stem) or not entry.is_file(follow_symlinks=False):
                        continue
                    st = entry.stat(follow_symlinks=False)
                    if datetime.fromtimestamp(st.st_mtime, tz=UTC) <= cutoff:
                        with suppress(FileNotFoundError):
                            os.unlink(entry.name, dir_fd=self._staging_fd)
                            removed += 1
        finally:
            os.close(listing_fd)
        return removed
