"""FsOwnerMediaStore: owner voice notes / photos under the admin-only Claudia dir (C61).

Implements `ports.owner_media.OwnerMediaStore`: one `<ULID>.ogg|.jpg` file
per inbox message in `<data_dir>/claudia/media/` (dir 0700, files 0600,
owner = this process's uid). Every access goes through directory file
descriptors opened with `O_NOFOLLOW`, names come only from a validated
ULID plus a fixed suffix, and a looser, foreign-owned or symlinked entry
is refused (fail closed; nothing is "fixed"). Files are written atomically,
capped in count and size, and swept by age.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import stat
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from preview_dashboard.domain.errors import (
    ConflictError,
    LimitExceededError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.domain.owner_media import MessageKind, media_max_bytes

MEDIA_DIR_NAME: Final = "media"  # under `<data_dir>/claudia/` (ADR 0034)
MEDIA_DIR_MODE: Final = 0o700
MEDIA_FILE_MODE: Final = 0o600
MAX_WAITING: Final = 50
_SUFFIXES: Final = {MessageKind.VOICE: ".ogg", MessageKind.PHOTO: ".jpg"}
_TMP_SUFFIX: Final = ".tmp"
_ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
_ENTRY_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}\.(ogg|jpg|tmp)")
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_WRITE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# Any group/other bit is "looser" (a POSIX ACL shows up in the group bits).
_FOREIGN_BITS: Final = stat.S_IRWXG | stat.S_IRWXO

_log = logging.getLogger(__name__)


def _check_id(media_id: object) -> str:
    if not isinstance(media_id, str) or not _ULID_RE.fullmatch(media_id):
        raise ValidationError("media id must be a ULID")
    return media_id


def _suffix(kind: MessageKind) -> str:
    try:
        return _SUFFIXES[MessageKind(kind)]
    except (KeyError, ValueError):
        raise ValidationError("a text message has no media file") from None


def _check_private_dir(st: os.stat_result, what: str) -> None:
    if not stat.S_ISDIR(st.st_mode):
        raise StorageUnavailableError(f"{what} must be a real directory")
    if st.st_uid != os.geteuid() or st.st_mode & _FOREIGN_BITS:
        raise StorageUnavailableError(f"{what} must be private to the admin user")


class FsOwnerMediaStore:
    """Media files under `claudia_dir/media` (created 0700 on the first save).

    Args:
        claudia_dir: the admin-only `<data_dir>/claudia` directory (created
            by `connect_claudia`, 0700); refused if it is anything looser.
        max_waiting: how many files may wait at once.
    """

    def __init__(self, claudia_dir: Path, *, max_waiting: int = MAX_WAITING) -> None:
        self._parent = Path(claudia_dir)
        self._max = max_waiting

    @contextlib.contextmanager
    def _media_dir(self, *, create: bool) -> Iterator[int]:
        """A validated fd of the media dir (FileNotFoundError if missing and not `create`)."""
        parent_fd = os.open(self._parent, _DIR_FLAGS)
        try:
            _check_private_dir(os.fstat(parent_fd), "Claudia directory")
            created = False
            try:
                fd = os.open(MEDIA_DIR_NAME, _DIR_FLAGS, dir_fd=parent_fd)
            except FileNotFoundError:
                if not create:
                    raise
                with contextlib.suppress(FileExistsError):
                    os.mkdir(MEDIA_DIR_NAME, MEDIA_DIR_MODE, dir_fd=parent_fd)
                    created = True
                fd = os.open(MEDIA_DIR_NAME, _DIR_FLAGS, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        try:
            if created:
                os.fchmod(fd, MEDIA_DIR_MODE)  # mkdir's mode is filtered by the umask
            _check_private_dir(os.fstat(fd), "media directory")
            yield fd
        finally:
            os.close(fd)

    def save(self, media_id: str, kind: MessageKind, data: bytes) -> None:
        """See `OwnerMediaStore.save` (temp file, fsync, rename; all under the dir fd)."""
        name = _check_id(media_id) + _suffix(kind)
        cap = media_max_bytes(MessageKind(kind))
        if not isinstance(data, bytes) or not 1 <= len(data) <= cap:
            raise ValidationError(f"media must be 1..{cap} bytes")
        tmp = media_id + _TMP_SUFFIX
        try:
            with self._media_dir(create=True) as dir_fd:
                if name in os.listdir(dir_fd):
                    raise ConflictError("media already stored")
                waiting = sum(1 for e in os.listdir(dir_fd) if not e.endswith(_TMP_SUFFIX))
                if waiting >= self._max:
                    raise LimitExceededError("too many photos / voice notes are waiting")
                fd = os.open(tmp, _WRITE_FLAGS, MEDIA_FILE_MODE, dir_fd=dir_fd)
                try:
                    os.fchmod(fd, MEDIA_FILE_MODE)
                    with os.fdopen(fd, "wb", closefd=False) as handle:
                        handle.write(data)
                        handle.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)
                try:
                    os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                except OSError:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp, dir_fd=dir_fd)
                    raise
        except OSError:
            raise StorageUnavailableError("media store is not writable") from None

    def load(self, media_id: str, kind: MessageKind) -> bytes | None:
        """See `OwnerMediaStore.load`; anything unexpected reads as absent (logged by id)."""
        try:
            name = _check_id(media_id) + _suffix(kind)
            cap = media_max_bytes(MessageKind(kind))
            with self._media_dir(create=False) as dir_fd:
                fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
                try:
                    st = os.fstat(fd)
                    if (
                        not stat.S_ISREG(st.st_mode)
                        or st.st_uid != os.geteuid()
                        or st.st_mode & _FOREIGN_BITS
                        or st.st_nlink != 1
                        or not 1 <= st.st_size <= cap
                    ):
                        _log.warning("media %s refused: unsafe or oversized file", media_id)
                        return None
                    with os.fdopen(fd, "rb", closefd=False) as handle:
                        data = handle.read(cap + 1)
                finally:
                    os.close(fd)
        except FileNotFoundError:
            return None
        except (OSError, ValidationError, StorageUnavailableError) as exc:
            _log.warning("media %s not readable (%s)", media_id, type(exc).__name__)
            return None
        return data if 1 <= len(data) <= cap else None

    def discard(self, media_id: str, kind: MessageKind) -> None:
        """See `OwnerMediaStore.discard`."""
        with contextlib.suppress(OSError, ValidationError, StorageUnavailableError):
            name = _check_id(media_id) + _suffix(kind)
            with self._media_dir(create=False) as dir_fd:
                os.unlink(name, dir_fd=dir_fd)

    def purge_older_than(self, seconds: float) -> int:
        """See `OwnerMediaStore.purge_older_than`; an unusable dir sweeps nothing."""
        cutoff, removed = time.time() - seconds, 0
        try:
            with self._media_dir(create=False) as dir_fd:
                for entry in os.listdir(dir_fd):
                    if not _ENTRY_RE.fullmatch(entry):
                        continue
                    with contextlib.suppress(OSError):
                        st = os.stat(entry, dir_fd=dir_fd, follow_symlinks=False)
                        if st.st_mtime < cutoff:
                            os.unlink(entry, dir_fd=dir_fd)
                            removed += 1
        except (OSError, StorageUnavailableError):
            return removed
        return removed
