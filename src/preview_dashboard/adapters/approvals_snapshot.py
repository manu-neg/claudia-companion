"""FileSnapshotSink: the admin writes the pending-approvals snapshot file (C46 view, unit M5b).

One JSON file in its own directory (`<data_dir>/claudia-view/`, created by
install.sh as `pdash-admin:pdash` 0750; the viewer may read it, never the
Claudia DB). The directory is opened `O_DIRECTORY | O_NOFOLLOW` and must be
a real, not group/world-writable directory; the file is written as a temp
file (`O_EXCL | O_NOFOLLOW`, 0640, the directory's group) then renamed over
the old one, so the viewer only ever sees a whole snapshot. A missing
directory means no snapshot (the viewer shows "nothing can be confirmed").
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
import stat
from pathlib import Path
from typing import Final

from preview_dashboard.domain.errors import StorageUnavailableError

_log = logging.getLogger("preview_dashboard.approvals")

SNAPSHOT_DIR_NAME: Final = "claudia-view"
SNAPSHOT_FILE_NAME: Final = "pending-approvals.json"
FILE_MODE: Final = 0o640
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_TMP_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_UNSAFE_DIR_BITS: Final = stat.S_IWGRP | stat.S_IWOTH


def default_snapshot_path(data_dir: Path) -> Path:
    """`<data_dir>/claudia-view/pending-approvals.json` (= viewer `claudia_approvals_snapshot`)."""
    return data_dir / SNAPSHOT_DIR_NAME / SNAPSHOT_FILE_NAME


class FileSnapshotSink:
    """`ApprovalsSnapshotSink` over one file, replaced atomically.

    Args:
        path: absolute snapshot path; its directory must already exist.

    Raises (constructor):
        ValueError: `path` is not absolute.
    """

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("snapshot path must be absolute")
        self._dir = path.parent
        self._name = path.name

    def write(self, data: bytes) -> None:
        """Replace the snapshot with `data` (0640, directory's group).

        Raises:
            StorageUnavailableError: the directory is missing/unsafe or the write failed.
        """
        dfd = self._open_dir()
        tmp = f".{self._name}.{secrets.token_hex(8)}.tmp"
        try:
            fd = os.open(tmp, _TMP_FLAGS, FILE_MODE, dir_fd=dfd)
            try:
                os.fchmod(fd, FILE_MODE)  # umask-independent
                dir_gid = os.fstat(dfd).st_gid
                if os.fstat(fd).st_gid != dir_gid:
                    # The viewer reads through the directory's group; best effort.
                    with contextlib.suppress(OSError):
                        os.fchown(fd, -1, dir_gid)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self._name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dfd)
            raise StorageUnavailableError("approvals snapshot could not be written") from exc
        finally:
            os.close(dfd)

    def clear(self) -> None:
        """Remove the snapshot if present; never raises."""
        try:
            dfd = self._open_dir()
        except StorageUnavailableError:
            return
        try:
            os.unlink(self._name, dir_fd=dfd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            _log.error("approvals snapshot could not be removed (%s)", type(exc).__name__)
        finally:
            os.close(dfd)

    def _open_dir(self) -> int:
        try:
            dfd = os.open(self._dir, _DIR_FLAGS)
        except OSError as exc:
            raise StorageUnavailableError("approvals snapshot directory is unavailable") from exc
        if os.fstat(dfd).st_mode & _UNSAFE_DIR_BITS:
            os.close(dfd)
            raise StorageUnavailableError("approvals snapshot directory is group/world-writable")
        return dfd


__all__ = [
    "FILE_MODE",
    "SNAPSHOT_DIR_NAME",
    "SNAPSHOT_FILE_NAME",
    "FileSnapshotSink",
    "default_snapshot_path",
]
