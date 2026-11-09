"""FileHaltFlag: the Claudia host's persisted KB halt as a marker file (C53, newcode-1).

A failed KB work-tree restore halts the host; the marker in the admin-only
state dir (`/var/lib/claudia-host`) keeps it halted across a crash, a
`Restart=on-failure` or a deploy until `/new` finds a clean tree.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from preview_dashboard.domain.errors import StorageUnavailableError

_log = logging.getLogger(__name__)
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC


class FileHaltFlag:
    """`HaltFlag` over one file; any entry at the path (even a symlink) means halted.

    Args:
        path: absolute path of the marker (its directory must exist).

    Raises (constructor):
        ValueError: `path` is not absolute.
    """

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("halt flag path must be absolute")
        self._path = path

    def is_set(self) -> bool:
        """See `HaltFlag.is_set`; an unreadable state counts as set (fail closed)."""
        try:
            os.lstat(self._path)
        except FileNotFoundError:
            return False
        except OSError as exc:
            _log.error("KB halt flag unreadable (%s); staying halted", type(exc).__name__)
            return True
        return True

    def set(self) -> None:
        """See `HaltFlag.set`; fsynced so a crash right after keeps it."""
        try:
            fd = os.open(self._path, _CREATE_FLAGS, 0o600)
            try:
                os.write(fd, b"halted\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            self._sync_dir()
        except OSError as exc:
            raise StorageUnavailableError("could not persist the KB halt") from exc

    def clear(self) -> None:
        """See `HaltFlag.clear`; a missing flag is already clear."""
        try:
            os.unlink(self._path)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise StorageUnavailableError("could not clear the KB halt") from exc
        try:
            self._sync_dir()
        except OSError as exc:
            # Removed but maybe not durable: a crash now only re-halts (fail closed).
            _log.warning("KB halt flag dir sync failed (%s)", type(exc).__name__)

    def _sync_dir(self) -> None:
        dfd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


__all__ = ["FileHaltFlag"]
