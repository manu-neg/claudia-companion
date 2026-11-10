"""Photo files in a Claudia run's work dir (docs/security.md C62): `RunMediaFiles` over the fs.

A photo turn's JPEG goes to `<workdir>/<window id>/media/<media ULID>.jpg`,
0600 in 0700 dirs, written through dir fds with `O_NOFOLLOW` (a symlinked
or foreign-owned dir is refused, never fixed) and `O_EXCL`. The host
deletes it when the run ends and sweeps leftovers at start (a crash).
Names come only from a validated window UUID and media ULID.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import stat
from pathlib import Path
from typing import Final

from preview_dashboard.domain.approvals import WindowId, parse_window_id
from preview_dashboard.domain.errors import StorageUnavailableError, ValidationError
from preview_dashboard.domain.models import is_ulid

_log = logging.getLogger(__name__)

MEDIA_DIR: Final = "media"
PHOTO_SUFFIX: Final = ".jpg"
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_MAX_SWEEP: Final = 4096


def _check_dir(fd: int) -> None:
    """Our own dir, not group/world-writable (anything else is refused, never fixed)."""
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise StorageUnavailableError("run media dir has an unsafe owner or mode")


def _subdir(parent_fd: int, name: str) -> int:
    """Open (creating 0700 if missing) the dir `name` under `parent_fd`; no symlink followed."""
    with contextlib.suppress(FileExistsError):
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    try:
        _check_dir(fd)
    except BaseException:
        os.close(fd)
        raise
    return fd


class WorkdirPhotoFiles:
    """`RunMediaFiles` under the host's run work dir.

    Args:
        workdir: the runs' cwd (`--workdir`, root 0700 by install.sh).
    """

    def __init__(self, workdir: Path) -> None:
        if not workdir.is_absolute():
            raise ValueError("workdir must be an absolute path")
        self._workdir = workdir

    def put_photo(self, window_id: WindowId, media_id: str, data: bytes) -> str:
        """See `RunMediaFiles.put_photo`."""
        window = parse_window_id(window_id)
        if not is_ulid(media_id):
            raise ValidationError("invalid media id")
        name = media_id + PHOTO_SUFFIX
        fds: list[int] = []
        try:
            root = os.open(self._workdir, _DIR_FLAGS)
            fds.append(root)
            fds.append(_subdir(root, window))
            fds.append(_subdir(fds[-1], MEDIA_DIR))
            self._write(fds[-1], name, data)
        except OSError as exc:
            raise StorageUnavailableError(f"photo not written ({type(exc).__name__})") from None
        finally:
            for fd in fds:
                os.close(fd)
        return str(self._workdir / window / MEDIA_DIR / name)

    @staticmethod
    def _write(dir_fd: int, name: str, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
        try:
            os.fchmod(fd, 0o600)  # whatever the umask
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
        except BaseException:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=dir_fd)
            raise
        os.close(fd)

    def _parts(self, path: str) -> tuple[str, str] | None:
        """`(window, file name)` of a path `put_photo` returned, else None."""
        try:
            rel = Path(path).relative_to(self._workdir).parts
        except ValueError:
            return None
        if len(rel) != 3 or rel[1] != MEDIA_DIR or not _UUID_RE.fullmatch(rel[0]):
            return None
        stem, suffix = rel[2][: -len(PHOTO_SUFFIX)], rel[2][-len(PHOTO_SUFFIX) :]
        if suffix != PHOTO_SUFFIX or not is_ulid(stem):
            return None
        return rel[0], rel[2]

    def discard(self, path: str) -> None:
        """See `RunMediaFiles.discard`."""
        parts = self._parts(path)
        if parts is None:
            _log.error("photo discard refused: not a run media path")
            return
        window, name = parts
        try:
            self._remove(window, (name,))
        except OSError as exc:
            _log.error("photo not deleted (%s)", type(exc).__name__)

    def _remove(self, window: str, names: tuple[str, ...] | None) -> int:
        """Unlink `names` (None = every photo) in the window's media dir, then prune empty dirs."""
        root = os.open(self._workdir, _DIR_FLAGS)
        try:
            try:
                win = os.open(window, _DIR_FLAGS, dir_fd=root)
            except FileNotFoundError:
                return 0
            try:
                removed = self._remove_in(win, names)
                with contextlib.suppress(OSError):
                    os.rmdir(MEDIA_DIR, dir_fd=win)
            finally:
                os.close(win)
            with contextlib.suppress(OSError):
                os.rmdir(window, dir_fd=root)  # only if empty
            return removed
        finally:
            os.close(root)

    @staticmethod
    def _remove_in(win_fd: int, names: tuple[str, ...] | None) -> int:
        try:
            media = os.open(MEDIA_DIR, _DIR_FLAGS, dir_fd=win_fd)
        except FileNotFoundError:
            return 0
        removed = 0
        try:
            listed = names if names is not None else tuple(os.listdir(media)[:_MAX_SWEEP])
            for name in listed:
                if not name.endswith(PHOTO_SUFFIX):
                    continue
                try:
                    os.unlink(name, dir_fd=media)
                    removed += 1
                except FileNotFoundError:
                    continue
        finally:
            os.close(media)
        return removed

    def sweep(self) -> int:
        """See `RunMediaFiles.sweep` (window dirs are UUID-named; nothing else is touched)."""
        try:
            entries = os.listdir(self._workdir)[:_MAX_SWEEP]
        except OSError as exc:
            _log.error("photo sweep failed (%s)", type(exc).__name__)
            return 0
        removed = 0
        for window in entries:
            if not _UUID_RE.fullmatch(window):
                continue
            try:
                removed += self._remove(window, None)
            except OSError as exc:
                _log.error("photo sweep of a window failed (%s)", type(exc).__name__)
        if removed:
            _log.warning("start: %d leftover photo(s) deleted from the run work dir", removed)
        return removed
