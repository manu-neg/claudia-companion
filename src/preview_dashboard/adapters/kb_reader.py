"""Read-only filesystem sources for the viewer: the knowledge base walk and the approvals snapshot.

`FsKbReader` walks the KB root fd-relative from a directory opened
`O_DIRECTORY|O_NOFOLLOW` and keeps only regular, single-link `.md` files with
safe names, within depth/count/size budgets (docs/security.md C57, I2). Every
other entry is skipped and only *counted* (logs never carry names, C29).
`FileApprovalsSnapshot` reads the admin's pending-approvals JSON the same
careful way. Neither class ever writes, lists raw directories to callers or
takes a path from a request.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.ports.kb_source import KbWalk, RawNote

logger = logging.getLogger("preview_dashboard.viewer.kb")

_KIB = 1024
# C57 budgets. Depth counts directories below the root (topics/<cat>/ is depth 2).
MAX_DEPTH = 4
MAX_FILES = 2000
MAX_FILE_BYTES = 64 * _KIB
MAX_TOTAL_BYTES = 8 * _KIB * _KIB
# Per directory: a planted directory with millions of entries can't stall a request.
MAX_ENTRIES_PER_DIR = 4096
MAX_SNAPSHOT_BYTES = 256 * _KIB
# Names: ASCII letters, digits, `.`, `_`, `-`; never a leading dot (`.git`, `.obsidian`, ...).
_NAME_RE = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK: a FIFO swapped in after the lstat can't block the open.
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_UNSAFE_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH


@dataclass(slots=True)
class _Budget:
    """Mutable counters of one walk."""

    files: int = 0
    total_bytes: int = 0
    skipped: int = 0
    truncated: bool = False


def _safe_dir(st: os.stat_result, expected_uid: int) -> bool:
    """A directory we may descend into: owned by the expected user, not group/world-writable."""
    return (
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == expected_uid
        and not st.st_mode & _UNSAFE_WRITE_BITS
    )


def _read_capped(fd: int, cap: int) -> bytes | None:
    """Read at most `cap` bytes; None when the file holds more (it grew after fstat)."""
    chunks: list[bytes] = []
    remaining = cap + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 64 * _KIB))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    return None if len(data) > cap else data


class FsKbReader:
    """`KbSource` over one directory, re-checked and re-walked on every call (no cache).

    Args:
        root: absolute KB root (config `kb_root`).
        expected_uid: owner every directory must have (root in production).
    """

    def __init__(self, root: Path, *, expected_uid: int = 0) -> None:
        self._root = root
        self._uid = expected_uid

    def walk(self) -> KbWalk:
        """Walk the KB once within the C57 budgets.

        Raises:
            StorageUnavailableError: the root is missing, a symlink (anywhere in its path),
                not a directory, not owned by `expected_uid`, or group/world-writable.
        """
        root_fd = self._open_root()
        budget = _Budget()
        notes: list[RawNote] = []
        try:
            self._walk_dir(root_fd, (), notes, budget)
        finally:
            os.close(root_fd)
        if budget.skipped or budget.truncated:
            # Counts only: names could carry note content or be attacker-chosen (C29).
            logger.info(
                "kb walk: %d notes, %d entries skipped, truncated=%s",
                len(notes),
                budget.skipped,
                budget.truncated,
            )
        return KbWalk(notes=tuple(notes), skipped=budget.skipped, truncated=budget.truncated)

    def _open_root(self) -> int:
        raw = str(self._root)
        # O_NOFOLLOW only guards the last component; a symlinked parent is refused here.
        if not self._root.is_absolute() or os.path.realpath(raw) != raw:
            raise StorageUnavailableError("knowledge base root is not a plain absolute path")
        try:
            fd = os.open(raw, _DIR_FLAGS)
        except OSError:
            raise StorageUnavailableError("knowledge base root unavailable") from None
        try:
            if not _safe_dir(os.fstat(fd), self._uid):
                raise StorageUnavailableError("knowledge base root is not safe to read")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _walk_dir(
        self, dir_fd: int, parts: tuple[str, ...], notes: list[RawNote], budget: _Budget
    ) -> None:
        try:
            with os.scandir(dir_fd) as entries:
                names = []
                for count, entry in enumerate(entries):
                    if count >= MAX_ENTRIES_PER_DIR:
                        budget.truncated = True
                        break
                    names.append(entry.name)
        except OSError:
            budget.skipped += 1
            return
        for name in sorted(names):
            if budget.truncated:
                return
            if _NAME_RE.fullmatch(name) is None:
                budget.skipped += 1
                continue
            try:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except OSError:
                budget.skipped += 1
                continue
            if stat.S_ISDIR(st.st_mode):
                self._descend(dir_fd, name, st, parts, notes, budget)
            elif stat.S_ISREG(st.st_mode) and name.endswith(".md"):
                note = self._read_note(dir_fd, name, st, parts, budget)
                if note is not None:
                    notes.append(note)
            else:
                # Symlinks, FIFOs, sockets, devices, non-.md files.
                budget.skipped += 1

    def _descend(
        self,
        dir_fd: int,
        name: str,
        st: os.stat_result,
        parts: tuple[str, ...],
        notes: list[RawNote],
        budget: _Budget,
    ) -> None:
        if len(parts) + 1 > MAX_DEPTH or not _safe_dir(st, self._uid):
            budget.skipped += 1
            return
        try:
            child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
        except OSError:
            budget.skipped += 1
            return
        try:
            opened = os.fstat(child)
            # Swapped between lstat and open (a different inode now): skip it.
            if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino) or not _safe_dir(
                opened, self._uid
            ):
                budget.skipped += 1
                return
            self._walk_dir(child, (*parts, name), notes, budget)
        finally:
            os.close(child)

    def _read_note(
        self,
        dir_fd: int,
        name: str,
        st: os.stat_result,
        parts: tuple[str, ...],
        budget: _Budget,
    ) -> RawNote | None:
        if budget.files >= MAX_FILES:
            budget.truncated = True
            budget.skipped += 1
            return None
        if st.st_nlink != 1 or st.st_size > MAX_FILE_BYTES:
            budget.skipped += 1
            return None
        if budget.total_bytes + st.st_size > MAX_TOTAL_BYTES:
            budget.truncated = True
            budget.skipped += 1
            return None
        data = self._read_file(dir_fd, name, st)
        if data is None or budget.total_bytes + len(data) > MAX_TOTAL_BYTES:
            budget.skipped += 1
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            budget.skipped += 1
            return None
        budget.files += 1
        budget.total_bytes += len(data)
        modified = datetime.fromtimestamp(st.st_mtime, tz=UTC)
        return RawNote(relpath="/".join((*parts, name)), text=text, modified=modified)

    @staticmethod
    def _read_file(dir_fd: int, name: str, st: os.stat_result) -> bytes | None:
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        except OSError:
            return None
        try:
            opened = os.fstat(fd)
            # Re-check on the open file: same inode, still regular, single link, small.
            if (
                (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size > MAX_FILE_BYTES
            ):
                return None
            return _read_capped(fd, MAX_FILE_BYTES)
        except OSError:
            return None
        finally:
            os.close(fd)


class FileApprovalsSnapshot:
    """`ApprovalsSnapshotSource` over one JSON file written by the admin (M5b).

    Fail closed: an absent, symlinked, multi-link, group/world-writable, oversized or
    unreadable file — or one in a group/world-writable directory — reads as None.

    Args:
        path: absolute snapshot path (config `claudia_approvals_snapshot`).
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def read(self) -> bytes | None:
        """Return the snapshot's bytes (≤ 256 KiB), or None."""
        raw = str(self._path)
        parent = os.path.dirname(raw)
        if not self._path.is_absolute() or os.path.realpath(parent) != parent:
            return None
        try:
            dir_fd = os.open(parent, _DIR_FLAGS)
        except OSError:
            return None
        try:
            if os.fstat(dir_fd).st_mode & _UNSAFE_WRITE_BITS:
                return None
            return self._read_in(dir_fd, os.path.basename(raw))
        except OSError:
            return None
        finally:
            os.close(dir_fd)

    @staticmethod
    def _read_in(dir_fd: int, name: str) -> bytes | None:
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_nlink != 1
                or st.st_mode & _UNSAFE_WRITE_BITS
                or st.st_size > MAX_SNAPSHOT_BYTES
            ):
                return None
            return _read_capped(fd, MAX_SNAPSHOT_BYTES)
        finally:
            os.close(fd)
