"""KbStore port: byte-level storage of the Claudia knowledge base (C53).

The application layer (`application/claudia/kb.py`) decides *what* may be
written (layout, caps, secret scan); an implementation only stores bytes under
validated relative paths. Implementation: `adapters/kb_store.py`; fake:
`tests/fakes.py`-style in-memory store in the KB tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from preview_dashboard.domain.errors import StorageUnavailableError


@dataclass(frozen=True, slots=True)
class KbStats:
    """Size of the whole KB: number of `.md` files and their total bytes."""

    files: int
    total_bytes: int


class KbBusyError(StorageUnavailableError):
    """Another process held the KB locks for the whole wait (e.g. a gardener run).

    Nothing was changed. A caller may retry later instead of treating it as
    a broken store (fixcheck-a-2: no writer can land while the lock is held).
    """


# Called with (current size of the target or None, whole-KB stats); raises to refuse.
KbAdmit = Callable[[int | None, KbStats], None]


class KbStore(Protocol):
    """Confined store of `.md` files below one root; paths are `/`-separated relpaths."""

    def read(self, relpath: str) -> bytes | None:
        """Return the file's bytes, or None when it does not exist.

        Raises:
            StorageUnavailableError: the path is not a plain single-link file
                (symlink, FIFO, hardlink ...), is too big, or unreadable.
        """
        ...

    def size(self, relpath: str) -> int | None:
        """Return the file's size in bytes, or None when it does not exist."""
        ...

    def write(self, relpath: str, data: bytes) -> None:
        """Atomically create or replace the file (parents created).

        Raises:
            StorageUnavailableError: the target or a parent is not a plain
                directory/file, or the write failed.
        """
        ...

    def delete(self, relpath: str) -> bool:
        """Remove the file; True if it existed.

        Raises:
            StorageUnavailableError: the target is not a plain file.
        """
        ...

    def stats(self) -> KbStats:
        """Count the `.md` files and their bytes (odd entries are skipped)."""
        ...

    def commit(self, message: str) -> str | None:
        """Commit every change since the last commit; return the id, None if clean.

        Raises:
            KbBusyError: another process held the KB locks too long.
            StorageUnavailableError: git failed.
        """
        ...

    def write_admitted(self, relpath: str, data: bytes, admit: KbAdmit) -> None:
        """Like `write`, but `admit(size, stats)` runs under the same lock hold (fixcheck-a-3).

        So a cap check and the write it allows are one step across processes.

        Raises:
            KbBusyError: another process held the KB locks too long.
            StorageUnavailableError: see `write`.
            Exception: whatever `admit` raises (nothing is written).
        """
        ...

    def update(self, relpath: str, fn: Callable[[bytes | None], bytes | None]) -> bool:
        """Read, transform and write one file under a single lock hold.

        `fn(current)` returns the new bytes, or None to leave the file alone.
        So a concurrent writer's change can't be lost between read and write.
        Returns True if the file was written.

        Raises:
            KbBusyError: another process held the KB locks too long.
            StorageUnavailableError: see `read` and `write`.
            Exception: whatever `fn` raises (nothing is written).
        """
        ...

    def run_locked[T](self, fn: Callable[[], T], *, wait_s: float | None = None) -> T:
        """Run `fn` holding the same locks as a write (git work-tree steps, fixcheck-a-2).

        `fn` must not call this store's own mutating methods (the locks are
        not re-entrant). `wait_s` overrides the store's lock wait.

        Raises:
            KbBusyError: the locks could not be taken in time (`fn` did not run).
            Exception: whatever `fn` raises.
        """
        ...
