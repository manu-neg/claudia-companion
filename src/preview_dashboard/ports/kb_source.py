"""Read-only sources for the viewer's knowledge map (C57) and pending-approvals list.

`KbSource` walks the knowledge base and hands back the notes that passed the
walk's filters; `ApprovalsSnapshotSource` returns the raw bytes of the
admin-written pending-approvals snapshot. Neither ever writes. Implementations:
`adapters/kb_reader.py` (both); fakes: in the knowledge-map tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True, slots=True)
class RawNote:
    """One note that passed the walk's filters.

    Attributes:
        relpath: `/`-separated path below the KB root (never shown as a filesystem path to
            the browser; it only feeds the opaque id and the category).
        text: the note, decoded as strict UTF-8.
        modified: the file's mtime, timezone-aware UTC.
    """

    relpath: str
    text: str
    modified: datetime


@dataclass(frozen=True, slots=True)
class KbWalk:
    """Result of one bounded walk.

    Attributes:
        notes: accepted notes in path order.
        skipped: entries refused by a filter (symlink, FIFO, hardlink, dotfile, bad name,
            too deep, oversize, not `.md`, undecodable, over the count or byte budget).
        truncated: the walk stopped early on the file-count or total-byte budget.
    """

    notes: tuple[RawNote, ...]
    skipped: int
    truncated: bool


class KbSource(Protocol):
    """The knowledge base, read live and read only."""

    def walk(self) -> KbWalk:
        """Walk the KB once (fresh every call: no cache, no copies).

        Raises:
            StorageUnavailableError: the root is missing or unsafe (symlinked, not owned by
                the expected user, group/world-writable): the map is off (fail closed).
        """
        ...


class ApprovalsSnapshotSource(Protocol):
    """The admin's sanitized snapshot of open approvals (a JSON file the viewer may read)."""

    def read(self) -> bytes | None:
        """Return the snapshot bytes, or None when absent or unsafe to read (fail closed)."""
        ...
