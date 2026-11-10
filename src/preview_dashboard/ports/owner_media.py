"""OwnerMediaStore port: checked owner voice notes / photos waiting for the host (C61).

Security obligations for every implementation (docs/security.md C61):
- **Private and confined:** files readable by the admin user only (dir
  0700, files 0600); names come only from a validated ULID plus a fixed
  per-kind suffix, so no path can escape the store; symlinks refused.
- **Bounded:** a file is never read past its kind's cap; the number of
  waiting files is capped.
- **Short-lived:** files are deleted once the host releases them, with
  their message, and by an age sweep (<= 24 h).
- **Never log content** (ids and counts only).
"""

from __future__ import annotations

from typing import Protocol

from preview_dashboard.domain.owner_media import MessageKind


class OwnerMediaStore(Protocol):
    """Stores one media file per inbox message, keyed by its `media_id` (a ULID)."""

    def save(self, media_id: str, kind: MessageKind, data: bytes) -> None:
        """Write a new file atomically (0600).

        Raises:
            ValidationError: bad id, a text kind, or data over the kind's cap.
            ConflictError: the id already has a file.
            LimitExceededError: too many files are waiting.
            StorageUnavailableError: the store cannot be written.
        """
        ...

    def load(self, media_id: str, kind: MessageKind) -> bytes | None:
        """The file's bytes, or None if absent, unsafe or over the kind's cap."""
        ...

    def discard(self, media_id: str, kind: MessageKind) -> None:
        """Delete the file; absent files and invalid ids are ignored."""
        ...

    def purge_older_than(self, seconds: float) -> int:
        """Delete files (and stray temp files) older than `seconds`; return the count."""
        ...
