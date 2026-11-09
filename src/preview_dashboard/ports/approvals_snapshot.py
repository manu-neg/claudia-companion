"""Port for the admin's pending-approvals snapshot sink (docs/security.md C46 "independent view").

The admin writes a sanitized JSON list of open approval requests for the
viewer (unit M5b); the viewer reads it through `ports.kb_source`'s
`ApprovalsSnapshotSource` (unit M8) and never opens the Claudia DB (S1).
"""

from __future__ import annotations

from typing import Protocol


class ApprovalsSnapshotSink(Protocol):
    """Where the snapshot bytes go (one file, replaced atomically)."""

    def write(self, data: bytes) -> None:
        """Replace the snapshot with `data`.

        Raises:
            StorageUnavailableError: it could not be written (the old one stays or is gone).
        """
        ...

    def clear(self) -> None:
        """Remove the snapshot (the viewer then shows "nothing can be confirmed"); never raises."""
        ...
