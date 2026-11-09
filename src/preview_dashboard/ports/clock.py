"""Clock port: the only source of "now" for the core.

Injected so purge/retention logic is deterministic under test (FixedClock).
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Source of the current time."""

    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        ...
