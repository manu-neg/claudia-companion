"""SystemClock: the real Clock adapter, backed by the OS wall clock.

Always returns UTC so every timestamp the core sees is already normalized;
`domain.models.ensure_utc` still guards call sites that accept other clocks.
"""

from __future__ import annotations

from datetime import UTC, datetime


class SystemClock:
    """Clock implementation backed by `datetime.now(UTC)`."""

    def now(self) -> datetime:
        """Return the current time, timezone-aware UTC."""
        return datetime.now(UTC)
