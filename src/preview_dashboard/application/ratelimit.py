"""Publish rate limiting: the `RateLimiter` protocol and an in-process sliding window.

Caps how many publishes may *start* per window (docs/security.md C18), so a
prompt-injected agent publishing in a loop hits a wall long before the
quotas. In-process by design: only the single admin process publishes; a
restart resets the window (accepted — quotas still bound the damage).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import timedelta
from typing import Protocol

from preview_dashboard.domain.errors import RateLimitedError


class RateLimiter(Protocol):
    """Admits or refuses one more operation."""

    def acquire(self) -> None:
        """Record one operation now.

        Raises:
            RateLimitedError: the rate limit is reached (nothing recorded).
        """
        ...


class SlidingWindowRateLimiter:
    """At most `limit` acquisitions within any trailing `window` (thread-safe).

    Every attempt counts, including publishes that later fail: failures
    (e.g. repeated secret-scan probes) must not be free.

    Timed with a **monotonic** clock: a wall clock stepped forward (NTP,
    manual change) would expire every entry at once and reopen the window
    early; a monotonic clock can't be moved by anyone.

    Args:
        limit: acquisitions allowed per window (> 0).
        window: window length (> 0).
        monotonic: seconds from a monotonic source (injectable for tests).

    Raises:
        ValueError: non-positive `limit` or `window`.
    """

    def __init__(
        self,
        *,
        limit: int,
        window: timedelta,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit <= 0:
            raise ValueError("limit must be > 0")
        if window <= timedelta(0):
            raise ValueError("window must be > 0")
        self._limit = limit
        self._window = window.total_seconds()
        self._monotonic = monotonic
        self._stamps: deque[float] = deque()
        # The admin API may run publishes on a thread pool.
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Record one acquisition now.

        Raises:
            RateLimitedError: (a `LimitExceededError`) `limit` acquisitions
                already happened within the trailing window.
        """
        with self._lock:
            now = self._monotonic()
            cutoff = now - self._window
            while self._stamps and self._stamps[0] <= cutoff:
                self._stamps.popleft()
            if len(self._stamps) >= self._limit:
                raise RateLimitedError("publish rate limit reached; try again later")
            self._stamps.append(now)
