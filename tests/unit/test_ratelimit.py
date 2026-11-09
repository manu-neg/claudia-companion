"""Unit tests for SlidingWindowRateLimiter (docs/security.md C18)."""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from preview_dashboard.application import SlidingWindowRateLimiter
from preview_dashboard.domain.errors import LimitExceededError, RateLimitedError
from tests.app_support import FakeMonotonic

pytestmark = pytest.mark.unit

HOUR = timedelta(hours=1)


def test_allows_up_to_limit_then_refuses() -> None:
    limiter = SlidingWindowRateLimiter(limit=2, window=HOUR, monotonic=FakeMonotonic())
    limiter.acquire()
    limiter.acquire()
    with pytest.raises(RateLimitedError):
        limiter.acquire()


def test_window_slides_per_entry() -> None:
    mono = FakeMonotonic()
    limiter = SlidingWindowRateLimiter(limit=2, window=HOUR, monotonic=mono)
    limiter.acquire()  # t=0
    mono.advance(30 * 60)
    limiter.acquire()  # t=30m
    mono.advance(29 * 60 + 59)
    with pytest.raises(LimitExceededError):
        limiter.acquire()
    mono.advance(1)  # t=60m: first entry expires (boundary)
    limiter.acquire()
    with pytest.raises(LimitExceededError):
        limiter.acquire()


def test_refused_attempts_are_not_recorded() -> None:
    mono = FakeMonotonic()
    limiter = SlidingWindowRateLimiter(limit=1, window=HOUR, monotonic=mono)
    limiter.acquire()
    for _ in range(5):
        with pytest.raises(LimitExceededError):
            limiter.acquire()
    mono.advance(HOUR.total_seconds())
    limiter.acquire()


def test_wall_clock_jumps_do_not_reopen_the_window() -> None:
    # A wall clock stepped forward (NTP, manual change) must not expire the
    # window early: the limiter takes no wall clock at all, only a monotonic
    # source, so only monotonic time can reopen it.
    limiter = SlidingWindowRateLimiter(limit=1, window=HOUR, monotonic=FakeMonotonic())
    limiter.acquire()
    with pytest.raises(RateLimitedError):
        limiter.acquire()


def test_defaults_to_a_real_monotonic_clock() -> None:
    limiter = SlidingWindowRateLimiter(limit=1, window=HOUR)
    limiter.acquire()
    with pytest.raises(RateLimitedError):
        limiter.acquire()


def test_thread_safe_never_over_admits() -> None:
    limiter = SlidingWindowRateLimiter(limit=50, window=HOUR, monotonic=FakeMonotonic())
    admitted: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(20):
            try:
                limiter.acquire()
            except LimitExceededError:
                continue
            with lock:
                admitted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(admitted) == 50


@pytest.mark.parametrize(("limit", "window"), [(0, HOUR), (1, timedelta(0))])
def test_invalid_arguments(limit: int, window: timedelta) -> None:
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(limit=limit, window=window)
