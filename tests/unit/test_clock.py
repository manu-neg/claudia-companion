"""Unit tests for SystemClock."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from preview_dashboard.adapters.clock import SystemClock

pytestmark = pytest.mark.unit


def test_now_is_utc_and_tz_aware() -> None:
    clock = SystemClock()
    now = clock.now()
    assert now.tzinfo is not None
    assert now.utcoffset() is not None
    assert now.tzinfo is UTC


def test_now_reflects_the_wall_clock() -> None:
    clock = SystemClock()
    before = datetime.now(UTC)
    now = clock.now()
    after = datetime.now(UTC)
    assert before <= now <= after
