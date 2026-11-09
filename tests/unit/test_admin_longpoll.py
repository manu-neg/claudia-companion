"""Tests for the admin long-poll helpers (`interfaces/admin/longpoll.py`).

`WaiterSlots` caps concurrent waiters; `long_poll` re-fetches on wake-ups
and at least every `recheck` seconds, stops at the deadline, and stops as
soon as the client disconnects (so a dropped client never pins a slot).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from preview_dashboard.interfaces.admin.longpoll import (
    WaiterSlots,
    long_poll,
    wait_unless_disconnected,
)

pytestmark = pytest.mark.unit


def test_waiter_slots_cap_and_release():
    slots = WaiterSlots(2)
    assert slots.try_acquire() and slots.try_acquire()
    assert not slots.try_acquire()
    assert slots.busy == 2
    slots.release()
    assert slots.try_acquire()
    slots.release()
    slots.release()
    slots.release()  # never below zero
    assert slots.busy == 0
    with pytest.raises(ValueError):
        WaiterSlots(0)


class _Receive:
    """ASGI receive: an empty request body, then (optionally) a disconnect."""

    def __init__(self, *, disconnect_after: float | None) -> None:
        self._sent_body = False
        self._after = disconnect_after

    async def __call__(self) -> dict[str, Any]:
        if not self._sent_body:
            self._sent_body = True
            return {"type": "http.request", "body": b"", "more_body": False}
        if self._after is None:
            await asyncio.Event().wait()  # never returns
            raise AssertionError("unreachable")
        await asyncio.sleep(self._after)
        return {"type": "http.disconnect"}


async def test_wait_unless_disconnected_returns_the_waiter_result():
    async def waiter() -> bool:
        return True

    assert await wait_unless_disconnected(_Receive(disconnect_after=None), waiter) is True


async def test_wait_unless_disconnected_gives_up_on_disconnect():
    async def waiter() -> bool:
        await asyncio.sleep(10)
        return True

    receive = _Receive(disconnect_after=0.01)
    assert await asyncio.wait_for(wait_unless_disconnected(receive, waiter), 2) is None


async def test_long_poll_returns_once_ready_after_a_wake_up():
    values = iter([0, 0, 1])
    wakes: list[float] = []

    async def fetch() -> int:
        return next(values)

    async def wake(timeout: float) -> bool:
        wakes.append(timeout)
        return True

    result = await long_poll(
        _Receive(disconnect_after=None), fetch=fetch, ready=bool, wake=wake, seconds=30
    )
    assert result == 1
    assert len(wakes) == 2
    assert all(t <= 5.0 for t in wakes)  # re-read at least every 5 s


async def test_long_poll_zero_seconds_fetches_once():
    calls = 0

    async def fetch() -> int:
        nonlocal calls
        calls += 1
        return 0

    async def wake(timeout: float) -> bool:
        raise AssertionError("must not wait")

    assert (
        await long_poll(
            _Receive(disconnect_after=None), fetch=fetch, ready=bool, wake=wake, seconds=0
        )
        == 0
    )
    assert calls == 1


async def test_long_poll_stops_at_the_deadline():
    clock = [0.0]

    async def fetch() -> int:
        return 0

    async def wake(timeout: float) -> bool:
        clock[0] += timeout  # time passes while waiting
        return False

    result = await long_poll(
        _Receive(disconnect_after=None),
        fetch=fetch,
        ready=bool,
        wake=wake,
        seconds=12,
        monotonic=lambda: clock[0],
    )
    assert result == 0
    assert clock[0] == 12.0  # 5 + 5 + 2: capped at the remaining time


async def test_long_poll_stops_when_the_client_disconnects():
    fetches = 0

    async def fetch() -> int:
        nonlocal fetches
        fetches += 1
        return 0

    async def wake(timeout: float) -> bool:
        await asyncio.sleep(timeout)
        return False

    result = await asyncio.wait_for(
        long_poll(_Receive(disconnect_after=0.01), fetch=fetch, ready=bool, wake=wake, seconds=60),
        2,
    )
    assert result == 0
    assert fetches == 1
