"""Tests for the asyncio wake-up adapters (`adapters/wakeups.py`): QuestionEvents, OutboxEvents.

`notify` is called from worker threads after a commit: it must wake waiters
on their own loop, never block, never raise, and be a no-op without waiters
or without any running loop (the purge process).
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from contextvars import Context

import pytest

from preview_dashboard.adapters.wakeups import AsyncioOutboxEvents, AsyncioQuestionEvents
from preview_dashboard.domain.questions import QuestionId

pytestmark = pytest.mark.unit

Q1 = QuestionId("01J00000000000000000000001")
Q2 = QuestionId("01J00000000000000000000002")


def test_notify_without_loop_or_waiters_is_a_no_op():
    AsyncioQuestionEvents().notify(Q1)
    AsyncioOutboxEvents().notify()


async def test_question_notify_wakes_only_that_question():
    events = AsyncioQuestionEvents()
    one = asyncio.create_task(events.wait(Q1, 5))
    two = asyncio.create_task(events.wait(Q2, 0.2))
    await asyncio.sleep(0)
    assert events.waiting() == 2
    events.notify(Q1)
    assert await asyncio.wait_for(one, 1) is True
    assert await two is False  # timed out
    assert events.waiting() == 0


async def test_timeout_returns_false_and_cleans_up():
    events = AsyncioQuestionEvents()
    started = time.monotonic()
    assert await events.wait(Q1, 0.05) is False
    assert time.monotonic() - started < 1
    assert events.waiting() == 0
    assert await events.wait(Q1, 0) is False


async def test_notify_from_a_worker_thread_wakes_the_loop():
    events = AsyncioOutboxEvents()
    waiter = asyncio.create_task(events.wait(5))
    await asyncio.sleep(0)
    thread = threading.Thread(target=events.notify)
    thread.start()
    thread.join()
    assert await asyncio.wait_for(waiter, 1) is True
    assert events.waiting() == 0


async def test_outbox_notify_wakes_every_waiter():
    events = AsyncioOutboxEvents()
    waiters = [asyncio.create_task(events.wait(5)) for _ in range(3)]
    await asyncio.sleep(0)
    events.notify()
    assert await asyncio.wait_for(asyncio.gather(*waiters), 1) == [True, True, True]


async def test_cancelled_waiter_is_removed():
    events = AsyncioQuestionEvents()
    waiter = asyncio.create_task(events.wait(Q1, 5))
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert events.waiting() == 0


class _ClosedForWakeups(asyncio.SelectorEventLoop):
    """A loop that refuses hand-offs like a closed one (it closed after `wake` popped it)."""

    def call_soon_threadsafe[*Ts](
        self, callback: Callable[[*Ts], object], *args: *Ts, context: Context | None = None
    ) -> asyncio.Handle:
        raise RuntimeError("Event loop is closed")


def test_notify_after_the_waiters_loop_closed_does_not_raise():
    # The race: notify() pops a waiter, its loop closes before the hand-off.
    # A real loop is never closed with the task pending here (that leaks the
    # task and logs "Task was destroyed but it is pending" at GC time).
    events = AsyncioQuestionEvents()
    loop = _ClosedForWakeups()
    try:
        task = loop.create_task(events.wait(Q1, 5))
        loop.run_until_complete(asyncio.sleep(0))  # the waiter registers
        events.notify(Q1)  # hand-off raises RuntimeError: swallowed
        assert events.waiting() == 0
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            loop.run_until_complete(task)
    finally:
        loop.close()
    assert task.done()
