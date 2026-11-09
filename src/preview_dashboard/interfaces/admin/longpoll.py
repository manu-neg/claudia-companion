"""Long-poll building blocks for the admin API: waiter caps and a disconnect-aware wait loop.

Long-polls (`GET /v1/questions/{id}?wait=`, `GET /v1/notifier/tasks?wait=`)
wait on the event loop only (an in-process wake-up, never a threadpool
worker), re-read the store at least every `RECHECK_SECONDS` (a change made
by another process, e.g. the purge job's expiry, wakes nobody here) and stop
holding anything as soon as the client goes away. Waiter counts are capped
(C37): past the cap a request is answered immediately instead of waiting.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Awaitable, Callable
from typing import Final

import anyio
from starlette.types import Receive

# Safety net: waiters re-read the store at least this often.
RECHECK_SECONDS: Final = 5.0
# At most this many concurrent question long-polls (C37).
MAX_QUESTION_WAITERS: Final = 16
# The outbox hands out due tasks without leasing them: one poller at a time,
# so a task can't be handed to two concurrent pollers (C37).
MAX_NOTIFIER_POLLERS: Final = 1
# Same for the Claudia host's inbox poll (messages are not leased either).
MAX_CLAUDIA_POLLERS: Final = 1
# The host waits on at most one open approval per window: a few waiters suffice.
MAX_APPROVAL_WAITERS: Final = 4


class WaiterSlots:
    """Counts concurrent waiters of one kind; `try_acquire` refuses beyond `limit`.

    Used only from the event loop thread (route code), so a plain counter
    is enough: there is no await between the check and the increment.

    Raises (constructor):
        ValueError: `limit` < 1.
    """

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = limit
        self._busy = 0

    @property
    def busy(self) -> int:
        """Slots currently held."""
        return self._busy

    def try_acquire(self) -> bool:
        """Take a slot if one is free; False when all `limit` slots are held."""
        if self._busy >= self.limit:
            return False
        self._busy += 1
        return True

    def release(self) -> None:
        """Give a slot back (call exactly once per successful `try_acquire`)."""
        self._busy = max(0, self._busy - 1)


async def _until_disconnect(receive: Receive) -> None:
    # GET bodies are empty: the first message is the (empty) request body,
    # the next one only arrives when the client goes away.
    while (await receive())["type"] != "http.disconnect":
        pass


async def wait_unless_disconnected(
    receive: Receive, waiter: Callable[[], Awaitable[bool]]
) -> bool | None:
    """Run `waiter()` but give up as soon as the client disconnects.

    Only for requests whose body was fully read (or is empty): it consumes
    `receive` messages.

    Returns:
        The waiter's result, or None if the client disconnected first.
    """
    result: bool | None = None
    async with anyio.create_task_group() as group:

        async def watch() -> None:
            await _until_disconnect(receive)
            group.cancel_scope.cancel()

        async def run() -> None:
            nonlocal result
            result = await waiter()
            group.cancel_scope.cancel()

        group.start_soon(watch)
        group.start_soon(run)
    return result


async def long_poll[T](
    receive: Receive,
    *,
    fetch: Callable[[], Awaitable[T]],
    ready: Callable[[T], bool],
    wake: Callable[[float], Awaitable[bool]],
    seconds: float,
    recheck: float = RECHECK_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> T:
    """Fetch until `ready(value)`, `seconds` elapse or the client disconnects.

    Args:
        receive: the request's ASGI `receive` (to notice a disconnect).
        fetch: reads the current value (runs its blocking work off the loop).
        ready: True once the value is worth returning.
        wake: `await wake(timeout)` returns when woken or after `timeout`.
        seconds: total time to hold the request (0 = fetch once).
        recheck: re-read at least this often even without a wake-up.
        monotonic: clock (tests).

    Returns:
        The last value fetched.
    """
    value = await fetch()
    deadline = monotonic() + seconds
    while not ready(value):
        remaining = deadline - monotonic()
        if remaining <= 0:
            break
        waiter = functools.partial(wake, min(remaining, recheck))
        woke = await wait_unless_disconnected(receive, waiter)
        if woke is None:
            break  # client gone: stop holding a waiter slot
        value = await fetch()
    return value
