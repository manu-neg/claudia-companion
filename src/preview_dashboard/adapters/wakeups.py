"""In-process asyncio wake-ups: `QuestionEvents` and `OutboxEvents` adapters (ADR 0021).

Long-poll routes (`GET /v1/questions/{id}?wait=`, `GET /v1/notifier/tasks?wait=`)
`await wait(...)` on the admin's event loop; services call `notify(...)`
from worker threads after a commit. `notify` hands the wake-up to each
waiter's own loop with `call_soon_threadsafe`, never blocks and never
raises: with no waiter (or no running loop, e.g. in the purge job) it is a
no-op. Wake-ups are advisory; waiters always re-read the store.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading

from preview_dashboard.domain.questions import QuestionId

_Waiter = tuple[asyncio.AbstractEventLoop, asyncio.Event]


class _WaiterSet:
    """Waiters grouped by key; thread-safe registration and wake-up."""

    def __init__(self) -> None:
        # A plain lock: notify() runs in worker threads, wait() on the loop.
        self._lock = threading.Lock()
        self._waiters: dict[object, set[_Waiter]] = {}

    def wake(self, key: object) -> None:
        with self._lock:
            waiters = self._waiters.pop(key, set())
        for loop, event in waiters:
            # A closed loop (process shutting down) has nobody left to wake.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(event.set)

    async def wait(self, key: object, timeout: float) -> bool:
        waiter: _Waiter = (asyncio.get_running_loop(), asyncio.Event())
        with self._lock:
            self._waiters.setdefault(key, set()).add(waiter)
        try:
            await asyncio.wait_for(waiter[1].wait(), max(0.0, timeout))
        except TimeoutError:
            return False
        finally:
            with self._lock:
                group = self._waiters.get(key)
                if group is not None:
                    group.discard(waiter)
                    if not group:
                        del self._waiters[key]
        return True

    def count(self) -> int:
        with self._lock:
            return sum(len(group) for group in self._waiters.values())


class AsyncioQuestionEvents:
    """`QuestionEvents` for one process: wakes `wait(question_id)` callers on `notify`."""

    def __init__(self) -> None:
        self._waiters = _WaiterSet()

    def notify(self, question_id: QuestionId) -> None:
        """Wake every waiter on `question_id` (thread-safe; no-op without waiters)."""
        self._waiters.wake(question_id)

    async def wait(self, question_id: QuestionId, timeout: float) -> bool:
        """Wait up to `timeout` s for `notify(question_id)`; True if woken."""
        return await self._waiters.wait(question_id, timeout)

    def waiting(self) -> int:
        """How many waiters are registered right now (tests, diagnostics)."""
        return self._waiters.count()


_OUTBOX_KEY = "outbox"


class AsyncioOutboxEvents:
    """`OutboxEvents` for one process: wakes the notifier's long-poll on new deliveries."""

    def __init__(self) -> None:
        self._waiters = _WaiterSet()

    def notify(self) -> None:
        """Wake every waiter (thread-safe; no-op without waiters)."""
        self._waiters.wake(_OUTBOX_KEY)

    async def wait(self, timeout: float) -> bool:
        """Wait up to `timeout` s for `notify()`; True if woken."""
        return await self._waiters.wait(_OUTBOX_KEY, timeout)

    def waiting(self) -> int:
        """How many waiters are registered right now (tests, diagnostics)."""
        return self._waiters.count()
