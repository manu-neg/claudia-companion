"""The notifier's process loop: two worker threads, backoff on errors, graceful shutdown.

One thread runs `run_once_deliveries` (admin long-poll), the other
`run_once_answers` (Telegram long-poll), each forever until `stop()`.
Errors are logged by exception **type name** only (C36) and followed by
an exponential backoff (1 s doubling to 60 s). Shutdown lets the current
rounds finish for a short grace period; abandoned long-polls are harmless
(tasks are re-fetched, taps are idempotent).
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import Callable
from typing import Final, Protocol

BACKOFF_FIRST: Final = 1.0
BACKOFF_MAX: Final = 60.0
# A round that returns this fast with no work is throttled: a misbehaving
# long-poll (answering instantly) must not turn into a busy loop.
MIN_IDLE_ROUND_SECONDS: Final = 1.0
DEFAULT_GRACE_SECONDS: Final = 10.0

_log = logging.getLogger(__name__)


class DeliveryRounds(Protocol):
    """What the runner drives (`application.delivery.DeliveryService`)."""

    def run_once_deliveries(self) -> int:
        """Fetch and deliver due tasks once; return how many were delivered."""
        ...

    def run_once_answers(self) -> int:
        """Poll and submit taps once; return how many were recorded."""
        ...


class Backoff:
    """Exponential delay after consecutive failures: first, 2x, 4x, ... capped at `maximum`.

    Raises (on construction):
        ValueError: non-positive `first` or `maximum < first`.
    """

    def __init__(self, first: float = BACKOFF_FIRST, maximum: float = BACKOFF_MAX) -> None:
        if first <= 0 or maximum < first:
            raise ValueError("need 0 < first <= maximum")
        self._first = first
        self._max = maximum
        self._failures = 0

    def next_delay(self) -> float:
        """Record one more failure; return how long to wait before retrying."""
        delay = min(self._first * float(2 ** min(self._failures, 30)), self._max)
        self._failures += 1
        return delay

    def reset(self) -> None:
        """Forget past failures (after a successful round)."""
        self._failures = 0


class NotifierRunner:
    """Runs the two notifier loops until stopped.

    Args:
        rounds: the delivery service.
        backoff_first / backoff_max: error backoff bounds, seconds.
        min_idle_round: throttle for rounds that return instantly with no work.
        monotonic: injectable clock (tests).
    """

    def __init__(
        self,
        rounds: DeliveryRounds,
        *,
        backoff_first: float = BACKOFF_FIRST,
        backoff_max: float = BACKOFF_MAX,
        min_idle_round: float = MIN_IDLE_ROUND_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._rounds = rounds
        self._backoff = (backoff_first, backoff_max)
        self._min_idle = min_idle_round
        self._monotonic = monotonic
        self._stop = threading.Event()

    @property
    def stopping(self) -> bool:
        """True once `stop()` was called."""
        return self._stop.is_set()

    def stop(self) -> None:
        """Ask both loops to finish (thread- and signal-safe)."""
        self._stop.set()

    def install_signal_handlers(self) -> None:
        """SIGTERM/SIGINT -> `stop()` (call from the main thread)."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda _signum, _frame: self.stop())

    def loop(self, name: str, round_fn: Callable[[], int]) -> None:
        """Call `round_fn` until stopped; back off after errors, throttle idle instant rounds."""
        backoff = Backoff(*self._backoff)
        while not self._stop.is_set():
            started = self._monotonic()
            try:
                work = round_fn()
            except Exception as exc:
                # Type name only: exception text may hold URLs or content (C36).
                delay = backoff.next_delay()
                _log.warning(
                    "%s round failed (%s); retrying in %.0f s", name, type(exc).__name__, delay
                )
                self._stop.wait(delay)
                continue
            backoff.reset()
            if work == 0 and self._monotonic() - started < self._min_idle:
                self._stop.wait(self._min_idle)

    def _guarded(self, name: str, round_fn: Callable[[], int]) -> None:
        # Anything escaping `loop` ends the thread; `run` sees it and stops.
        # Logged by type name only: the default thread hook would print text.
        try:
            self.loop(name, round_fn)
        except BaseException as exc:
            _log.error("%s loop crashed (%s)", name, type(exc).__name__)

    def run(self, *, grace: float = DEFAULT_GRACE_SECONDS) -> bool:
        """Run both loops in daemon threads until `stop()` or a thread dies.

        Returns:
            True on a requested stop, False if a loop died unexpectedly
            (the caller exits non-zero so systemd restarts the service).
        """
        threads = [
            threading.Thread(
                target=self._guarded,
                args=("deliveries", self._rounds.run_once_deliveries),
                name="notifier-deliveries",
                daemon=True,
            ),
            threading.Thread(
                target=self._guarded,
                args=("answers", self._rounds.run_once_answers),
                name="notifier-answers",
                daemon=True,
            ),
        ]
        for thread in threads:
            thread.start()
        healthy = True
        # Short waits keep the main thread responsive to signals.
        while not self._stop.wait(0.5):
            if not all(t.is_alive() for t in threads):
                _log.error("a notifier loop died unexpectedly; stopping")
                healthy = False
                self.stop()
        _log.info("notifier stopping")
        deadline = self._monotonic() + grace
        for thread in threads:
            thread.join(max(0.0, deadline - self._monotonic()))
        return healthy
