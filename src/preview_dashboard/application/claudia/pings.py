"""Host progress pings for long Claudia runs (F-CL2, C56): fixed texts on a fixed schedule.

`ProgressPings.start` arms one run's pings: "👀 On it…" once the run passes
~20 s, then "⏳ Still working… N min" at 5 and 10 min (at most 3 per run).
The texts are fixed host strings, never model output or message text, and
go through the admin's ping budget (`PingReplies`). `PingTicket.cancel` is
race-safe: once it returns, no ping is being sent and none will be, so the
final reply always comes last. Framework-free (stdlib only).
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

from preview_dashboard.domain.owner_messages import OwnerMessageId

_log = logging.getLogger(__name__)

PING_FIRST_TEXT: Final = "👀 On it…"
FIRST_PING_AFTER_S: Final = 20.0
PING_EVERY_S: Final = 300.0
MAX_PINGS_PER_RUN: Final = 3
# The only shapes a ping may have: the admin refuses any other ping text (C56).
PING_TEXT_RE: Final = re.compile(r"👀 On it…|⏳ Still working… [1-9][0-9]{0,2} min")


def still_working_text(minutes: int) -> str:
    """The fixed "still working" ping for `minutes` (1..999) since the run started.

    Raises:
        ValueError: `minutes` out of range.
    """
    if not 1 <= minutes <= 999:
        raise ValueError("minutes must be in 1..999")
    return f"⏳ Still working… {minutes} min"


def is_ping_text(text: str) -> bool:
    """True if `text` is exactly one of the fixed ping texts."""
    return PING_TEXT_RE.fullmatch(text) is not None


@dataclass(frozen=True, slots=True)
class PingStep:
    """One scheduled ping: send `text` at `at_s` seconds after the run started."""

    at_s: float
    text: str


def ping_schedule(
    *,
    first_after_s: float = FIRST_PING_AFTER_S,
    every_s: float = PING_EVERY_S,
    max_pings: int = MAX_PINGS_PER_RUN,
) -> tuple[PingStep, ...]:
    """The fixed schedule: "On it" at `first_after_s`, then one "still working" per `every_s`.

    Raises:
        ValueError: non-positive timings or a negative cap.
    """
    if first_after_s <= 0 or every_s <= 0 or max_pings < 0:
        raise ValueError("ping timings must be positive and the cap >= 0")
    steps = [PingStep(first_after_s, PING_FIRST_TEXT)]
    n = 1
    while len(steps) < max_pings:
        at = every_s * n
        if at > first_after_s:
            steps.append(PingStep(at, still_working_text(max(1, int(at // 60)))))
        n += 1
    return tuple(steps[:max_pings])


class PingReplies(Protocol):
    """Posts one host ping (`POST /v1/claudia/replies` with `ping: true`, own budget, C56)."""

    def send_ping(self, text: str, *, message_id: OwnerMessageId) -> bool:
        """Queue a fixed ping text; False if the admin refused it (ping cap, hourly reserve)."""
        ...


# Waits on `event` for up to `seconds`; True if the event was set (= cancelled).
Waiter = Callable[[threading.Event, float], bool]
Spawner = Callable[[Callable[[], None]], None]


def _event_wait(event: threading.Event, seconds: float) -> bool:
    return event.wait(seconds)


def _daemon_thread(target: Callable[[], None]) -> None:
    threading.Thread(target=target, name="claudia-pings", daemon=True).start()


class PingTicket:
    """The pings of one run; `cancel()` ends them for good (thread-safe)."""

    def __init__(self, sender: PingReplies, message_id: OwnerMessageId) -> None:
        self._sender = sender
        self._message_id = message_id
        self._cancelled = threading.Event()
        # Held while a ping is sent: cancel() waits for it, so no ping lands after the reply.
        self._send_lock = threading.Lock()
        self.sent = 0

    @property
    def cancelled(self) -> threading.Event:
        """Set once `cancel()` ran (the schedule's waits end on it)."""
        return self._cancelled

    def request_cancel(self) -> None:
        """Stop new pings now without waiting for one in flight (`/stop` kills first)."""
        self._cancelled.set()

    def cancel(self) -> None:
        """Stop the pings; on return no ping is in flight and none will start."""
        self.request_cancel()
        with self._send_lock:
            pass

    def fire(self, text: str) -> None:
        """Send one ping unless cancelled; never raises."""
        with self._send_lock:
            if self._cancelled.is_set():
                return
            try:
                if self._sender.send_ping(text, message_id=self._message_id):
                    self.sent += 1
            except Exception as exc:
                # A ping is a courtesy: its failure never touches the run.
                _log.warning("progress ping not sent (%s)", type(exc).__name__)


class ProgressPings:
    """Arms host progress pings for owner-message runs.

    Args:
        sender: posts pings through the admin's ping budget.
        schedule: when and what to send (default `ping_schedule()`).
        wait: interruptible wait (tests inject a fake clock).
        spawn: runs the schedule loop (default: a daemon thread).
    """

    def __init__(
        self,
        sender: PingReplies,
        *,
        schedule: tuple[PingStep, ...] | None = None,
        wait: Waiter = _event_wait,
        spawn: Spawner = _daemon_thread,
    ) -> None:
        self._sender = sender
        self._schedule = ping_schedule() if schedule is None else schedule
        for step in self._schedule:
            # Fixed texts only (C56): a bad schedule is a programming error.
            if not is_ping_text(step.text):
                raise ValueError("ping texts must be the fixed host texts")
        self._wait = wait
        self._spawn = spawn

    def start(self, message_id: OwnerMessageId) -> PingTicket:
        """Arm the pings of one run for `message_id`; cancel the ticket when the run ends."""
        ticket = PingTicket(self._sender, message_id)
        self._spawn(lambda: self._loop(ticket))
        return ticket

    def _loop(self, ticket: PingTicket) -> None:
        elapsed = 0.0
        for step in self._schedule:
            if self._wait(ticket.cancelled, max(0.0, step.at_s - elapsed)):
                return
            elapsed = step.at_s
            ticket.fire(step.text)
