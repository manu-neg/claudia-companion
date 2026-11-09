"""Claudia's conversation windows and host commands (ADR 0031, docs/security.md C58).

One window = one Claude session at a time. It closes after 3 h without an
owner message or at the 8 h hard cap, but never while work it dispatched is
still running; `/new` closes it early, `/stop` halts it (no new run until the
next owner message). Host commands are exact whole-message matches, fixed
host functions that never reach the model or the screen (C48). A KB halt
(failed work-tree restore, C53) is persisted through the `HaltFlag` port.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from preview_dashboard.domain.approvals import WindowId
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.ports.claudia_host import HaltFlag, WindowIds
from preview_dashboard.ports.clock import Clock

_log = logging.getLogger(__name__)

IDLE_LIMIT = timedelta(hours=3)
HARD_CAP = timedelta(hours=8)


class HostCommand(StrEnum):
    """Fixed host commands (C58); the value is the exact message text."""

    NEW = "/new"
    STOP = "/stop"
    STATUS = "/status"
    VOICE = "/voice"


def parse_host_command(text: str) -> HostCommand | None:
    """The command `text` is, or None.

    Exact whole-message match only: no trimming, case folding or arguments,
    so `/stop now` or ` /stop` are ordinary (screened) messages.
    """
    try:
        return HostCommand(text)
    except ValueError:
        return None


class CloseReason(StrEnum):
    """Why a window closes (the recap turn names it)."""

    IDLE = "idle"
    CAP = "cap"
    NEW = "new"


@dataclass(frozen=True, slots=True)
class WindowPolicy:
    """Window limits (plan D2); both must be positive and `idle <= cap`.

    Raises (constructor):
        ValueError: non-positive limits or `idle > cap`.
    """

    idle: timedelta = IDLE_LIMIT
    cap: timedelta = HARD_CAP

    def __post_init__(self) -> None:
        if self.idle <= timedelta(0) or self.cap <= timedelta(0) or self.idle > self.cap:
            raise ValueError("need 0 < idle <= cap")


@dataclass(frozen=True, slots=True, kw_only=True)
class Window:
    """One open window.

    Attributes:
        started: the Claude session exists (later turns use `--resume`).
        voice: `/voice` toggle for this window (replies as voice, unit M10).
    """

    id: WindowId
    opened_at: datetime
    last_message_at: datetime
    started: bool = False
    voice: bool = False

    def age(self, now: datetime) -> timedelta:
        """Time since the window opened."""
        return now - self.opened_at

    def idle_for(self, now: datetime) -> timedelta:
        """Time since the last owner message."""
        return now - self.last_message_at


class WindowTracker:
    """The host's single current window plus the `/stop` halt flag (thread-safe).

    Args:
        clock: source of "now".
        ids: window id generator (host-generated UUIDs, never from text, C51).
        policy: idle / hard-cap limits.
        kb_halt: persists the KB halt across restarts (newcode-1); read once
            here, so a host that restarts halted stays halted. None = memory only.
    """

    def __init__(
        self,
        clock: Clock,
        ids: WindowIds,
        policy: WindowPolicy | None = None,
        *,
        kb_halt: HaltFlag | None = None,
    ) -> None:
        self._clock = clock
        self._ids = ids
        self._policy = policy or WindowPolicy()
        self._lock = threading.Lock()
        self._window: Window | None = None
        self._halted = False
        self._halt_epoch = 0  # generation of the newest /stop
        self._kb_flag = kb_halt
        # Separate from `_halted`: an owner message must NOT clear this one, only `/new`.
        self._kb_halted = kb_halt is not None and kb_halt.is_set()
        if self._kb_halted:
            _log.warning("starting KB-halted: a /new must find a clean KB work tree")

    @property
    def current(self) -> Window | None:
        """The open window, if any."""
        with self._lock:
            return self._window

    @property
    def halted(self) -> bool:
        """True after `/stop` until the next message, or while KB-halted (no run may start)."""
        with self._lock:
            return self._halted or self._kb_halted

    @property
    def kb_halted(self) -> bool:
        """True after a failed KB work-tree restore, until `/new` (fail closed, C53)."""
        with self._lock:
            return self._kb_halted

    def halt_kb(self) -> None:
        """Halt the host because the KB work tree could not be restored (persisted too).

        A flag that can't be written still halts this process (logged only).
        """
        with self._lock:
            self._kb_halted = True
            if self._kb_flag is None:
                return
            try:
                self._kb_flag.set()
            except StorageUnavailableError:
                _log.error("KB halt not persisted: a restart would forget it")

    def clear_kb_halt(self) -> bool:
        """Lift the KB halt (`/new` after a clean work-tree check); False = still halted.

        Raises nothing: a persisted flag that can't be removed keeps the halt
        (fail closed), so a restart can't silently differ from this process.
        """
        with self._lock:
            if self._kb_flag is not None:
                try:
                    self._kb_flag.clear()
                except StorageUnavailableError:
                    _log.error("KB halt flag could not be removed; staying halted")
                    return False
            self._kb_halted = False
            return True

    def due(self, *, busy: bool) -> CloseReason | None:
        """Why the open window should close now, or None.

        Never while `busy` (work it dispatched still runs), not even at the
        hard cap: closing then would orphan that work's context (C58).
        """
        now = self._clock.now()
        with self._lock:
            window = self._window
        if window is None or busy:
            return None
        if window.age(now) >= self._policy.cap:
            return CloseReason.CAP
        if window.idle_for(now) >= self._policy.idle:
            return CloseReason.IDLE
        return None

    def for_message(self, generation: int) -> Window | None:
        """The window an owner message runs in (opened if none); clears the halt.

        `generation` is the host's `/stop` generation when the message was
        queued. A message queued before the last `halt` changes nothing and
        gets None (host-flow-2: it must not clear the halt of a later stop).
        Call `due()` and close the old window first: this never closes one.
        """
        now = self._clock.now()
        with self._lock:
            if generation < self._halt_epoch:
                return None
            self._halted = False
            if self._window is None:
                self._window = Window(
                    id=self._ids.new_window_id(), opened_at=now, last_message_at=now
                )
            else:
                self._window = replace(self._window, last_message_at=now)
            return self._window

    def open_for_resume(self, generation: int) -> Window | None:
        """A window for an approval resume turn when none is open (F-CL3 carry-over).

        Unlike `for_message` it never clears a `/stop` halt and is no owner
        message (the idle clock starts now). None while halted or if a stop
        came after `generation`.
        """
        now = self._clock.now()
        with self._lock:
            if self._halted or self._kb_halted or generation < self._halt_epoch:
                return None
            if self._window is None:
                self._window = Window(
                    id=self._ids.new_window_id(), opened_at=now, last_message_at=now
                )
            return self._window

    def mark_started(self, window_id: WindowId) -> None:
        """Record that the session of `window_id` exists (no-op if it is no longer current)."""
        with self._lock:
            if self._window is not None and self._window.id == window_id:
                self._window = replace(self._window, started=True)

    def toggle_voice(self) -> bool | None:
        """Flip the voice flag of the open window; return it (None: no window)."""
        with self._lock:
            if self._window is None:
                return None
            self._window = replace(self._window, voice=not self._window.voice)
            return self._window.voice

    def close(self) -> Window | None:
        """Retire the open window; return it (None if there was none)."""
        with self._lock:
            window, self._window = self._window, None
            return window

    def halt(self, epoch: int) -> Window | None:
        """`/stop` with generation `epoch`: no run until a message queued at or after it.

        Returns the open window.
        """
        with self._lock:
            self._halted = True
            self._halt_epoch = max(self._halt_epoch, epoch)
            return self._window
