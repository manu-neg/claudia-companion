"""Unit tests for the host progress-ping scheduler (F-CL2) over a fake clock.

Covers: nothing under 20 s, the 5-minute cadence, the cap of 3, cancel on
run end / `/stop`, no ping after cancel, and a failing sender never raising.
"""

from __future__ import annotations

import threading

import pytest

from preview_dashboard.application.claudia.pings import (
    PING_FIRST_TEXT,
    PingTicket,
    ProgressPings,
    ping_schedule,
    still_working_text,
)
from preview_dashboard.domain.owner_messages import OwnerMessageId

MID = OwnerMessageId("0" * 25 + "1")


class FakeTimeline:
    """`Waiter` over a fake clock: the run 'ends' (cancel) at `ends_at` seconds."""

    def __init__(self, ends_at: float | None) -> None:
        self.now = 0.0
        self.ends_at = ends_at

    def wait(self, event: threading.Event, seconds: float) -> bool:
        if event.is_set():
            return True
        target = self.now + seconds
        if self.ends_at is not None and target >= self.ends_at:
            self.now = self.ends_at
            return True
        self.now = target
        return False


class Sender:
    def __init__(self, *, fail: bool = False, refuse: bool = False) -> None:
        self.sent: list[tuple[float, str]] = []
        self.timeline: FakeTimeline | None = None
        self.fail = fail
        self.refuse = refuse

    def send_ping(self, text: str, *, message_id: OwnerMessageId) -> bool:
        assert message_id == MID
        if self.fail:
            raise OSError("admin down")
        self.sent.append((self.timeline.now if self.timeline else -1.0, text))
        return not self.refuse


def _run(ends_at: float | None, sender: Sender | None = None) -> tuple[Sender, PingTicket]:
    sender = sender or Sender()
    timeline = FakeTimeline(ends_at)
    sender.timeline = timeline
    pings = ProgressPings(sender, wait=timeline.wait, spawn=lambda loop: loop())
    return sender, pings.start(MID)


def test_no_ping_for_a_run_under_20_seconds() -> None:
    sender, _ = _run(ends_at=19.9)
    assert sender.sent == []


def test_cadence_and_cap_of_three() -> None:
    sender, ticket = _run(ends_at=None)  # a run that never ends
    assert sender.sent == [
        (20.0, PING_FIRST_TEXT),
        (300.0, still_working_text(5)),
        (600.0, still_working_text(10)),
    ]
    assert ticket.sent == 3


def test_run_ending_between_pings_stops_the_rest() -> None:
    sender, _ = _run(ends_at=301.0)
    assert [text for _, text in sender.sent] == [PING_FIRST_TEXT, still_working_text(5)]


def test_no_ping_after_cancel() -> None:
    sender = Sender()
    ticket = PingTicket(sender, MID)
    ticket.cancel()
    ticket.fire(PING_FIRST_TEXT)
    assert sender.sent == []


def test_cancel_waits_for_a_ping_in_flight() -> None:
    entered, release = threading.Event(), threading.Event()
    order: list[str] = []

    class SlowSender:
        def send_ping(self, text: str, *, message_id: OwnerMessageId) -> bool:
            entered.set()
            release.wait(5)
            order.append("ping")
            return True

    ticket = PingTicket(SlowSender(), MID)
    firing = threading.Thread(target=ticket.fire, args=(PING_FIRST_TEXT,))
    firing.start()
    assert entered.wait(5)

    def cancel_run() -> None:
        ticket.cancel()
        order.append("cancelled")

    cancel = threading.Thread(target=cancel_run)
    cancel.start()
    release.set()
    firing.join(5)
    cancel.join(5)
    assert order == ["ping", "cancelled"]  # the final reply can only follow


def test_failing_or_refused_sender_never_raises() -> None:
    sender, ticket = _run(ends_at=None, sender=Sender(fail=True))
    assert ticket.sent == 0
    sender, ticket = _run(ends_at=None, sender=Sender(refuse=True))
    assert len(sender.sent) == 3 and ticket.sent == 0


def test_real_wait_is_cancelled_by_the_ticket() -> None:
    sender = Sender()
    pings = ProgressPings(sender)  # real 20 s wait on a daemon thread
    ticket = pings.start(MID)
    ticket.cancel()
    assert ticket.cancelled.is_set()
    assert sender.sent == []


@pytest.mark.parametrize("kwargs", [{"first_after_s": 0}, {"every_s": -1}, {"max_pings": -1}])
def test_schedule_rejects_bad_timings(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        ping_schedule(**kwargs)  # type: ignore[arg-type]


def test_still_working_text_range() -> None:
    with pytest.raises(ValueError):
        still_working_text(0)
