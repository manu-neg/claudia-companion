"""Unit tests for the notifier run loop: backoff, idle throttle, graceful stop, dead loops."""

from __future__ import annotations

import logging
import signal
import threading

import pytest

from preview_dashboard.interfaces.notifier.runner import Backoff, NotifierRunner

pytestmark = pytest.mark.unit


def test_backoff_doubles_and_caps_then_resets() -> None:
    b = Backoff(1.0, 8.0)
    assert [b.next_delay() for _ in range(6)] == [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]
    b.reset()
    assert b.next_delay() == 1.0
    with pytest.raises(ValueError):
        Backoff(0, 1)
    with pytest.raises(ValueError):
        Backoff(2, 1)


class ScriptedRounds:
    """Rounds that follow a script (int = work, Exception = raise), then stop the runner."""

    def __init__(self, script: list[int | Exception]) -> None:
        self.script = script
        self.runner: NotifierRunner | None = None
        self.calls = 0

    def round(self) -> int:
        self.calls += 1
        if not self.script:
            assert self.runner is not None
            self.runner.stop()
            return 1
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    run_once_deliveries = round
    run_once_answers = round


def test_loop_backs_off_after_errors_and_logs_type_only(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    rounds = ScriptedRounds([RuntimeError("https://api.telegram.org/botSECRET/x"), OSError("y"), 1])
    runner = NotifierRunner(rounds, backoff_first=0.01, backoff_max=0.02, min_idle_round=0)
    rounds.runner = runner
    waits: list[float] = []
    real_wait = runner._stop.wait

    def record(timeout: float) -> bool:
        waits.append(timeout)
        return real_wait(0)

    monkeypatch.setattr(runner._stop, "wait", record)
    with caplog.at_level(logging.WARNING):
        runner.loop("deliveries", rounds.round)
    assert waits == [0.01, 0.02]
    assert "RuntimeError" in caplog.text and "OSError" in caplog.text
    assert "SECRET" not in caplog.text and "api.telegram.org" not in caplog.text


def test_instant_idle_rounds_are_throttled(monkeypatch: pytest.MonkeyPatch) -> None:
    rounds = ScriptedRounds([0, 0, 3])
    runner = NotifierRunner(rounds, min_idle_round=5.0)
    rounds.runner = runner
    waits: list[float] = []

    def record(timeout: float) -> bool:
        waits.append(timeout)
        return False

    monkeypatch.setattr(runner._stop, "wait", record)
    runner.loop("answers", rounds.round)
    assert waits == [5.0, 5.0]  # not after the round that did work


def test_run_stops_gracefully_on_request() -> None:
    started = threading.Event()

    class Blocking:
        def run_once_deliveries(self) -> int:
            started.set()
            return 0

        def run_once_answers(self) -> int:
            return 0

    runner = NotifierRunner(Blocking(), min_idle_round=0.05)
    timer = threading.Timer(0.2, runner.stop)
    timer.start()
    assert runner.run(grace=2.0) is True
    assert started.is_set() and runner.stopping


def test_run_reports_a_dead_loop() -> None:
    class Dying:
        def run_once_deliveries(self) -> int:
            raise SystemExit  # BaseException: escapes the loop's `except Exception`

        def run_once_answers(self) -> int:
            return 0

    runner = NotifierRunner(Dying(), min_idle_round=0.05)
    assert runner.run(grace=2.0) is False
    assert runner.stopping


def test_signal_handlers_stop_the_runner() -> None:
    runner = NotifierRunner(ScriptedRounds([]))
    old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        runner.install_signal_handlers()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)
        assert runner.stopping
    finally:
        for sig, h in old.items():
            signal.signal(sig, h)
