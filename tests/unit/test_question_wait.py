"""Tests for the shared question wait loop (`interfaces/question_wait.py`).

Fake admin client + manual clock: resolution, timeout, reconnect with
backoff after an admin restart, non-retryable errors, no hammering when the
admin answers "open" immediately (waiter cap), duration parsing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from preview_dashboard.interfaces.mcp.client import (
    AdminNotFoundError,
    AdminServerError,
    AdminUnavailableError,
)
from preview_dashboard.interfaces.question_wait import (
    option_label,
    parse_duration,
    wait_for_question,
)

pytestmark = pytest.mark.unit

QID = "01J00000000000000000000001"


def question(state: str = "open", **extra: Any) -> dict[str, Any]:
    return {"question": {"id": QID, "state": state, "options": [], **extra}}


class Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FakeApi:
    """Replays scripted replies; each honors `wait` by advancing the clock."""

    def __init__(self, clock: Clock, replies: list[Any]) -> None:
        self.clock = clock
        self.replies = replies
        self.waits: list[int] = []

    def get_question(self, question_id: str, *, wait: int = 0) -> dict[str, object]:
        assert question_id == QID
        self.waits.append(wait)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            reply = reply(wait)
        return reply  # type: ignore[no-any-return]


def held(state: str = "open") -> Callable[[int], dict[str, Any]]:
    """A reply after the server held the request `wait` seconds."""

    def reply(wait: int) -> dict[str, Any]:
        clock.now += wait
        return question(state)

    return reply


clock = Clock()


@pytest.fixture(autouse=True)
def fresh_clock() -> None:
    global clock
    clock = Clock()


def run(replies: list[Any], timeout: float) -> tuple[Any, FakeApi]:
    api = FakeApi(clock, replies)
    outcome = wait_for_question(
        api, QID, timeout=timeout, sleep=clock.sleep, monotonic=clock.monotonic
    )
    return outcome, api


def test_returns_when_resolved():
    outcome, api = run([held(), question("answered", answer_key="a")], timeout=600)
    assert outcome.timed_out is False
    assert outcome.question["state"] == "answered"
    assert api.waits == [60, 60]


def test_times_out_while_open():
    outcome, api = run([held(), held(), held()], timeout=130)
    assert outcome.timed_out is True
    assert outcome.question["state"] == "open"
    assert api.waits == [60, 60, 10]


def test_reconnects_with_backoff_after_an_admin_restart():
    down = AdminUnavailableError("admin API unreachable", code="unavailable")
    busy = AdminServerError("admin API 503", status=503, code="http_503")
    outcome, _ = run([down, down, busy, down, question("expired")], timeout=600)
    assert outcome.question["state"] == "expired"
    assert clock.sleeps == [1.0, 2.0, 4.0, 8.0]


def test_backoff_is_capped_and_resets():
    down = AdminUnavailableError("x", code="unavailable")
    run([down] * 7 + [held(), down, question("answered")], timeout=10_000)
    assert clock.sleeps[:7] == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert clock.sleeps[7] == 1.0  # reset after a successful read


def test_unreachable_until_timeout_raises_if_never_read():
    down = AdminUnavailableError("x", code="unavailable")
    with pytest.raises(AdminUnavailableError):
        run([down] * 10, timeout=3)


def test_unreachable_after_a_read_reports_timeout():
    down = AdminUnavailableError("x", code="unavailable")
    outcome, _ = run([held(), down, down, down, down], timeout=62)
    assert outcome.timed_out is True


@pytest.mark.parametrize(
    "error",
    [
        AdminNotFoundError("admin API 404 not_found", status=404, code="not_found"),
        AdminServerError("admin API 500", status=500, code="internal_error"),
        AdminUnavailableError("malformed", code="bad_response"),
    ],
)
def test_non_retryable_errors_propagate(error):
    with pytest.raises(type(error)):
        run([error], timeout=600)


def test_malformed_reply_is_an_error():
    with pytest.raises(AdminUnavailableError):
        run([{"question": {"id": QID}}], timeout=600)


def test_immediate_open_replies_are_paced():
    # The admin's waiter cap is full: it answers "open" at once every time.
    outcome, _ = run([question()] * 4 + [question("answered")], timeout=600)
    assert outcome.question["state"] == "answered"
    assert clock.sleeps == [5.0, 5.0, 5.0, 5.0]


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [("90", 90), ("45s", 45), ("30m", 1800), ("24h", 86400), ("2d", 172800)],
)
def test_parse_duration(raw, seconds):
    assert parse_duration(raw) == seconds


@pytest.mark.parametrize("raw", ["", "0", "-5", "1.5h", "5w", "٣h", "9d", "1h30m", " 5"])
def test_parse_duration_rejects(raw):
    with pytest.raises(ValueError):
        parse_duration(raw)


def test_option_label():
    q = {"options": [{"key": "a", "label": "Alpha"}, {"key": "b", "label": "Beta"}]}
    assert option_label(q, "b") == "Beta"
    assert option_label(q, "z") is None
    assert option_label(q, None) is None
    assert option_label({"options": "junk"}, "a") is None
