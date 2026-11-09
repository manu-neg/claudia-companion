"""Waiting for a question's answer over the admin API: shared by the CLI and the MCP tool.

`wait_for_question` loops `GET /v1/questions/{id}?wait=<=60` until the
question is resolved or the caller's timeout passes, and rides out an admin
restart (socket gone, 502/503/504) with a capped exponential backoff. Long
waits (hours) belong to `preview-dashboard question wait`, run in the
background; the MCP tool waits at most 10 minutes (ADR 0021, D8).
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from preview_dashboard.interfaces.mcp.client import (
    MAX_QUESTION_WAIT_SECONDS,
    AdminClientError,
    AdminServerError,
    AdminUnavailableError,
)

OPEN_STATE: Final = "open"
BACKOFF_FIRST_SECONDS: Final = 1.0
BACKOFF_MAX_SECONDS: Final = 30.0
# A long-poll that returns "open" faster than this was not held (cap reached).
EARLY_REPLY_SECONDS: Final = 1.0
EARLY_REPLY_PAUSE_SECONDS: Final = 5.0
# Server errors that mean "admin restarting / busy", not "request is wrong".
_RETRY_STATUSES: Final = frozenset({502, 503, 504})
_DURATION_RE: Final = re.compile(r"([1-9][0-9]{0,6})([smhd]?)")
_UNIT_SECONDS: Final = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
MAX_DURATION_SECONDS: Final = 8 * 86400


class QuestionReader(Protocol):
    """What the wait loop needs from the admin client (`AdminClient` implements it)."""

    def get_question(self, question_id: str, *, wait: int = ...) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class WaitOutcome:
    """Result of `wait_for_question`.

    Attributes:
        question: the last question JSON seen (`{"id", "state", ...}`).
        timed_out: True if it was still open when the timeout passed.
    """

    question: Mapping[str, object]
    timed_out: bool


def parse_duration(raw: str) -> float:
    """Parse `90`, `45s`, `30m`, `24h`, `2d` into seconds (1 s .. 8 days).

    Raises:
        ValueError: anything else (ASCII digits + optional unit only).
    """
    match = _DURATION_RE.fullmatch(raw)
    if match is None:
        raise ValueError("duration must look like 90, 45s, 30m, 24h or 2d")
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2)]
    if seconds > MAX_DURATION_SECONDS:
        raise ValueError("duration must be at most 8 days")
    return float(seconds)


def _retryable(exc: AdminClientError) -> bool:
    if isinstance(exc, AdminUnavailableError):
        return exc.code == "unavailable"  # not a malformed reply: that won't heal
    return isinstance(exc, AdminServerError) and exc.status in _RETRY_STATUSES


def _question_of(reply: Mapping[str, object]) -> Mapping[str, object]:
    question = reply.get("question")
    if not isinstance(question, Mapping) or not isinstance(question.get("state"), str):
        raise AdminUnavailableError("admin API returned a malformed question", code="bad_response")
    return question


def wait_for_question(
    api: QuestionReader,
    question_id: str,
    *,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> WaitOutcome:
    """Long-poll until the question leaves `open` or `timeout` seconds pass.

    Raises:
        AdminClientError: a non-retryable admin error (unknown question,
            bad id, auth), or the admin stayed unreachable until the timeout
            before the question was ever read.
    """
    deadline = monotonic() + max(0.0, timeout)
    delay = BACKOFF_FIRST_SECONDS
    last: Mapping[str, object] | None = None
    while True:
        remaining = deadline - monotonic()
        wait = min(MAX_QUESTION_WAIT_SECONDS, max(0, math.ceil(remaining)))
        started = monotonic()
        try:
            question = _question_of(api.get_question(question_id, wait=wait))
        except AdminClientError as exc:
            if not _retryable(exc):
                raise
            remaining = deadline - monotonic()
            if remaining <= 0:
                if last is None:
                    raise
                return WaitOutcome(last, timed_out=True)
            # Admin restarting: back off (1 s, 2 s, ... 30 s), then reconnect.
            sleep(min(delay, remaining))
            delay = min(delay * 2, BACKOFF_MAX_SECONDS)
            continue
        delay = BACKOFF_FIRST_SECONDS
        last = question
        if question["state"] != OPEN_STATE:
            return WaitOutcome(question, timed_out=False)
        now = monotonic()
        if now >= deadline:
            return WaitOutcome(question, timed_out=True)
        if wait > 0 and now - started < EARLY_REPLY_SECONDS:
            # The admin answered "open" at once (its waiter cap is full):
            # pause instead of hammering it.
            sleep(min(EARLY_REPLY_PAUSE_SECONDS, deadline - now))


def option_label(question: Mapping[str, object], key: object) -> str | None:
    """The label of option `key` in a question JSON, or None."""
    options = question.get("options")
    for option in options if isinstance(options, list) else []:
        if isinstance(option, Mapping) and option.get("key") == key and key is not None:
            label = option.get("label")
            return label if isinstance(label, str) else None
    return None
