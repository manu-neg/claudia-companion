"""Builders and an in-memory core for question/notification tests (ADR 0021).

`make_question` / `make_notification` / `make_task` build valid values
(override per test); `build_harness()` wires `QuestionService`,
`NotifyService` and `OutboxService` over the fakes. Shared by unit N1's
tests and meant for N2's contract suites and N3/N4's tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from preview_dashboard.application.notify import NotifyService, OutboxService
from preview_dashboard.application.questions import QuestionService
from preview_dashboard.application.ratelimit import SlidingWindowRateLimiter
from preview_dashboard.domain.notifications import (
    DashboardLinks,
    DeliveryAction,
    DeliveryTask,
    MessageButton,
    MessageContent,
    Notification,
    NotificationId,
    TaskId,
)
from preview_dashboard.domain.questions import Question, QuestionId, QuestionOption, QuestionState
from tests.builders import T0, ulid
from tests.fakes import (
    FakeContentScanner,
    FakeOutboxEvents,
    FakeQuestionEvents,
    FixedClock,
    InMemoryNotificationOutbox,
    InMemoryQuestionRepository,
    SequentialIdGenerator,
)

DASHBOARD = "https://dash.example.ts.net"


def qid(n: int) -> QuestionId:
    """Deterministic question id (offset keeps it apart from item ids in tests)."""
    return QuestionId(ulid(50_000 + n))


def nid(n: int) -> NotificationId:
    """Deterministic notification id."""
    return NotificationId(ulid(60_000 + n))


def tid(n: int) -> TaskId:
    """Deterministic task id."""
    return TaskId(ulid(70_000 + n))


def make_options(*labels: str) -> tuple[QuestionOption, ...]:
    """Options keyed `a`, `b`, ... (default labels `SQLite`, `Postgres`)."""
    labels = labels or ("SQLite", "Postgres")
    return tuple(QuestionOption(key=chr(ord("a") + i), label=lab) for i, lab in enumerate(labels))


def make_question(n: int = 1, **overrides: Any) -> Question:
    """A valid OPEN question `qid(n)` created at T0, expiring after 24 h."""
    fields: dict[str, Any] = {
        "id": qid(n),
        "prompt": f"Question {n}?",
        "options": make_options(),
        "created_at": T0,
        "expires_at": T0 + timedelta(hours=24),
        "updated_at": T0,
    }
    fields.update(overrides)
    return Question(**fields)


def make_notification(n: int = 1, **overrides: Any) -> Notification:
    """A valid `done` notification `nid(n)` created at T0."""
    fields: dict[str, Any] = {
        "id": nid(n),
        "event_type": "done",
        "title": f"Task {n} done",
        "created_at": T0,
    }
    fields.update(overrides)
    return Notification(**fields)


def make_content(
    text: str = "✅ done", *, buttons: Sequence[tuple[str, str]] = ()
) -> MessageContent:
    """A MessageContent; `buttons` as `(key, label)` pairs."""
    return MessageContent(
        text=text, buttons=tuple(MessageButton(key=k, label=lab) for k, lab in buttons)
    )


def make_task(n: int = 1, *, notification: int = 1, **overrides: Any) -> DeliveryTask:
    """A valid PENDING SEND `tid(n)` for `nid(notification)` on channel `fake`, due at T0."""
    fields: dict[str, Any] = {
        "id": tid(n),
        "notification_id": nid(notification),
        "channel": "fake",
        "action": DeliveryAction.SEND,
        "content": make_content(),
        "created_at": T0,
        "next_attempt_at": T0,
    }
    if overrides.get("action") is DeliveryAction.RESOLVE:
        fields["final_state"] = QuestionState.ANSWERED
    fields.update(overrides)
    return DeliveryTask(**fields)


class ManualMonotonic:
    """Injectable monotonic clock for `SlidingWindowRateLimiter`."""

    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass
class NotifyHarness:
    """An in-memory admin core for questions and notifications."""

    clock: FixedClock
    ids: SequentialIdGenerator
    scanner: FakeContentScanner
    outbox: InMemoryNotificationOutbox
    repo: InMemoryQuestionRepository
    events: FakeQuestionEvents
    outbox_events: FakeOutboxEvents
    monotonic: ManualMonotonic
    limiter: SlidingWindowRateLimiter
    questions: QuestionService
    notify: NotifyService
    outbox_service: OutboxService


def build_harness(
    *,
    channels: Sequence[str] = ("fake",),
    rate_per_hour: int = 20,
    dashboard: str | None = DASHBOARD,
    ttl: timedelta = timedelta(hours=24),
    scanner: FakeContentScanner | None = None,
) -> NotifyHarness:
    """Wire the three admin-side services over fresh fakes (one shared rate limiter)."""
    clock = FixedClock()
    ids = SequentialIdGenerator(start=1)
    scanner = scanner if scanner is not None else FakeContentScanner()
    outbox = InMemoryNotificationOutbox()
    repo = InMemoryQuestionRepository(outbox)
    events = FakeQuestionEvents()
    outbox_events = FakeOutboxEvents()
    monotonic = ManualMonotonic()
    limiter = SlidingWindowRateLimiter(
        limit=rate_per_hour, window=timedelta(hours=1), monotonic=monotonic
    )
    links = DashboardLinks(dashboard)
    questions = QuestionService(
        repo=repo,
        outbox=outbox,
        events=events,
        clock=clock,
        ids=ids,
        scanner=scanner,
        rate_limiter=limiter,
        channels=channels,
        ttl=ttl,
        links=links,
        outbox_events=outbox_events,
    )
    notify = NotifyService(
        outbox=outbox,
        clock=clock,
        ids=ids,
        scanner=scanner,
        rate_limiter=limiter,
        channels=channels,
        links=links,
        outbox_events=outbox_events,
    )
    return NotifyHarness(
        clock=clock,
        ids=ids,
        scanner=scanner,
        outbox=outbox,
        repo=repo,
        events=events,
        outbox_events=outbox_events,
        monotonic=monotonic,
        limiter=limiter,
        questions=questions,
        notify=notify,
        outbox_service=OutboxService(outbox=outbox, clock=clock),
    )
