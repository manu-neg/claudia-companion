"""Unit tests for NotifyService (done/failed alerts) and OutboxService (the notifier's view)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from preview_dashboard.application.questions import AskCommand
from preview_dashboard.domain.errors import NotFoundError, RateLimitedError, ValidationError
from preview_dashboard.domain.notifications import (
    MAX_DELIVERY_ATTEMPTS,
    DeliveryAction,
    DeliveryState,
    backoff_delay,
)
from tests.builders import T0, ulid
from tests.notify_support import DASHBOARD, NotifyHarness, build_harness, tid

pytestmark = pytest.mark.unit

ASK = AskCommand(
    session_label="s1", prompt="Which DB?", options=[("a", "SQLite"), ("b", "Postgres")]
)


@pytest.fixture
def h() -> NotifyHarness:
    return build_harness()


@pytest.mark.parametrize(("event", "emoji"), [("done", "✅"), ("failed", "❌")])
def test_notify_stores_notification_and_sends(h: NotifyHarness, event: str, emoji: str) -> None:
    n = h.notify.notify(event, "R5 finished: 3 findings", item_id=ulid(4))
    assert h.outbox.notifications[n.id] == n
    assert (n.event_type, n.title, n.item_id, n.question_id) == (
        event,
        "R5 finished: 3 findings",
        ulid(4),
        None,
    )
    (task,) = h.outbox.tasks_of(n.id)
    assert (task.channel, task.action, task.state) == (
        "fake",
        DeliveryAction.SEND,
        DeliveryState.PENDING,
    )
    assert task.content.text == f"{emoji} R5 finished: 3 findings"
    assert task.content.buttons == ()
    assert task.content.link == f"{DASHBOARD}/#/item/{ulid(4)}"
    assert h.outbox_events.notified == 1


def test_notify_without_item_links_home(h: NotifyHarness) -> None:
    n = h.notify.notify("done", "ok")
    assert h.outbox.tasks_of(n.id)[0].content.link == f"{DASHBOARD}/"


def test_notify_disabled_stores_without_tasks() -> None:
    h = build_harness(channels=())
    n = h.notify.notify("done", "ok")
    assert n.id in h.outbox.notifications
    assert h.outbox.tasks == {}
    assert h.outbox_events.notified == 0


@pytest.mark.parametrize(
    ("event", "title", "item_id"),
    [
        ("question", "t", None),  # actionable: only via ask
        ("nope", "t", None),
        ("done", "", None),
        ("done", "t", "not-an-id"),
    ],
)
def test_notify_rejects_bad_input(
    h: NotifyHarness, event: str, title: str, item_id: str | None
) -> None:
    with pytest.raises(ValidationError):
        h.notify.notify(event, title, item_id=item_id)
    assert h.outbox.notifications == {}


def test_notify_and_ask_share_one_rate_limit() -> None:
    h = build_harness(rate_per_hour=3)
    h.notify.notify("done", "one")
    h.questions.ask(ASK)
    h.notify.notify("failed", "three")
    with pytest.raises(RateLimitedError):
        h.notify.notify("done", "four")
    with pytest.raises(RateLimitedError):
        h.questions.ask(ASK)


def test_channel_config_is_validated() -> None:
    with pytest.raises(ValueError, match="unique"):
        build_harness(channels=("fake", "fake"))
    with pytest.raises(ValidationError):
        build_harness(channels=("Bad Name",))


# --- OutboxService ----------------------------------------------------------------


def test_outbox_service_round_trip(h: NotifyHarness) -> None:
    n = h.notify.notify("done", "ok")
    (pending,) = h.outbox_service.pending(20)
    assert pending.payload.content.text == "✅ ok"
    assert pending.payload.question_id is None
    task = h.outbox_service.done(pending.id, "42")
    assert (task.state, task.message_ref) == (DeliveryState.DONE, "42")
    assert h.outbox_service.pending(20) == []
    assert h.outbox.tasks_of(n.id)[0].state is DeliveryState.DONE


def test_outbox_service_failed_backs_off(h: NotifyHarness) -> None:
    h.notify.notify("done", "ok")
    (pending,) = h.outbox_service.pending(20)
    task = h.outbox_service.failed(pending.id)
    assert (task.attempts, task.next_attempt_at) == (1, T0 + backoff_delay(1))
    assert h.outbox_service.pending(20) == []
    h.clock.advance(backoff_delay(1))
    assert [p.id for p in h.outbox_service.pending(20)] == [pending.id]


def test_outbox_service_gives_up_after_eight_tries(h: NotifyHarness) -> None:
    h.notify.notify("done", "ok")
    (pending,) = h.outbox_service.pending(20)
    for _ in range(MAX_DELIVERY_ATTEMPTS):
        task = h.outbox_service.failed(pending.id)
        h.clock.advance(timedelta(hours=1))
    assert task.state is DeliveryState.FAILED
    assert h.outbox_service.pending(20) == []
    # Late reports are no-ops, not errors.
    assert h.outbox_service.failed(pending.id).state is DeliveryState.FAILED
    assert h.outbox_service.done(pending.id, "x").state is DeliveryState.FAILED


@pytest.mark.parametrize("limit", [0, 101, True, "5"])
def test_outbox_service_limit(h: NotifyHarness, limit: object) -> None:
    with pytest.raises(ValidationError):
        h.outbox_service.pending(limit)  # type: ignore[arg-type]


def test_outbox_service_ids(h: NotifyHarness) -> None:
    with pytest.raises(ValidationError):
        h.outbox_service.done("../x", None)
    with pytest.raises(ValidationError):
        h.outbox_service.failed("x")
    with pytest.raises(NotFoundError):
        h.outbox_service.done(tid(99), None)
    h.notify.notify("done", "ok")
    (pending,) = h.outbox_service.pending(20)
    with pytest.raises(ValidationError):
        h.outbox_service.done(pending.id, "bad ref with spaces")
