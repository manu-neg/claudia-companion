"""NotifyService (done/failed alerts) and OutboxService (the notifier's view of the outbox).

Also the helpers every alert producer shares (`QuestionService` too):
channel validation, the secret scan of outgoing text, the shared alert
rate limit and SEND-task creation. Pure core: ports only (ADR 0021,
docs/security.md C35, C37).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Sequence
from datetime import datetime

from preview_dashboard.application.ratelimit import RateLimiter
from preview_dashboard.domain.errors import RateLimitedError, ValidationError
from preview_dashboard.domain.models import ItemId, parse_item_id
from preview_dashboard.domain.notifications import (
    DashboardLinks,
    DeliveryTask,
    MessageContent,
    Notification,
    NotificationId,
    PendingTask,
    TaskId,
    parse_task_id,
    validate_channel_name,
)
from preview_dashboard.domain.unicode import remove_default_ignorables
from preview_dashboard.events import EventRegistry, RenderContext, default_event_registry
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.notify import NotificationOutbox, OutboxEvents
from preview_dashboard.ports.scanner import ContentScanner

MAX_PENDING_LIMIT = 100


def validate_channels(channels: Iterable[str]) -> tuple[str, ...]:
    """Return the enabled channel names as a tuple (empty = notifications disabled).

    Raises:
        ValidationError: a malformed name.
        ValueError: a duplicate name (configuration error).
    """
    names = tuple(validate_channel_name(c) for c in channels)
    if len(set(names)) != len(names):
        raise ValueError("channel names must be unique")
    return names


def new_ulid(ids: IdGenerator) -> str:
    """A fresh canonical ULID for a question, notification or task.

    Reuses the item-id stream of the existing `IdGenerator` port: any
    canonical ULID will do, and a separate method would change every adapter.
    """
    return str(ids.new_item_id())


def scan_texts(scanner: ContentScanner, texts: Iterable[str | None]) -> None:
    """Secret-scan outgoing text (callers pass raw, sanitized and rendered forms, C35).

    Each text is fed as-is and, where different, also NFKC-normalized and
    with every Default_Ignorable char (ZWJ/ZWNJ, variation selectors, ZWSP,
    tags ...) removed, plain and NFKC: the regex rules are ASCII, so a
    fullwidth, styled or joiner-split token would otherwise slip past them.

    Raises:
        SecretDetectedError: a rule matched (names the rule, never the text).
    """
    session = scanner.new_session()
    for text in texts:
        if text is None:
            continue
        joined = remove_default_ignorables(text)
        forms = (text, *(unicodedata.normalize("NFKC", t) for t in (text, joined)), joined)
        for form in dict.fromkeys(forms):  # de-duplicated, order kept
            # surrogatepass: raw text may hold lone surrogates; the scan must not crash.
            session.feed(form.encode("utf-8", "surrogatepass") + b"\n")
    session.finish()


def content_texts(content: MessageContent) -> tuple[str, ...]:
    """Every text of a rendered message that a channel shows (text + button labels)."""
    return (content.text, *(b.label for b in content.buttons))


def acquire_alert(limiter: RateLimiter) -> None:
    """Take one slot of the shared alert budget (questions + notifications, C37).

    Raises:
        RateLimitedError: the budget (default 20/hour) is used up.
    """
    try:
        limiter.acquire()
    except RateLimitedError:
        # The limiter's own message talks about publishing.
        raise RateLimitedError("notification rate limit reached; try again later") from None


def send_tasks(
    ids: IdGenerator,
    *,
    notification_id: NotificationId,
    channels: Sequence[str],
    content: MessageContent,
    now: datetime,
) -> tuple[DeliveryTask, ...]:
    """One PENDING SEND per enabled channel (none when notifications are disabled)."""
    return tuple(
        DeliveryTask.new_send(
            id=TaskId(new_ulid(ids)),
            notification_id=notification_id,
            channel=channel,
            content=content,
            now=now,
        )
        for channel in channels
    )


class NotifyService:
    """Enqueues informational alerts (`done`, `failed`) for every enabled channel.

    Shares its rate limiter with `QuestionService` (one alert budget).
    Questions are never sent through here: actionable event types are refused.
    """

    def __init__(
        self,
        *,
        outbox: NotificationOutbox,
        clock: Clock,
        ids: IdGenerator,
        scanner: ContentScanner,
        rate_limiter: RateLimiter,
        channels: Sequence[str],
        registry: EventRegistry | None = None,
        links: DashboardLinks | None = None,
        outbox_events: OutboxEvents | None = None,
    ) -> None:
        self._outbox = outbox
        self._clock = clock
        self._ids = ids
        self._scanner = scanner
        self._limiter = rate_limiter
        self._channels = validate_channels(channels)
        self._registry = registry or default_event_registry()
        self._links = links or DashboardLinks()
        self._outbox_events = outbox_events

    def notify(self, event_type: str, title: str, item_id: str | None = None) -> Notification:
        """Store a `done`/`failed` notification and its SEND tasks.

        Every attempt counts against the rate limit, including refused ones.

        Raises:
            RateLimitedError: alert budget used up (a `LimitExceededError`).
            ValidationError: unknown or actionable event type, bad title (incl.
                a link, C35) or item id.
            SecretDetectedError: the title (raw, sanitized or as rendered)
                matches a secret rule.
        """
        acquire_alert(self._limiter)
        kind = self._registry.get(event_type)
        if kind.actionable:
            raise ValidationError("questions are asked with dashboard_ask, not notify")
        target: ItemId | None = None if item_id is None else parse_item_id(item_id)
        now = self._clock.now()
        notification = Notification(
            id=NotificationId(new_ulid(self._ids)),
            event_type=kind.name,
            title=title,
            created_at=now,
            item_id=target,
        )
        # Links come only from `DashboardLinks`, never from the caller (C35).
        content = kind.render(
            RenderContext(title=notification.title, link=self._links.link_for(target))
        )
        scan_texts(self._scanner, (title, notification.title, *content_texts(content)))
        tasks = send_tasks(
            self._ids,
            notification_id=notification.id,
            channels=self._channels,
            content=content,
            now=now,
        )
        self._outbox.add(notification, tasks)
        if tasks and self._outbox_events is not None:
            self._outbox_events.notify()
        return notification


class OutboxService:
    """What the notifier may do with the outbox (behind `/notifier/*`): fetch, report.

    Answers go through `QuestionService.answer`; nothing here can read or
    change questions.
    """

    def __init__(self, *, outbox: NotificationOutbox, clock: Clock) -> None:
        self._outbox = outbox
        self._clock = clock

    def pending(self, limit: int) -> list[PendingTask]:
        """Due tasks (at most `limit`, 1..100), oldest first.

        Raises:
            ValidationError: `limit` out of range.
        """
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit must be an int")
        if not 1 <= limit <= MAX_PENDING_LIMIT:
            raise ValidationError(f"limit must be 1..{MAX_PENDING_LIMIT}")
        return self._outbox.pending(self._clock.now(), limit)

    def done(self, task_id: str, message_ref: str | None) -> DeliveryTask:
        """Record a delivery (no-op if the task is no longer PENDING).

        Raises:
            ValidationError: malformed task id or `message_ref`.
            NotFoundError: no such task.
        """
        return self._outbox.mark_done(parse_task_id(task_id), message_ref)

    def failed(self, task_id: str) -> DeliveryTask:
        """Record a failed try: backoff, FAILED for good after 8 (no-op if not PENDING).

        Raises:
            ValidationError: malformed task id.
            NotFoundError: no such task.
        """
        return self._outbox.mark_failed(parse_task_id(task_id), now=self._clock.now())
