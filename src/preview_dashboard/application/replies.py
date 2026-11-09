"""ReplyService: Claudia's `reply` messages under their own budget (C56, M3 part).

A reply is plain text (1..4096 chars, newlines allowed) under the outgoing
policy of C35: no invisible/control characters, no web address, secret scan
of the raw and normalized forms. Budget, separate from the 20/hour alert
budget: at most 3 replies per inbox message and 120 per hour overall; a
reply tied to no message (a background job's result) counts against the
hourly cap only. Only valid replies use budget: one that fails to queue
(rendered content refused, outbox down) gives its budget back. Reply text
is never logged.
Pure core: ports only.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Sequence
from datetime import timedelta
from typing import Final

from preview_dashboard.application.notify import (
    new_ulid,
    scan_texts,
    send_tasks,
    validate_channels,
)
from preview_dashboard.domain.errors import NotFoundError, RateLimitedError, ValidationError
from preview_dashboard.domain.models import ItemId, parse_item_id
from preview_dashboard.domain.notifications import (
    DashboardLinks,
    Notification,
    NotificationId,
    utf16_length,
)
from preview_dashboard.domain.owner_messages import OwnerMessageId, parse_owner_message_id
from preview_dashboard.domain.text import reject_invisible, reject_links
from preview_dashboard.events import (
    REPLY_EVENT,
    EventRegistry,
    RenderContext,
    default_event_registry,
)
from preview_dashboard.ports.claudia import ReplyOutbox
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.notify import NotificationOutbox, OutboxEvents
from preview_dashboard.ports.owner_messages import OwnerMessageStore
from preview_dashboard.ports.scanner import ContentScanner

logger = logging.getLogger("preview_dashboard.replies")

REPLY_MAX_CHARS: Final = 4096
REPLIES_PER_MESSAGE: Final = 3
REPLIES_PER_HOUR: Final = 120
# Per-message counters for this many recent messages; older ones are long
# answered (the hourly cap still bounds everything).
_TRACKED_MESSAGES: Final = 1024
_KEEP: Final = frozenset({"\n"})


class ReplyBudget:
    """A sliding-window budget (at most `limit` per trailing `window`) that can be refunded.

    Like `SlidingWindowRateLimiter` (monotonic clock, thread-safe), but
    `acquire` returns a stamp that `release` gives back: a reply that was
    never queued must not use budget (C56, S-C1 S11).

    Args:
        limit: acquisitions allowed per window (> 0).
        window: window length (> 0).
        monotonic: seconds from a monotonic source (injectable for tests).

    Raises:
        ValueError: non-positive `limit` or `window`.
    """

    def __init__(
        self,
        *,
        limit: int,
        window: timedelta,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit <= 0:
            raise ValueError("limit must be > 0")
        if window <= timedelta(0):
            raise ValueError("window must be > 0")
        self._limit = limit
        self._window = window.total_seconds()
        self._monotonic = monotonic
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Record one use now; return its stamp (for `release`).

        Raises:
            RateLimitedError: `limit` uses already happened within the window.
        """
        with self._lock:
            now = self._monotonic()
            cutoff = now - self._window
            while self._stamps and self._stamps[0] <= cutoff:
                self._stamps.popleft()
            if len(self._stamps) >= self._limit:
                raise RateLimitedError("reply rate limit reached; try again later")
            self._stamps.append(now)
            return now

    def release(self, stamp: float) -> None:
        """Give back one use recorded at `stamp` (no-op if it already left the window)."""
        with self._lock:
            # Search from the newest end: the refunded use is almost always the last one.
            for index in range(len(self._stamps) - 1, -1, -1):
                if self._stamps[index] == stamp:
                    del self._stamps[index]
                    return


def hourly_reply_limiter() -> ReplyBudget:
    """The 120/hour reply budget (C56), separate from the alert budget (C37)."""
    return ReplyBudget(limit=REPLIES_PER_HOUR, window=timedelta(hours=1))


def validate_reply_text(raw: object) -> str:
    """Check a reply's text against the outgoing policy (no cleaning: refuse instead).

    Raises:
        ValidationError: not a string, empty/blank or over 4096 chars,
            invisible or control characters (newline allowed), a web address.
    """
    # Telegram counts UTF-16 code units: astral chars (most emoji) count twice.
    if not isinstance(raw, str) or not 1 <= utf16_length(raw) <= REPLY_MAX_CHARS:
        raise ValidationError(f"reply text must be 1..{REPLY_MAX_CHARS} characters")
    if raw.isspace():
        raise ValidationError("reply text must not be blank")
    reject_invisible(raw, name="reply text", keep=_KEEP)
    reject_links(raw, name="reply text")
    return raw


REPLY_TITLE: Final = "Claudia reply"


class OutboxReplyQueue:
    """`ReplyOutbox` over the notification outbox: one `reply` notification + SEND per channel.

    The stored title is fixed (`Claudia reply`): the text lives only in the
    delivery content, never a second time in the title. Links come only
    from `DashboardLinks` (C35).
    """

    def __init__(
        self,
        *,
        outbox: NotificationOutbox,
        clock: Clock,
        ids: IdGenerator,
        channels: Sequence[str],
        links: DashboardLinks | None = None,
        registry: EventRegistry | None = None,
        outbox_events: OutboxEvents | None = None,
    ) -> None:
        self._outbox = outbox
        self._clock = clock
        self._ids = ids
        self._channels = validate_channels(channels)
        self._links = links or DashboardLinks()
        self._registry = registry or default_event_registry()
        self._outbox_events = outbox_events

    def queue_reply(
        self,
        text: str,
        *,
        item_id: ItemId | None,
        message_id: OwnerMessageId | None,
        before_visible: Callable[[str], None] | None = None,
    ) -> str:
        """Store the reply notification and its SEND tasks; return the notification id.

        `before_visible(id)` runs after rendering and before the outbox write, so
        anything the notifier will fetch for this id exists before it can ask.

        Raises:
            ValidationError: the rendered content breaks the outgoing policy.
        """
        del message_id  # budget bookkeeping only (ReplyService)
        now = self._clock.now()
        kind = self._registry.get(REPLY_EVENT)
        notification = Notification(
            id=NotificationId(new_ulid(self._ids)),
            event_type=kind.name,
            title=REPLY_TITLE,
            created_at=now,
            item_id=item_id,
        )
        content = kind.render(
            RenderContext(title=REPLY_TITLE, link=self._links.link_for(item_id), body=text)
        )
        tasks = send_tasks(
            self._ids,
            notification_id=notification.id,
            channels=self._channels,
            content=content,
            now=now,
        )
        if before_visible is not None:
            before_visible(notification.id)
        self._outbox.add(notification, tasks)
        if tasks and self._outbox_events is not None:
            self._outbox_events.notify()
        return notification.id


class ReplyService:
    """Validates, scans and budgets Claudia's replies, then queues them (`claudia` token).

    Args:
        outbox: queues the reply for delivery.
        messages: the inbox (a reply's message id must exist).
        scanner: secret scanner (C35).
        hourly: the 120/hour budget (default `hourly_reply_limiter()`).
        per_message: replies allowed per inbox message (default 3).
    """

    def __init__(
        self,
        *,
        outbox: ReplyOutbox,
        messages: OwnerMessageStore,
        scanner: ContentScanner,
        hourly: ReplyBudget | None = None,
        per_message: int = REPLIES_PER_MESSAGE,
    ) -> None:
        self._outbox = outbox
        self._messages = messages
        self._scanner = scanner
        self._hourly = hourly or hourly_reply_limiter()
        self._per_message = per_message
        self._counts: OrderedDict[OwnerMessageId, int] = OrderedDict()
        self._lock = threading.Lock()

    def send(
        self,
        text: str,
        *,
        message_id: str | None,
        item_id: str | None,
        before_visible: Callable[[str], None] | None = None,
    ) -> str:
        """Queue one reply; return its delivery id.

        `before_visible(id)` runs before the reply becomes visible to the notifier.

        Raises:
            ValidationError: bad text (see `validate_reply_text`), item id,
                or an unknown inbox message id.
            SecretDetectedError: the text matches a secret rule.
            RateLimitedError: 3 replies to this message, or 120 this hour.
            StorageUnavailableError: delivery is not available.
        """
        validate_reply_text(text)
        target: ItemId | None = None if item_id is None else parse_item_id(item_id)
        mid = None if message_id is None else self._known_message(message_id)
        scan_texts(self._scanner, (text,))
        stamp = self._take_budget(mid)
        try:
            if before_visible is None:  # keeps plain outboxes (and fakes) on the old signature
                reply_id = self._outbox.queue_reply(text, item_id=target, message_id=mid)
            else:
                reply_id = self._outbox.queue_reply(
                    text, item_id=target, message_id=mid, before_visible=before_visible
                )
        except BaseException:
            # Not queued (rendered content refused, outbox down): it used no budget (S-C1 S11).
            self._return_budget(mid, stamp)
            raise
        logger.info("claudia reply queued: id=%s message=%s", reply_id, mid or "-")
        return reply_id

    def _known_message(self, raw: str) -> OwnerMessageId:
        mid = parse_owner_message_id(raw)
        try:
            self._messages.get(mid)
        except NotFoundError:
            raise ValidationError("unknown inbox message") from None
        return mid

    def _take_budget(self, mid: OwnerMessageId | None) -> float:
        with self._lock:
            used = 0 if mid is None else self._counts.get(mid, 0)
            if used >= self._per_message:
                raise RateLimitedError("reply budget for this message is used up")
            try:
                stamp = self._hourly.acquire()
            except RateLimitedError:
                raise RateLimitedError("hourly reply budget is used up; try again later") from None
            if mid is not None:
                self._counts[mid] = used + 1
                self._counts.move_to_end(mid)
                while len(self._counts) > _TRACKED_MESSAGES:
                    self._counts.popitem(last=False)
            return stamp

    def _return_budget(self, mid: OwnerMessageId | None, stamp: float) -> None:
        with self._lock:
            self._hourly.release(stamp)
            used = 0 if mid is None else self._counts.get(mid, 0)
            if mid is not None and used > 0:
                self._counts[mid] = used - 1
