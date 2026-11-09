"""Notifications and their per-channel deliveries (transactional outbox, ADR 0021).

Holds the channel-neutral message (`MessageContent`), the server-built
dashboard link (`DashboardLinks`) and the origin channels pin it to
(`dashboard_origin`, `is_dashboard_link`), `Notification`, `DeliveryTask`
(one SEND or RESOLVE per channel, with retry/backoff) and the DTOs the
notifier receives (`DeliveryPayload`, `PendingTask`). An approval prompt
(C46) is a notification with an `approval_id`: its payload carries that id
and no buttons; the channel adds the fixed Approve/Deny pair itself. Pure
stdlib; every value validates on construction, so the notifier re-checks
what the admin sends.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import NewType
from urllib.parse import urlsplit

from preview_dashboard.domain.approvals import ApprovalId, parse_approval_id
from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.models import ItemId, ensure_utc, is_ulid, parse_item_id
from preview_dashboard.domain.questions import (
    MAX_OPTIONS,
    QuestionId,
    QuestionState,
    parse_question_id,
    sanitize_option_label,
    validate_option_key,
    validate_plugin_name,
)
from preview_dashboard.domain.text import (
    TITLE_MAX_CHARS,
    reject_invisible,
    reject_links,
    sanitize_outgoing_line,
)

NotificationId = NewType("NotificationId", str)
"""Canonical ULID string."""

TaskId = NewType("TaskId", str)
"""Canonical ULID string."""

# Alerts (question/done/failed) are composed to fit this (`events.compose_text`).
MESSAGE_TEXT_MAX_CHARS = 300
# Claudia's `reply`/`voice` text (C56): Telegram's own message limit, which it
# counts in UTF-16 code units, so astral chars (most emoji) count twice.
REPLY_TEXT_MAX_CHARS = 4096
MESSAGE_REF_MAX_CHARS = 64
LINK_MAX_CHARS = 512
MAX_DELIVERY_ATTEMPTS = 8
BACKOFF_FIRST = timedelta(seconds=5)
BACKOFF_MAX = timedelta(minutes=30)
# 5 s, 20 s, 80 s, 5.3 min, 21 min, 30, 30: ~1.5 h of retries before giving up.
_BACKOFF_FACTOR = 4

# A channel message id (Telegram: "<chat>:<message>" digits) is echoed back
# to the channel later, so only visible ASCII is allowed.
_MESSAGE_REF_RE = re.compile(r"[\x21-\x7e]{1,64}")
_BASE_URL_RE = re.compile(r"https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?")
# Links are only ever built by `DashboardLinks`; this is the backstop shape.
_LINK_RE = re.compile(
    r"https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?/[A-Za-z0-9._~/#-]{0,200}"
)
# Message text is several sanitized lines joined by "\n" (`events.compose_text`).
_MESSAGE_KEEP = frozenset({"\n"})


def parse_notification_id(raw: object) -> NotificationId:
    """Validate an untrusted value as a NotificationId.

    Raises:
        ValidationError: not a canonical ULID string.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid notification id")
    return NotificationId(str(raw))


def parse_task_id(raw: object) -> TaskId:
    """Validate an untrusted value as a TaskId.

    Raises:
        ValidationError: not a canonical ULID string.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid task id")
    return TaskId(str(raw))


def utf16_length(text: str) -> int:
    """Length of `text` in UTF-16 code units (how Telegram counts its 4096 limit)."""
    return len(text) + sum(1 for ch in text if ord(ch) > 0xFFFF)


def validate_channel_name(raw: object) -> str:
    """Validate a channel name (`[a-z][a-z0-9-]{0,31}`, e.g. `telegram`).

    Raises:
        ValidationError: anything else.
    """
    return validate_plugin_name(raw, "channel")


def validate_message_ref(raw: object) -> str:
    """Validate a channel message reference (1..64 visible ASCII chars).

    Raises:
        ValidationError: anything else.
    """
    if not isinstance(raw, str) or not _MESSAGE_REF_RE.fullmatch(raw):
        raise ValidationError("message_ref must be 1..64 visible ASCII characters")
    return raw


def dashboard_origin(allowed_hosts: Iterable[str]) -> str | None:
    """The dashboard origin `https://<host>` for the configured hosts, or None if there are none.

    With several hosts the lexicographically first one is used, so the
    admin (which builds links) and the notifier (which pins them, C35)
    derive the same origin from the same config.

    Raises:
        ValidationError: the chosen host is not a lowercase DNS name.
    """
    hosts = sorted(allowed_hosts)
    if not hosts:
        return None
    return DashboardLinks(f"https://{hosts[0]}").base


def is_dashboard_link(link: str, origin: str | None) -> bool:
    """True only if `link` is a valid notification link on exactly `origin` (C35).

    Scheme, host and port must equal `origin`'s and the path must be under
    `/`; look-alikes (`https://<host>.evil.example/`, `https://<host>@evil/`,
    another port or `http://`) are False, and so is everything when
    `origin` is None (fail closed).
    """
    if origin is None or not _BASE_URL_RE.fullmatch(origin) or not isinstance(link, str):
        return False
    if len(link) > LINK_MAX_CHARS or not _LINK_RE.fullmatch(link):
        return False
    if not link.startswith(f"{origin}/"):
        return False
    # Second opinion from a URL parser: the prefix test above is the rule.
    parts, pinned = urlsplit(link), urlsplit(origin)
    return (
        parts.scheme == pinned.scheme == "https"
        and parts.netloc == pinned.netloc
        and parts.username is None
        and parts.password is None
    )


def backoff_delay(attempts: int) -> timedelta:
    """Delay before the next try after `attempts` (>= 1) failed ones: 5 s x 4^(n-1), <= 30 min."""
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    # Cap the exponent first: 4**n for large n is a pointless big integer.
    exponent = min(attempts - 1, 10)
    return min(BACKOFF_FIRST * int(_BACKOFF_FACTOR**exponent), BACKOFF_MAX)


class DeliveryAction(StrEnum):
    """SEND posts a new message; RESOLVE edits a question's message to its outcome."""

    SEND = "send"
    RESOLVE = "resolve"


class DeliveryState(StrEnum):
    """PENDING (due at `next_attempt_at`) --> DONE | FAILED (both terminal)."""

    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageButton:
    """One answer button: an option key plus its label (both validated like options).

    Invariants (`ValidationError`): `label` is already sanitized
    (`sanitize_option_label` leaves it unchanged): a stored or relayed label
    with invisible chars is refused, never silently cleaned.
    """

    key: str
    label: str

    def __post_init__(self) -> None:
        validate_option_key(self.key)
        if sanitize_option_label(self.label) != self.label:
            raise ValidationError("option label contains a forbidden character")


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageContent:
    """A channel-neutral message: plain text, answer buttons, optional dashboard link.

    Channels format it (plain text only, never markup: docs/security.md C35).

    Invariants (`ValidationError`): `text` 1..300 chars (C35, every alert),
    or 1..4096 UTF-16 code units only when `long_form` is set (set only by
    the `reply`/`voice` event types, C56; a long-form message has no answer
    buttons); nothing the outgoing-text policy removes (`domain.text.reject_invisible`: control
    chars except `\\n`, bidi, Default_Ignorable, blank look-alikes; ZWJ and
    VS16 only inside emoji/script sequences) and no web addresses
    (`domain.text.reject_links`); <= 8 buttons with unique keys; `link`
    None or an `https://host/...` URL of at most 512 chars (built by
    `DashboardLinks`, never taken from input; channels still show it only
    if `is_dashboard_link` pins it to their configured origin).
    """

    text: str
    buttons: tuple[MessageButton, ...] = ()
    link: str | None = None
    long_form: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.long_form, bool):
            raise ValidationError("long_form must be a bool")
        if not isinstance(self.text, str):
            raise ValidationError("message text must be a string")
        # Only replies may be long (C56); every alert keeps the C35 cap.
        if self.long_form:
            if not 1 <= utf16_length(self.text) <= REPLY_TEXT_MAX_CHARS:
                raise ValidationError(f"reply text must be 1..{REPLY_TEXT_MAX_CHARS} characters")
        elif not 1 <= len(self.text) <= MESSAGE_TEXT_MAX_CHARS:
            raise ValidationError(f"message text must be 1..{MESSAGE_TEXT_MAX_CHARS} characters")
        reject_invisible(self.text, name="message text", keep=_MESSAGE_KEEP)
        reject_links(self.text, name="message text")
        buttons = tuple(self.buttons) if isinstance(self.buttons, Iterable) else ()
        if not all(isinstance(b, MessageButton) for b in buttons) or len(buttons) > MAX_OPTIONS:
            raise ValidationError(f"a message has at most {MAX_OPTIONS} MessageButton buttons")
        if buttons and self.long_form:
            raise ValidationError("a long-form reply has no answer buttons")
        if len({b.key for b in buttons}) != len(buttons):
            raise ValidationError("button keys must be unique")
        object.__setattr__(self, "buttons", buttons)
        if self.link is not None and (
            not isinstance(self.link, str)
            or len(self.link) > LINK_MAX_CHARS
            or not _LINK_RE.fullmatch(self.link)
        ):
            raise ValidationError("link must be an https dashboard URL")


@dataclass(frozen=True, slots=True)
class DashboardLinks:
    """Builds the only links a notification may carry: dashboard URLs (C35).

    Args:
        base: dashboard origin, `https://<host>[:port]` without a trailing
            slash (the admin's `viewer_base_url`), or None for no links.

    Raises:
        ValidationError: `base` has another shape.
    """

    base: str | None = None

    def __post_init__(self) -> None:
        if self.base is not None and (
            not isinstance(self.base, str) or not _BASE_URL_RE.fullmatch(self.base)
        ):
            raise ValidationError("dashboard base must be https://<host>[:port]")

    def link_for(self, item_id: ItemId | None) -> str | None:
        """Item page for `item_id` (validated), the dashboard home without one, None if unset."""
        if self.base is None:
            return None
        if item_id is None:
            return f"{self.base}/"
        return f"{self.base}/#/item/{parse_item_id(item_id)}"


@dataclass(frozen=True, slots=True, kw_only=True)
class Notification:
    """One alert (question, done, failed); delivered by one `DeliveryTask` per channel.

    Invariants (`ValidationError`): ids canonical ULIDs; `event_type` a
    valid name; `title` sanitized 1..200 chars without links (C35);
    `created_at` tz-aware.
    Only question notifications carry `question_id`; only approval prompts
    carry `approval_id` (C46); never both.
    """

    id: NotificationId
    event_type: str
    title: str
    created_at: datetime
    item_id: ItemId | None = None
    question_id: QuestionId | None = None
    approval_id: ApprovalId | None = None

    def __post_init__(self) -> None:
        parse_notification_id(self.id)
        validate_plugin_name(self.event_type, "event type")
        object.__setattr__(
            self,
            "title",
            sanitize_outgoing_line(self.title, name="title", max_chars=TITLE_MAX_CHARS),
        )
        if self.item_id is not None:
            parse_item_id(self.item_id)
        if self.question_id is not None:
            parse_question_id(self.question_id)
        if self.approval_id is not None:
            parse_approval_id(self.approval_id)
            if self.question_id is not None:
                raise ValidationError("a notification is a question or an approval, not both")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at, "created_at"))


@dataclass(frozen=True, slots=True, kw_only=True)
class DeliveryTask:
    """Delivery of one notification to one channel (outbox row).

    `content` is exactly what the channel shows: for SEND the alert, for
    RESOLVE the question's final message (outcome line, no buttons).

    Invariants (`ValidationError`): ids ULIDs; channel name; `attempts` in
    0..8; `message_ref` only when DONE; SEND has no `final_state`; RESOLVE
    has a terminal `final_state` and no buttons; datetimes tz-aware.
    """

    id: TaskId
    notification_id: NotificationId
    channel: str
    action: DeliveryAction
    content: MessageContent
    created_at: datetime
    next_attempt_at: datetime
    state: DeliveryState = DeliveryState.PENDING
    attempts: int = 0
    message_ref: str | None = None
    final_state: QuestionState | None = None

    def __post_init__(self) -> None:
        parse_task_id(self.id)
        parse_notification_id(self.notification_id)
        validate_channel_name(self.channel)
        try:
            object.__setattr__(self, "action", DeliveryAction(self.action))
            object.__setattr__(self, "state", DeliveryState(self.state))
            if self.final_state is not None:
                object.__setattr__(self, "final_state", QuestionState(self.final_state))
        except ValueError:
            raise ValidationError("invalid delivery action or state") from None
        if not isinstance(self.content, MessageContent):
            raise ValidationError("content must be a MessageContent")
        if (
            not isinstance(self.attempts, int)
            or isinstance(self.attempts, bool)
            or not 0 <= self.attempts <= MAX_DELIVERY_ATTEMPTS
        ):
            raise ValidationError(f"attempts must be an int in 0..{MAX_DELIVERY_ATTEMPTS}")
        if self.message_ref is not None:
            validate_message_ref(self.message_ref)
            if self.state is not DeliveryState.DONE:
                raise ValidationError("only a delivered task has a message_ref")
        if self.action is DeliveryAction.SEND and self.final_state is not None:
            raise ValidationError("a SEND task has no final_state")
        if self.action is DeliveryAction.RESOLVE and (
            self.final_state is None or not self.final_state.is_terminal or self.content.buttons
        ):
            raise ValidationError("a RESOLVE task needs a terminal final_state and no buttons")
        object.__setattr__(self, "created_at", ensure_utc(self.created_at, "created_at"))
        object.__setattr__(
            self, "next_attempt_at", ensure_utc(self.next_attempt_at, "next_attempt_at")
        )

    # --- construction --------------------------------------------------------

    @classmethod
    def new_send(
        cls,
        *,
        id: TaskId,  # shadows the builtin on purpose: mirrors the field name
        notification_id: NotificationId,
        channel: str,
        content: MessageContent,
        now: datetime,
    ) -> DeliveryTask:
        """A PENDING SEND, due immediately."""
        return cls(
            id=id,
            notification_id=notification_id,
            channel=channel,
            action=DeliveryAction.SEND,
            content=content,
            created_at=now,
            next_attempt_at=now,
        )

    @classmethod
    def new_resolve(
        cls,
        *,
        id: TaskId,  # shadows the builtin on purpose: mirrors the field name
        notification_id: NotificationId,
        channel: str,
        content: MessageContent,
        final_state: QuestionState,
        now: datetime,
    ) -> DeliveryTask:
        """A PENDING RESOLVE, due immediately (the outbox holds it until its SEND is DONE)."""
        return cls(
            id=id,
            notification_id=notification_id,
            channel=channel,
            action=DeliveryAction.RESOLVE,
            content=content,
            created_at=now,
            next_attempt_at=now,
            final_state=final_state,
        )

    # --- transitions ---------------------------------------------------------

    def done(self, message_ref: str | None) -> DeliveryTask:
        """Return this task delivered (`message_ref`: the channel's id for the message).

        Raises:
            InvalidStateError: not PENDING.
            ValidationError: malformed `message_ref`.
        """
        self._require_pending()
        return dataclasses.replace(self, state=DeliveryState.DONE, message_ref=message_ref)

    def failed_attempt(self, now: datetime) -> DeliveryTask:
        """Return this task after one more failed try: backed off, or FAILED after 8 tries.

        Raises:
            InvalidStateError: not PENDING.
        """
        self._require_pending()
        attempts = self.attempts + 1
        if attempts >= MAX_DELIVERY_ATTEMPTS:
            return dataclasses.replace(self, state=DeliveryState.FAILED, attempts=attempts)
        return dataclasses.replace(
            self,
            attempts=attempts,
            next_attempt_at=ensure_utc(now, "now") + backoff_delay(attempts),
        )

    def dropped(self) -> DeliveryTask:
        """Return this task given up without a try (a RESOLVE whose message never went out).

        Raises:
            InvalidStateError: not PENDING.
        """
        self._require_pending()
        return dataclasses.replace(self, state=DeliveryState.FAILED)

    def _require_pending(self) -> None:
        if self.state is not DeliveryState.PENDING:
            raise InvalidStateError(f"delivery task is already {self.state}")


@dataclass(frozen=True, slots=True, kw_only=True)
class DeliveryPayload:
    """What a channel needs to show one task (flat JSON on the notifier wire).

    Invariants (`ValidationError`): buttons need a `question_id` (they
    answer it); `final_state` (RESOLVE) is terminal and needs a `question_id`.
    An approval prompt (`approval_id` set, C46) is short-form text only: no
    `question_id`, `final_state`, buttons or link, so the only buttons it
    ever shows are the channel's fixed Approve/Deny pair for that id.
    `voice_id` (C56) is the reply's notification id under which a voice
    note may wait in the admin's voice store; only a long-form reply
    carries it, and the text is always sent whether or not audio exists.
    """

    content: MessageContent
    question_id: QuestionId | None = None
    final_state: QuestionState | None = None
    approval_id: ApprovalId | None = None
    voice_id: NotificationId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.content, MessageContent):
            raise ValidationError("content must be a MessageContent")
        if self.voice_id is not None:
            parse_notification_id(self.voice_id)
            if not self.content.long_form or self.approval_id is not None:
                raise ValidationError("only a long-form reply can carry a voice id")
        if self.question_id is not None:
            parse_question_id(self.question_id)
        if self.approval_id is not None:
            parse_approval_id(self.approval_id)
            content = self.content
            if (
                self.question_id is not None
                or self.final_state is not None
                or content.buttons
                or content.link is not None
                or content.long_form
            ):
                raise ValidationError("an approval prompt carries only its id and text")
        if self.final_state is not None:
            try:
                state = QuestionState(self.final_state)
            except ValueError:
                raise ValidationError("invalid final_state") from None
            if not state.is_terminal:
                raise ValidationError("final_state must be terminal")
            object.__setattr__(self, "final_state", state)
        if (self.content.buttons or self.final_state is not None) and self.question_id is None:
            raise ValidationError("answer buttons and final_state need a question_id")


@dataclass(frozen=True, slots=True, kw_only=True)
class PendingTask:
    """A due delivery as handed to the notifier (`NotificationOutbox.pending`).

    `message_ref` is set for RESOLVE only: the id of the message its SEND
    posted, which the channel edits.

    Raises (on construction):
        ValidationError: bad id/channel; RESOLVE without `message_ref` or
            `final_state`; SEND with either.
    """

    id: TaskId
    channel: str
    action: DeliveryAction
    payload: DeliveryPayload
    message_ref: str | None = None

    def __post_init__(self) -> None:
        parse_task_id(self.id)
        validate_channel_name(self.channel)
        try:
            object.__setattr__(self, "action", DeliveryAction(self.action))
        except ValueError:
            raise ValidationError("invalid delivery action") from None
        if not isinstance(self.payload, DeliveryPayload):
            raise ValidationError("payload must be a DeliveryPayload")
        if self.message_ref is not None:
            validate_message_ref(self.message_ref)
        parts = (self.message_ref is not None, self.payload.final_state is not None)
        expected = (True, True) if self.action is DeliveryAction.RESOLVE else (False, False)
        if parts != expected:
            raise ValidationError("a RESOLVE needs message_ref and final_state; a SEND neither")
