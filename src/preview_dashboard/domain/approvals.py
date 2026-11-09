"""Approval requests for Claudia's risky steps (ADR 0031, docs/security.md C46, C59).

Holds `ApprovalId`, `WindowId`, `ApprovalKind`, `ActionKind`,
`ApprovalState` and `ApprovalRequest`: a request is bound to one action
(immutable text plus a structured `action_kind` + `action_target` the
risky-action hook matches on), single use and expires 24 h after creation
(rows stored before F-CL3 keep their 600 s lifetime, ADR 0041).
Transitions return new instances and check expiry; `check_successor` is the
rule every store applies inside its compare-and-swap, so no writer can skip
a step (e.g. PENDING straight to APPROVED) or edit the bound action.
"""

from __future__ import annotations

import dataclasses
import itertools
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import NewType

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.models import ensure_utc, is_ulid
from preview_dashboard.domain.owner_messages import OwnerMessageId, parse_owner_message_id
from preview_dashboard.domain.text import sanitize_line, sanitize_outgoing_line

ApprovalId = NewType("ApprovalId", str)
"""Canonical ULID string."""

WindowId = NewType("WindowId", str)
"""Claudia window (Claude session) id: a host-generated, canonical lowercase UUID (C51)."""

# Owner decision 2026-11-09 (F-CL3, ADR 0041): a request waits up to 24 h for the
# owner, so a step asked late in the evening can still be approved the next day.
APPROVAL_TTL = timedelta(hours=24)
# Rows created before F-CL3 expire 600 s after creation; they stay valid as stored
# (no data migration). Only these two lifetimes exist: a store can't widen one.
LEGACY_APPROVAL_TTL = timedelta(seconds=600)
APPROVAL_TTLS = frozenset({LEGACY_APPROVAL_TTL, APPROVAL_TTL})
ACTION_TEXT_MAX_CHARS = 200
ACTION_TARGET_MAX_CHARS = 200
FLAGGED_EXCERPT_MAX_CHARS = 80
_FLAGGED_EXCERPT_WITHHELD = "(excerpt withheld)"

_WINDOW_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# The host's resume turn embeds the action text (C46); text that already
# looks like such a turn could make one turn read as two approvals.
_RESUME_MARKERS = ("approved by the owner", "denied by the owner")
_REQUEST_ID_RE = re.compile(r"request\s*[0-9a-hjkmnp-tv-z]{26}")
_ONE_US = timedelta(microseconds=1)


def parse_approval_id(raw: object) -> ApprovalId:
    """Validate an untrusted value as an ApprovalId.

    Raises:
        ValidationError: `raw` is not a canonical ULID string.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid approval id")
    return ApprovalId(str(raw))


def parse_window_id(raw: object) -> WindowId:
    """Validate an untrusted value as a WindowId (canonical lowercase UUID).

    Raises:
        ValidationError: anything else.
    """
    if not isinstance(raw, str) or not _WINDOW_ID_RE.fullmatch(raw):
        raise ValidationError("invalid window id")
    return WindowId(raw)


class ApprovalKind(StrEnum):
    """What an approval request is for (C46)."""

    ACTION = "action"
    FLAGGED_MESSAGE = "flagged_message"
    PEER_MESSAGE = "peer_message"


class ActionKind(StrEnum):
    """Closed set of structured risky actions the hook matches on (C59).

    `unknown` (an unparseable command) is deliberately absent: no approval
    can ever cover it.
    """

    PR_MERGE = "pr_merge"
    DEPLOY = "deploy"
    GIT_PUSH_MAIN = "git_push_main"
    RM = "rm"
    DASHBOARD_DELETE = "dashboard_delete"
    SETTINGS_EDIT = "settings_edit"
    PEER_MESSAGE = "peer_message"


# The kinds Claudia may ask for with `request_approval` (F-CL3, C46). `peer_message`
# stays canonical for stored rows but is no longer needed (C60, ADR 0041).
APPROVABLE_KINDS = frozenset(
    {
        ActionKind.PR_MERGE,
        ActionKind.DEPLOY,
        ActionKind.GIT_PUSH_MAIN,
        ActionKind.RM,
        ActionKind.DASHBOARD_DELETE,
        ActionKind.SETTINGS_EDIT,
    }
)


class ApprovalState(StrEnum):
    """Lifecycle of an approval request (C46).

    PENDING --tapped--> TAPPED --approved (code verified)--> APPROVED
    --consumed--> CONSUMED; PENDING/TAPPED --denied--> DENIED; any open
    state --expired / cancelled--> EXPIRED / CANCELLED. The last four are
    terminal.
    """

    PENDING = "pending"
    TAPPED = "tapped"
    APPROVED = "approved"
    CONSUMED = "consumed"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    @property
    def is_open(self) -> bool:
        """True for PENDING, TAPPED and APPROVED (not yet resolved)."""
        return self in _OPEN_STATES


_OPEN_STATES = frozenset({ApprovalState.PENDING, ApprovalState.TAPPED, ApprovalState.APPROVED})
# The only legal single steps; `check_successor` enforces them in every store.
_SUCCESSORS: dict[ApprovalState, frozenset[ApprovalState]] = {
    ApprovalState.PENDING: frozenset(
        {
            ApprovalState.TAPPED,
            ApprovalState.DENIED,
            ApprovalState.EXPIRED,
            ApprovalState.CANCELLED,
        }
    ),
    ApprovalState.TAPPED: frozenset(
        {
            ApprovalState.APPROVED,
            ApprovalState.DENIED,
            ApprovalState.EXPIRED,
            ApprovalState.CANCELLED,
        }
    ),
    ApprovalState.APPROVED: frozenset(
        {ApprovalState.CONSUMED, ApprovalState.EXPIRED, ApprovalState.CANCELLED}
    ),
}


def _reject_resume_lookalikes(text: str, *, name: str) -> str:
    folded = unicodedata.normalize("NFKC", text).casefold()
    if any(marker in folded for marker in _RESUME_MARKERS) or _REQUEST_ID_RE.search(folded):
        raise ValidationError(f"{name} must not look like an approval resume turn")
    return text


def sanitize_action_text(raw: str) -> str:
    """Sanitize an action text: one outgoing line, 1..200 chars, no link, no resume look-alike.

    Raises:
        ValidationError: see `domain.text.sanitize_outgoing_line`; or the text
            contains `Approved by the owner` / `Denied by the owner` or a
            `request <ULID>` shape.
    """
    text = sanitize_outgoing_line(raw, name="action text", max_chars=ACTION_TEXT_MAX_CHARS)
    return _reject_resume_lookalikes(text, name="action text")


def normalize_action_target(raw: str) -> str:
    """Sanitize an action target (`owner/repo#31`, a path, a session id) like the text.

    The hook must normalize its classifier output with this same function
    before comparing, so both sides agree on one spelling.

    Raises:
        ValidationError: see `sanitize_action_text` (limit 200 chars).
    """
    text = sanitize_outgoing_line(raw, name="action target", max_chars=ACTION_TARGET_MAX_CHARS)
    return _reject_resume_lookalikes(text, name="action target")


def flagged_message_prefix(message_id: OwnerMessageId) -> str:
    """The fixed start of every `flagged_message` action text (host-built, C46)."""
    return f"Treat flagged message {message_id} as your request: "


def flagged_message_text(message_id: OwnerMessageId, message_text: str) -> str:
    """Build the host-owned action text of a `flagged_message` request (C46).

    `Treat flagged message <id> as your request: <first 80 chars, sanitized>`.
    The excerpt is replaced by `(excerpt withheld)` if it has no visible
    char, or holds a link or a resume-turn look-alike, so building never
    fails on hostile owner text.

    Raises:
        ValidationError: `message_id` is not a canonical ULID.
    """
    prefix = flagged_message_prefix(parse_owner_message_id(message_id))
    try:
        excerpt = sanitize_line(
            str(message_text)[: 4 * FLAGGED_EXCERPT_MAX_CHARS],
            name="excerpt",
            max_chars=4 * FLAGGED_EXCERPT_MAX_CHARS,
        )[:FLAGGED_EXCERPT_MAX_CHARS].rstrip()
        return sanitize_action_text(prefix + excerpt)
    except ValidationError:
        return sanitize_action_text(prefix + _FLAGGED_EXCERPT_WITHHELD)


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalRequest:
    """One approval request bound to a single action in one window (C46).

    Invariants (`ValidationError` on construction):
    - `id` canonical ULID, `window_id` canonical UUID, `message_id` None or a ULID;
    - `action_text` sanitized one line (1..200, no link, no resume look-alike);
    - kind ACTION: `action_kind` any risky kind except PEER_MESSAGE, plus a
      target; kind PEER_MESSAGE: `action_kind` PEER_MESSAGE plus a target;
      kind FLAGGED_MESSAGE: no structured action, `message_id` required and
      `action_text` starts with `flagged_message_prefix(message_id)`;
    - `expires_at - created_at` is 24 h (new requests) or 600 s (rows stored
      before F-CL3); `created_at <= tapped_at <=
      approved_at <= resolved_at <= updated_at` for the stamps the state has;
      taps and approvals happen before `expires_at`, EXPIRED at or after it.
    """

    id: ApprovalId
    window_id: WindowId
    kind: ApprovalKind
    action_text: str
    created_at: datetime
    expires_at: datetime
    updated_at: datetime
    action_kind: ActionKind | None = None
    action_target: str | None = None
    message_id: OwnerMessageId | None = None
    state: ApprovalState = ApprovalState.PENDING
    tapped_at: datetime | None = None
    approved_at: datetime | None = None
    resolved_at: datetime | None = None

    def __post_init__(self) -> None:
        parse_approval_id(self.id)
        parse_window_id(self.window_id)
        if self.message_id is not None:
            parse_owner_message_id(self.message_id)
        self._set("kind", _enum(ApprovalKind, self.kind, "approval kind"))
        self._set("state", _enum(ApprovalState, self.state, "approval state"))
        self._set("action_text", sanitize_action_text(self.action_text))
        self._check_action()
        self._check_times()

    def _set(self, name: str, value: object) -> None:
        # Frozen dataclass: normalization in __post_init__ bypasses __setattr__.
        object.__setattr__(self, name, value)

    def _check_action(self) -> None:
        if self.kind is ApprovalKind.FLAGGED_MESSAGE:
            # Never a structured action: a flagged-message approval can't cover any hook action.
            if self.action_kind is not None or self.action_target is not None:
                raise ValidationError("a flagged_message request has no structured action")
            if self.message_id is None:
                raise ValidationError("a flagged_message request needs its inbox message id")
            if not self.action_text.startswith(flagged_message_prefix(self.message_id)):
                raise ValidationError("a flagged_message text must be host-built")
            return
        if self.action_kind is None or self.action_target is None:
            raise ValidationError(f"a {self.kind} request needs action_kind and action_target")
        action_kind = _enum(ActionKind, self.action_kind, "action kind")
        self._set("action_kind", action_kind)
        if (action_kind is ActionKind.PEER_MESSAGE) != (self.kind is ApprovalKind.PEER_MESSAGE):
            raise ValidationError("action_kind peer_message belongs to kind peer_message only")
        self._set("action_target", normalize_action_target(self.action_target))

    def _check_times(self) -> None:
        for name in ("created_at", "expires_at", "updated_at"):
            self._set(name, ensure_utc(getattr(self, name), name))
        for name in ("tapped_at", "approved_at", "resolved_at"):
            value = getattr(self, name)
            if value is not None:
                self._set(name, ensure_utc(value, name))
        if self.expires_at - self.created_at not in APPROVAL_TTLS:
            raise ValidationError("an approval request expires 24 h (or 600 s) after creation")
        state = self.state
        needs_tap = state in {ApprovalState.TAPPED, ApprovalState.APPROVED, ApprovalState.CONSUMED}
        needs_approval = state in {ApprovalState.APPROVED, ApprovalState.CONSUMED}
        if needs_tap and self.tapped_at is None:
            raise ValidationError(f"a {state} request needs tapped_at")
        if state is ApprovalState.PENDING and self.tapped_at is not None:
            raise ValidationError("a pending request has no tapped_at")
        if needs_approval and self.approved_at is None:
            raise ValidationError(f"a {state} request needs approved_at")
        # EXPIRED / CANCELLED may follow APPROVED and keep its stamp; the
        # others can never have been approved.
        no_approval = {ApprovalState.PENDING, ApprovalState.TAPPED, ApprovalState.DENIED}
        if self.approved_at is not None and (state in no_approval or self.tapped_at is None):
            raise ValidationError(f"approved_at does not fit state {state}")
        if (self.resolved_at is not None) != (not state.is_open):
            raise ValidationError(f"resolved_at does not fit state {state}")
        stamps = [self.created_at]
        stamps += [t for t in (self.tapped_at, self.approved_at, self.resolved_at) if t is not None]
        stamps.append(self.updated_at)
        if any(a > b for a, b in itertools.pairwise(stamps)):
            raise ValidationError("approval timestamps are out of order")
        for stamp in (self.tapped_at, self.approved_at):
            if stamp is not None and stamp >= self.expires_at:
                raise ValidationError("a request cannot be tapped or approved after it expired")
        if state is ApprovalState.EXPIRED and (
            self.resolved_at is None or self.resolved_at < self.expires_at
        ):
            raise ValidationError("a request cannot expire before expires_at")

    # --- construction --------------------------------------------------------

    @classmethod
    def new(
        cls,
        *,
        id: ApprovalId,  # shadows the builtin on purpose: mirrors the field name
        window_id: WindowId,
        kind: ApprovalKind,
        action_text: str,
        now: datetime,
        action_kind: ActionKind | None = None,
        action_target: str | None = None,
        message_id: OwnerMessageId | None = None,
    ) -> ApprovalRequest:
        """Create a PENDING request expiring 24 h after `now` (the only way to create one).

        Raises:
            ValidationError: any invariant of the class.
        """
        now = ensure_utc(now, "now")
        return cls(
            id=id,
            window_id=window_id,
            kind=kind,
            action_text=action_text,
            created_at=now,
            expires_at=now + APPROVAL_TTL,
            updated_at=now,
            action_kind=action_kind,
            action_target=action_target,
            message_id=message_id,
        )

    # --- derived -------------------------------------------------------------

    def is_expired(self, now: datetime) -> bool:
        """True if EXPIRED, or still open with `now >= expires_at` (due for `expired()`)."""
        if self.state is ApprovalState.EXPIRED:
            return True
        return self.state.is_open and ensure_utc(now, "now") >= self.expires_at

    def covers(self, action_kind: ActionKind, action_target: str) -> bool:
        """True if this is a CONSUMED request for exactly this structured action.

        FLAGGED_MESSAGE requests never cover anything (C46, C59).
        """
        return (
            self.state is ApprovalState.CONSUMED
            and self.kind is not ApprovalKind.FLAGGED_MESSAGE
            and self.action_kind is action_kind
            and self.action_target == action_target
        )

    def next_change_at(self, now: datetime) -> datetime:
        """`now`, but strictly after `updated_at` (the compare-and-swap version).

        Raises:
            ValidationError: `now` is naive, or `updated_at` is at `datetime.max`.
        """
        try:
            return max(ensure_utc(now, "now"), self.updated_at + _ONE_US)
        except OverflowError:
            raise ValidationError("approval timestamp is out of range") from None

    def resume_turn(self) -> str:
        """The host's resume turn, built from this stored request only (C46).

        Raises:
            InvalidStateError: the request is neither CONSUMED nor DENIED.
        """
        if self.state is ApprovalState.CONSUMED:
            return (
                "Approved by the owner via Telegram button + authenticator code: "
                f"{self.action_text} (request {self.id})"
            )
        if self.state is ApprovalState.DENIED:
            return f"Denied by the owner: {self.action_text} (request {self.id}). Do not run it."
        raise InvalidStateError(f"no resume turn for a {self.state} request")

    # --- transitions ---------------------------------------------------------

    def tapped(self, at: datetime) -> ApprovalRequest:
        """Return this request after the owner tapped Approve (PENDING -> TAPPED).

        Raises:
            InvalidStateError: not PENDING, or expired at `at`.
            ValidationError: `at` is naive or precedes `updated_at`.
        """
        at = self._begin(at, ApprovalState.PENDING)
        return self._to(ApprovalState.TAPPED, at, tapped_at=at)

    def approved(self, at: datetime) -> ApprovalRequest:
        """Return this request after the admin verified the owner's code (TAPPED -> APPROVED).

        Raises:
            InvalidStateError: not TAPPED, or expired at `at`.
            ValidationError: `at` is naive or precedes `updated_at`.
        """
        at = self._begin(at, ApprovalState.TAPPED)
        return self._to(ApprovalState.APPROVED, at, approved_at=at)

    def consumed(self, at: datetime) -> ApprovalRequest:
        """Return this request used up by the host before resuming (APPROVED -> CONSUMED).

        Raises:
            InvalidStateError: not APPROVED (e.g. already consumed), or expired at `at`.
            ValidationError: `at` is naive or precedes `updated_at`.
        """
        at = self._begin(at, ApprovalState.APPROVED)
        return self._to(ApprovalState.CONSUMED, at, resolved_at=at)

    def denied(self, at: datetime) -> ApprovalRequest:
        """Return this request after the owner tapped Deny (PENDING/TAPPED -> DENIED).

        Raises:
            InvalidStateError: not PENDING or TAPPED, or expired at `at`.
            ValidationError: `at` is naive or precedes `updated_at`.
        """
        at = self._begin(at, ApprovalState.PENDING, ApprovalState.TAPPED)
        return self._to(ApprovalState.DENIED, at, resolved_at=at)

    def expired(self, at: datetime) -> ApprovalRequest:
        """Return this open request expired at `at`.

        Raises:
            InvalidStateError: not open, or `at < expires_at`.
            ValidationError: `at` is naive or precedes `updated_at`.
        """
        at = self._begin(at, *_OPEN_STATES, check_expiry=False)
        if at < self.expires_at:
            raise InvalidStateError("approval request has not expired yet")
        return self._to(ApprovalState.EXPIRED, at, resolved_at=at)

    def cancelled(self, at: datetime) -> ApprovalRequest:
        """Return this open request cancelled (`/stop`, C58); allowed even after expiry.

        Raises:
            InvalidStateError: not open.
            ValidationError: `at` is naive or precedes `updated_at`.
        """
        at = self._begin(at, *_OPEN_STATES, check_expiry=False)
        return self._to(ApprovalState.CANCELLED, at, resolved_at=at)

    def _begin(self, at: datetime, *allowed: ApprovalState, check_expiry: bool = True) -> datetime:
        if self.state not in allowed:
            raise InvalidStateError(f"approval request is {self.state}")
        at = ensure_utc(at, "at")
        if at < self.updated_at:
            raise ValidationError("transition time must not precede updated_at")
        # Expiry is checked on every owner/host step: an expired request never approves.
        if check_expiry and at >= self.expires_at:
            raise InvalidStateError("approval request has expired")
        return at

    def _to(
        self,
        state: ApprovalState,
        at: datetime,
        *,
        tapped_at: datetime | None = None,
        approved_at: datetime | None = None,
        resolved_at: datetime | None = None,
    ) -> ApprovalRequest:
        # Earlier stamps are kept; the version must strictly grow
        # (check_successor), even for a same-instant step.
        return dataclasses.replace(
            self,
            state=state,
            updated_at=self.next_change_at(at),
            tapped_at=tapped_at or self.tapped_at,
            approved_at=approved_at or self.approved_at,
            resolved_at=resolved_at or self.resolved_at,
        )


def check_successor(stored: ApprovalRequest, new: ApprovalRequest) -> None:
    """Check that `new` is one legal step after `stored` (applied by every store's save).

    The bound action (kind, text, structured action, window, message,
    creation and expiry) is immutable; the state moves one edge of the
    lifecycle; earlier stamps are kept; the version strictly grows.

    Raises:
        ValidationError: another request, or an immutable field changed.
        InvalidStateError: the state change is not a legal single step.
    """
    immutable = (
        "id",
        "window_id",
        "kind",
        "action_text",
        "action_kind",
        "action_target",
        "message_id",
        "created_at",
        "expires_at",
    )
    if any(getattr(stored, f) != getattr(new, f) for f in immutable):
        raise ValidationError("an approval request's bound action is immutable")
    if new.state not in _SUCCESSORS.get(stored.state, frozenset()):
        raise InvalidStateError(f"approval request cannot go from {stored.state} to {new.state}")
    for name in ("tapped_at", "approved_at"):
        before = getattr(stored, name)
        if before is not None and getattr(new, name) != before:
            raise ValidationError(f"{name} is immutable once set")
    if new.updated_at <= stored.updated_at:
        raise ValidationError("a saved approval request needs a newer updated_at")


def _enum[E: StrEnum](cls: type[E], raw: object, what: str) -> E:
    if not isinstance(raw, str):  # enum members are str too
        raise ValidationError(f"invalid {what}")
    try:
        return cls(raw)
    except ValueError:
        raise ValidationError(f"invalid {what}") from None


__all__ = [
    "APPROVABLE_KINDS",
    "APPROVAL_TTL",
    "APPROVAL_TTLS",
    "LEGACY_APPROVAL_TTL",
    "ActionKind",
    "ApprovalId",
    "ApprovalKind",
    "ApprovalRequest",
    "ApprovalState",
    "WindowId",
    "check_successor",
    "flagged_message_prefix",
    "flagged_message_text",
    "normalize_action_target",
    "parse_approval_id",
    "parse_window_id",
    "sanitize_action_text",
]
