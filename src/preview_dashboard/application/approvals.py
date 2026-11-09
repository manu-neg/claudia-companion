"""ApprovalService: create, tap, approve, consume, cancel and expire approval requests (C46).

Who may do what is fixed by the routes that call in (C45): the `claudia`
token creates PENDING requests, reads them, consumes APPROVED ones and
cancels open ones (`/stop`, C58: cancel only ever closes a request); the
notifier token records Approve/Deny taps; only `StepUpService` (after a
verified TOTP code) moves TAPPED -> APPROVED. Every transition is the
store's compare-and-swap, expiry (24 h; legacy rows 600 s) is checked first on every access,
and unknown or malformed ids yield `unknown` (no existence oracle). Action
text and target are secret-scanned like alert text (C35); a
`flagged_message` text is always built here from the stored inbox message,
never taken from the caller. Creation is bounded (storage-totp-2, newcode-7):
at most 10 created requests per hour (5 per window; `/stop` resets the
window's share) and at most 3 open across all windows, so no loop can flood
the owner with prompts; refused attempts have their own budget (30/h, 10 per
window) and never use the created one. Pure core: ports only.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from preview_dashboard.application.notify import new_ulid, scan_texts
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    flagged_message_text,
    parse_approval_id,
    parse_window_id,
)
from preview_dashboard.domain.errors import (
    ConflictError,
    InvalidStateError,
    NotFoundError,
    RateLimitedError,
    SecretDetectedError,
    ValidationError,
)
from preview_dashboard.domain.owner_messages import (
    OwnerMessage,
    OwnerMessageId,
    parse_owner_message_id,
)
from preview_dashboard.ports.approvals import ApprovalStore
from preview_dashboard.ports.claudia import ApprovalPrompts, ChangeEvents
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.owner_messages import OwnerMessageStore
from preview_dashboard.ports.scanner import ContentScanner

logger = logging.getLogger("preview_dashboard.approvals")


class TapDecision(StrEnum):
    """The owner's button (`p:<ULID>:ok` / `:no` on Telegram; wire values below)."""

    APPROVE = "approve"
    DENY = "deny"


class TapResult(StrEnum):
    """Outcome of one tap (C46): the notifier may tell the owner, nothing more.

    Values equal `wire.notifier_messages.TapResult` (a test keeps them equal).
    """

    TAPPED = "tapped"
    DENIED = "denied"
    ALREADY_DECIDED = "already_decided"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class ConsumeResult(StrEnum):
    """Outcome of the host's consume (single use, C46)."""

    CONSUMED = "consumed"
    ALREADY_CONSUMED = "already_consumed"
    NOT_APPROVED = "not_approved"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class CancelResult(StrEnum):
    """Outcome of the host's cancel (`/stop`, C58); values equal `wire.claudia.CANCEL_RESULTS`."""

    CANCELLED = "cancelled"
    ALREADY_RESOLVED = "already_resolved"
    BUSY = "busy"  # still open but kept changing under us: the host retries
    UNKNOWN = "unknown"


# CAS retries per cancel: each lost race means the request moved one step.
_CANCEL_ATTEMPTS = 3
# Prompt-fatigue bounds (storage-totp-2, newcode-7): a real session needs a handful
# an hour. Only created requests (the ones that prompt the owner) use these.
APPROVAL_CREATE_BUDGET: Final = 10
APPROVAL_WINDOW_CREATE_BUDGET: Final = 5
# Refused attempts use their own budget, so they never lock out a real request;
# past it a refusal answers "rate limited" instead of its reason (no free probing).
APPROVAL_REFUSED_BUDGET: Final = 30
APPROVAL_WINDOW_REFUSED_BUDGET: Final = 10
APPROVAL_CREATE_WINDOW: Final = timedelta(hours=1)
MAX_OPEN_APPROVALS: Final = 3
# Per-window budgets kept at most for this many windows (ids are the caller's choice).
MAX_TRACKED_WINDOWS: Final = 64


class SlidingBudget:
    """At most `limit` charges in any trailing `window`, with a separate room check (thread-safe).

    Unlike `RateLimiter.acquire`, checking room and charging are two steps, so
    a caller can charge only what actually happened (newcode-7). Monotonic
    time, like `SlidingWindowRateLimiter`.

    Raises (constructor):
        ValueError: non-positive `limit` or `window`.
    """

    def __init__(
        self, *, limit: int, window: timedelta, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        if limit <= 0 or window <= timedelta(0):
            raise ValueError("limit and window must be > 0")
        self._limit = limit
        self._window = window.total_seconds()
        self._monotonic = monotonic
        self._stamps: deque[float] = deque()
        self._lock = threading.Lock()

    def has_room(self) -> bool:
        """True if one more charge fits now."""
        with self._lock:
            self._expire()
            return len(self._stamps) < self._limit

    def charge(self) -> None:
        """Record one charge now (may go over the limit; check `has_room` first)."""
        with self._lock:
            self._stamps.append(self._monotonic())

    def reset(self) -> None:
        """Forget every charge."""
        with self._lock:
            self._stamps.clear()

    def _expire(self) -> None:
        cutoff = self._monotonic() - self._window
        while self._stamps and self._stamps[0] <= cutoff:
            self._stamps.popleft()


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalBudgetPolicy:
    """Hourly approval budgets (C46, newcode-7); every value must be > 0."""

    created: int = APPROVAL_CREATE_BUDGET
    created_per_window: int = APPROVAL_WINDOW_CREATE_BUDGET
    refused: int = APPROVAL_REFUSED_BUDGET
    refused_per_window: int = APPROVAL_WINDOW_REFUSED_BUDGET
    window: timedelta = APPROVAL_CREATE_WINDOW


class _ApprovalBudgets:
    """Global + per-window budgets for created and for refused requests."""

    def __init__(self, policy: ApprovalBudgetPolicy, monotonic: Callable[[], float]) -> None:
        self._policy = policy
        self._monotonic = monotonic
        self.created = self._budget(policy.created)
        self.refused = self._budget(policy.refused)
        self._windows: OrderedDict[WindowId, tuple[SlidingBudget, SlidingBudget]] = OrderedDict()
        self._lock = threading.Lock()

    def _budget(self, limit: int) -> SlidingBudget:
        return SlidingBudget(limit=limit, window=self._policy.window, monotonic=self._monotonic)

    def window(self, window_id: WindowId) -> tuple[SlidingBudget, SlidingBudget]:
        """(created, refused) budgets of one window, made on first use (LRU-bounded)."""
        with self._lock:
            pair = self._windows.get(window_id)
            if pair is None:
                pair = (
                    self._budget(self._policy.created_per_window),
                    self._budget(self._policy.refused_per_window),
                )
                self._windows[window_id] = pair
                # Evicting only loses a per-window budget; the global ones still bound.
                while len(self._windows) > MAX_TRACKED_WINDOWS:
                    self._windows.popitem(last=False)
            else:
                self._windows.move_to_end(window_id)
            return pair

    def reset_window(self, window_id: WindowId) -> None:
        """`/stop`: the window's own budgets start over (the global ones do not)."""
        with self._lock:
            self._windows.pop(window_id, None)


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalCreateCommand:
    """A `claudia`-token request for a new approval (values still raw, validated here).

    `action_text` is required for kinds `action` and `peer_message` and
    refused for `flagged_message` (whose text the admin builds itself).
    """

    window_id: str
    kind: str
    action_text: str | None = None
    action_kind: str | None = None
    action_target: str | None = None
    message_id: str | None = None


def _enum[E: StrEnum](cls: type[E], raw: object, what: str) -> E:
    if not isinstance(raw, str):
        raise ValidationError(f"invalid {what}")
    try:
        return cls(raw)
    except ValueError:
        raise ValidationError(f"invalid {what}") from None


class ApprovalService:
    """The approval lifecycle behind the admin routes (C46). Thread-safe via store CAS.

    Args:
        store: approval requests (CAS saves, one open request per window).
        messages: the inbox (for `flagged_message` texts).
        clock: time source (expiry).
        ids: ULID source for request ids.
        scanner: secret scanner for action text and target (C35).
        prompts: queues the Approve/Deny message for a new request.
        events: wakes long-polls on any state change (optional).
        budgets: hourly budgets for created and refused requests, global and
            per window (in-process like the alert budget; a restart resets them).
        max_open: open (unexpired) requests allowed across all windows.
        monotonic: time source of the budgets (tests inject one).
    """

    def __init__(
        self,
        *,
        store: ApprovalStore,
        messages: OwnerMessageStore,
        clock: Clock,
        ids: IdGenerator,
        scanner: ContentScanner,
        prompts: ApprovalPrompts,
        events: ChangeEvents | None = None,
        budgets: ApprovalBudgetPolicy | None = None,
        max_open: int = MAX_OPEN_APPROVALS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_open < 1:
            raise ValueError("max_open must be >= 1")
        self._store = store
        self._messages = messages
        self._clock = clock
        self._ids = ids
        self._scanner = scanner
        self._prompts = prompts
        self._events = events
        self._budgets = _ApprovalBudgets(budgets or ApprovalBudgetPolicy(), monotonic)
        self._max_open = max_open
        # The open-count check and the insert must not interleave (one admin process).
        self._create_lock = threading.Lock()

    # --- claudia token -----------------------------------------------------------

    def create(self, command: ApprovalCreateCommand) -> ApprovalRequest:
        """Create a PENDING request and queue its Approve/Deny message.

        Budgets (newcode-7): only a created request uses the created budget
        (global and per window); a refused attempt uses the separate refused
        budget, and once that is spent it answers `RateLimitedError` instead
        of its reason. So refusals can't lock out a real request, and probing
        (e.g. the secret scan) is still not free.

        Raises:
            RateLimitedError: the created budget (global or the window's) is
                used up, or this attempt was refused with the refused budget spent.
            ValidationError: bad window id / kind / action fields, an unknown
                inbox message, or a client text for `flagged_message`.
            SecretDetectedError: the action text or target matches a secret rule.
            ConflictError: the window already has an open request, or
                `max_open` requests are already open (any window).
            StorageUnavailableError: the prompt could not be queued (the new
                request is cancelled first: no silent pending approval; any
                other prompt failure cancels it too and propagates).
        """
        window_id: WindowId | None = None
        try:
            window_id = parse_window_id(command.window_id)
            request = self._new_request(command, window_id)
            with self._create_lock:
                self._add_within_budget(request)
        except (ValidationError, SecretDetectedError, ConflictError):
            self._charge_refusal(window_id)
            raise
        try:
            self._prompts.prompt(request)
        except Exception:
            # Any failure (not only "unavailable"): never leave a request no one can tap.
            self._cancel_quietly(request)
            raise
        self._changed()
        logger.info("approval request created: id=%s kind=%s", request.id, request.kind)
        return request

    def _add_within_budget(self, request: ApprovalRequest) -> None:
        """Open cap + created budgets, then insert (caller holds `_create_lock`)."""
        # "One per window" alone is no bound: window ids are the caller's choice.
        now = self._clock.now()
        open_now = sum(1 for r in self._store.list_open() if not r.is_expired(now))
        if open_now >= self._max_open:
            logger.warning("approval request refused: %d requests already open", open_now)
            # Same answer as a busy window (409): wait for one to be decided.
            raise ConflictError("too many open approval requests")
        window_created, _ = self._budgets.window(request.window_id)
        if not (self._budgets.created.has_room() and window_created.has_room()):
            logger.warning("approval request refused: create budget used up")
            raise RateLimitedError("approval request budget reached; try again later")
        self._store.add(request)  # ConflictError: the window has an open request
        # Charged only once it exists: it is what prompts the owner.
        self._budgets.created.charge()
        window_created.charge()

    def _charge_refusal(self, window_id: WindowId | None) -> None:
        """Charge a refused attempt; past the refused budget, answer rate-limited instead.

        Raises:
            RateLimitedError: the refused budget (global or the window's) is spent.
        """
        budgets = [self._budgets.refused]
        if window_id is not None:
            budgets.append(self._budgets.window(window_id)[1])
        if not all(b.has_room() for b in budgets):
            logger.warning("approval request refused: refused-attempt budget used up")
            raise RateLimitedError("approval request budget reached; try again later") from None
        for budget in budgets:
            budget.charge()

    def _new_request(self, command: ApprovalCreateCommand, window_id: WindowId) -> ApprovalRequest:
        """Validate `command` and build the PENDING request (not stored yet).

        Raises:
            ValidationError, SecretDetectedError: see `create`.
        """
        kind = _enum(ApprovalKind, command.kind, "approval kind")
        message_id = (
            None if command.message_id is None else parse_owner_message_id(command.message_id)
        )
        action_kind = (
            None
            if command.action_kind is None
            else _enum(ActionKind, command.action_kind, "action kind")
        )
        if kind is ApprovalKind.FLAGGED_MESSAGE:
            text = self._flagged_text(command, message_id)
        else:
            if command.action_text is None:
                raise ValidationError(f"a {kind} request needs action_text")
            text = command.action_text
            scan_texts(self._scanner, (text, command.action_target))
        if message_id is not None and kind is not ApprovalKind.FLAGGED_MESSAGE:
            self._require_message(message_id)
        request = ApprovalRequest.new(
            id=ApprovalId(new_ulid(self._ids)),
            window_id=window_id,
            kind=kind,
            action_text=text,
            now=self._clock.now(),
            action_kind=action_kind,
            action_target=command.action_target,
            message_id=message_id,
        )
        # The sanitized forms are what Telegram shows: scan them too.
        scan_texts(self._scanner, (request.action_text, request.action_target))
        return request

    def get(self, approval_id: str) -> ApprovalRequest:
        """Return a request (marked EXPIRED first if its lifetime is over).

        Raises:
            NotFoundError: malformed or unknown id (same error: no oracle).
        """
        try:
            parsed = parse_approval_id(approval_id)
            return self._fresh(self._store.get(parsed))
        except ValidationError:
            raise NotFoundError("no such approval request") from None

    def consume(self, approval_id: str) -> tuple[ConsumeResult, ApprovalRequest | None]:
        """APPROVED -> CONSUMED (CAS); the host must do this before resuming (single use).

        Returns:
            The result and the request as now stored (None for `unknown`).
        """
        request = self._lookup(approval_id)
        if request is None:
            return ConsumeResult.UNKNOWN, None
        if request.state is not ApprovalState.APPROVED:
            return self._consume_refusal(request), request
        try:
            consumed = request.consumed(self._at(request))
            self._store.save(consumed, expected_updated_at=request.updated_at)
        except (ConflictError, InvalidStateError):
            # Lost a race: report what the winner left behind.
            again = self._lookup(approval_id)
            if again is None:
                return ConsumeResult.UNKNOWN, None
            return self._consume_refusal(again), again
        self._changed()
        logger.info("approval request consumed: id=%s", consumed.id)
        return ConsumeResult.CONSUMED, consumed

    def cancel(self, approval_id: str) -> tuple[CancelResult, ApprovalRequest | None]:
        """Any open state -> CANCELLED (CAS; `/stop`, C58). Only ever closes a request.

        Returns:
            The result and the request as now stored (None for `unknown`).
            A request already resolved (incl. one that just expired) is
            `already_resolved`; losing a race reports what the winner left.
        """
        for _ in range(_CANCEL_ATTEMPTS):
            request = self._lookup(approval_id)
            if request is None:
                return CancelResult.UNKNOWN, None
            if not request.state.is_open:
                return CancelResult.ALREADY_RESOLVED, request
            try:
                cancelled = request.cancelled(self._at(request))
                self._store.save(cancelled, expected_updated_at=request.updated_at)
            except (ConflictError, InvalidStateError):
                # Lost a race; if it is still open (e.g. tapped meanwhile), /stop
                # must still win, so read it again and retry.
                continue
            self._changed()
            logger.info("approval request cancelled: id=%s", cancelled.id)
            return CancelResult.CANCELLED, cancelled
        logger.warning("approval request %s not cancelled: kept changing", approval_id)
        final = self._lookup(approval_id)
        if final is None:
            return CancelResult.UNKNOWN, None
        result = CancelResult.BUSY if final.state.is_open else CancelResult.ALREADY_RESOLVED
        return result, final

    def cancel_open(self, window_id: str | None = None) -> list[ApprovalRequest]:
        """Cancel every open request (of `window_id`, or of all windows); return the cancelled.

        For `/stop` (C58). Each one is its own CAS; a request that is
        resolved meanwhile (tap, code, consume, expiry) is skipped. With a
        `window_id`, that window's own create budgets start over (newcode-7);
        the global budgets stay, so cancelling can't lift the prompt bound.

        Raises:
            ValidationError: `window_id` is not a canonical lowercase UUID.
        """
        window = None if window_id is None else parse_window_id(window_id)
        if window is not None:
            self._budgets.reset_window(window)
        done: list[ApprovalRequest] = []
        for request in self._store.list_open(window):
            result, stored = self.cancel(request.id)
            if result is CancelResult.CANCELLED and stored is not None:
                done.append(stored)
        return done

    # --- notifier token ------------------------------------------------------------

    def tap(self, approval_id: str, decision: TapDecision) -> TapResult:
        """Record the owner's Approve (PENDING -> TAPPED) or Deny (-> DENIED); first wins."""
        request = self._lookup(approval_id)
        if request is None:
            return TapResult.UNKNOWN
        if request.state is ApprovalState.EXPIRED:
            return TapResult.EXPIRED
        now = self._at(request)
        try:
            if decision is TapDecision.APPROVE:
                if request.state is not ApprovalState.PENDING:
                    return TapResult.ALREADY_DECIDED
                updated, result = request.tapped(now), TapResult.TAPPED
            else:
                if request.state not in (ApprovalState.PENDING, ApprovalState.TAPPED):
                    return TapResult.ALREADY_DECIDED
                updated, result = request.denied(now), TapResult.DENIED
            self._store.save(updated, expected_updated_at=request.updated_at)
        except (ConflictError, InvalidStateError):
            return TapResult.ALREADY_DECIDED
        self._changed()
        logger.info("approval request %s: id=%s", result, request.id)
        return result

    # --- step-up (TOTP verified) ------------------------------------------------------

    def tapped_requests(self) -> list[ApprovalRequest]:
        """Open TAPPED requests that are not expired now (the ones a code may approve)."""
        now = self._clock.now()
        return [
            r
            for r in self._store.list_open()
            if r.state is ApprovalState.TAPPED and not r.is_expired(now)
        ]

    def approve(self, request: ApprovalRequest) -> bool:
        """TAPPED -> APPROVED after a verified code (CAS); False if expired or raced."""
        try:
            approved = request.approved(self._at(request))
            self._store.save(approved, expected_updated_at=request.updated_at)
        except (ConflictError, InvalidStateError, NotFoundError):
            return False
        self._changed()
        logger.info("approval request approved: id=%s", request.id)
        return True

    # --- housekeeping ----------------------------------------------------------------

    def expire_due(self) -> int:
        """Mark every open request past its expiry EXPIRED; return how many changed."""
        now = self._clock.now()
        changed = 0
        for request in self._store.list_expirable(now):
            try:
                expired = request.expired(max(now, request.updated_at))
                self._store.save(expired, expected_updated_at=request.updated_at)
                changed += 1
            except (ConflictError, InvalidStateError):
                continue  # someone else resolved it first
        if changed:
            self._changed()
        return changed

    # --- helpers ---------------------------------------------------------------------

    def _flagged_text(
        self, command: ApprovalCreateCommand, message_id: OwnerMessageId | None
    ) -> str:
        if command.action_text is not None:
            raise ValidationError("a flagged_message text is built by the admin, not sent")
        if command.action_kind is not None or command.action_target is not None:
            raise ValidationError("a flagged_message request has no structured action")
        if message_id is None:
            raise ValidationError("a flagged_message request needs message_id")
        stored = self._require_message(message_id)
        text = flagged_message_text(message_id, stored.text)
        try:
            scan_texts(self._scanner, (text,))
        except SecretDetectedError:
            # Never echo a secret the owner pasted: keep the prefix, drop the excerpt.
            text = flagged_message_text(message_id, "")
        return text

    def _require_message(self, message_id: OwnerMessageId) -> OwnerMessage:
        try:
            return self._messages.get(message_id)
        except NotFoundError:
            raise ValidationError("unknown inbox message") from None

    def _lookup(self, approval_id: str) -> ApprovalRequest | None:
        try:
            return self._fresh(self._store.get(parse_approval_id(approval_id)))
        except (ValidationError, NotFoundError):
            return None

    def _fresh(self, request: ApprovalRequest) -> ApprovalRequest:
        """Mark an overdue open request EXPIRED before anyone looks at it."""
        now = self._clock.now()
        if not (request.state.is_open and request.is_expired(now)):
            return request
        try:
            expired = request.expired(self._at(request))
            self._store.save(expired, expected_updated_at=request.updated_at)
        except (ConflictError, InvalidStateError):
            return self._store.get(request.id)
        self._changed()
        return expired

    def _at(self, request: ApprovalRequest) -> datetime:
        # Never before the stored version: two steps in the same clock tick
        # (or a clock stepped back) must still be one ordered CAS chain.
        return max(self._clock.now(), request.updated_at)

    def _changed(self) -> None:
        if self._events is not None:
            self._events.notify()

    def _consume_refusal(self, request: ApprovalRequest) -> ConsumeResult:
        if request.state is ApprovalState.CONSUMED:
            return ConsumeResult.ALREADY_CONSUMED
        if request.state is ApprovalState.EXPIRED:
            return ConsumeResult.EXPIRED
        return ConsumeResult.NOT_APPROVED

    def _cancel_quietly(self, request: ApprovalRequest) -> None:
        try:
            self._store.save(
                request.cancelled(self._at(request)), expected_updated_at=request.updated_at
            )
        except (ConflictError, InvalidStateError, NotFoundError):
            logger.warning("approval request %s could not be cancelled", request.id)
