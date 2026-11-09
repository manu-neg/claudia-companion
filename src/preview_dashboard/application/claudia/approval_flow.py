"""Claudia's approval flow (ADR 0031; docs/security.md C46 resume, C55): ask, wait, consume, resume.

A run that ends with the line `waiting for approval: <description>` makes
the host (never the model) open one approval request:
- after a full-set turn, for the **last approvable action the C59/C60 hook
  denied in that run** (`DenialRecorder` watches the gate's audit entries),
  so `action_kind` + `action_target` are the classifier's, never the
  model's; the shown text is host-built (`<kind label>: <target>`) with her
  short description after it;
- after a flagged / degraded (read-only) turn, a `flagged_message` request
  for that inbox message (its text is built by the admin, C46).
The host then long-polls until the owner decides. DENIED -> a read-only
"denied" turn; APPROVED -> consume (single use) -> resume with the stored
request's `resume_turn()` in a full-set run whose only cover is that
approval. A permission denial in a run that held a CONSUMED action
approval is a guard block (C55): one `failed` alert naming the step, no
re-run, and the same action is refused for the rest of the window.
Expired -> fixed text; cancelled (`/stop`) -> silence. Ports only.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Protocol

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    sanitize_action_text,
)
from preview_dashboard.domain.errors import ConflictError, DomainError, ValidationError
from preview_dashboard.domain.owner_messages import OwnerMessageId
from preview_dashboard.ports.claudia_host import (
    ApprovalAdmin,
    AuditLog,
    AuditValue,
    HostAlerts,
    RunOutcome,
)
from preview_dashboard.ports.clock import Clock

_log = logging.getLogger(__name__)

POLL_SECONDS: Final = 50.0
MAX_CHAINED_APPROVALS: Final = 3
DESCRIPTION_MAX_CHARS: Final = 120
# Admin-side expiry is authoritative; this only bounds the host's wait.
_WAIT_MARGIN: Final = timedelta(seconds=5)
_MAX_POLL_FAILURES: Final = 3
_RETRY_PAUSE_SECONDS: Final = 5.0
_MIN_POLL: Final = timedelta(seconds=1)
_HOOK_DENY_EVENT: Final = "hook_deny"
_UNDECIDED: Final = frozenset({ApprovalState.PENDING, ApprovalState.TAPPED})
# Markdown emphasis she may wrap the marker line in; nothing else is stripped.
_EMPHASIS: Final = "*_` \t"
_WAITING_RE: Final = re.compile(r"waiting for approval\s*:\s*(.*)", re.IGNORECASE | re.DOTALL)

# Fixed host texts (never model output).
NO_ACTION_SEEN_TEXT: Final = (
    "I couldn't ask for your approval: the safety check didn't see the exact step. "
    "Ask me again and I'll try it first, so the check can name it."
)
LOCKED_TEXT: Final = (
    "That step was blocked after your approval, so I won't try it again in this conversation."
)
BUSY_TEXT: Final = "Another approval request is still open; answer it or let it expire first."
REFUSED_TEXT: Final = "I couldn't open that approval request safely, so nothing was run."
OPEN_FAILED_TEXT: Final = "I couldn't open the approval request, so nothing was run."
EXPIRED_TEXT: Final = "The approval request expired, so nothing was run."
NOT_USABLE_TEXT: Final = "The approval could no longer be used, so nothing was run."
GUARD_BLOCK_TITLE: Final = "Claudia stopped a step blocked after approval: {action}"

_ACTION_LABELS: Final = {
    ActionKind.PR_MERGE: "Merge PR",
    ActionKind.DEPLOY: "Deploy",
    ActionKind.GIT_PUSH_MAIN: "Push to main",
    ActionKind.RM: "Delete files",
    ActionKind.DASHBOARD_DELETE: "Delete from the dashboard",
    ActionKind.SETTINGS_EDIT: "Edit settings",
    ActionKind.PEER_MESSAGE: "Message session",
}


def parse_waiting_request(text: str | None) -> str | None:
    """Her description if the **last** non-empty line is `waiting for approval: …`, else None.

    Only the last line counts ("the run ends with"), so quoting the phrase
    mid-reply never opens a request. Returns `""` for an empty description.
    """
    if not text:
        return None
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    match = _WAITING_RE.fullmatch(lines[-1].strip(_EMPHASIS))
    if match is None:
        return None
    return match.group(1).strip(_EMPHASIS + ".")


_TRASH_TARGET_RE: Final = re.compile(r"trash:([0-9A-Z]{26})")
_PRUNE_TARGET_RE: Final = re.compile(r"prune:([0-9A-Z]{26}):keep=([1-9][0-9]{0,8})")


def readable_target(kind: ActionKind, target: str) -> str:
    """The owner-facing words for a classifier target (hook-6 dashboard deletes).

    `trash:<id>`, `prune:<id>:keep=N` and `empty:trash` become plain words;
    anything else is shown as is. Only the shown text changes: the stored
    `action_target` (what the approval covers) stays the classifier's.
    """
    if kind is not ActionKind.DASHBOARD_DELETE:
        return target
    if target == "empty:trash":
        return "empty the trash permanently"
    if match := _TRASH_TARGET_RE.fullmatch(target):
        return f"move item {match[1]} to trash"
    if match := _PRUNE_TARGET_RE.fullmatch(target):
        return f"delete old versions of {match[1]}, keep {match[2]}"
    return target


def build_action_text(kind: ActionKind, target: str, description: str) -> str | None:
    """The shown action text: host-built `<label>: <target>` first, her description after.

    The structured part always comes first and whole, so a misleading
    description can't hide what is approved; a description that breaks
    the text rules (link, resume look-alike, control chars) is dropped.
    None if even the structured part does not fit the 200-char rule.
    """
    head = f"{_ACTION_LABELS[kind]}: {readable_target(kind, target)}"
    try:
        head = sanitize_action_text(head)
    except ValidationError:
        return None
    description = description[:DESCRIPTION_MAX_CHARS].strip()
    if not description:
        return head
    try:
        return sanitize_action_text(f"{head} ({description})")
    except ValidationError:
        return head


@dataclass(frozen=True, slots=True)
class DeniedAction:
    """An approvable action the hook denied (kind + normalized target from the classifier)."""

    kind: ActionKind
    target: str


class DenialRecorder:
    """`AuditLog` decorator in front of the hook gate's log: remembers its last approvable deny.

    Every entry is forwarded unchanged. A `hook_deny` entry with a canonical
    action kind and a target is kept per window, so the flow asks for exactly
    what the classifier saw (C59), never for what the model claims.

    Args:
        inner: the real audit log.
    """

    def __init__(self, inner: AuditLog) -> None:
        self._inner = inner
        self._lock = threading.Lock()
        self._last: dict[str, DeniedAction] = {}

    def record(self, entry: Mapping[str, AuditValue]) -> None:
        """Note an approvable deny, then forward the entry; never raises."""
        try:
            self._note(entry)
        except Exception as exc:  # the audit entry still goes through
            _log.error("denial recorder failed (%s)", type(exc).__name__)
        self._inner.record(entry)

    def clear(self, window_id: WindowId) -> None:
        """Forget the window's last deny (called at the start of every run)."""
        with self._lock:
            self._last.pop(window_id, None)

    def last(self, window_id: WindowId) -> DeniedAction | None:
        """The last approvable deny of the window's current run, if any."""
        with self._lock:
            return self._last.get(window_id)

    def _note(self, entry: Mapping[str, AuditValue]) -> None:
        if entry.get("event") != _HOOK_DENY_EVENT:
            return
        window, label = entry.get("window"), entry.get("action_kind")
        target = entry.get("action_target")
        if not isinstance(window, str) or not isinstance(label, str) or not isinstance(target, str):
            return  # `unknown` or no exact target: nothing any approval could cover
        try:
            kind = ActionKind(label)
        except ValueError:
            return
        with self._lock:
            self._last[window] = DeniedAction(kind, target)


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalAsk:
    """What the host is about to request (all fields host-derived)."""

    window_id: WindowId
    kind: ApprovalKind
    action_text: str | None
    action_kind: ActionKind | None
    action_target: str | None
    message_id: OwnerMessageId | None


@dataclass(frozen=True, slots=True)
class OpenApproval:
    """The request the host is waiting on (for `/status`; no action text)."""

    kind: ApprovalKind
    action_kind: ActionKind | None
    state: ApprovalState
    expires_at: datetime


class TurnHooks(Protocol):
    """What the flow needs from the host for one owner message."""

    def run_turn(
        self,
        prompt: str,
        *,
        full: bool,
        covers: tuple[ApprovalRequest, ...],
        approved_sessions: tuple[str, ...],
    ) -> RunOutcome | None:
        """Run one resume turn in the window; None if it did not run or `/stop` ended it."""
        ...

    def reply_run(self, outcome: RunOutcome) -> str | None:
        """Send her reply for `outcome`; return her text if the run succeeded, else None."""
        ...

    def reply(self, text: str) -> None:
        """Send a fixed host text."""
        ...

    def stopped(self) -> bool:
        """True once `/stop` happened after this message started."""
        ...


class ApprovalFlow:
    """Runs the approval round-trips of one window's turns (C46, C55). Thread-safe for status.

    Args:
        admin: the approval routes (`claudia` token).
        denials: the gate's `DenialRecorder` (what the hook denied this run).
        alerts: fixed `failed` alerts.
        clock: source of "now".
        record: logs each request state to the audit log (C52), optional.
        poll_seconds: long-poll length per wait round.
        pause: sleep between retries after an admin error (tests inject a no-op).
    """

    def __init__(
        self,
        *,
        admin: ApprovalAdmin,
        denials: DenialRecorder,
        alerts: HostAlerts,
        clock: Clock,
        record: Callable[[ApprovalRequest], None] | None = None,
        poll_seconds: float = POLL_SECONDS,
        pause: Callable[[float], None] = time.sleep,
    ) -> None:
        self._admin = admin
        self._denials = denials
        self._alerts = alerts
        self._clock = clock
        self._record = record
        self._poll = poll_seconds
        self._pause = pause
        self._lock = threading.Lock()
        self._open: ApprovalRequest | None = None
        # C55: action texts and kind+target keys locked per window after a guard block.
        self._locked: dict[str, set[str]] = {}

    # --- host hooks ----------------------------------------------------------------------

    def begin_run(self, window_id: WindowId) -> None:
        """Called before every run: the deny that names an ask must come from that run."""
        self._denials.clear(window_id)

    def open_approval(self) -> OpenApproval | None:
        """The request being waited on, if any (`/status`)."""
        with self._lock:
            request = self._open
        if request is None:
            return None
        return OpenApproval(request.kind, request.action_kind, request.state, request.expires_at)

    def status_line(self, now: datetime) -> str:
        """`/status` line: count, kind, state, minutes left; never the action text (C58)."""
        current = self.open_approval()
        if current is None:
            return "approvals open: none"
        kind = current.action_kind.value if current.action_kind is not None else current.kind.value
        minutes = max(0, int((current.expires_at - now).total_seconds()) // 60)
        return f"approvals open: 1 ({kind}, {current.state.value}, expires in {minutes} min)"

    def is_locked(self, window_id: WindowId, ask: ApprovalAsk) -> bool:
        """True if C55 locked this action in the window (same text or same kind + target)."""
        keys = self._keys(ask.action_text, ask.action_kind, ask.action_target)
        with self._lock:
            return bool(keys & self._locked.get(window_id, set()))

    def forget_window(self, window_id: WindowId) -> None:
        """Drop the window's C55 locks once it is closed (a new window starts clean)."""
        with self._lock:
            self._locked.pop(window_id, None)

    # --- the flow ------------------------------------------------------------------------

    def follow(
        self,
        window_id: WindowId,
        result_text: str | None,
        *,
        actionable: bool,
        message_id: OwnerMessageId | None,
        hooks: TurnHooks,
    ) -> None:
        """Handle `waiting for approval:` at the end of a run (after its reply was sent).

        At most `MAX_CHAINED_APPROVALS` round-trips per owner message. Raises
        nothing for admin failures (fixed texts instead); a bug propagates to
        the host's per-message isolation.
        """
        text = result_text
        for _ in range(MAX_CHAINED_APPROVALS):
            description = parse_waiting_request(text)
            if description is None or hooks.stopped():
                return
            ask = self.ask_for(window_id, description, actionable=actionable, message_id=message_id)
            if ask is None:
                hooks.reply(NO_ACTION_SEEN_TEXT)
                return
            if self.is_locked(window_id, ask):
                _log.warning("window %s: approval refused, action locked after a block", window_id)
                hooks.reply(LOCKED_TEXT)
                return
            request = self._create(ask, hooks)
            if request is None:
                return
            final = self._wait(request, hooks)
            if final is None:
                return
            text = self._resolve(final, hooks)
            # A resumed run used the full set: any further ask is an action ask.
            actionable = True

    def ask_for(
        self,
        window_id: WindowId,
        description: str,
        *,
        actionable: bool,
        message_id: OwnerMessageId | None,
    ) -> ApprovalAsk | None:
        """The request for this run, or None if the host can't name one exactly.

        Read-only turns (flagged / degraded) can only ask to treat their
        message as a request; full turns ask for the hook's last deny.
        """
        if not actionable:
            if message_id is None:
                return None
            return ApprovalAsk(
                window_id=window_id,
                kind=ApprovalKind.FLAGGED_MESSAGE,
                action_text=None,
                action_kind=None,
                action_target=None,
                message_id=message_id,
            )
        denied = self._denials.last(window_id)
        if denied is None:
            return None
        text = build_action_text(denied.kind, denied.target, description)
        if text is None:
            return None
        kind = (
            ApprovalKind.PEER_MESSAGE
            if denied.kind is ActionKind.PEER_MESSAGE
            else ApprovalKind.ACTION
        )
        return ApprovalAsk(
            window_id=window_id,
            kind=kind,
            action_text=text,
            action_kind=denied.kind,
            action_target=denied.target,
            message_id=message_id,
        )

    # --- steps ---------------------------------------------------------------------------

    def _create(self, ask: ApprovalAsk, hooks: TurnHooks) -> ApprovalRequest | None:
        try:
            request = self._admin.request_approval(
                window_id=ask.window_id,
                kind=ask.kind,
                action_text=ask.action_text,
                action_kind=ask.action_kind,
                action_target=ask.action_target,
                message_id=ask.message_id,
            )
        except ConflictError:
            hooks.reply(BUSY_TEXT)
            return None
        except ValidationError:
            hooks.reply(REFUSED_TEXT)
            return None
        except DomainError as exc:
            _log.error("approval request failed (%s)", type(exc).__name__)
            hooks.reply(OPEN_FAILED_TEXT)
            return None
        _log.info("approval %s requested (%s)", request.id, request.kind)
        self._audit(request)
        return request

    def _wait(self, request: ApprovalRequest, hooks: TurnHooks) -> ApprovalRequest | None:
        """Poll until decided; None if stopped / cancelled (silence) or given up (fixed text)."""
        current = request
        failures = 0
        deadline = request.expires_at + _WAIT_MARGIN
        self._set_open(current)
        try:
            while current.state in _UNDECIDED:
                if hooks.stopped():
                    self._cancel(current)
                    return None
                left = (deadline - self._clock.now()).total_seconds()
                if left <= 0:
                    self._cancel(current)
                    hooks.reply(EXPIRED_TEXT)
                    return None
                started = self._clock.now()
                try:
                    current = self._admin.get_approval(
                        current.id, wait=max(1.0, min(self._poll, left))
                    )
                    if current.state in _UNDECIDED and self._clock.now() - started < _MIN_POLL:
                        # The admin answered at once (its waiter slots were full): don't spin.
                        self._pause(_MIN_POLL.total_seconds())
                except DomainError as exc:
                    failures += 1
                    _log.warning("approval poll failed (%s)", type(exc).__name__)
                    if failures >= _MAX_POLL_FAILURES:
                        self._cancel(current)
                        hooks.reply(OPEN_FAILED_TEXT)
                        return None
                    self._pause(_RETRY_PAUSE_SECONDS)
                    continue
                failures = 0
                self._set_open(current)
        finally:
            self._set_open(None)
        self._audit(current)
        if hooks.stopped() or current.state is ApprovalState.CANCELLED:
            return None
        if current.state is ApprovalState.EXPIRED:
            hooks.reply(EXPIRED_TEXT)
            return None
        return current

    def _resolve(self, decided: ApprovalRequest, hooks: TurnHooks) -> str | None:
        """Run the denied or approved turn; return her text if a further ask may follow."""
        if decided.state is ApprovalState.DENIED:
            outcome = hooks.run_turn(
                decided.resume_turn(), full=False, covers=(), approved_sessions=()
            )
            if outcome is not None:
                hooks.reply_run(outcome)
            return None  # a denial never chains into a new ask
        if decided.state is not ApprovalState.APPROVED:
            hooks.reply(NOT_USABLE_TEXT)
            return None
        consumed = self._consume(decided)
        if consumed is None:
            hooks.reply(NOT_USABLE_TEXT)
            return None
        is_action = consumed.kind is not ApprovalKind.FLAGGED_MESSAGE
        covers = (consumed,) if is_action else ()
        sessions = (
            (consumed.action_target,)
            if consumed.kind is ApprovalKind.PEER_MESSAGE and consumed.action_target
            else ()
        )
        outcome = hooks.run_turn(
            consumed.resume_turn(), full=True, covers=covers, approved_sessions=sessions
        )
        if outcome is None:
            return None
        if is_action and outcome.permission_denials > 0:
            self._guard_block(consumed)
            return None
        return hooks.reply_run(outcome)

    def _consume(self, request: ApprovalRequest) -> ApprovalRequest | None:
        try:
            result, consumed = self._admin.consume_approval(request.id)
        except DomainError as exc:
            _log.error("approval consume failed (%s)", type(exc).__name__)
            return None
        _log.info("approval %s consume: %s", request.id, result)
        valid = (
            result == "consumed"
            and consumed is not None
            and consumed.state is ApprovalState.CONSUMED
            and consumed.id == request.id
            and consumed.window_id == request.window_id
        )
        if not valid or consumed is None:
            return None
        self._audit(consumed)
        return consumed

    def _guard_block(self, consumed: ApprovalRequest) -> None:
        """C55: the step ends here; never re-run, reworded, split or rerouted."""
        keys = self._keys(consumed.action_text, consumed.action_kind, consumed.action_target)
        with self._lock:
            self._locked.setdefault(consumed.window_id, set()).update(keys)
        _log.error("approval %s: run denied after consume; step stopped", consumed.id)
        self._alerts.failed(GUARD_BLOCK_TITLE.format(action=consumed.action_text))

    # --- helpers ---------------------------------------------------------------------------

    def _cancel(self, request: ApprovalRequest) -> None:
        try:
            self._admin.cancel_approval(request.id)
        except DomainError as exc:
            # It still expires on its own after 600 s.
            _log.warning("approval cancel failed (%s)", type(exc).__name__)

    def _set_open(self, request: ApprovalRequest | None) -> None:
        with self._lock:
            self._open = request

    def _audit(self, request: ApprovalRequest) -> None:
        if self._record is None:
            return
        try:
            self._record(request)
        except Exception as exc:
            _log.error("approval audit failed (%s)", type(exc).__name__)

    @staticmethod
    def _keys(text: str | None, kind: ActionKind | None, target: str | None) -> set[str]:
        keys: set[str] = set()
        if text is not None:
            keys.add(f"text:{text}")
        if kind is not None and target is not None:
            keys.add(f"action:{kind.value}:{target}")
        return keys


__all__ = [
    "BUSY_TEXT",
    "EXPIRED_TEXT",
    "GUARD_BLOCK_TITLE",
    "LOCKED_TEXT",
    "MAX_CHAINED_APPROVALS",
    "NOT_USABLE_TEXT",
    "NO_ACTION_SEEN_TEXT",
    "OPEN_FAILED_TEXT",
    "REFUSED_TEXT",
    "ApprovalAsk",
    "ApprovalFlow",
    "DenialRecorder",
    "DeniedAction",
    "OpenApproval",
    "TurnHooks",
    "build_action_text",
    "parse_waiting_request",
]
