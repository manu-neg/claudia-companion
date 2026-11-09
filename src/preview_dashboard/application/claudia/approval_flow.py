"""Claudia's approval flow (ADR 0031, 0038, 0041; docs/security.md C46, C55): ask, park, resume.

A request is opened by the host (never by the model's words alone) in two ways:
- **reply line**: a run that ends with `waiting for approval: <description>`
  asks, after a full-set turn, for the **last approvable action the C59/C60
  hook denied in that run** (`DenialRecorder`), or after a flagged /
  degraded (read-only) turn, a `flagged_message` request for that message;
- **`request_approval` tool** (F-CL3): during a full-set turn she names a
  canonical approvable kind + exact target + a short reason; the host
  checks them (`request_from_tool`) and opens the same kind of request.
The shown text is always host-built (`<kind label>: <target>`, her short
words after it). A request lives up to 24 h, so the host never blocks its
worker on it: it is **parked** and a separate poller (`poll_parked`) watches
the admin; a decided request is handed back to the host's worker, which
calls `settle`. DENIED -> a read-only "denied" turn; APPROVED -> consume
(single use) -> resume with the stored request's `resume_turn()` in a
full-set run whose only cover is that approval, in the request's window or,
if that window closed meanwhile, in the current / a new one (carry-over). A
permission denial in a run that held a CONSUMED action approval is a guard
block (C55): one `failed` alert naming the step, no re-run, and the same
action is refused for the rest of that window. Expired -> fixed text;
cancelled (`/stop`) -> silence. Ports only.
"""

from __future__ import annotations

import hmac
import logging
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Final, Protocol

from preview_dashboard.domain.approvals import (
    APPROVABLE_KINDS,
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    normalize_action_target,
    sanitize_action_text,
)
from preview_dashboard.domain.errors import ConflictError, DomainError, ValidationError
from preview_dashboard.domain.owner_messages import OwnerMessageId
from preview_dashboard.domain.text import reject_invisible
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
TARGET_INPUT_MAX_CHARS: Final = 400
# Admin-side expiry is authoritative; this only bounds how long the host watches.
_WAIT_MARGIN: Final = timedelta(seconds=5)
_MIN_ROUND_SECONDS: Final = 1.0
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

# `request_approval` answers (fixed texts; the tool returns them to her, F-CL3).
TOOL_PENDING_TEXT: Final = (
    "Approval request {id} is pending. Tell the owner in your reply what it is for and end "
    "your turn; the host resumes you once they decide (it expires in 24 hours)."
)
TOOL_NO_RUN_TEXT: Final = "refused: no Claudia turn is running"  # also: wrong/missing run nonce
TOOL_READ_ONLY_TEXT: Final = "refused: this turn is read-only, so it can't ask for an action"
TOOL_ONE_PER_TURN_TEXT: Final = "refused: one approval request per turn"
TOOL_CHAIN_TEXT: Final = "refused: too many approvals in a row for this message; ask the owner"
TOOL_BAD_KIND_TEXT: Final = (
    "refused: action_kind must be one of deploy, dashboard_delete, git_push_main, pr_merge, "
    "rm, settings_edit"
)
TOOL_BAD_TARGET_TEXT: Final = (
    "refused: action_target must be the exact target from the safety check's deny message"
)
TOOL_BAD_REASON_TEXT: Final = (
    "refused: reason must be one short plain line (at most 120 characters, no links, "
    "no invisible characters)"
)

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


def _action_head(kind: ActionKind, target: str) -> str | None:
    try:
        return sanitize_action_text(f"{_ACTION_LABELS[kind]}: {readable_target(kind, target)}")
    except ValidationError:
        return None


def build_action_text(kind: ActionKind, target: str, description: str) -> str | None:
    """The shown action text: host-built `<label>: <target>` first, her description after.

    The structured part always comes first and whole, so a misleading
    description can't hide what is approved; a description that breaks
    the text rules (link, resume look-alike, control chars) is dropped.
    None if even the structured part does not fit the 200-char rule.
    """
    head = _action_head(kind, target)
    if head is None:
        return None
    description = description[:DESCRIPTION_MAX_CHARS].strip()
    if not description:
        return head
    try:
        return sanitize_action_text(f"{head} ({description})")
    except ValidationError:
        return head


def check_tool_reason(raw: object) -> str | None:
    """Her `request_approval` reason if it is one short clean line, else None (F-CL3).

    Strict, unlike the reply-line description (which is dropped when unsafe):
    the tool says why it refused, so she can fix it. At most 120 chars, no
    control / invisible / bidi chars (C35 policy), no link and no resume
    look-alike (checked again on the whole text by `sanitize_action_text`).
    """
    if not isinstance(raw, str):
        return None
    reason = raw.strip()
    if not 1 <= len(reason) <= DESCRIPTION_MAX_CHARS:
        return None
    try:
        reject_invisible(reason, name="reason")
        sanitize_action_text(reason)
    except ValidationError:
        return None
    return reason


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
    """What the host is about to request (all fields host-derived or host-checked)."""

    window_id: WindowId
    kind: ApprovalKind
    action_text: str | None
    action_kind: ActionKind | None
    action_target: str | None
    message_id: OwnerMessageId | None


@dataclass(frozen=True, slots=True, kw_only=True)
class RunContext:
    """The run in progress, as the flow needs it for `request_approval` (F-CL3).

    Attributes:
        window_id: the run's window.
        message_id: the owner message it answers (replies go there), if any.
        actionable: full tool set (only then may she ask for an action).
        generation: the host's `/stop` generation the run belongs to.
        chain: approval round-trips already behind this owner message.
        nonce: the run's random token (env of its `claude` child, read by the
            `claudia-kb` MCP server); `request_approval` must present it. ""
            = the run has none, so the tool is refused.
    """

    window_id: WindowId
    message_id: OwnerMessageId | None
    actionable: bool
    generation: int
    chain: int = 0
    nonce: str = field(default="", repr=False)  # a secret: never in logs or reprs


@dataclass(frozen=True, slots=True, kw_only=True)
class ParkedApproval:
    """An open request the host watches until it is decided (24 h at most, F-CL3).

    Attributes:
        request: the request as last seen.
        message_id: the owner message whose replies it continues.
        generation: the `/stop` generation it was asked under (older -> dropped).
        chain: its round-trip index for that message (0 = first ask).
        gave_up: the host stopped watching at the deadline (treated as expired).
    """

    request: ApprovalRequest
    message_id: OwnerMessageId | None
    generation: int
    chain: int
    gave_up: bool = False


@dataclass(frozen=True, slots=True)
class ToolAnswer:
    """What `request_approval` returns to her: a pending id, or a fixed refusal text."""

    approval_id: ApprovalId | None
    text: str

    @property
    def pending(self) -> bool:
        """True if a request was opened."""
        return self.approval_id is not None


@dataclass(frozen=True, slots=True)
class OpenApproval:
    """A request being waited on (for `/status`; no action text)."""

    kind: ApprovalKind
    action_kind: ActionKind | None
    state: ApprovalState
    expires_at: datetime


class TurnHooks(Protocol):
    """What the flow needs from the host to settle one decided request."""

    def run_turn(
        self,
        prompt: str,
        *,
        full: bool,
        covers: tuple[ApprovalRequest, ...],
        approved_sessions: tuple[str, ...],
    ) -> RunOutcome | None:
        """Run one resume turn; None if it did not run or `/stop` ended it."""
        ...

    def reply_run(self, outcome: RunOutcome) -> str | None:
        """Send her reply for `outcome`; return her text if the run succeeded, else None."""
        ...

    def reply(self, text: str) -> None:
        """Send a fixed host text."""
        ...

    def stopped(self) -> bool:
        """True once `/stop` happened after the request was asked."""
        ...

    def window(self) -> WindowId | None:
        """The window the last resume turn ran in (a chained ask belongs to it)."""
        ...


class ApprovalFlow:
    """Opens, parks and settles approval requests (C46, C55). Thread-safe.

    Three threads use it: the host's worker (runs, `follow`, `settle`), the
    hook control socket (`request_from_tool`) and the approvals poller
    (`poll_parked`); `/stop` (`cancel_parked`) comes from the poller of the inbox.

    Args:
        admin: the approval routes (`claudia` token).
        denials: the gate's `DenialRecorder` (what the hook denied this run).
        alerts: fixed `failed` alerts.
        clock: source of "now".
        record: logs each request state to the audit log (C52), optional.
        poll_seconds: long-poll length per watch round.
        pause: sleep after a round the admin answered at once (tests inject a no-op).
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
        self._wake = threading.Condition(self._lock)
        self._parked: dict[ApprovalId, ParkedApproval] = {}
        self._run: RunContext | None = None
        # Windows whose current run already opened a request with the tool.
        self._tool_asked: set[WindowId] = set()
        # C55: action texts and kind+target keys locked per window after a guard block.
        self._locked: dict[str, set[str]] = {}

    # --- host hooks ----------------------------------------------------------------------

    def begin_run(self, window_id: WindowId, context: RunContext | None = None) -> None:
        """Called before every run: denies and tool asks must come from that run.

        `context` None (recap) means `request_approval` is refused during it.
        """
        self._denials.clear(window_id)
        with self._lock:
            self._tool_asked.discard(window_id)
            self._run = context

    def end_run(self) -> None:
        """Called after every run: the tool has no run to ask for any more."""
        with self._lock:
            self._run = None

    def open_approvals(self) -> list[OpenApproval]:
        """The requests being watched, soonest expiry first (`/status`)."""
        with self._lock:
            parked = [p.request for p in self._parked.values()]
        parked.sort(key=lambda r: (r.expires_at, r.id))
        return [OpenApproval(r.kind, r.action_kind, r.state, r.expires_at) for r in parked]

    def status_line(self, now: datetime) -> str:
        """`/status` line: count, then kind, state, time left of the soonest; never text (C58)."""
        current = self.open_approvals()
        if not current:
            return "approvals open: none"
        first = current[0]
        kind = first.action_kind.value if first.action_kind is not None else first.kind.value
        minutes = max(0, int((first.expires_at - now).total_seconds()) // 60)
        left = f"{minutes // 60}h{minutes % 60:02d}m"
        return f"approvals open: {len(current)} ({kind}, {first.state.value}, expires in {left})"

    def is_locked(self, window_id: WindowId, ask: ApprovalAsk) -> bool:
        """True if C55 locked this action in the window (same text or same kind + target)."""
        keys = self._keys(ask.action_text, ask.action_kind, ask.action_target)
        with self._lock:
            return bool(keys & self._locked.get(window_id, set()))

    def forget_window(self, window_id: WindowId) -> None:
        """Drop the window's C55 locks once it is closed; parked requests stay (F-CL3)."""
        with self._lock:
            self._locked.pop(window_id, None)

    # --- asking --------------------------------------------------------------------------

    def follow(
        self,
        window_id: WindowId,
        result_text: str | None,
        *,
        actionable: bool,
        message_id: OwnerMessageId | None,
        hooks: TurnHooks,
        generation: int = 0,
        chain: int = 0,
    ) -> None:
        """Handle `waiting for approval:` at the end of a run (after its reply was sent).

        Opens and parks the request; never waits. Ignored if the run already
        asked with the tool, and past `MAX_CHAINED_APPROVALS` round-trips per
        owner message. Raises nothing for admin failures (fixed texts instead).
        """
        with self._lock:
            if window_id in self._tool_asked:
                return  # the tool already opened this run's request
        description = parse_waiting_request(result_text)
        if description is None or hooks.stopped() or chain >= MAX_CHAINED_APPROVALS:
            return
        ask = self.ask_for(window_id, description, actionable=actionable, message_id=message_id)
        if ask is None:
            hooks.reply(NO_ACTION_SEEN_TEXT)
            return
        if self.is_locked(window_id, ask):
            _log.warning("window %s: approval refused, action locked after a block", window_id)
            hooks.reply(LOCKED_TEXT)
            return
        try:
            request = self._create(ask)
        except _RefusedError as refused:
            hooks.reply(refused.text)
            return
        self._park(request, message_id=message_id, generation=generation, chain=chain)

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

    def request_from_tool(
        self, action_kind: object, action_target: object, reason: object, nonce: object
    ) -> ToolAnswer:
        """`request_approval` (F-CL3): open a request for the run in progress; never raises.

        Only for the caller that presents the run's own nonce (F-CL3b: the
        MCP server of that run, not a stray process on the socket), in a
        full-set run, once per run, for a canonical approvable kind
        (never `unknown` or `peer_message`), an exact target (normalized like
        the hook's) and a short clean reason. The text is host-built
        (`<label>: <target> (<reason>)`); the admin applies the same checks,
        budgets and one-open-per-window rule as for the reply-line path.
        """
        try:
            return self._tool_request(action_kind, action_target, reason, nonce)
        except Exception as exc:  # a bug must not leave the socket thread hanging
            _log.error("request_approval failed (%s)", type(exc).__name__)
            return ToolAnswer(None, OPEN_FAILED_TEXT)

    def _tool_request(
        self, action_kind: object, action_target: object, reason: object, nonce: object
    ) -> ToolAnswer:
        with self._lock:
            run = self._run
            # Fail closed: no run, a run without a nonce, or a wrong/missing one -> same answer.
            if run is None or not _nonce_matches(run.nonce, nonce):
                return ToolAnswer(None, TOOL_NO_RUN_TEXT)
            if not run.actionable:
                return ToolAnswer(None, TOOL_READ_ONLY_TEXT)
            if run.chain >= MAX_CHAINED_APPROVALS:
                return ToolAnswer(None, TOOL_CHAIN_TEXT)
            if run.window_id in self._tool_asked:
                return ToolAnswer(None, TOOL_ONE_PER_TURN_TEXT)
        kind = _approvable_kind(action_kind)
        if kind is None:
            return ToolAnswer(None, TOOL_BAD_KIND_TEXT)
        target = _exact_target(action_target)
        if target is None:
            return ToolAnswer(None, TOOL_BAD_TARGET_TEXT)
        head = _action_head(kind, target)
        if head is None:
            return ToolAnswer(None, TOOL_BAD_TARGET_TEXT)
        description = check_tool_reason(reason)
        if description is None:
            return ToolAnswer(None, TOOL_BAD_REASON_TEXT)
        try:
            # The structured part first and whole (as for the reply line), then her words.
            text = sanitize_action_text(f"{head} ({description})")
        except ValidationError:
            return ToolAnswer(None, TOOL_BAD_REASON_TEXT)
        ask = ApprovalAsk(
            window_id=run.window_id,
            kind=ApprovalKind.ACTION,
            action_text=text,
            action_kind=kind,
            action_target=target,
            message_id=run.message_id,
        )
        if self.is_locked(run.window_id, ask):
            return ToolAnswer(None, LOCKED_TEXT)
        with self._lock:
            # Reserve before the admin call: a second concurrent call gets "one per turn".
            if self._run is not run or run.window_id in self._tool_asked:
                return ToolAnswer(None, TOOL_ONE_PER_TURN_TEXT)
            self._tool_asked.add(run.window_id)
        try:
            request = self._create(ask)
        except _RefusedError as refused:
            with self._lock:
                self._tool_asked.discard(run.window_id)
            return ToolAnswer(None, refused.text)
        self._park(request, message_id=run.message_id, generation=run.generation, chain=run.chain)
        return ToolAnswer(request.id, TOOL_PENDING_TEXT.format(id=request.id))

    # --- watching ------------------------------------------------------------------------

    def poll_parked(self) -> list[ParkedApproval]:
        """One watch round over the parked requests; return the ones now decided.

        Blocks up to `poll_seconds` when nothing is parked. Admin errors keep
        a request parked (the 24 h deadline still ends it); past its expiry
        (plus a margin) the host cancels it and returns it as `gave_up`.
        Decided / given-up requests are unparked and audited.
        """
        with self._lock:
            if not self._parked:
                self._wake.wait(timeout=self._poll)
            parked = list(self._parked.values())
        if not parked:
            return []
        started = time.monotonic()
        wait = max(_MIN_ROUND_SECONDS, self._poll / len(parked))
        decided: list[ParkedApproval] = []
        for entry in parked:
            outcome = self._watch(entry, wait)
            if outcome is not None:
                decided.append(outcome)
        if not decided and time.monotonic() - started < _MIN_ROUND_SECONDS:
            self._pause(_MIN_ROUND_SECONDS)  # the admin answered at once: don't spin
        return decided

    def _watch(self, entry: ParkedApproval, wait: float) -> ParkedApproval | None:
        request = entry.request
        if self._clock.now() >= request.expires_at + _WAIT_MARGIN:
            self._cancel(request)
            return self._unpark(replace(entry, gave_up=True))
        try:
            current = self._admin.get_approval(request.id, wait=wait)
        except DomainError as exc:
            _log.warning("approval poll failed (%s)", type(exc).__name__)
            return None
        if current.id != request.id:
            _log.error("approval poll answered for another request; ignored")
            return None
        if current.state in _UNDECIDED:
            with self._lock:
                if request.id in self._parked:
                    self._parked[request.id] = replace(entry, request=current)
            return None
        return self._unpark(replace(entry, request=current))

    def cancel_parked(self) -> int:
        """`/stop` (C58): cancel and forget every parked request, any window; return how many."""
        with self._lock:
            parked, self._parked = list(self._parked.values()), {}
        for entry in parked:
            self._cancel(entry.request)
        return len(parked)

    # --- settling ------------------------------------------------------------------------

    def settle(self, decided: ParkedApproval, hooks: TurnHooks) -> None:
        """Act on a decided request (host worker thread): resume, deny turn, or fixed text.

        A resumed run may end with a new ask, which is parked as the next
        round-trip of the same owner message.
        """
        request = decided.request
        if hooks.stopped() or request.state is ApprovalState.CANCELLED:
            return
        if decided.gave_up or request.state is ApprovalState.EXPIRED:
            hooks.reply(EXPIRED_TEXT)
            return
        text = self._resolve(request, hooks)
        window = hooks.window()
        if text is None or window is None:
            return
        self.follow(
            window,
            text,
            actionable=True,  # a resumed run used the full set
            message_id=decided.message_id,
            hooks=hooks,
            generation=decided.generation,
            chain=decided.chain + 1,
        )

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
            self._guard_block(consumed, hooks.window() or consumed.window_id)
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

    def _guard_block(self, consumed: ApprovalRequest, window_id: WindowId) -> None:
        """C55: the step ends here; never re-run, reworded, split or rerouted."""
        keys = self._keys(consumed.action_text, consumed.action_kind, consumed.action_target)
        with self._lock:
            # The window it was asked in and the one it ran in (they differ after carry-over).
            for window in {consumed.window_id, window_id}:
                self._locked.setdefault(window, set()).update(keys)
        _log.error("approval %s: run denied after consume; step stopped", consumed.id)
        self._alerts.failed(GUARD_BLOCK_TITLE.format(action=consumed.action_text))

    # --- helpers ---------------------------------------------------------------------------

    def _create(self, ask: ApprovalAsk) -> ApprovalRequest:
        """Open the request on the admin.

        Raises:
            _RefusedError: with the fixed text to show (busy, refused, failed).
        """
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
            raise _RefusedError(BUSY_TEXT) from None
        except ValidationError:
            raise _RefusedError(REFUSED_TEXT) from None
        except DomainError as exc:
            _log.error("approval request failed (%s)", type(exc).__name__)
            raise _RefusedError(OPEN_FAILED_TEXT) from None
        _log.info("approval %s requested (%s)", request.id, request.kind)
        self._audit(request)
        return request

    def _park(
        self,
        request: ApprovalRequest,
        *,
        message_id: OwnerMessageId | None,
        generation: int,
        chain: int,
    ) -> None:
        entry = ParkedApproval(
            request=request, message_id=message_id, generation=generation, chain=chain
        )
        with self._lock:
            self._parked[request.id] = entry
            self._wake.notify_all()

    def _unpark(self, entry: ParkedApproval) -> ParkedApproval | None:
        with self._lock:
            if self._parked.pop(entry.request.id, None) is None:
                return None  # `/stop` took it meanwhile: nothing to settle
        self._audit(entry.request)
        return entry

    def _cancel(self, request: ApprovalRequest) -> None:
        try:
            self._admin.cancel_approval(request.id)
        except DomainError as exc:
            # It still expires on its own (24 h, the admin checks it on every step).
            _log.warning("approval cancel failed (%s)", type(exc).__name__)

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


class _RefusedError(Exception):
    """Internal: the request was not opened; `text` is the fixed text to show."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


def _nonce_matches(expected: str, presented: object) -> bool:
    """Constant-time compare; an empty expected nonce never matches (fail closed)."""
    if not expected or not isinstance(presented, str):
        return False
    return hmac.compare_digest(expected.encode("utf-8"), presented.encode("utf-8"))


def _approvable_kind(raw: object) -> ActionKind | None:
    if not isinstance(raw, str):
        return None
    try:
        kind = ActionKind(raw)
    except ValueError:
        return None  # `unknown` and anything else
    return kind if kind in APPROVABLE_KINDS else None


def _exact_target(raw: object) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw) > TARGET_INPUT_MAX_CHARS:
        return None
    try:
        return normalize_action_target(raw)
    except ValidationError:
        return None


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
    "TOOL_BAD_KIND_TEXT",
    "TOOL_BAD_REASON_TEXT",
    "TOOL_BAD_TARGET_TEXT",
    "TOOL_CHAIN_TEXT",
    "TOOL_NO_RUN_TEXT",
    "TOOL_ONE_PER_TURN_TEXT",
    "TOOL_PENDING_TEXT",
    "TOOL_READ_ONLY_TEXT",
    "ApprovalAsk",
    "ApprovalFlow",
    "DenialRecorder",
    "DeniedAction",
    "OpenApproval",
    "ParkedApproval",
    "RunContext",
    "ToolAnswer",
    "TurnHooks",
    "build_action_text",
    "check_tool_reason",
    "parse_waiting_request",
]
