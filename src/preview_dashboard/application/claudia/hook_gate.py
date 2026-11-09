"""The host side of the risky-action hook (docs/security.md C59, C60): deny, or no decision.

`HookGate.decide` takes one PreToolUse call forwarded by the hook command
and answers `deny` (reason = the action kind, never command text) or
**no decision**, so the permission guard still decides; it never grants.
A risky call gets no decision only if the run in progress holds a
CONSUMED approval with the same `action_kind` + `action_target` that no
earlier call used: one approval covers **one** call (orchestrator decision,
backlog §15.2) and its cover ends with the run. `SendMessage` needs the
peer prefix, and for an interactive or unknown session a `peer_message`
approval for that session (C60). A tool it does not know, malformed
input, no run in progress or another session id: deny (fail closed). A
call that would reach the owner past the host (dashboard MCP server, CLI,
admin socket; `domain/dashboard_bypass.py`, F-CL1) is denied as
`dashboard_bypass`, never approvable. Framework-free; thread-safe.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    normalize_action_target,
    parse_window_id,
)
from preview_dashboard.domain.dashboard_bypass import DASHBOARD_BYPASS_LABEL, is_dashboard_bypass
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.risky_actions import (
    SEND_MESSAGE_TOOL,
    UNKNOWN_LABEL,
    RiskyAction,
    classify_tool_call,
    has_peer_prefix,
    is_known_tool,
)
from preview_dashboard.ports.claudia_host import AuditLog, PeerDirectory
from preview_dashboard.ports.clock import Clock

_log = logging.getLogger(__name__)

HOOK_EVENT: Final = "PreToolUse"
MAX_FIELD_CHARS: Final = 4096
_TOOL_NAME_MAX: Final = 200


class HookVerdict(StrEnum):
    """What the hook prints: `deny`, or nothing at all (`no_decision`)."""

    DENY = "deny"
    NO_DECISION = "no_decision"


@dataclass(frozen=True, slots=True)
class HookDecision:
    """One answer to the hook; `reason` is a fixed label (never command text)."""

    verdict: HookVerdict
    reason: str | None = None

    @classmethod
    def deny(cls, reason: str) -> HookDecision:
        """A deny with a fixed, content-free reason."""
        return cls(HookVerdict.DENY, reason)

    @classmethod
    def no_decision(cls) -> HookDecision:
        """No opinion: the permission guard decides as usual."""
        return cls(HookVerdict.NO_DECISION)


# Fixed reasons; the action kind is the only variable part (C59).
REASON_MALFORMED: Final = "malformed hook input"
REASON_NO_RUN: Final = "no Claudia run in progress for this session"
REASON_ERROR: Final = "hook check failed"
REASON_PEER_PREFIX: Final = "peer_message: text must start with the Claudia prefix"
REASON_UNKNOWN_TOOL: Final = "unknown: this tool is not available in Claudia runs"
# <= 160 chars of the hook's reason charset (interfaces/claudia/hook.py).
REASON_DASHBOARD_BYPASS: Final = (
    "dashboard_bypass: reach the owner only through your reply, never via the dashboard "
    "MCP server, CLI, admin socket or Telegram. Say what you need in the reply"
)


def needs_approval(label: str) -> str:
    """The deny reason for a risky call without a matching consumed approval."""
    return f"{label}: needs a consumed owner approval for this exact action"


@dataclass(frozen=True, slots=True, kw_only=True)
class HookCall:
    """A validated PreToolUse call: session, cwd, tool name and its input."""

    session_id: WindowId
    cwd: str | None
    tool_name: str
    tool_input: Mapping[str, object]

    def __repr__(self) -> str:
        # Tool input holds command text: never in reprs or logs (C59).
        return f"HookCall(session_id={self.session_id!r}, tool_name={self.tool_name!r})"


def parse_hook_call(raw: object) -> HookCall:
    """Validate a forwarded hook input strictly.

    Raises:
        ValidationError: not an object, wrong event, bad session id, cwd or
            tool name, or `tool_input` not an object.
    """
    if not isinstance(raw, Mapping):
        raise ValidationError("hook input must be an object")
    if raw.get("hook_event_name") != HOOK_EVENT:
        raise ValidationError("not a PreToolUse event")
    session = parse_window_id(raw.get("session_id"))
    cwd = raw.get("cwd")
    if cwd is not None and (
        not isinstance(cwd, str) or not cwd.startswith("/") or len(cwd) > MAX_FIELD_CHARS
    ):
        raise ValidationError("bad cwd")
    tool = raw.get("tool_name")
    if not isinstance(tool, str) or not 0 < len(tool) <= _TOOL_NAME_MAX or not tool.isprintable():
        raise ValidationError("bad tool name")
    tool_input = raw.get("tool_input")
    if not isinstance(tool_input, Mapping):
        raise ValidationError("tool_input must be an object")
    return HookCall(session_id=session, cwd=cwd, tool_name=tool, tool_input=dict(tool_input))


@dataclass(slots=True)
class _Run:
    window_id: WindowId
    covers: tuple[ApprovalRequest, ...]
    used: set[ApprovalId]


class HookGate:
    """Decides hook calls against the run in progress (C59, C60).

    Args:
        peers: resolves `SendMessage` targets (unknown -> interactive).
        audit: records denies and used covers (kind + target only, C52).
        clock: time for audit entries.
        realpath: optional symlink resolver for edited paths (`os.path.realpath`).
    """

    def __init__(
        self,
        peers: PeerDirectory,
        audit: AuditLog,
        clock: Clock,
        *,
        realpath: Callable[[str], str] | None = None,
    ) -> None:
        self._peers = peers
        self._audit = audit
        self._clock = clock
        self._realpath = realpath
        self._lock = threading.Lock()
        self._run: _Run | None = None

    # --- run lifecycle (called by the host around every `claude -p` run) ---------------

    def begin_run(self, window_id: WindowId, covers: Iterable[ApprovalRequest] = ()) -> None:
        """Start a run of `window_id`, with the approvals the host consumed for it.

        Raises:
            ValidationError: a cover is not CONSUMED, belongs to another
                window, or is a `flagged_message` request (covers nothing, C46).
        """
        window = parse_window_id(window_id)
        checked = tuple(covers)
        for request in checked:
            if request.state is not ApprovalState.CONSUMED or request.window_id != window:
                raise ValidationError("a run's cover must be a CONSUMED approval of its window")
            if request.kind is ApprovalKind.FLAGGED_MESSAGE:
                raise ValidationError("a flagged_message approval covers no action")
        with self._lock:
            self._run = _Run(window, checked, set())

    def end_run(self) -> None:
        """End the run in progress: its covers end with it (C59)."""
        with self._lock:
            self._run = None

    # --- decisions ---------------------------------------------------------------------

    def decide(self, raw: object) -> HookDecision:
        """Answer one forwarded hook call; never raises (any error is a deny)."""
        try:
            return self._decide(raw)
        except Exception as exc:
            # Type name only: messages may quote the command (C59: no command text).
            _log.error("hook decision failed (%s)", type(exc).__name__)
            return HookDecision.deny(REASON_ERROR)

    def _decide(self, raw: object) -> HookDecision:
        try:
            call = parse_hook_call(raw)
        except ValidationError:
            _log.warning("hook: malformed input denied")
            return HookDecision.deny(REASON_MALFORMED)
        run = self._current(call.session_id)
        if run is None:
            _log.warning("hook: call outside a Claudia run denied")
            return HookDecision.deny(REASON_NO_RUN)
        if call.tool_name == SEND_MESSAGE_TOOL:
            return self._send_message(run, call)
        if not is_known_tool(call.tool_name):
            # host-flow-3: the hook sees every tool; one we don't know (e.g. a
            # new built-in that runs commands) could act without any check.
            self._record(run, "hook_deny", UNKNOWN_LABEL, None, reason="unknown_tool")
            return HookDecision.deny(REASON_UNKNOWN_TOOL)
        if is_dashboard_bypass(call.tool_name, call.tool_input):
            # F-CL1: she reaches the owner only through her reply; no target, so
            # no approval can ever cover it.
            self._record(run, "hook_deny", DASHBOARD_BYPASS_LABEL, None, reason="dashboard_bypass")
            _log.info("hook: %s denied", DASHBOARD_BYPASS_LABEL)
            return HookDecision.deny(REASON_DASHBOARD_BYPASS)
        action = classify_tool_call(
            call.tool_name, call.tool_input, call.cwd, realpath=self._realpath
        )
        if action is None:
            return HookDecision.no_decision()
        if action.kind is ActionKind.PEER_MESSAGE:
            return self._deny(run, action)  # never via a non-SendMessage tool
        return self._covered(run, action)

    def _current(self, session_id: WindowId) -> _Run | None:
        with self._lock:
            run = self._run
        return run if run is not None and run.window_id == session_id else None

    def _send_message(self, run: _Run, call: HookCall) -> HookDecision:
        """C60: prefix always; interactive or unknown target needs a `peer_message` cover."""
        target = call.tool_input.get("to")
        if not isinstance(target, str) or not target or len(target) > MAX_FIELD_CHARS:
            return HookDecision.deny(REASON_MALFORMED)
        if not has_peer_prefix(call.tool_input.get("message")):
            self._record(run, "hook_deny", "peer_message", None, reason="missing_prefix")
            return HookDecision.deny(REASON_PEER_PREFIX)
        try:
            peer = self._peers.lookup(target)
        except Exception as exc:
            _log.warning("hook: peer lookup failed (%s)", type(exc).__name__)
            peer = None
        if peer is not None and not peer.interactive:
            return HookDecision.no_decision()
        session = peer.session_id if peer is not None else target
        try:
            normalized: str | None = normalize_action_target(session)
        except ValidationError:
            normalized = None
        return self._covered(run, RiskyAction(ActionKind.PEER_MESSAGE, normalized))

    def _covered(self, run: _Run, action: RiskyAction) -> HookDecision:
        if action.kind is None or action.target is None:
            return self._deny(run, action)
        found: ApprovalRequest | None = None
        with self._lock:
            if self._run is not run:
                return HookDecision.deny(REASON_NO_RUN)  # the run ended meanwhile
            for request in run.covers:
                if request.id not in run.used and request.covers(action.kind, action.target):
                    # Single use (C46): this approval covers this one call only.
                    run.used.add(request.id)
                    found = request
                    break
        if found is None:
            return self._deny(run, action)
        self._record(run, "hook_cover_used", action.label, action.target, approval=found.id)
        return HookDecision.no_decision()

    def _deny(self, run: _Run, action: RiskyAction) -> HookDecision:
        self._record(run, "hook_deny", action.label, action.target)
        _log.info("hook: %s denied", action.label)
        return HookDecision.deny(needs_approval(action.label))

    def _record(
        self,
        run: _Run,
        event: str,
        label: str,
        target: str | None,
        *,
        reason: str | None = None,
        approval: str | None = None,
    ) -> None:
        # Kind + target only, never the command or message text (C52, C59).
        entry: dict[str, str | None] = {
            "event": event,
            "at": self._clock.now().isoformat(),
            "window": run.window_id,
            "action_kind": label,
            "action_target": target,
        }
        if reason is not None:
            entry["reason"] = reason
        if approval is not None:
            entry["approval"] = approval
        try:
            self._audit.record(entry)
        except Exception as exc:
            _log.error("hook audit failed (%s)", type(exc).__name__)


__all__ = [
    "HOOK_EVENT",
    "REASON_DASHBOARD_BYPASS",
    "REASON_MALFORMED",
    "REASON_NO_RUN",
    "REASON_PEER_PREFIX",
    "REASON_UNKNOWN_TOOL",
    "HookCall",
    "HookDecision",
    "HookGate",
    "HookVerdict",
    "needs_approval",
    "parse_hook_call",
]
