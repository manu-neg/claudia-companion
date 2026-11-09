"""Peer-message audit (ADR 0031, docs/security.md C52): the detective layer behind the C60 hook.

After every run the host reads the `SendMessage` calls Claude Code wrote
to that run's transcript (not model output) and records each one: time,
target, summary, length and SHA-256 of the text, never the text. A message
without the `From Claudia (owner's companion):` prefix, or to an
interactive (or unknown) session without a consumed `peer_message`
approval for that session, is a violation: the caller alerts and stops.
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection
from dataclasses import dataclass
from enum import StrEnum

from preview_dashboard.domain.approvals import ApprovalRequest, WindowId
from preview_dashboard.ports.claudia_host import (
    AuditLog,
    PeerDirectory,
    SendMessageCall,
    TranscriptReader,
)
from preview_dashboard.ports.clock import Clock

PEER_PREFIX = "From Claudia (owner's companion):"
SUMMARY_MAX_CHARS = 80
TARGET_MAX_CHARS = 100


class AuditViolation(StrEnum):
    """Why an audited run breaks the peer rules (C52)."""

    MISSING_PREFIX = "missing_prefix"
    INTERACTIVE_WITHOUT_APPROVAL = "interactive_without_approval"
    # An unreadable / oversized transcript can't show what was sent: fail closed.
    TRANSCRIPT_INCOMPLETE = "transcript_incomplete"


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Result of auditing one run: how many messages, and the violations found."""

    messages: int
    violations: tuple[AuditViolation, ...]

    @property
    def clean(self) -> bool:
        """True if nothing broke the rules."""
        return not self.violations


def clip(text: str, limit: int) -> str:
    """Printable chars only, cut to `limit` (audit fields are display-only, never text)."""
    return "".join(ch for ch in text if ch.isprintable())[:limit]


class PeerAudit:
    """Audits the `SendMessage` calls of a run against C52.

    Args:
        transcripts: the window transcripts (written by Claude Code).
        peers: resolves targets to sessions (unknown -> interactive).
        log: the audit log (no message text).
        clock: source of "now" for entries.
    """

    def __init__(
        self, transcripts: TranscriptReader, peers: PeerDirectory, log: AuditLog, clock: Clock
    ) -> None:
        self._transcripts = transcripts
        self._peers = peers
        self._log = log
        self._clock = clock

    def offset(self, window_id: WindowId) -> int:
        """Transcript position to audit from (take it before the run starts)."""
        return self._transcripts.offset(window_id)

    def audit_run(
        self, window_id: WindowId, since: int, approved_sessions: Collection[str] = ()
    ) -> AuditReport:
        """Audit the calls written after `since`; record every one (C52).

        Args:
            approved_sessions: targets of `peer_message` approvals consumed
                for this run (unit M5); empty means none, so every message
                to an interactive session is a violation.
        """
        found = self._transcripts.send_messages(window_id, since)
        violations: list[AuditViolation] = []
        for call in found.calls:
            violations.extend(self._audit_call(window_id, call, approved_sessions))
        if not found.complete:
            violations.append(AuditViolation.TRANSCRIPT_INCOMPLETE)
            self._log.record(
                {
                    "event": "transcript_incomplete",
                    "at": self._clock.now().isoformat(),
                    "window": window_id,
                    "malformed_lines": found.malformed_lines,
                }
            )
        return AuditReport(messages=len(found.calls), violations=tuple(violations))

    def record_approval(self, request: ApprovalRequest) -> None:
        """Log one approval request's state (id, kind, structured action; C52)."""
        self._log.record(
            {
                "event": "approval",
                "at": self._clock.now().isoformat(),
                "window": request.window_id,
                "approval": request.id,
                "kind": str(request.kind),
                "action_kind": None if request.action_kind is None else str(request.action_kind),
                "action_target": request.action_target,
                "state": str(request.state),
            }
        )

    def _audit_call(
        self, window_id: WindowId, call: SendMessageCall, approved_sessions: Collection[str]
    ) -> list[AuditViolation]:
        peer = self._peers.lookup(call.target)
        interactive = peer is None or peer.interactive  # unknown -> interactive (fail closed)
        approved = peer is not None and peer.session_id in approved_sessions
        prefixed = call.text.startswith(PEER_PREFIX)
        self._log.record(
            {
                "event": "peer_message",
                "at": self._clock.now().isoformat(),
                "sent_at": None if call.timestamp is None else clip(call.timestamp, 40),
                "window": window_id,
                "target": clip(call.target, TARGET_MAX_CHARS),
                "session": None if peer is None else clip(peer.session_id, TARGET_MAX_CHARS),
                "interactive": interactive,
                "summary": clip(call.summary, SUMMARY_MAX_CHARS),
                "length": len(call.text),
                # A digest, not the text: proves what was sent without storing it.
                "sha256": hashlib.sha256(call.text.encode("utf-8", "surrogatepass")).hexdigest(),
                "prefixed": prefixed,
                "approved": approved,
            }
        )
        violations: list[AuditViolation] = []
        if not prefixed:
            violations.append(AuditViolation.MISSING_PREFIX)
        if interactive and not approved:
            violations.append(AuditViolation.INTERACTIVE_WITHOUT_APPROVAL)
        return violations
