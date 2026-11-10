"""Dashboard decisions on approval requests (F-CL6, docs/security.md C46/C47, ADR 0043).

The owner may Approve (with an authenticator code) or Deny a request from
the dashboard's "Waiting for your approval" panel. This module holds the
two decisions, the closed set of verdicts the admin returns, and the strict
parser shared by the viewer (first check) and the admin (the one that
counts): an untrusted `{decision, code}` pair becomes a `DecisionCommand`
or a `ValidationError` that never echoes the input.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from preview_dashboard.domain.approvals import ApprovalId, parse_approval_id
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.totp import parse_code


class Decision(StrEnum):
    """What the owner clicked in the panel."""

    APPROVE = "approve"
    DENY = "deny"


class DecisionResult(StrEnum):
    """The admin's verdict on one dashboard decision (fixed texts on the client).

    Never says *why* a code failed beyond "wrong" (no oracle on the secret),
    and `unknown` covers malformed and unknown ids alike.
    """

    APPROVED = "approved"
    DENIED = "denied"
    WRONG_CODE = "wrong_code"
    LOCKED = "locked"
    ALREADY_DECIDED = "already_decided"
    EXPIRED = "expired"
    UNKNOWN = "unknown"
    RATE_LIMITED = "rate_limited"
    # Server-side failure (secret or step-up state unusable): fail closed.
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class DecisionCommand:
    """One validated dashboard decision. `code` is set exactly for APPROVE.

    `repr` hides the code so it can never reach a log line by accident.
    """

    approval_id: ApprovalId
    decision: Decision
    code: str | None

    def __repr__(self) -> str:
        return f"DecisionCommand(approval_id={self.approval_id!r}, decision={self.decision!r})"


def parse_decision_command(approval_id: object, decision: object, code: object) -> DecisionCommand:
    """Validate an untrusted decision (C46/C47).

    Approve needs exactly six ASCII digits; Deny takes no code at all (it
    only ever reduces power, so a stray code is a client bug, not a hint).

    Raises:
        ValidationError: bad id, unknown decision, a missing/malformed code
            on Approve or any code on Deny (messages never echo the input).
    """
    parsed_id = parse_approval_id(approval_id)
    if not isinstance(decision, str):
        raise ValidationError("invalid decision")
    try:
        parsed = Decision(decision)
    except ValueError:
        raise ValidationError("invalid decision") from None
    if parsed is Decision.DENY:
        if code is not None:
            raise ValidationError("deny takes no code")
        return DecisionCommand(parsed_id, parsed, None)
    return DecisionCommand(parsed_id, parsed, parse_code(code))


__all__ = ["Decision", "DecisionCommand", "DecisionResult", "parse_decision_command"]
