"""Wire format of the viewer-token route (`/v1/viewer/*`, F-CL6): one dashboard decision.

`POST /v1/viewer/approvals/{id}/decision` with `{"decision": "approve", "code":
"123456"}` or `{"decision": "deny"}` → `{"result": <DecisionResult>}`.
Shared by the admin route (server) and the viewer's admin client, so both
parse the same strict shape: no extra keys, the code only on Approve. No
framework imports.
"""

from __future__ import annotations

from typing import Final

from preview_dashboard.domain.approval_decisions import (
    Decision,
    DecisionCommand,
    DecisionResult,
    parse_decision_command,
)
from preview_dashboard.domain.approvals import parse_approval_id
from preview_dashboard.domain.errors import ValidationError

VIEWER_PREFIX: Final = "/v1/viewer"
_REQUEST_KEYS: Final = frozenset({"decision", "code"})


def decision_path(approval_id: str) -> str:
    """The route path for one request's decision.

    Raises:
        ValidationError: `approval_id` is not a canonical ULID.
    """
    return f"{VIEWER_PREFIX}/approvals/{parse_approval_id(approval_id)}/decision"


def decision_request_to_json(command: DecisionCommand) -> dict[str, object]:
    """The request body for `command` (the code key only for Approve)."""
    body: dict[str, object] = {"decision": command.decision.value}
    if command.decision is Decision.APPROVE:
        body["code"] = command.code
    return body


def parse_decision_request(approval_id: object, body: object) -> DecisionCommand:
    """Parse an untrusted request body (admin side) for `approval_id` from the path.

    Raises:
        ValidationError: not an object, unknown keys, or see `parse_decision_command`.
    """
    if not isinstance(body, dict) or not set(body) <= _REQUEST_KEYS or "decision" not in body:
        raise ValidationError("body must be {decision[, code]}")
    return parse_decision_command(approval_id, body.get("decision"), body.get("code"))


def decision_result_to_json(result: DecisionResult) -> dict[str, object]:
    """The response body."""
    return {"result": result.value}


def parse_decision_result(body: object) -> DecisionResult:
    """Parse the admin's verdict (viewer side).

    Raises:
        ValidationError: anything but `{"result": <known value>}`.
    """
    if not isinstance(body, dict) or set(body) != {"result"}:
        raise ValidationError("malformed decision result")
    raw = body["result"]
    if not isinstance(raw, str):
        raise ValidationError("malformed decision result")
    try:
        return DecisionResult(raw)
    except ValueError:
        raise ValidationError("malformed decision result") from None


__all__ = [
    "VIEWER_PREFIX",
    "decision_path",
    "decision_request_to_json",
    "decision_result_to_json",
    "parse_decision_request",
    "parse_decision_result",
]
