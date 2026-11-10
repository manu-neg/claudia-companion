"""Admin API route for the viewer (`/v1/viewer/*`, viewer token only; F-CL6, C46/C47).

One route: the owner's Approve (+ authenticator code) or Deny from the
dashboard panel. The viewer only forwards; everything is re-validated here
(request exists, PENDING/TAPPED, unexpired; the code through the shared
`StepUpService`). The other tokens are refused by `BearerAuthMiddleware`,
and the route re-checks the role (`require_viewer`). The code is never
logged or echoed; the answer is one fixed verdict.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from preview_dashboard.interfaces.admin.api import NO_STORE, read_json_object, run_blocking
from preview_dashboard.interfaces.admin.auth import VIEWER_ROLE, role_of
from preview_dashboard.interfaces.admin.claudia_api import claudia_core
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from preview_dashboard.wire.viewer_decisions import (
    VIEWER_PREFIX,
    decision_result_to_json,
    parse_decision_request,
)

logger = logging.getLogger("preview_dashboard.admin")

router = APIRouter(prefix=VIEWER_PREFIX)

# Bodies are tiny (`{"decision": "approve", "code": "123456"}`).
_MAX_BODY_BYTES = 256


def require_viewer(request: Request) -> None:
    """Defense in depth next to `BearerAuthMiddleware`: only the viewer token gets here.

    Raises:
        ForbiddenError: another (or no) token role.
    """
    if role_of(request.scope) != VIEWER_ROLE:
        raise ForbiddenError("this route needs the viewer token")


@router.post("/approvals/{approval_id}/decision")
async def decide_approval(request: Request, approval_id: str) -> JSONResponse:
    """Apply the owner's dashboard decision; `{"result": ...}` (unknown ids → `unknown`).

    Malformed input is a 400 that never echoes it; a verdict (incl. a wrong
    code or a lost race) is always a 200 with one fixed result value.
    """
    require_viewer(request)
    body = await read_json_object(request, max_bytes=_MAX_BODY_BYTES)
    claudia = claudia_core(request)
    command = parse_decision_request(approval_id, body)
    result = await run_blocking(lambda: claudia.decisions.decide(command))
    return JSONResponse(decision_result_to_json(result), headers=NO_STORE)
