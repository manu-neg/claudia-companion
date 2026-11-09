"""Admin API routes for the Claudia host (`/v1/claudia/*`, `claudia` token only; C45, C46, C56).

Long-poll the owner-message inbox and mark a message handled (CAS), post a
reply or voice reply (own budget, C56), create an approval **request** (always PENDING),
read one (long-poll until decided), consume an APPROVED one, cancel one or
every open one (`/stop`, C58; CAS, only ever closes a request), report
screen health. Deliberately **no** route here answers questions, records
taps, takes or checks codes, edits an action text, or moves a request
towards APPROVED (C45): those are notifier-token routes or don't exist.
The other tokens are refused by
`BearerAuthMiddleware`, and every route re-checks the role
(`require_claudia`). Formats come from `preview_dashboard.wire.claudia`.
"""

from __future__ import annotations

import logging
from typing import Final

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from preview_dashboard.application.approvals import ApprovalCreateCommand
from preview_dashboard.application.inbox import ScreenHealth
from preview_dashboard.bootstrap import ClaudiaCore
from preview_dashboard.domain.approvals import ApprovalRequest, ApprovalState
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_messages import OwnerMessage
from preview_dashboard.interfaces.admin.api import (
    NO_STORE,
    admin_core,
    read_json_object,
    run_blocking,
)
from preview_dashboard.interfaces.admin.auth import CLAUDIA_ROLE, role_of
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from preview_dashboard.interfaces.admin.longpoll import WaiterSlots, long_poll
from preview_dashboard.wire.claudia import (
    CLAUDIA_PREFIX,
    approval_envelope,
    cancel_open_result_to_json,
    cancel_result_to_json,
    consume_result_to_json,
    messages_to_json,
    owner_message_to_json,
    parse_approval_create,
    parse_cancel_open_request,
    parse_health_request,
    parse_messages_limit,
    parse_reply_request,
    reply_result_to_json,
)
from preview_dashboard.wire.claudia_voice import (
    MAX_VOICE_BODY_BYTES,
    parse_voice_request,
    voice_result_to_json,
)
from preview_dashboard.wire.notifier import parse_wait_param

logger = logging.getLogger("preview_dashboard.admin")

router = APIRouter(prefix=CLAUDIA_PREFIX)

_MESSAGE_PARAMS: Final = frozenset({"wait", "limit"})
_WAIT_PARAMS: Final = frozenset({"wait"})
# A request is "decided" for the host's wait once it left PENDING/TAPPED.
_UNDECIDED: Final = frozenset({ApprovalState.PENDING, ApprovalState.TAPPED})


def require_claudia(request: Request) -> None:
    """Defense in depth next to `BearerAuthMiddleware`: only the `claudia` token gets here.

    Raises:
        ForbiddenError: another (or no) token role.
    """
    if role_of(request.scope) != CLAUDIA_ROLE:
        raise ForbiddenError("this route needs the claudia token")


def claudia_core(request: Request) -> ClaudiaCore:
    """The Claudia services of the admin core.

    Raises:
        ValidationError: the companion is not enabled (`claudia_enabled`).
    """
    claudia = admin_core(request).claudia
    if claudia is None:
        raise ValidationError("the Claudia companion is not enabled")
    return claudia


def _query(request: Request, allowed: frozenset[str]) -> dict[str, str]:
    items = request.query_params.multi_items()
    keys = [key for key, _ in items]
    if len(keys) != len(set(keys)) or not set(keys) <= allowed:
        raise ValidationError(f"allowed query parameters: {', '.join(sorted(allowed))}")
    return dict(items)


@router.get("/messages")
async def unhandled_messages(request: Request) -> JSONResponse:
    """Unhandled owner messages (`?wait=0..60&limit=1..20`), held until one arrives.

    One poller at a time (messages are not leased): a concurrent second
    request gets `{"messages": []}` at once.
    """
    require_claudia(request)
    params = _query(request, _MESSAGE_PARAMS)
    wait = parse_wait_param(params.get("wait"))
    limit = parse_messages_limit(params.get("limit"))
    claudia = claudia_core(request)
    gate: WaiterSlots = request.app.state.claudia_gate
    if not gate.try_acquire():
        return JSONResponse(messages_to_json([]), headers=NO_STORE)

    async def fetch() -> list[OwnerMessage]:
        return await run_blocking(lambda: claudia.inbox.unhandled(limit))

    try:
        messages = await long_poll(
            request.receive, fetch=fetch, ready=bool, wake=claudia.inbox_events.wait, seconds=wait
        )
    finally:
        gate.release()
    return JSONResponse(messages_to_json(messages), headers=NO_STORE)


@router.post("/messages/{message_id}/handled")
async def mark_handled(request: Request, message_id: str) -> JSONResponse:
    """Mark a message handled (CAS: 409 if it already was; 404 unknown)."""
    require_claudia(request)
    claudia = claudia_core(request)
    message = await run_blocking(lambda: claudia.inbox.mark_handled(message_id))
    return JSONResponse({"message": owner_message_to_json(message)}, headers=NO_STORE)


@router.post("/replies")
async def post_reply(request: Request) -> JSONResponse:
    """Queue one reply (<= 4096 chars; 3 per inbox message, 120 per hour, C56).

    `"ping": true` = a host progress ping (F-CL2): fixed texts only, own cap
    of 3 per message, refused once the hour has used 110.
    """
    require_claudia(request)
    body = parse_reply_request(await read_json_object(request))
    claudia = claudia_core(request)
    message_id = body.message_id
    if body.ping and message_id is not None:
        mid = message_id
        reply_id = await run_blocking(lambda: claudia.replies.send_ping(body.text, message_id=mid))
    else:
        reply_id = await run_blocking(
            lambda: claudia.replies.send(body.text, message_id=message_id, item_id=body.item_id)
        )
    return JSONResponse(reply_result_to_json(reply_id), status_code=201, headers=NO_STORE)


@router.post("/voice")
async def post_voice(request: Request) -> JSONResponse:
    """Queue one reply with its voice note (same budget as `/replies`, C56).

    The audio (<= 1 MiB, <= 60 s Ogg/Opus) is validated before the text goes
    through the reply path; the text is always delivered too.
    """
    require_claudia(request)
    body = parse_voice_request(await read_json_object(request, max_bytes=MAX_VOICE_BODY_BYTES))
    claudia = claudia_core(request)
    voice_id = await run_blocking(
        lambda: claudia.voice.send(
            body.text, body.audio, message_id=body.message_id, item_id=body.item_id
        )
    )
    return JSONResponse(voice_result_to_json(voice_id), status_code=201, headers=NO_STORE)


@router.post("/approvals")
async def create_approval(request: Request) -> JSONResponse:
    """Create a PENDING approval request and queue its Approve/Deny message (C46)."""
    require_claudia(request)
    body = parse_approval_create(await read_json_object(request))
    command = ApprovalCreateCommand(
        window_id=body.window_id,
        kind=body.kind,
        action_text=body.action_text,
        action_kind=body.action_kind,
        action_target=body.action_target,
        message_id=body.message_id,
    )
    claudia = claudia_core(request)
    created = await run_blocking(lambda: claudia.approvals.create(command))
    return JSONResponse(approval_envelope(created), status_code=201, headers=NO_STORE)


@router.get("/approvals/{approval_id}")
async def get_approval(request: Request, approval_id: str) -> JSONResponse:
    """One request; with `?wait=N` (<= 60 s) held until it leaves PENDING/TAPPED."""
    require_claudia(request)
    wait = parse_wait_param(_query(request, _WAIT_PARAMS).get("wait"))
    claudia = claudia_core(request)

    async def fetch() -> ApprovalRequest:
        return await run_blocking(lambda: claudia.approvals.get(approval_id))

    current = await fetch()
    slots: WaiterSlots = request.app.state.approval_slots
    if wait == 0 or current.state not in _UNDECIDED or not slots.try_acquire():
        return JSONResponse(approval_envelope(current), headers=NO_STORE)
    try:
        current = await long_poll(
            request.receive,
            fetch=fetch,
            ready=lambda r: r.state not in _UNDECIDED,
            wake=claudia.approval_events.wait,
            seconds=wait,
        )
    finally:
        slots.release()
    return JSONResponse(approval_envelope(current), headers=NO_STORE)


@router.post("/approvals/{approval_id}/consume")
async def consume_approval(request: Request, approval_id: str) -> JSONResponse:
    """APPROVED -> CONSUMED, once: `{"result": consumed | already_consumed | ...}`."""
    require_claudia(request)
    claudia = claudia_core(request)
    result, stored = await run_blocking(lambda: claudia.approvals.consume(approval_id))
    logger.info("claudia consume: %s", result)
    return JSONResponse(consume_result_to_json(str(result), stored), headers=NO_STORE)


# Declared before `/approvals/{approval_id}/cancel`; distinct shapes anyway
# (two segments vs three), so the literal can never be read as an id.
@router.post("/approvals/cancel-open")
async def cancel_open_approvals(request: Request) -> JSONResponse:
    """Cancel every open request (`{}`) or those of one window (`{"window_id"}`), for `/stop`."""
    require_claudia(request)
    window_id = parse_cancel_open_request(await read_json_object(request))
    claudia = claudia_core(request)
    cancelled = await run_blocking(lambda: claudia.approvals.cancel_open(window_id))
    logger.info("claudia cancel-open: %d cancelled", len(cancelled))
    return JSONResponse(cancel_open_result_to_json(cancelled), headers=NO_STORE)


@router.post("/approvals/{approval_id}/cancel")
async def cancel_approval(request: Request, approval_id: str) -> JSONResponse:
    """Open -> CANCELLED (CAS): `{"result": cancelled | already_resolved | busy | unknown}`."""
    require_claudia(request)
    claudia = claudia_core(request)
    result, stored = await run_blocking(lambda: claudia.approvals.cancel(approval_id))
    logger.info("claudia cancel: %s", result)
    return JSONResponse(cancel_result_to_json(str(result), stored), headers=NO_STORE)


@router.post("/health")
async def report_health(request: Request) -> JSONResponse:
    """Record the host's screen health (`{"screen": "ok" | "degraded" | "down"}`)."""
    require_claudia(request)
    screen = ScreenHealth(parse_health_request(await read_json_object(request)))
    report = claudia_core(request).health.report(screen)
    return JSONResponse(
        {"screen": str(report.screen), "reported_at": report.reported_at.isoformat()},
        headers=NO_STORE,
    )
