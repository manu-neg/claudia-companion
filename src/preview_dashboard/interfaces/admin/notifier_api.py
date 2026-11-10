"""Admin API routes for the notifier (`/v1/notifier/*`, notifier token only; ADR 0021, 0031).

Fetch due deliveries (long-poll, one poller at a time), report them done or
failed, and submit button taps as answers. This is the **only** place
`QuestionService.answer` is reachable (C34). For the Claudia companion it
also takes the owner's text messages (C44), Approve/Deny taps (C46) and
authenticator codes (C47): the only routes that store inbox messages, tap
an approval or verify a code; `/media` takes the owner's voice notes and
photos (C61). The voice routes hand a reply's stored audio
to the notifier and delete it after sending (C56). The other tokens are refused here by
`BearerAuthMiddleware`, and each route re-checks the role. Formats come
from `preview_dashboard.wire.notifier` and `wire.notifier_messages`,
shared with the notifier.
"""

from __future__ import annotations

import logging
from typing import Final

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse, Response

from preview_dashboard.application.approvals import TapDecision
from preview_dashboard.application.inbox import OwnerMessageSubmission
from preview_dashboard.application.owner_media import OwnerMediaSubmission
from preview_dashboard.domain.errors import NotFoundError, UnsupportedContentError, ValidationError
from preview_dashboard.domain.notifications import PendingTask, parse_notification_id
from preview_dashboard.interfaces.admin.api import (
    NO_STORE,
    admin_core,
    read_json_object,
    run_blocking,
)
from preview_dashboard.interfaces.admin.auth import NOTIFIER_ROLE, role_of
from preview_dashboard.interfaces.admin.claudia_api import claudia_core
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from preview_dashboard.interfaces.admin.longpoll import WaiterSlots, long_poll
from preview_dashboard.wire.notifier import (
    NOTIFIER_PREFIX,
    VOICE_CONTENT_TYPE,
    answer_result_to_json,
    parse_answer_request,
    parse_done_request,
    parse_failed_request,
    parse_limit_param,
    parse_wait_param,
    tasks_to_json,
)
from preview_dashboard.wire.notifier_media import MAX_MEDIA_BODY_BYTES, parse_media_request
from preview_dashboard.wire.notifier_messages import CodeResult as WireCodeResult
from preview_dashboard.wire.notifier_messages import (
    MessageResult,
    code_result_to_json,
    message_result_to_json,
    parse_approval_tap_request,
    parse_code_request,
    parse_message_request,
    tap_result_to_json,
)
from preview_dashboard.wire.notifier_messages import TapResult as WireTapResult

logger = logging.getLogger("preview_dashboard.admin")

router = APIRouter(prefix=NOTIFIER_PREFIX)

_TASK_PARAMS: Final = frozenset({"wait", "limit"})


def require_notifier(request: Request) -> None:
    """Defense in depth next to `BearerAuthMiddleware`: only the notifier token gets here.

    Raises:
        ForbiddenError: another (or no) token role.
    """
    if role_of(request.scope) != NOTIFIER_ROLE:
        raise ForbiddenError("this route needs the notifier token")


def _parse_task_query(request: Request) -> tuple[int, int]:
    params = request.query_params
    keys = [key for key, _ in params.multi_items()]
    if len(keys) != len(set(keys)) or not set(keys) <= _TASK_PARAMS:
        raise ValidationError("allowed query parameters: limit, wait")
    return parse_wait_param(params.get("wait")), parse_limit_param(params.get("limit"))


@router.get("/tasks")
async def pending_tasks(request: Request) -> JSONResponse:
    """Due deliveries (`?wait=0..60&limit=1..20`), held until some are due or `wait` passes.

    One poller at a time: tasks are not leased, so a concurrent second
    request gets `{"tasks": []}` at once instead of the same tasks (C37).
    """
    require_notifier(request)
    wait, limit = _parse_task_query(request)
    core = admin_core(request)
    gate: WaiterSlots = request.app.state.notifier_gate
    if not gate.try_acquire():
        return JSONResponse(tasks_to_json([]), headers=NO_STORE)

    async def fetch() -> list[PendingTask]:
        return await run_blocking(lambda: core.outbox.pending(limit))

    try:
        tasks = await long_poll(
            request.receive,
            fetch=fetch,
            ready=bool,
            wake=core.outbox_events.wait,
            seconds=wait,
        )
    finally:
        gate.release()
    return JSONResponse(tasks_to_json(tasks), headers=NO_STORE)


@router.post("/tasks/{task_id}/done")
async def task_done(request: Request, task_id: str) -> JSONResponse:
    """Record a delivery (`{"message_ref": str | null}`); no-op if no longer pending."""
    require_notifier(request)
    message_ref = parse_done_request(await read_json_object(request))
    await run_blocking(lambda: admin_core(request).outbox.done(task_id, message_ref))
    return JSONResponse({}, headers=NO_STORE)


@router.post("/tasks/{task_id}/failed")
async def task_failed(request: Request, task_id: str) -> JSONResponse:
    """Record a failed try (`{}`): backoff, given up after 8 tries."""
    require_notifier(request)
    parse_failed_request(await read_json_object(request))
    await run_blocking(lambda: admin_core(request).outbox.failed(task_id))
    return JSONResponse({}, headers=NO_STORE)


@router.post("/answers")
async def submit_answer(request: Request) -> JSONResponse:
    """Submit one tap; returns `{"result": ...}` (unknown ids/keys → `unknown`, C34).

    The source must be an enabled answer source (none when notifications
    are off); the first answer to an OPEN question wins.
    """
    require_notifier(request)
    core = admin_core(request)
    submission = parse_answer_request(await read_json_object(request))
    if submission.source not in core.answer_sources:
        raise ValidationError("unknown answer source")
    result = await run_blocking(
        lambda: core.questions.answer(submission.question_id, submission.key, submission.source)
    )
    # Result only: ids/keys are untrusted callback data, actor_ref a Telegram user id.
    logger.info("notifier answer submitted: %s", result)
    return JSONResponse(answer_result_to_json(result), headers=NO_STORE)


# --- Claudia companion (ADR 0031): owner messages, approval taps, codes ----------------


@router.post("/messages")
async def submit_message(request: Request) -> JSONResponse:
    """Store one owner text message in the inbox (C44): `{"result": stored | duplicate}`.

    The admin re-checks the sender against its own configured owner; the
    text is never logged.
    """
    require_notifier(request)
    submission = parse_message_request(await read_json_object(request))
    claudia = claudia_core(request)
    command = OwnerMessageSubmission(
        update_id=submission.update_id,
        telegram_message_id=submission.message_id,
        sender_id=submission.sender_id,
        text=submission.text,
        is_forwarded=submission.is_forwarded,
        reply_to_message_id=submission.reply_to_message_id,
        quote_text=submission.quote_text,
    )
    try:
        result, _stored = await run_blocking(lambda: claudia.inbox.receive(command))
    except ValidationError as exc:
        # 422, not 400/403: the notifier drops a refused message instead of retrying it.
        raise UnsupportedContentError(str(exc)) from None
    return JSONResponse(message_result_to_json(MessageResult(str(result))), headers=NO_STORE)


@router.post("/media")
async def submit_media(request: Request) -> JSONResponse:
    """Store one owner voice note or photo (C61): `{"result": stored | duplicate}`.

    The admin re-checks the owner and the kind's switch, then the bytes by
    content (Ogg/Opus duration, JPEG structure; metadata stripped). Body ≤
    `MAX_MEDIA_BODY_BYTES` (base64 file + caption); nothing of it is logged.
    """
    require_notifier(request)
    raw = await read_json_object(request, max_bytes=MAX_MEDIA_BODY_BYTES)
    submission = parse_media_request(raw)
    del raw  # the base64 copy: no need to hold it while the bytes are checked
    claudia = claudia_core(request)
    command = OwnerMediaSubmission(
        update_id=submission.update_id,
        telegram_message_id=submission.message_id,
        sender_id=submission.sender_id,
        kind=submission.kind,
        data=submission.data,
        caption=submission.caption,
        is_forwarded=submission.is_forwarded,
        reply_to_message_id=submission.reply_to_message_id,
        quote_text=submission.quote_text,
    )
    try:
        result, _stored = await run_blocking(lambda: claudia.media.receive(command))
    except ValidationError as exc:
        # 422: refused for good (owner, switch off, bad content); the notifier drops it.
        raise UnsupportedContentError(str(exc)) from None
    return JSONResponse(message_result_to_json(MessageResult(str(result))), headers=NO_STORE)


@router.post("/approvals")
async def submit_approval_tap(request: Request) -> JSONResponse:
    """Record one Approve/Deny tap (C46); unknown ids -> `unknown` (no oracle).

    The only route that moves a request to TAPPED or DENIED.
    """
    require_notifier(request)
    submission = parse_approval_tap_request(await read_json_object(request))
    core = admin_core(request)
    if submission.source not in core.answer_sources:
        raise ValidationError("unknown tap source")
    claudia = claudia_core(request)
    decision = TapDecision(str(submission.decision))
    result = await run_blocking(lambda: claudia.approvals.tap(submission.request_id, decision))
    logger.info("notifier approval tap submitted: %s", result)
    return JSONResponse(tap_result_to_json(WireTapResult(str(result))), headers=NO_STORE)


@router.post("/codes")
async def submit_code(request: Request) -> JSONResponse:
    """Check one authenticator code (C47); the only route that can approve a request.

    The code itself is never logged, stored or echoed.
    """
    require_notifier(request)
    submission = parse_code_request(await read_json_object(request))
    claudia = claudia_core(request)
    result = await run_blocking(
        lambda: claudia.stepup.submit_code(
            submission.code,
            update_id=submission.update_id,
            message_id=submission.message_id,
            sender_id=submission.sender_id,
        )
    )
    logger.info("notifier code submitted: %s", result)
    return JSONResponse(code_result_to_json(WireCodeResult(str(result))), headers=NO_STORE)


# --- Claudia voice notes (C56): fetch the audio of a delivered reply, then release it ----


@router.get("/voice/{voice_id}")
async def fetch_voice(request: Request, voice_id: str) -> Response:
    """The stored Ogg/Opus audio of reply `voice_id` (404 when there is none).

    Notifier token only: the audio is a reply's spoken form and leaves the
    admin's private store only for the notifier's `sendVoice`.
    """
    require_notifier(request)
    parse_notification_id(voice_id)
    claudia = claudia_core(request)
    audio = await run_blocking(lambda: claudia.voice.fetch(voice_id))
    if audio is None:
        raise NotFoundError("no voice note waiting")
    return Response(audio, media_type=VOICE_CONTENT_TYPE, headers=NO_STORE)


@router.post("/voice/{voice_id}/release")
async def release_voice(request: Request, voice_id: str) -> JSONResponse:
    """Delete the audio of reply `voice_id` after it was sent (idempotent)."""
    require_notifier(request)
    parse_notification_id(voice_id)
    parse_failed_request(await read_json_object(request))  # body must be `{}`
    claudia = claudia_core(request)
    await run_blocking(lambda: claudia.voice.release(voice_id))
    return JSONResponse({}, headers=NO_STORE)
