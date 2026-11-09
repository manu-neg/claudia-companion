"""Admin API question and alert routes (admin token only): ask, get/long-poll, cancel, notify.

`POST /v1/questions`, `GET /v1/questions/{id}?wait=0..60`,
`POST /v1/questions/{id}/cancel`, `POST /v1/notifications` (docs/api.md).
There is deliberately no answer route here: answers come only through
`/v1/notifier/answers` with the notifier token (C34). Bodies are parsed by
hand and strictly (unknown keys → 400, nothing echoed). The long-poll waits
on the event loop, capped at 16 concurrent waiters (C37). `require_admin`
(defense in depth, C33) is shared with `folders_api.py` and `api.py`,
defined in `admin/api.py`.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from preview_dashboard.application import AskCommand
from preview_dashboard.config import MAX_QUESTION_TTL_SECONDS, MIN_QUESTION_TTL_SECONDS
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import Notification
from preview_dashboard.domain.questions import MAX_OPTIONS, Question, QuestionState
from preview_dashboard.interfaces.admin.api import (
    NO_STORE,
    admin_core,
    read_json_object,
    run_blocking,
)

# Explicit re-export (mypy no_implicit_reexport): kept importable from here,
# like before the shared `require_admin` moved to `admin/api.py`.
from preview_dashboard.interfaces.admin.api import require_admin as require_admin
from preview_dashboard.interfaces.admin.longpoll import WaiterSlots, long_poll
from preview_dashboard.wire.notifier import parse_wait_param

router = APIRouter(prefix="/v1")

_ASK_REQUIRED: Final = frozenset({"prompt", "options", "session_label"})
_ASK_OPTIONAL: Final = frozenset({"default_key", "item_id", "expires_in_s"})
_OPTION_FIELDS: Final = frozenset({"key", "label"})
_NOTIFY_REQUIRED: Final = frozenset({"event", "title"})
_NOTIFY_OPTIONAL: Final = frozenset({"item_id"})
_GET_PARAMS: Final = frozenset({"wait"})


def question_json(question: Question, viewer_base: str | None) -> dict[str, object]:
    """Serialize a question (docs/api.md "Question JSON").

    `viewer_url` links the item the question is about (None without an item
    or without a configured dashboard host).
    """
    url = (
        None
        if viewer_base is None or question.item_id is None
        else f"{viewer_base}/#/item/{question.item_id}"
    )
    return {
        "id": question.id,
        "prompt": question.prompt,
        "options": [{"key": o.key, "label": o.label} for o in question.options],
        "default_key": question.default_key,
        "item_id": question.item_id,
        "session_label": question.session_label,
        "state": str(question.state),
        "answer_key": question.answer_key,
        "answer_source": question.answer_source,
        "created_at": question.created_at.isoformat(),
        "expires_at": question.expires_at.isoformat(),
        "resolved_at": None if question.resolved_at is None else question.resolved_at.isoformat(),
        "viewer_url": url,
    }


def notification_json(notification: Notification) -> dict[str, object]:
    """Serialize a `done`/`failed` notification: `{id, event, title, item_id, created_at}`."""
    return {
        "id": notification.id,
        "event": notification.event_type,
        "title": notification.title,
        "item_id": notification.item_id,
        "created_at": notification.created_at.isoformat(),
    }


def _fields(
    body: dict[str, object], required: frozenset[str], optional: frozenset[str]
) -> dict[str, object]:
    keys = set(body)
    if not required <= keys or not keys <= required | optional:
        allowed = ", ".join(sorted(required | optional))
        raise ValidationError(f"required fields: {', '.join(sorted(required))}; allowed: {allowed}")
    return body


def _str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    return value


def _optional_str(value: object, name: str) -> str | None:
    return None if value is None else _str(value, name)


def _options(raw: object) -> list[tuple[str, str]]:
    # Bounded before any work; the domain checks 2..8, key syntax and labels.
    if not isinstance(raw, list) or len(raw) > MAX_OPTIONS:
        raise ValidationError(f"options must be a list of at most {MAX_OPTIONS} objects")
    options: list[tuple[str, str]] = []
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != _OPTION_FIELDS:
            raise ValidationError("each option must be an object with exactly key and label")
        options.append((_str(entry["key"], "option key"), _str(entry["label"], "option label")))
    return options


def _expires_in(raw: object) -> timedelta | None:
    if raw is None:
        return None
    low, high = MIN_QUESTION_TTL_SECONDS, MAX_QUESTION_TTL_SECONDS
    if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
        raise ValidationError(f"expires_in_s must be an integer in {low}..{high}")
    return timedelta(seconds=raw)


def parse_ask_request(body: dict[str, object]) -> AskCommand:
    """Turn a `POST /v1/questions` body into an `AskCommand` (shape and types only).

    Raises:
        ValidationError: missing/unknown fields, wrong types, too many
            options, `expires_in_s` outside 60..604800.
    """
    fields = _fields(body, _ASK_REQUIRED, _ASK_OPTIONAL)
    return AskCommand(
        prompt=_str(fields["prompt"], "prompt"),
        options=_options(fields["options"]),
        session_label=_str(fields["session_label"], "session_label"),
        default_key=_optional_str(fields.get("default_key"), "default_key"),
        item_id=_optional_str(fields.get("item_id"), "item_id"),
        expires_in=_expires_in(fields.get("expires_in_s")),
    )


def _parse_wait(request: Request) -> int:
    params = request.query_params
    keys = [key for key, _ in params.multi_items()]
    if len(keys) != len(set(keys)) or not set(keys) <= _GET_PARAMS:
        raise ValidationError("the only query parameter is wait (0..60)")
    return parse_wait_param(params.get("wait"))


def _respond(request: Request, question: Question, status: int = 200) -> JSONResponse:
    body = {"question": question_json(question, request.app.state.viewer_base)}
    return JSONResponse(body, status_code=status, headers=NO_STORE)


@router.post("/questions")
async def ask_question(request: Request) -> JSONResponse:
    """Ask the owner a choice question; its alert is queued for every enabled channel."""
    require_admin(request)
    command = parse_ask_request(await read_json_object(request))
    question = await run_blocking(lambda: admin_core(request).questions.ask(command))
    return _respond(request, question, status=201)


@router.get("/questions/{question_id}")
async def get_question(request: Request, question_id: str) -> JSONResponse:
    """A question; with `?wait=N` (<= 60 s) held until it is resolved or N seconds pass.

    Beyond 16 concurrent waiters the current state is returned at once (C37).
    """
    require_admin(request)
    wait = _parse_wait(request)
    core = admin_core(request)

    async def fetch() -> Question:
        return await run_blocking(lambda: core.questions.get(question_id))

    question = await fetch()
    slots: WaiterSlots = request.app.state.question_slots
    if wait == 0 or question.state is not QuestionState.OPEN or not slots.try_acquire():
        return _respond(request, question)
    qid = question.id
    try:
        question = await long_poll(
            request.receive,
            fetch=fetch,
            ready=lambda q: q.state is not QuestionState.OPEN,
            wake=lambda timeout: core.question_events.wait(qid, timeout),
            seconds=wait,
        )
    finally:
        slots.release()
    return _respond(request, question)


@router.post("/questions/{question_id}/cancel")
async def cancel_question(request: Request, question_id: str) -> JSONResponse:
    """Withdraw an OPEN question (idempotent: a resolved one is returned unchanged)."""
    require_admin(request)
    question = await run_blocking(lambda: admin_core(request).questions.cancel(question_id))
    return _respond(request, question)


@router.post("/notifications")
async def send_notification(request: Request) -> JSONResponse:
    """Queue a `done`/`failed` alert (shares the 20/hour budget with questions, C37)."""
    require_admin(request)
    fields = _fields(await read_json_object(request), _NOTIFY_REQUIRED, _NOTIFY_OPTIONAL)
    event = _str(fields["event"], "event")
    title = _str(fields["title"], "title")
    item_id = _optional_str(fields.get("item_id"), "item_id")
    notification = await run_blocking(
        lambda: admin_core(request).notify.notify(event, title, item_id)
    )
    return JSONResponse(
        {"notification": notification_json(notification)}, status_code=201, headers=NO_STORE
    )
