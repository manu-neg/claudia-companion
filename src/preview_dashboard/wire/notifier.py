"""JSON wire format between the admin API's `/v1/notifier/*` routes and the notifier (ADR 0021).

The single definition of the route paths, query parameters and bodies: the
admin side (`interfaces/admin/notifier_routes.py`) serializes with `*_to_json`
and parses requests with `parse_*_request`; the notifier
(`adapters/admin_queue.py`) does the reverse. Framework-free (stdlib +
domain) and outside `interfaces/`, so adapters and both processes import it
without depending on an interface layer. Parsers are strict: unknown keys,
wrong types and out-of-range values raise `ValidationError`, and every
value is re-validated by the domain types.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from preview_dashboard.domain.approvals import parse_approval_id
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    MessageButton,
    MessageContent,
    PendingTask,
    TaskId,
    approval_outcome,
    parse_notification_id,
    parse_task_id,
    validate_message_ref,
)
from preview_dashboard.domain.questions import (
    AnswerResult,
    QuestionState,
    parse_question_id,
    validate_plugin_name,
)

# --- routes --------------------------------------------------------------------------

NOTIFIER_PREFIX: Final = "/v1/notifier"
TASKS_PATH: Final = f"{NOTIFIER_PREFIX}/tasks"
ANSWERS_PATH: Final = f"{NOTIFIER_PREFIX}/answers"
MAX_WAIT_SECONDS: Final = 60
DEFAULT_WAIT_SECONDS: Final = 0
MAX_TASKS_LIMIT: Final = 20
DEFAULT_TASKS_LIMIT: Final = 20
# Raw callback fields: Telegram callback data is <= 64 bytes in total, so
# anything longer is a broken client, not a tap (400, not `unknown`).
MAX_RAW_FIELD_CHARS: Final = 64

_DIGITS_RE = re.compile(r"[0-9]{1,6}")
_ACTOR_REF_RE = re.compile(r"[\x21-\x7e]{1,64}")
_PAYLOAD_REQUIRED: Final = frozenset({"text", "buttons"})
# `long_form` (C56): only `reply`/`voice` payloads carry it, as `true`.
# `approval_id` (C46): only approval prompts carry it, as a ULID string.
# `voice_id` (C56): a reply's notification id; its audio may wait under it.
# `approval_outcome` (F-CL5): only a decided prompt's RESOLVE carries it.
_PAYLOAD_OPTIONAL: Final = frozenset(
    {
        "link",
        "question_id",
        "final_state",
        "long_form",
        "approval_id",
        "voice_id",
        "approval_outcome",
    }
)
_TASK_REQUIRED: Final = frozenset({"id", "channel", "action", "payload"})
_ANSWER_FIELDS: Final = frozenset({"question_id", "key", "source", "actor_ref"})


def task_done_path(task_id: str) -> str:
    """`POST` path reporting task `task_id` delivered (id validated first).

    Raises:
        ValidationError: `task_id` is not a canonical ULID (no path injection).
    """
    return f"{TASKS_PATH}/{parse_task_id(task_id)}/done"


def task_failed_path(task_id: str) -> str:
    """`POST` path reporting a failed try of task `task_id` (id validated first).

    Raises:
        ValidationError: `task_id` is not a canonical ULID.
    """
    return f"{TASKS_PATH}/{parse_task_id(task_id)}/failed"


VOICE_PATH: Final = f"{NOTIFIER_PREFIX}/voice"
VOICE_CONTENT_TYPE: Final = "audio/ogg"


def voice_path(voice_id: str) -> str:
    """`GET` path of the stored audio of reply `voice_id` (id validated first).

    Raises:
        ValidationError: `voice_id` is not a canonical ULID (no path injection).
    """
    return f"{VOICE_PATH}/{parse_notification_id(voice_id)}"


def voice_release_path(voice_id: str) -> str:
    """`POST` path that deletes the audio of reply `voice_id` once it was sent.

    Raises:
        ValidationError: `voice_id` is not a canonical ULID.
    """
    return f"{voice_path(voice_id)}/release"


def _parse_bounded_int(raw: str | None, *, name: str, low: int, high: int, default: int) -> int:
    if raw is None:
        return default
    # ASCII digits only: int() would also accept "+5", " 5", "1_0" or non-ASCII digits.
    if not isinstance(raw, str) or not _DIGITS_RE.fullmatch(raw):
        raise ValidationError(f"{name} must be an integer in {low}..{high}")
    value = int(raw)
    if not low <= value <= high:
        raise ValidationError(f"{name} must be an integer in {low}..{high}")
    return value


def parse_wait_param(raw: str | None) -> int:
    """`?wait=` of `GET /notifier/tasks`: seconds 0..60 (default 0 = no wait).

    Raises:
        ValidationError: not ASCII digits or out of range.
    """
    return _parse_bounded_int(
        raw, name="wait", low=0, high=MAX_WAIT_SECONDS, default=DEFAULT_WAIT_SECONDS
    )


def parse_limit_param(raw: str | None) -> int:
    """`?limit=` of `GET /notifier/tasks`: 1..20 (default 20).

    Raises:
        ValidationError: not ASCII digits or out of range.
    """
    return _parse_bounded_int(
        raw, name="limit", low=1, high=MAX_TASKS_LIMIT, default=DEFAULT_TASKS_LIMIT
    )


# --- helpers ---------------------------------------------------------------------------


def _object(
    raw: object, what: str, required: frozenset[str], optional: frozenset[str] = frozenset()
) -> dict[str, object]:
    """`raw` as a JSON object with all `required` keys and otherwise only `optional` ones."""
    if not isinstance(raw, dict) or not all(isinstance(k, str) for k in raw):
        raise ValidationError(f"{what} must be a JSON object")
    keys = set(raw)
    if not required <= keys or not keys <= required | optional:
        raise ValidationError(f"{what} has missing or unknown fields")
    return raw


def _str(raw: object, what: str) -> str:
    if not isinstance(raw, str):
        raise ValidationError(f"{what} must be a string")
    return raw


def _optional_str(raw: object, what: str) -> str | None:
    return None if raw is None else _str(raw, what)


# --- tasks (admin -> notifier) -----------------------------------------------------------


def payload_to_json(payload: DeliveryPayload) -> dict[str, object]:
    """`{text, buttons: [{key, label}], link, question_id, final_state}` (nulls kept).

    A long-form reply (C56) adds `"long_form": true`; an approval prompt (C46)
    adds `"approval_id": "<ULID>"`; a reply that may have audio adds
    `"voice_id": "<ULID>"`; alerts carry none of these keys.
    """
    content = payload.content
    body: dict[str, object] = {
        "text": content.text,
        "buttons": [{"key": b.key, "label": b.label} for b in content.buttons],
        "link": content.link,
        "question_id": payload.question_id,
        "final_state": None if payload.final_state is None else str(payload.final_state),
    }
    if content.long_form:
        body["long_form"] = True
    if payload.approval_id is not None:
        body["approval_id"] = payload.approval_id
    if payload.voice_id is not None:
        body["voice_id"] = payload.voice_id
    if payload.approval_outcome is not None:
        body["approval_outcome"] = str(payload.approval_outcome)
    return body


def task_to_json(task: PendingTask) -> dict[str, object]:
    """`{id, channel, action, payload, message_ref}` for one due task."""
    return {
        "id": task.id,
        "channel": task.channel,
        "action": str(task.action),
        "payload": payload_to_json(task.payload),
        "message_ref": task.message_ref,
    }


def tasks_to_json(tasks: Sequence[PendingTask]) -> dict[str, object]:
    """Response body of `GET /notifier/tasks`: `{"tasks": [task, ...]}`."""
    return {"tasks": [task_to_json(t) for t in tasks]}


def _parse_button(raw: object) -> MessageButton:
    fields = _object(raw, "button", frozenset({"key", "label"}))
    return MessageButton(key=_str(fields["key"], "key"), label=_str(fields["label"], "label"))


def parse_payload(raw: object) -> DeliveryPayload:
    """Parse and re-validate one task payload (`question_id`/`final_state` may be absent).

    Raises:
        ValidationError: malformed JSON shape or any domain invariant broken.
    """
    fields = _object(raw, "payload", _PAYLOAD_REQUIRED, _PAYLOAD_OPTIONAL)
    buttons = fields["buttons"]
    if not isinstance(buttons, list):
        raise ValidationError("buttons must be a list")
    long_form = fields.get("long_form", False)
    if not isinstance(long_form, bool):
        raise ValidationError("long_form must be a bool")
    content = MessageContent(
        text=_str(fields["text"], "text"),
        buttons=tuple(_parse_button(b) for b in buttons),
        link=_optional_str(fields.get("link"), "link"),
        long_form=long_form,
    )
    question_id = fields.get("question_id")
    final_state = _optional_str(fields.get("final_state"), "final_state")
    try:
        state = None if final_state is None else QuestionState(final_state)
    except ValueError:
        raise ValidationError("invalid final_state") from None
    # Present means a real id: `null` is refused like any other non-ULID.
    approval_id = parse_approval_id(fields["approval_id"]) if "approval_id" in fields else None
    voice_id = parse_notification_id(fields["voice_id"]) if "voice_id" in fields else None
    outcome = (
        approval_outcome(_str(fields["approval_outcome"], "approval_outcome"))
        if "approval_outcome" in fields
        else None
    )
    return DeliveryPayload(
        content=content,
        question_id=None if question_id is None else parse_question_id(question_id),
        final_state=state,
        approval_id=approval_id,
        voice_id=voice_id,
        approval_outcome=outcome,
    )


def parse_task(raw: object) -> PendingTask:
    """Parse and re-validate one task of `GET /notifier/tasks`.

    Raises:
        ValidationError: malformed JSON shape or any domain invariant broken.
    """
    fields = _object(raw, "task", _TASK_REQUIRED, frozenset({"message_ref"}))
    try:
        action = DeliveryAction(_str(fields["action"], "action"))
    except ValueError:
        raise ValidationError("invalid action") from None
    ref = fields.get("message_ref")
    return PendingTask(
        id=parse_task_id(fields["id"]),
        channel=_str(fields["channel"], "channel"),
        action=action,
        payload=parse_payload(fields["payload"]),
        message_ref=None if ref is None else validate_message_ref(ref),
    )


def task_id_of(raw: object) -> TaskId | None:
    """The valid id of a (maybe malformed) task object, or None; lets a bad task be failed."""
    if isinstance(raw, dict):
        try:
            return parse_task_id(raw.get("id"))
        except ValidationError:
            return None
    return None


def parse_tasks_envelope(raw: object) -> list[object]:
    """The raw task list of a `GET /notifier/tasks` body (<= 20 entries, not yet parsed).

    Raises:
        ValidationError: not `{"tasks": [...]}` or too many tasks.
    """
    tasks = _object(raw, "tasks response", frozenset({"tasks"}))["tasks"]
    if not isinstance(tasks, list) or len(tasks) > MAX_TASKS_LIMIT:
        raise ValidationError(f"tasks must be a list of at most {MAX_TASKS_LIMIT}")
    return list(tasks)


# --- done / failed (notifier -> admin) -------------------------------------------------


def done_request_to_json(message_ref: str | None) -> dict[str, object]:
    """Body of `POST /notifier/tasks/{id}/done`: `{"message_ref": str | null}`."""
    return {"message_ref": message_ref}


def parse_done_request(raw: object) -> str | None:
    """The `message_ref` of a done report (`{}` or `{"message_ref": null}` mean none).

    Raises:
        ValidationError: unknown fields or a malformed `message_ref`.
    """
    ref = _object(raw, "done request", frozenset(), frozenset({"message_ref"})).get("message_ref")
    return None if ref is None else validate_message_ref(ref)


def failed_request_to_json() -> dict[str, object]:
    """Body of `POST /notifier/tasks/{id}/failed`: `{}`."""
    return {}


def parse_failed_request(raw: object) -> None:
    """Check a failed report's body is `{}`.

    Raises:
        ValidationError: any field present.
    """
    _object(raw, "failed request", frozenset())


# --- answers (notifier -> admin) ---------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class AnswerSubmission:
    """One tap as submitted to `POST /notifier/answers`.

    `question_id` and `key` stay **raw** (bounded strings only): the admin's
    `QuestionService.answer` turns anything unknown into `unknown` (C34, no
    existence oracle). `source` is a plug-in name, `actor_ref` visible ASCII.
    """

    question_id: str
    key: str
    source: str
    actor_ref: str


def answer_request_to_json(submission: AnswerSubmission) -> dict[str, object]:
    """Body of `POST /notifier/answers`: `{question_id, key, source, actor_ref}`."""
    return {
        "question_id": submission.question_id,
        "key": submission.key,
        "source": submission.source,
        "actor_ref": submission.actor_ref,
    }


def parse_answer_request(raw: object) -> AnswerSubmission:
    """Parse a submitted tap (shape and bounds only, see `AnswerSubmission`).

    Raises:
        ValidationError: unknown/missing fields, non-strings, raw fields over
            64 chars, a malformed `source` or `actor_ref`.
    """
    fields = _object(raw, "answer", _ANSWER_FIELDS)
    question_id = _str(fields["question_id"], "question_id")
    key = _str(fields["key"], "key")
    if len(question_id) > MAX_RAW_FIELD_CHARS or len(key) > MAX_RAW_FIELD_CHARS:
        raise ValidationError(f"question_id and key are at most {MAX_RAW_FIELD_CHARS} chars")
    actor_ref = _str(fields["actor_ref"], "actor_ref")
    if not _ACTOR_REF_RE.fullmatch(actor_ref):
        raise ValidationError("actor_ref must be 1..64 visible ASCII characters")
    return AnswerSubmission(
        question_id=question_id,
        key=key,
        source=validate_plugin_name(fields["source"], "answer source"),
        actor_ref=actor_ref,
    )


def answer_result_to_json(result: AnswerResult) -> dict[str, object]:
    """Response body of `POST /notifier/answers`: `{"result": "recorded" | ...}`."""
    return {"result": str(result)}


def parse_answer_result(raw: object) -> AnswerResult:
    """Parse the admin's verdict on a tap.

    Raises:
        ValidationError: not `{"result": <AnswerResult value>}`.
    """
    value = _object(raw, "answer result", frozenset({"result"}))["result"]
    try:
        return AnswerResult(_str(value, "result"))
    except ValueError:
        raise ValidationError("unknown answer result") from None
