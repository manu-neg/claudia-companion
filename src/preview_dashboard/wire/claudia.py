"""JSON wire format of the admin API's `/v1/claudia/*` routes (`claudia` token, ADR 0031, C45).

The single definition of the route paths and bodies shared by the admin
side (`interfaces/admin/claudia_api.py`) and the Claudia host (unit M4):
inbox long-poll + handled mark, voice/photo bytes fetch + release (C61),
replies, approval requests (create, read,
consume, cancel one / cancel all open for `/stop`) and screen health.
Framework-free (stdlib + domain). Parsers are strict: unknown keys, wrong
types and out-of-range values raise `ValidationError`, and entities are
re-validated by their domain types. There is deliberately no answer, tap,
code, approve or edit shape here (C45); cancel only ever closes a request.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    parse_approval_id,
    parse_window_id,
)
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_media import MessageKind
from preview_dashboard.domain.owner_messages import (
    InboxState,
    OwnerMessage,
    parse_owner_message_id,
)

# --- routes --------------------------------------------------------------------------

CLAUDIA_PREFIX: Final = "/v1/claudia"
MESSAGES_PATH: Final = f"{CLAUDIA_PREFIX}/messages"
REPLIES_PATH: Final = f"{CLAUDIA_PREFIX}/replies"
APPROVALS_PATH: Final = f"{CLAUDIA_PREFIX}/approvals"
# Not an id-shaped segment, so it can never collide with `/approvals/{id}`.
APPROVALS_CANCEL_OPEN_PATH: Final = f"{APPROVALS_PATH}/cancel-open"
HEALTH_PATH: Final = f"{CLAUDIA_PREFIX}/health"
MAX_MESSAGES_LIMIT: Final = 20
DEFAULT_MESSAGES_LIMIT: Final = 20

# Mirrors `application.approvals.ConsumeResult` (a test keeps them equal).
CONSUME_RESULTS: Final = frozenset(
    {"consumed", "already_consumed", "not_approved", "expired", "unknown"}
)
# Mirrors `application.approvals.CancelResult` (a test keeps them equal).
CANCEL_RESULTS: Final = frozenset({"cancelled", "already_resolved", "busy", "unknown"})
MAX_CANCELLED: Final = 100
SCREEN_STATES: Final = frozenset({"ok", "degraded", "down"})

_DIGITS_RE = re.compile(r"[0-9]{1,3}")
_APPROVAL_CREATE_REQUIRED: Final = frozenset({"window_id", "kind"})
_APPROVAL_CREATE_OPTIONAL: Final = frozenset(
    {"action_text", "action_kind", "action_target", "message_id"}
)
_APPROVAL_FIELDS: Final = frozenset(
    {
        "id",
        "window_id",
        "kind",
        "action_text",
        "action_kind",
        "action_target",
        "message_id",
        "state",
        "created_at",
        "expires_at",
        "updated_at",
        "tapped_at",
        "approved_at",
        "resolved_at",
    }
)
_MESSAGE_FIELDS: Final = frozenset(
    {
        "id",
        "update_id",
        "telegram_message_id",
        "text",
        "received_at",
        "is_forwarded",
        "reply_to_message_id",
        "quote_text",
        "state",
        "handled_at",
        # C61: "text" | "voice" | "photo"; media_id / media_bytes null for text.
        "kind",
        "media_id",
        "media_bytes",
    }
)
_REPLY_OPTIONAL: Final = frozenset({"message_id", "item_id", "ping"})


def message_handled_path(message_id: str) -> str:
    """`POST` path marking inbox message `message_id` handled (id validated first).

    Raises:
        ValidationError: not a canonical ULID (no path injection).
    """
    return f"{MESSAGES_PATH}/{parse_owner_message_id(message_id)}/handled"


def message_media_path(message_id: str) -> str:
    """`GET` path of a voice/photo message's checked bytes (C61; id validated first).

    Raises:
        ValidationError: not a canonical ULID.
    """
    return f"{MESSAGES_PATH}/{parse_owner_message_id(message_id)}/media"


def message_media_release_path(message_id: str) -> str:
    """`POST` path (`{}` body) deleting a voice/photo message's bytes once used (C61).

    Raises:
        ValidationError: not a canonical ULID.
    """
    return f"{message_media_path(message_id)}/release"


def parse_release_request(raw: object) -> None:
    """A media release body must be exactly `{}`.

    Raises:
        ValidationError: any field.
    """
    _object(raw, "release request", frozenset())


def approval_path(approval_id: str) -> str:
    """`GET` path of one approval request (id validated first).

    Raises:
        ValidationError: not a canonical ULID.
    """
    return f"{APPROVALS_PATH}/{parse_approval_id(approval_id)}"


def approval_consume_path(approval_id: str) -> str:
    """`POST` path consuming an APPROVED request (id validated first).

    Raises:
        ValidationError: not a canonical ULID.
    """
    return f"{approval_path(approval_id)}/consume"


def approval_cancel_path(approval_id: str) -> str:
    """`POST` path cancelling one open request (id validated first).

    Raises:
        ValidationError: not a canonical ULID.
    """
    return f"{approval_path(approval_id)}/cancel"


def parse_messages_limit(raw: str | None) -> int:
    """`?limit=` of `GET /v1/claudia/messages`: 1..20 (default 20).

    Raises:
        ValidationError: not ASCII digits or out of range.
    """
    if raw is None:
        return DEFAULT_MESSAGES_LIMIT
    if not isinstance(raw, str) or not _DIGITS_RE.fullmatch(raw):
        raise ValidationError(f"limit must be an integer in 1..{MAX_MESSAGES_LIMIT}")
    value = int(raw)
    if not 1 <= value <= MAX_MESSAGES_LIMIT:
        raise ValidationError(f"limit must be an integer in 1..{MAX_MESSAGES_LIMIT}")
    return value


# --- helpers ---------------------------------------------------------------------------


def _object(
    raw: object, what: str, required: frozenset[str], optional: frozenset[str] = frozenset()
) -> dict[str, object]:
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


def _time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _parse_time(raw: object, what: str) -> datetime:
    try:
        return datetime.fromisoformat(_str(raw, what))
    except ValueError:
        raise ValidationError(f"{what} must be an ISO 8601 time") from None


def _parse_optional_time(raw: object, what: str) -> datetime | None:
    return None if raw is None else _parse_time(raw, what)


def _enum[E: StrEnum](cls: type[E], raw: object, what: str) -> E:
    try:
        return cls(_str(raw, what))
    except ValueError:
        raise ValidationError(f"invalid {what}") from None


def _int(raw: object, what: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValidationError(f"{what} must be an integer")
    return raw


# --- inbox (admin -> host) ---------------------------------------------------------------


def owner_message_to_json(message: OwnerMessage) -> dict[str, object]:
    """One inbox message: ids, verbatim (redacted) text, metadata, state, kind (C61).

    For `voice` / `photo`, `text` is the caption ("" = none), `media_id`
    the stored file's ULID and `media_bytes` its size; the bytes come from
    `message_media_path(<message id>)`. All three media keys are null /
    `"text"` for a text message.
    """
    return {
        "kind": str(message.kind),
        "media_id": message.media_id,
        "media_bytes": message.media_bytes,
        "id": message.id,
        "update_id": message.update_id,
        "telegram_message_id": message.telegram_message_id,
        "text": message.text,
        "received_at": message.received_at.isoformat(),
        "is_forwarded": message.is_forwarded,
        "reply_to_message_id": message.reply_to_message_id,
        "quote_text": message.quote_text,
        "state": str(message.state),
        "handled_at": _time(message.handled_at),
    }


def messages_to_json(messages: Sequence[OwnerMessage]) -> dict[str, object]:
    """Body of `GET /v1/claudia/messages`: `{"messages": [message, ...]}`."""
    return {"messages": [owner_message_to_json(m) for m in messages]}


def parse_owner_message(raw: object) -> OwnerMessage:
    """Parse and re-validate one inbox message (host side).

    Raises:
        ValidationError: malformed shape or any `OwnerMessage` invariant.
    """
    fields = _object(raw, "message", _MESSAGE_FIELDS)
    forwarded = fields["is_forwarded"]
    if not isinstance(forwarded, bool):
        raise ValidationError("is_forwarded must be a bool")
    reply_to = fields["reply_to_message_id"]
    media_bytes = fields["media_bytes"]
    return OwnerMessage(
        kind=_enum(MessageKind, fields["kind"], "kind"),
        media_id=_optional_str(fields["media_id"], "media_id"),
        media_bytes=None if media_bytes is None else _int(media_bytes, "media_bytes"),
        id=parse_owner_message_id(fields["id"]),
        update_id=_int(fields["update_id"], "update_id"),
        telegram_message_id=_int(fields["telegram_message_id"], "telegram_message_id"),
        text=_str(fields["text"], "text"),
        received_at=_parse_time(fields["received_at"], "received_at"),
        is_forwarded=forwarded,
        reply_to_message_id=None if reply_to is None else _int(reply_to, "reply_to_message_id"),
        quote_text=_optional_str(fields["quote_text"], "quote_text"),
        state=_enum(InboxState, fields["state"], "state"),
        handled_at=_parse_optional_time(fields["handled_at"], "handled_at"),
    )


def parse_messages_envelope(raw: object) -> list[OwnerMessage]:
    """The messages of a `GET /v1/claudia/messages` body (<= 20).

    Raises:
        ValidationError: not `{"messages": [...]}`, too many, or a bad message.
    """
    messages = _object(raw, "messages response", frozenset({"messages"}))["messages"]
    if not isinstance(messages, list) or len(messages) > MAX_MESSAGES_LIMIT:
        raise ValidationError(f"messages must be a list of at most {MAX_MESSAGES_LIMIT}")
    return [parse_owner_message(m) for m in messages]


# --- replies (host -> admin) -------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class ReplyRequest:
    """Body of `POST /v1/claudia/replies`: text plus optional inbox message and item link.

    `ping`: a host progress ping (F-CL2): fixed text only, needs `message_id`,
    no item link, its own budget.
    """

    text: str
    message_id: str | None = None
    item_id: str | None = None
    ping: bool = False


def reply_request_to_json(request: ReplyRequest) -> dict[str, object]:
    """`{"text", "message_id", "item_id"}` (nulls kept), plus `"ping": true` for a ping."""
    body: dict[str, object] = {
        "text": request.text,
        "message_id": request.message_id,
        "item_id": request.item_id,
    }
    if request.ping:
        body["ping"] = True
    return body


def parse_reply_request(raw: object) -> ReplyRequest:
    """Parse a reply body (shape only; the admin validates text, ids and budget).

    Raises:
        ValidationError: missing/unknown fields, non-string values, a non-boolean
            `ping`, or a ping without `message_id` or with `item_id`.
    """
    fields = _object(raw, "reply", frozenset({"text"}), _REPLY_OPTIONAL)
    ping = fields.get("ping", False)
    if not isinstance(ping, bool):
        raise ValidationError("ping must be a boolean")
    request = ReplyRequest(
        text=_str(fields["text"], "text"),
        message_id=_optional_str(fields.get("message_id"), "message_id"),
        item_id=_optional_str(fields.get("item_id"), "item_id"),
        ping=ping,
    )
    if ping and (request.message_id is None or request.item_id is not None):
        raise ValidationError("a ping needs message_id and takes no item_id")
    return request


def reply_result_to_json(reply_id: str) -> dict[str, object]:
    """Response of `POST /v1/claudia/replies`: `{"id": <delivery id>}`."""
    return {"id": reply_id}


# --- approvals (host <-> admin) ------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalCreateRequest:
    """Body of `POST /v1/claudia/approvals` (raw strings; the admin validates).

    `action_text` is required for `action` / `peer_message` and refused for
    `flagged_message`, whose text the admin builds from the stored message.
    """

    window_id: str
    kind: str
    action_text: str | None = None
    action_kind: str | None = None
    action_target: str | None = None
    message_id: str | None = None


def approval_create_to_json(request: ApprovalCreateRequest) -> dict[str, object]:
    """The create body; absent optional fields are omitted."""
    body: dict[str, object] = {"window_id": request.window_id, "kind": request.kind}
    for name in ("action_text", "action_kind", "action_target", "message_id"):
        value = getattr(request, name)
        if value is not None:
            body[name] = value
    return body


def parse_approval_create(raw: object) -> ApprovalCreateRequest:
    """Parse a create body (shape and types only).

    Raises:
        ValidationError: missing/unknown fields or non-string values.
    """
    fields = _object(raw, "approval request", _APPROVAL_CREATE_REQUIRED, _APPROVAL_CREATE_OPTIONAL)
    return ApprovalCreateRequest(
        window_id=_str(fields["window_id"], "window_id"),
        kind=_str(fields["kind"], "kind"),
        action_text=_optional_str(fields.get("action_text"), "action_text"),
        action_kind=_optional_str(fields.get("action_kind"), "action_kind"),
        action_target=_optional_str(fields.get("action_target"), "action_target"),
        message_id=_optional_str(fields.get("message_id"), "message_id"),
    )


def approval_to_json(request: ApprovalRequest) -> dict[str, object]:
    """One approval request with its state and every timestamp (nulls kept)."""
    return {
        "id": request.id,
        "window_id": request.window_id,
        "kind": str(request.kind),
        "action_text": request.action_text,
        "action_kind": None if request.action_kind is None else str(request.action_kind),
        "action_target": request.action_target,
        "message_id": request.message_id,
        "state": str(request.state),
        "created_at": request.created_at.isoformat(),
        "expires_at": request.expires_at.isoformat(),
        "updated_at": request.updated_at.isoformat(),
        "tapped_at": _time(request.tapped_at),
        "approved_at": _time(request.approved_at),
        "resolved_at": _time(request.resolved_at),
    }


def parse_approval(raw: object) -> ApprovalRequest:
    """Parse and re-validate one approval request (host side).

    Raises:
        ValidationError: malformed shape or any `ApprovalRequest` invariant.
    """
    f = _object(raw, "approval", _APPROVAL_FIELDS)
    action_kind, message_id = f["action_kind"], f["message_id"]
    return ApprovalRequest(
        id=parse_approval_id(f["id"]),
        window_id=parse_window_id(f["window_id"]),
        kind=_enum(ApprovalKind, f["kind"], "kind"),
        action_text=_str(f["action_text"], "action_text"),
        action_kind=None if action_kind is None else _enum(ActionKind, action_kind, "action_kind"),
        action_target=_optional_str(f["action_target"], "action_target"),
        message_id=None if message_id is None else parse_owner_message_id(message_id),
        state=_enum(ApprovalState, f["state"], "state"),
        created_at=_parse_time(f["created_at"], "created_at"),
        expires_at=_parse_time(f["expires_at"], "expires_at"),
        updated_at=_parse_time(f["updated_at"], "updated_at"),
        tapped_at=_parse_optional_time(f["tapped_at"], "tapped_at"),
        approved_at=_parse_optional_time(f["approved_at"], "approved_at"),
        resolved_at=_parse_optional_time(f["resolved_at"], "resolved_at"),
    )


def approval_envelope(request: ApprovalRequest) -> dict[str, object]:
    """Body of create / get responses: `{"approval": approval}`."""
    return {"approval": approval_to_json(request)}


def consume_result_to_json(result: str, request: ApprovalRequest | None) -> dict[str, object]:
    """Response of consume: `{"result": ..., "approval": approval | null}`.

    Raises:
        ValidationError: `result` is not one of `CONSUME_RESULTS`.
    """
    if result not in CONSUME_RESULTS:
        raise ValidationError("unknown consume result")
    return {"result": result, "approval": None if request is None else approval_to_json(request)}


def parse_consume_result(raw: object) -> tuple[str, ApprovalRequest | None]:
    """Parse a consume response (host side).

    Raises:
        ValidationError: unknown result or a malformed approval.
    """
    fields = _object(raw, "consume result", frozenset({"result", "approval"}))
    result = _str(fields["result"], "result")
    if result not in CONSUME_RESULTS:
        raise ValidationError("unknown consume result")
    approval = fields["approval"]
    return result, None if approval is None else parse_approval(approval)


def cancel_result_to_json(result: str, request: ApprovalRequest | None) -> dict[str, object]:
    """Response of cancel: `{"result": ..., "approval": approval | null}`.

    Raises:
        ValidationError: `result` is not one of `CANCEL_RESULTS`.
    """
    if result not in CANCEL_RESULTS:
        raise ValidationError("unknown cancel result")
    return {"result": result, "approval": None if request is None else approval_to_json(request)}


def parse_cancel_result(raw: object) -> tuple[str, ApprovalRequest | None]:
    """Parse a cancel response (host side).

    Raises:
        ValidationError: unknown result or a malformed approval.
    """
    fields = _object(raw, "cancel result", frozenset({"result", "approval"}))
    result = _str(fields["result"], "result")
    if result not in CANCEL_RESULTS:
        raise ValidationError("unknown cancel result")
    approval = fields["approval"]
    return result, None if approval is None else parse_approval(approval)


def cancel_open_request_to_json(window_id: str | None) -> dict[str, object]:
    """Body of `POST /v1/claudia/approvals/cancel-open`: `{}` or `{"window_id": ...}`."""
    return {} if window_id is None else {"window_id": window_id}


def parse_cancel_open_request(raw: object) -> str | None:
    """The optional window of a cancel-open body (None = every window).

    Raises:
        ValidationError: unknown fields or a malformed window id.
    """
    window = _object(raw, "cancel-open request", frozenset(), frozenset({"window_id"})).get(
        "window_id"
    )
    return None if window is None else parse_window_id(window)


def cancel_open_result_to_json(cancelled: Sequence[ApprovalRequest]) -> dict[str, object]:
    """Response of cancel-open: `{"cancelled": [approval id, ...]}` (first 100 listed).

    One open request per window makes more than a few impossible in
    practice; the cap only keeps the host's strict parser bounded.
    """
    return {"cancelled": [r.id for r in cancelled][:MAX_CANCELLED]}


def parse_cancel_open_result(raw: object) -> list[str]:
    """The ids a cancel-open response reports as cancelled (host side, <= 100).

    Raises:
        ValidationError: not `{"cancelled": [ULID, ...]}`.
    """
    ids = _object(raw, "cancel-open result", frozenset({"cancelled"}))["cancelled"]
    if not isinstance(ids, list) or len(ids) > MAX_CANCELLED:
        raise ValidationError(f"cancelled must be a list of at most {MAX_CANCELLED} ids")
    return [parse_approval_id(i) for i in ids]


# --- screen health (host -> admin) ----------------------------------------------------------


def health_request_to_json(screen: str) -> dict[str, object]:
    """Body of `POST /v1/claudia/health`: `{"screen": "ok" | "degraded" | "down"}`."""
    return {"screen": screen}


def parse_health_request(raw: object) -> str:
    """The screen state of a health report.

    Raises:
        ValidationError: not exactly `{"screen": <ok|degraded|down>}`.
    """
    screen = _str(_object(raw, "health report", frozenset({"screen"}))["screen"], "screen")
    if screen not in SCREEN_STATES:
        raise ValidationError("screen must be ok, degraded or down")
    return screen
