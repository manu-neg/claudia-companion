"""JSON wire format of the notifier's owner-update routes (ADR 0031, security.md C44, C46, C47).

The single definition of three notifier-token routes and the approval
callback data, shared by the notifier (`adapters/admin_queue.py`, M2) and the
admin server side (`interfaces/admin/notifier_api.py`, M3):

| Route | Request | Response |
|---|---|---|
| `POST /v1/notifier/messages` | `MessageSubmission` | `{"result": "stored" \\| "duplicate"}` |
| `POST /v1/notifier/approvals` | `ApprovalTapSubmission` | `{"result": TapResult}` |
| `POST /v1/notifier/codes` | `CodeSubmission` | `{"result": CodeResult}` |

Approval buttons carry `p:<request ULID>:ok|no`. Parsers are strict
(unknown keys, wrong types, out-of-range values -> `ValidationError`, never
echoing a value); the admin re-validates everything with the domain types.
Framework-free (stdlib + domain), like `wire/notifier.py`.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.domain.owner_messages import (
    STORED_MESSAGE_MAX_CHARS,
    STORED_QUOTE_MAX_CHARS,
    is_code_message,
    redact_code_runs,
)
from preview_dashboard.domain.questions import validate_plugin_name
from preview_dashboard.wire.notifier import NOTIFIER_PREFIX

# --- routes ---------------------------------------------------------------------------

MESSAGES_PATH: Final = f"{NOTIFIER_PREFIX}/messages"
APPROVALS_PATH: Final = f"{NOTIFIER_PREFIX}/approvals"
CODES_PATH: Final = f"{NOTIFIER_PREFIX}/codes"

# Telegram ids are positive 64-bit integers (the SQLite INTEGER range).
_MAX_TELEGRAM_ID: Final = 2**63 - 1
_ACTOR_REF_RE = re.compile(r"[\x21-\x7e]{1,64}")
_CODE_RE = re.compile(r"[0-9]{6}")
_MESSAGE_REQUIRED: Final = frozenset(
    {"update_id", "message_id", "sender_id", "text", "is_forwarded"}
)
_MESSAGE_OPTIONAL: Final = frozenset({"reply_to_message_id", "quote_text"})
_TAP_FIELDS: Final = frozenset({"request_id", "decision", "source", "actor_ref"})
_CODE_FIELDS: Final = frozenset({"update_id", "message_id", "sender_id", "code"})


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


def _telegram_id(raw: object, name: str, *, minimum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= _MAX_TELEGRAM_ID:
        raise ValidationError(f"{name} must be an integer in {minimum}..{_MAX_TELEGRAM_ID}")
    return raw


def _owner_text(raw: object, name: str, max_chars: int) -> str:
    """Untrusted owner text as the inbox stores it: verbatim, but already redacted (C44).

    Mirrors the domain's checks so the notifier refuses what the admin
    would (the admin still re-validates with `OwnerMessage`).
    """
    if not isinstance(raw, str):
        raise ValidationError(f"{name} must be a string")
    if not 1 <= len(raw) <= max_chars:
        raise ValidationError(f"{name} must be 1..{max_chars} characters")
    if "\x00" in raw or any(unicodedata.category(ch) == "Cs" for ch in raw):
        raise ValidationError(f"{name} contains an invalid character")
    if raw.isspace():
        raise ValidationError(f"{name} must not be blank")
    if is_code_message(raw):
        raise ValidationError("an authenticator code never enters the inbox")
    if redact_code_runs(raw) != raw:
        raise ValidationError(f"{name} contains an unredacted code-like digit run")
    return raw


def _actor_ref(raw: object) -> str:
    if not isinstance(raw, str) or not _ACTOR_REF_RE.fullmatch(raw):
        raise ValidationError("actor_ref must be 1..64 visible ASCII characters")
    return raw


def _result[E: StrEnum](cls: type[E], raw: object, what: str) -> E:
    value = _object(raw, what, frozenset({"result"}))["result"]
    if not isinstance(value, str):
        raise ValidationError(f"{what} must be a string")
    try:
        return cls(value)
    except ValueError:
        raise ValidationError(f"unknown {what}") from None


# --- owner messages (notifier -> admin) --------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageSubmission:
    """One owner text message for the inbox (`POST /v1/notifier/messages`, C44).

    The notifier has already checked the sender (`from.id == chat.id ==
    owner`, private chat, not a bot) and redacted 6-digit runs; the admin
    re-checks `sender_id` against its own config and stores the text with
    `OwnerMessage` (idempotent on `update_id` + `message_id`). `text` and
    `quote_text` are excluded from `repr` (never logged, C29).

    Invariants (`ValidationError`): `update_id >= 0`, `message_id >= 1`,
    `sender_id >= 1`, `reply_to_message_id` None or >= 1; `text` 1..20480
    chars (<= 4096 before redaction), `quote_text` None or 1..5120 chars,
    both without NUL / lone surrogates / blank-only / unredacted 6-digit
    runs, `text` not a code; `is_forwarded` a bool.
    """

    update_id: int
    message_id: int
    sender_id: int
    text: str = field(repr=False)
    is_forwarded: bool = False
    reply_to_message_id: int | None = None
    quote_text: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _telegram_id(self.update_id, "update_id", minimum=0)
        _telegram_id(self.message_id, "message_id", minimum=1)
        _telegram_id(self.sender_id, "sender_id", minimum=1)
        if self.reply_to_message_id is not None:
            _telegram_id(self.reply_to_message_id, "reply_to_message_id", minimum=1)
        _owner_text(self.text, "message text", STORED_MESSAGE_MAX_CHARS)
        if self.quote_text is not None:
            _owner_text(self.quote_text, "quote", STORED_QUOTE_MAX_CHARS)
        if not isinstance(self.is_forwarded, bool):
            raise ValidationError("is_forwarded must be a bool")


def message_request_to_json(submission: MessageSubmission) -> dict[str, object]:
    """Body of `POST /v1/notifier/messages` (all seven keys, nulls kept)."""
    return {
        "update_id": submission.update_id,
        "message_id": submission.message_id,
        "sender_id": submission.sender_id,
        "text": submission.text,
        "is_forwarded": submission.is_forwarded,
        "reply_to_message_id": submission.reply_to_message_id,
        "quote_text": submission.quote_text,
    }


def parse_message_request(raw: object) -> MessageSubmission:
    """Parse a submitted owner message (shape and `MessageSubmission` invariants).

    Raises:
        ValidationError: unknown/missing fields or any invariant broken.
    """
    fields = _object(raw, "message", _MESSAGE_REQUIRED, _MESSAGE_OPTIONAL)
    reply_to = fields.get("reply_to_message_id")
    quote = fields.get("quote_text")
    forwarded = fields["is_forwarded"]
    if not isinstance(forwarded, bool):
        raise ValidationError("is_forwarded must be a bool")
    return MessageSubmission(
        update_id=_telegram_id(fields["update_id"], "update_id", minimum=0),
        message_id=_telegram_id(fields["message_id"], "message_id", minimum=1),
        sender_id=_telegram_id(fields["sender_id"], "sender_id", minimum=1),
        text=_owner_text(fields["text"], "message text", STORED_MESSAGE_MAX_CHARS),
        is_forwarded=forwarded,
        reply_to_message_id=(
            None if reply_to is None else _telegram_id(reply_to, "reply_to_message_id", minimum=1)
        ),
        quote_text=None if quote is None else _owner_text(quote, "quote", STORED_QUOTE_MAX_CHARS),
    )


class MessageResult(StrEnum):
    """The admin's verdict on a submitted message: newly stored, or a re-delivery."""

    STORED = "stored"
    DUPLICATE = "duplicate"


def message_result_to_json(result: MessageResult) -> dict[str, object]:
    """Response body of `POST /v1/notifier/messages`: `{"result": "stored" | "duplicate"}`."""
    return {"result": str(result)}


def parse_message_result(raw: object) -> MessageResult:
    """Parse the admin's verdict on a message.

    Raises:
        ValidationError: not `{"result": <MessageResult value>}`.
    """
    return _result(MessageResult, raw, "message result")


# --- approval taps (notifier -> admin) ---------------------------------------------------

APPROVAL_CALLBACK_PREFIX: Final = "p"
_APPROVAL_CALLBACK_RE = re.compile(r"p:([0-9A-Z]{26}):(ok|no)")


class ApprovalDecision(StrEnum):
    """The owner's tap on an approval request; values are the JSON `decision`."""

    APPROVE = "approve"
    DENY = "deny"


_CALLBACK_SUFFIX: Final = {ApprovalDecision.APPROVE: "ok", ApprovalDecision.DENY: "no"}


def approval_callback_data(request_id: str, decision: ApprovalDecision) -> str:
    """`p:<request_id>:ok|no` for one approval button (<= 31 bytes, under Telegram's 64).

    Raises:
        ValidationError: `request_id` is not a canonical ULID.
    """
    if not is_ulid(request_id):
        raise ValidationError("invalid approval request id")
    return f"{APPROVAL_CALLBACK_PREFIX}:{request_id}:{_CALLBACK_SUFFIX[decision]}"


def parse_approval_callback(data: object) -> tuple[str, ApprovalDecision] | None:
    """`(request_id, decision)` for exactly `p:<canonical ULID>:(ok|no)`, else None."""
    match = _APPROVAL_CALLBACK_RE.fullmatch(data) if isinstance(data, str) else None
    if match is None or not is_ulid(match.group(1)):
        return None
    decision = ApprovalDecision.APPROVE if match.group(2) == "ok" else ApprovalDecision.DENY
    return match.group(1), decision


@dataclass(frozen=True, slots=True, kw_only=True)
class ApprovalTapSubmission:
    """One Approve/Deny tap (`POST /v1/notifier/approvals`, C46).

    Only the notifier token may submit taps; the admin's approval service
    turns an unknown id into `unknown` (no existence oracle, as C34).

    Invariants (`ValidationError`): `request_id` canonical ULID; `decision`
    an `ApprovalDecision`; `source` a plug-in name; `actor_ref` 1..64
    visible ASCII.
    """

    request_id: str
    decision: ApprovalDecision
    source: str
    actor_ref: str

    def __post_init__(self) -> None:
        if not is_ulid(self.request_id):
            raise ValidationError("invalid approval request id")
        try:
            object.__setattr__(self, "decision", ApprovalDecision(self.decision))
        except ValueError:
            raise ValidationError("decision must be approve or deny") from None
        validate_plugin_name(self.source, "tap source")
        _actor_ref(self.actor_ref)


def approval_tap_request_to_json(submission: ApprovalTapSubmission) -> dict[str, object]:
    """Body of `POST /v1/notifier/approvals`: `{request_id, decision, source, actor_ref}`."""
    return {
        "request_id": submission.request_id,
        "decision": str(submission.decision),
        "source": submission.source,
        "actor_ref": submission.actor_ref,
    }


def parse_approval_tap_request(raw: object) -> ApprovalTapSubmission:
    """Parse a submitted tap.

    Raises:
        ValidationError: unknown/missing fields or any invariant broken.
    """
    fields = _object(raw, "approval tap", _TAP_FIELDS)
    request_id = fields["request_id"]
    if not is_ulid(request_id):
        raise ValidationError("invalid approval request id")
    raw_decision = fields["decision"]
    if not isinstance(raw_decision, str) or raw_decision not in set(ApprovalDecision):
        raise ValidationError("decision must be approve or deny")
    decision = ApprovalDecision(raw_decision)
    return ApprovalTapSubmission(
        request_id=str(request_id),
        decision=decision,
        source=validate_plugin_name(fields["source"], "tap source"),
        actor_ref=_actor_ref(fields["actor_ref"]),
    )


class TapResult(StrEnum):
    """The admin's verdict on a tap (first tap wins; every transition a CAS, C46)."""

    TAPPED = "tapped"  # Approve recorded: the owner now sends the code
    DENIED = "denied"
    ALREADY_DECIDED = "already_decided"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


# Sent once as a chat message after an Approve tap is recorded (C46/C47):
# fixed text, so nothing a request or a caller supplies ever reaches it.
CODE_PROMPT_TEXT: Final = "Approve recorded. Send your authenticator code (6 digits) now."


class OwnerNotice(StrEnum):
    """Fixed chat messages the notifier itself may send the owner (F-C1b; no caller text)."""

    # The admin saw this exact code message before (re-delivery): not a try.
    CODE_NOT_CHECKED = "code_not_checked"
    # A code message could not be deleted within Telegram's 48 h delete window.
    CODE_NOT_DELETED = "code_not_deleted"


OWNER_NOTICE_TEXTS: Final = {
    OwnerNotice.CODE_NOT_CHECKED: (
        "That code was not checked (message already received). "
        "If you still need to approve, send a new code."
    ),
    OwnerNotice.CODE_NOT_DELETED: (
        "Failed: an authenticator code message could not be deleted. "
        "Delete it from this chat yourself."
    ),
}

# Fixed toasts: the notifier never shows request text it did not get from the outbox.
TAP_ACK_TEXTS: Final = {
    TapResult.TAPPED: "Approved. Now send your authenticator code.",
    TapResult.DENIED: "Denied",
    TapResult.ALREADY_DECIDED: "Already decided",
    TapResult.EXPIRED: "Expired",
    TapResult.UNKNOWN: "Unknown",
}


def tap_result_to_json(result: TapResult) -> dict[str, object]:
    """Response body of `POST /v1/notifier/approvals`: `{"result": <TapResult>}`."""
    return {"result": str(result)}


def parse_tap_result(raw: object) -> TapResult:
    """Parse the admin's verdict on a tap.

    Raises:
        ValidationError: not `{"result": <TapResult value>}`.
    """
    return _result(TapResult, raw, "tap result")


# --- codes (notifier -> admin) ------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class CodeSubmission:
    """One authenticator code message (`POST /v1/notifier/codes`, C47).

    `code` is the message text with ASCII spaces removed: exactly ASCII
    `[0-9]{6}`. It is excluded from `repr` and never logged or stored by
    the notifier. The admin treats a repeated `update_id` + `message_id`
    as `duplicate` (a re-delivered update), never as a second (wrong) try.

    Invariants (`ValidationError`): `update_id >= 0`, `message_id >= 1`,
    `sender_id >= 1`, `code` exactly six ASCII digits.
    """

    update_id: int
    message_id: int
    sender_id: int
    code: str = field(repr=False)

    def __post_init__(self) -> None:
        _telegram_id(self.update_id, "update_id", minimum=0)
        _telegram_id(self.message_id, "message_id", minimum=1)
        _telegram_id(self.sender_id, "sender_id", minimum=1)
        if not isinstance(self.code, str) or not _CODE_RE.fullmatch(self.code):
            raise ValidationError("code must be exactly six ASCII digits")


def code_request_to_json(submission: CodeSubmission) -> dict[str, object]:
    """Body of `POST /v1/notifier/codes`: `{update_id, message_id, sender_id, code}`."""
    return {
        "update_id": submission.update_id,
        "message_id": submission.message_id,
        "sender_id": submission.sender_id,
        "code": submission.code,
    }


def parse_code_request(raw: object) -> CodeSubmission:
    """Parse a submitted code.

    Raises:
        ValidationError: unknown/missing fields or any invariant broken.
    """
    fields = _object(raw, "code", _CODE_FIELDS)
    code = fields["code"]
    if not isinstance(code, str):
        raise ValidationError("code must be exactly six ASCII digits")
    return CodeSubmission(
        update_id=_telegram_id(fields["update_id"], "update_id", minimum=0),
        message_id=_telegram_id(fields["message_id"], "message_id", minimum=1),
        sender_id=_telegram_id(fields["sender_id"], "sender_id", minimum=1),
        code=code,
    )


class CodeResult(StrEnum):
    """The admin's verdict on a code; feedback to the owner comes as outbox alerts (C47)."""

    ACCEPTED = "accepted"  # a TAPPED request is now APPROVED
    REFUSED = "refused"  # wrong code, replay, or no TAPPED request (counts as wrong)
    LOCKED = "locked"  # rate-limit lockout: every code refused
    DUPLICATE = "duplicate"  # same update seen before: not counted again


def code_result_to_json(result: CodeResult) -> dict[str, object]:
    """Response body of `POST /v1/notifier/codes`: `{"result": <CodeResult>}`."""
    return {"result": str(result)}


def parse_code_result(raw: object) -> CodeResult:
    """Parse the admin's verdict on a code.

    Raises:
        ValidationError: not `{"result": <CodeResult value>}`.
    """
    return _result(CodeResult, raw, "code result")
