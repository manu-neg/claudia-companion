"""ClaudiaAdminClient: the host's `HostAdmin` over the admin Unix socket (`claudia` token, C45).

Talks only to `/v1/claudia/*` in the format of `wire/claudia.py` (inbox,
handled mark, replies, approvals, health), the cancel routes of unit A1
(`/approvals/{id}/cancel`, `/approvals/cancel-open {"window_id"}`, for
`/stop`, C58; result codes parsed strictly), the voice route (C56) and the
owner-media fetch/release routes (C61/C62). Implements the `HostAdmin`,
`ApprovalAdmin`, `VoiceReplies` and `HostMedia` ports.
The token lives only in the client's default headers (never logged or
repr'd); proxies/env are ignored; responses are size-bounded and
re-validated by the domain types. `ReplyAlerts` sends the host's fixed
`failed` alerts as replies (the only Telegram route this token has).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Final

import httpx

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    parse_approval_id,
    parse_window_id,
)
from preview_dashboard.domain.errors import (
    ConflictError,
    NotFoundError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.domain.owner_media import PHOTO_MAX_BYTES
from preview_dashboard.domain.owner_messages import OwnerMessage, OwnerMessageId
from preview_dashboard.wire import claudia as wire
from preview_dashboard.wire.claudia_voice import VOICE_PATH, VoiceRequest, voice_request_to_json

_BASE_URL: Final = "http://admin.local"
MAX_RESPONSE_BYTES: Final = 1024 * 1024
MAX_WAIT_SECONDS: Final = 60
LONG_POLL_MARGIN: Final = 15.0
_TIMEOUT: Final = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0)
_ERROR_CODE_RE = re.compile(r"[a-z_]{1,32}")
# A1's cancel routes (server side in `interfaces/admin/claudia_api.py`).
APPROVALS_CANCEL_OPEN_PATH: Final = f"{wire.APPROVALS_PATH}/cancel-open"
# Statuses meaning "the admin refused this reply" (scan, length, budget): not an outage.
_REPLY_REFUSED: Final = frozenset({400, 409, 413, 422, 429})
ALERT_PREFIX: Final = "Alert (failed): "
_CANCEL_ATTEMPTS: Final = 3

_log = logging.getLogger(__name__)


def approval_cancel_path(approval_id: str) -> str:
    """`POST` path cancelling one open request (id validated first).

    Raises:
        ValidationError: not a canonical ULID.
    """
    return f"{wire.approval_path(approval_id)}/cancel"


class ClaudiaAdminError(StorageUnavailableError):
    """A `/v1/claudia/*` call failed; `str()` names the route family and status only.

    Attributes:
        status: HTTP status, or None if no usable response arrived.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ClaudiaAdminClient:
    """Blocking client of the admin API's Claudia routes.

    Args:
        socket_path: the admin Unix socket (verified before, `verify_admin_socket`).
        token: the `claudia` token (C12 file loader).
        transport: override the transport (tests); default httpx over UDS.
    """

    def __init__(
        self, socket_path: Path, token: bytes, *, transport: httpx.BaseTransport | None = None
    ) -> None:
        self._http = httpx.Client(
            transport=transport or httpx.HTTPTransport(uds=str(socket_path), trust_env=False),
            base_url=_BASE_URL,
            timeout=_TIMEOUT,
            headers={b"Authorization": b"Bearer " + token, b"Accept-Encoding": b"identity"},
            follow_redirects=False,
            trust_env=False,  # the socket only: no proxies/netrc from env
        )

    def __repr__(self) -> str:
        return "ClaudiaAdminClient()"  # never expose headers (the token)

    def close(self) -> None:
        """Close the connection pool. Idempotent."""
        self._http.close()

    # --- inbox ---------------------------------------------------------------------------

    def unhandled(self, wait: float) -> Sequence[OwnerMessage]:
        """`GET /v1/claudia/messages?wait=` (long-poll, <= 60 s).

        Raises:
            ClaudiaAdminError: transport error, non-200 or a malformed envelope.
        """
        seconds = max(0, min(int(wait), MAX_WAIT_SECONDS))
        request = self._http.build_request(
            "GET",
            wire.MESSAGES_PATH,
            params={"wait": str(seconds)},
            timeout=httpx.Timeout(
                connect=5.0, read=seconds + LONG_POLL_MARGIN, write=10.0, pool=10.0
            ),
        )
        body = self._send(request, "messages")
        try:
            return wire.parse_messages_envelope(body)
        except ValidationError:
            raise ClaudiaAdminError("admin API messages: malformed response") from None

    def mark_handled(self, message_id: OwnerMessageId) -> bool:
        """`POST .../messages/{id}/handled` (CAS): True if claimed, False if already handled.

        Raises:
            ClaudiaAdminError: transport error or another non-200 status.
        """
        try:
            self._post(wire.message_handled_path(message_id), {}, "messages")
        except ClaudiaAdminError as exc:
            if exc.status == 409:
                return False
            raise
        return True

    # --- replies / health ----------------------------------------------------------------

    def send_reply(self, text: str, *, message_id: OwnerMessageId | None) -> bool:
        """`POST /v1/claudia/replies`; False if the admin refused the text or budget (C56).

        Raises:
            ClaudiaAdminError: transport error or an unexpected status.
        """
        body = wire.reply_request_to_json(wire.ReplyRequest(text=text, message_id=message_id))
        try:
            self._post(wire.REPLIES_PATH, body, "replies", ok=(201,))
        except ClaudiaAdminError as exc:
            if exc.status in _REPLY_REFUSED:
                _log.warning("reply refused by the admin (%s)", exc.status)
                return False
            raise
        return True

    def send_ping(self, text: str, *, message_id: OwnerMessageId) -> bool:
        """`POST /v1/claudia/replies` with `ping: true` (F-CL2, own budget); False if refused.

        Raises:
            ClaudiaAdminError: transport error or an unexpected status.
        """
        body = wire.reply_request_to_json(
            wire.ReplyRequest(text=text, message_id=message_id, ping=True)
        )
        try:
            self._post(wire.REPLIES_PATH, body, "replies", ok=(201,))
        except ClaudiaAdminError as exc:
            if exc.status in _REPLY_REFUSED:
                _log.info("progress ping refused by the admin (%s)", exc.status)
                return False
            raise
        return True

    def report_health(self, screen: str) -> None:
        """`POST /v1/claudia/health`.

        Raises:
            ClaudiaAdminError: transport error or non-200.
        """
        self._post(wire.HEALTH_PATH, wire.health_request_to_json(screen), "health")

    # --- approvals -----------------------------------------------------------------------

    def create_approval(self, request: wire.ApprovalCreateRequest) -> ApprovalRequest:
        """`POST /v1/claudia/approvals` (always PENDING, C46).

        Raises:
            ClaudiaAdminError: transport error, non-201 or a malformed approval.
        """
        body = self._post(
            wire.APPROVALS_PATH, wire.approval_create_to_json(request), "approvals", ok=(201,)
        )
        return self._approval(body)

    def get_approval(self, approval_id: ApprovalId, wait: float = 0) -> ApprovalRequest:
        """`GET /v1/claudia/approvals/{id}?wait=` (held until decided, <= 60 s).

        Raises:
            ClaudiaAdminError: transport error, non-200 or a malformed approval.
        """
        seconds = max(0, min(int(wait), MAX_WAIT_SECONDS))
        request = self._http.build_request(
            "GET",
            wire.approval_path(approval_id),
            params={"wait": str(seconds)},
            timeout=httpx.Timeout(
                connect=5.0, read=seconds + LONG_POLL_MARGIN, write=10.0, pool=10.0
            ),
        )
        approval = self._approval(self._send(request, "approvals"))
        if approval.id != approval_id:
            raise ClaudiaAdminError("admin API approvals: another request in the response")
        return approval

    def consume_approval(self, approval_id: ApprovalId) -> tuple[str, ApprovalRequest | None]:
        """`POST .../approvals/{id}/consume`: `(result, approval)` (single use, C46).

        Raises:
            ClaudiaAdminError: transport error, non-200 or a malformed result.
        """
        body = self._post(wire.approval_consume_path(approval_id), {}, "approvals")
        try:
            return wire.parse_consume_result(body)
        except ValidationError:
            raise ClaudiaAdminError("admin API approvals: malformed response") from None

    def request_approval(
        self,
        *,
        window_id: WindowId,
        kind: ApprovalKind,
        action_text: str | None,
        action_kind: ActionKind | None,
        action_target: str | None,
        message_id: OwnerMessageId | None,
    ) -> ApprovalRequest:
        """`create_approval` from domain values (`ApprovalAdmin` port, unit M5b).

        The returned request must be PENDING and match what was asked;
        anything else is a malformed answer (Claudia can't create a granted one).

        Raises:
            ConflictError: 409, the window already has an open request.
            ValidationError: 400/413/422, the admin refused the text, target or ids.
            ClaudiaAdminError: transport error, another status or a mismatched answer.
        """
        request = wire.ApprovalCreateRequest(
            window_id=parse_window_id(window_id),
            kind=str(kind),
            action_text=action_text,
            action_kind=None if action_kind is None else str(action_kind),
            action_target=action_target,
            message_id=message_id,
        )
        try:
            created = self.create_approval(request)
        except ClaudiaAdminError as exc:
            if exc.status == 409:
                raise ConflictError("the window already has an open approval request") from None
            if exc.status in (400, 413, 422):
                raise ValidationError("the admin refused the approval request") from None
            raise
        if (
            created.state is not ApprovalState.PENDING
            or created.window_id != window_id
            or created.kind is not kind
            or created.action_kind is not action_kind
        ):
            raise ClaudiaAdminError("admin API approvals: unexpected approval in the response")
        return created

    def cancel_approval(self, approval_id: ApprovalId) -> str:
        """`POST .../approvals/{id}/cancel` (A1, CAS); returns the result code.

        `busy` (still changing under the admin) is retried twice; a request
        already resolved is fine (`already_resolved`; a 409 is read the same).

        Raises:
            ClaudiaAdminError: transport error, an unexpected status or a malformed result.
        """
        path = approval_cancel_path(parse_approval_id(approval_id))
        result = "busy"
        for _ in range(_CANCEL_ATTEMPTS):
            try:
                body = self._post(path, {}, "approvals")
            except ClaudiaAdminError as exc:
                if exc.status == 409:
                    return "already_resolved"
                raise
            try:
                result, _ = wire.parse_cancel_result(body)
            except ValidationError:
                raise ClaudiaAdminError("admin API approvals: malformed response") from None
            if result != "busy":
                return result
        return result

    def cancel_open_approvals(self, window_id: WindowId) -> list[str]:
        """`POST .../approvals/cancel-open` for one window (A1, `/stop`, C58).

        Body `{"window_id": …}` (never `{}`, which would cancel every
        window's requests); returns the cancelled ids from the response.

        Raises:
            ClaudiaAdminError: transport error, non-200 or a malformed result.
        """
        return self._cancel_open(parse_window_id(window_id))

    def cancel_all_open_approvals(self) -> list[str]:
        """`POST .../approvals/cancel-open` with `{}`: every window's open requests.

        For host start and `/stop` (F-CL3b); a separate method so the one-window
        call above can never fall back to this by accident.

        Raises:
            ClaudiaAdminError: transport error, non-200 or a malformed result.
        """
        return self._cancel_open(None)

    def _cancel_open(self, window_id: WindowId | None) -> list[str]:
        body = wire.cancel_open_request_to_json(window_id)
        answer = self._post(APPROVALS_CANCEL_OPEN_PATH, body, "approvals")
        try:
            return list(wire.parse_cancel_open_result(answer))
        except ValidationError:
            raise ClaudiaAdminError("admin API approvals: malformed response") from None

    # --- voice (unit M10 route, wired by M5b) ----------------------------------------------

    def send_voice(self, text: str, audio: bytes, *, message_id: OwnerMessageId | None) -> bool:
        """`POST /v1/claudia/voice` (text + Ogg/Opus); False if refused (scan, caps, budget, C56).

        Raises:
            ClaudiaAdminError: transport error or an unexpected status.
        """
        body = voice_request_to_json(VoiceRequest(text=text, audio=audio, message_id=message_id))
        try:
            self._post(VOICE_PATH, body, "voice", ok=(201,))
        except ClaudiaAdminError as exc:
            if exc.status in _REPLY_REFUSED:
                _log.warning("voice reply refused by the admin (%s)", exc.status)
                return False
            raise
        return True

    # --- owner media (C61 routes, used by unit F-CL4 B, C62) -----------------------------

    def fetch_media(self, message_id: OwnerMessageId) -> bytes:
        """`GET …/messages/{id}/media`: the checked bytes (<= 10 MiB, the photo cap).

        Raises:
            NotFoundError: 404 (text message, released or purged).
            ClaudiaAdminError: transport error, another status or an oversized body.
        """
        request = self._http.build_request("GET", wire.message_media_path(message_id))
        status, raw, failure = self._exchange(request, limit=PHOTO_MAX_BYTES)
        if failure is not None:
            raise ClaudiaAdminError(f"admin API media: request failed ({failure})")
        if status == 404:
            raise NotFoundError("no media for this message")
        if status != 200 or not raw:
            raise ClaudiaAdminError(f"admin API media: {status}", status=status)
        return raw

    def release_media(self, message_id: OwnerMessageId) -> None:
        """`POST …/messages/{id}/media/release` (`{}`; idempotent at the admin).

        Raises:
            ClaudiaAdminError: transport error or a non-200 status.
        """
        self._post(wire.message_media_release_path(message_id), {}, "media")

    # --- internals -----------------------------------------------------------------------

    @staticmethod
    def _approval(body: object) -> ApprovalRequest:
        try:
            fields = body if isinstance(body, dict) else {}
            if set(fields) != {"approval"}:
                raise ValidationError("approval envelope")
            return wire.parse_approval(fields["approval"])
        except ValidationError:
            raise ClaudiaAdminError("admin API approvals: malformed response") from None

    def _post(
        self, path: str, body: dict[str, object], family: str, *, ok: tuple[int, ...] = (200,)
    ) -> object:
        return self._send(self._http.build_request("POST", path, json=body), family, ok=ok)

    def _send(self, request: httpx.Request, family: str, *, ok: tuple[int, ...] = (200,)) -> object:
        status, raw, failure = self._exchange(request)
        if failure is not None:
            raise ClaudiaAdminError(f"admin API {family}: request failed ({failure})")
        try:
            body = json.loads(raw) if raw else None
        except (ValueError, RecursionError):
            body = None
        if status not in ok:
            fields = body if isinstance(body, dict) else {}
            code = fields.get("error")
            label = code if isinstance(code, str) and _ERROR_CODE_RE.fullmatch(code) else "error"
            raise ClaudiaAdminError(f"admin API {family}: {status} {label}", status=status)
        return body

    def _exchange(
        self, request: httpx.Request, *, limit: int = MAX_RESPONSE_BYTES
    ) -> tuple[int, bytes, str | None]:
        try:
            response = self._http.send(request, stream=True)
        except httpx.HTTPError as exc:
            return 0, b"", type(exc).__name__
        try:
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                return response.status_code, b"", "UnexpectedEncoding"
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > limit:
                    return response.status_code, b"", "ResponseTooLarge"
            return response.status_code, bytes(body), None
        except httpx.HTTPError as exc:
            return response.status_code, b"", type(exc).__name__
        finally:
            response.close()


class ReplyAlerts:
    """`HostAlerts` as a fixed-text reply (the `claudia` token has no alert route).

    Titles are fixed host strings; the reply's own C56 checks still apply.
    """

    def __init__(self, client: ClaudiaAdminClient) -> None:
        self._client = client

    def failed(self, title: str) -> None:
        """Send `Alert (failed): <title>`; never raises (logged by type name)."""
        try:
            self._client.send_reply(ALERT_PREFIX + title, message_id=None)
        except Exception as exc:
            _log.error("failed alert could not be sent (%s)", type(exc).__name__)
