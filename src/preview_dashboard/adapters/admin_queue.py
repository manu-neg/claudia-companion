"""AdminDeliveryQueue: the `DeliveryQueue` port over the admin Unix socket (notifier side).

Talks only to the `/notifier/*` routes with the scoped notifier token
(C33), in the JSON format of `wire/notifier.py` (tasks, answers) and
`wire/notifier_messages.py` (owner messages, approval taps, codes). The token lives
only in the client's default headers (never logged or repr'd, C36); proxies
and env are ignored; responses are size-bounded and re-validated by the
domain types before the notifier acts on them.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Final

import httpx

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import PendingTask, TaskId
from preview_dashboard.domain.questions import AnswerResult
from preview_dashboard.wire import notifier as wire
from preview_dashboard.wire import notifier_messages as wm

_BASE_URL: Final = "http://admin.local"
# Tasks are small (<= 20 x a 300-char message): anything bigger is refused.
MAX_RESPONSE_BYTES: Final = 512 * 1024
# A voice note is at most 1 MiB (`events.voice`); a little slack for nothing else.
MAX_VOICE_RESPONSE_BYTES: Final = 1024 * 1024 + 1024
# Headroom on top of the server-side long-poll before the read times out.
LONG_POLL_MARGIN: Final = 15.0
_TIMEOUT: Final = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0)
_ERROR_CODE_RE = re.compile(r"[a-z_]{1,32}")

_log = logging.getLogger(__name__)


class AdminQueueError(RuntimeError):
    """A `/notifier/*` call failed; `str()` names the route family and status only.

    Attributes:
        status: HTTP status, or None if no (usable) response was received.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AdminDeliveryQueue:
    """Blocking client of the admin API's notifier routes.

    Args:
        socket_path: the admin Unix socket (verify it before, see
            `interfaces/mcp/admin_socket.verify_admin_socket`).
        token: the notifier token (from the C12 file loader).
        limit: tasks per fetch (1..20).
        transport: override the transport (tests); default httpx over UDS.
    """

    def __init__(
        self,
        socket_path: Path,
        token: bytes,
        *,
        limit: int = wire.MAX_TASKS_LIMIT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not 1 <= limit <= wire.MAX_TASKS_LIMIT:
            raise ValueError(f"limit must be 1..{wire.MAX_TASKS_LIMIT}")
        self._limit = limit
        self._http = httpx.Client(
            # trust_env on the transport too: the client's flag doesn't reach it.
            transport=transport or httpx.HTTPTransport(uds=str(socket_path), trust_env=False),
            base_url=_BASE_URL,
            timeout=_TIMEOUT,
            headers={b"Authorization": b"Bearer " + token, b"Accept-Encoding": b"identity"},
            follow_redirects=False,
            trust_env=False,  # the socket only: no proxies/netrc from env
        )

    def __repr__(self) -> str:
        return "AdminDeliveryQueue()"  # never expose headers (the token)

    def close(self) -> None:
        """Close the connection pool. Idempotent."""
        self._http.close()

    # --- DeliveryQueue ----------------------------------------------------------------

    def pending(self, wait: float) -> list[PendingTask]:
        """`GET /notifier/tasks?wait=&limit=`; malformed tasks are reported failed and skipped.

        Raises:
            AdminQueueError: transport error, non-200, or a malformed envelope.
        """
        seconds = max(0, min(int(wait), wire.MAX_WAIT_SECONDS))
        request = self._http.build_request(
            "GET",
            wire.TASKS_PATH,
            params={"wait": str(seconds), "limit": str(self._limit)},
            timeout=httpx.Timeout(
                connect=5.0, read=seconds + LONG_POLL_MARGIN, write=10.0, pool=10.0
            ),
        )
        body = self._send(request, "tasks")
        try:
            raw_tasks = wire.parse_tasks_envelope(body)
        except ValidationError:
            raise AdminQueueError("admin API tasks: malformed response") from None
        tasks: list[PendingTask] = []
        for raw in raw_tasks:
            try:
                tasks.append(wire.parse_task(raw))
            except ValidationError:
                self._reject(raw)
        return tasks

    def done(self, task_id: TaskId, message_ref: str | None) -> None:
        """`POST /notifier/tasks/{id}/done`; a task gone meanwhile (404) is ignored.

        Raises:
            AdminQueueError: transport error or another non-200 status.
        """
        self._report(wire.task_done_path(task_id), wire.done_request_to_json(message_ref))

    def failed(self, task_id: TaskId) -> None:
        """`POST /notifier/tasks/{id}/failed`; a task gone meanwhile (404) is ignored.

        Raises:
            AdminQueueError: transport error or another non-200 status.
        """
        self._report(wire.task_failed_path(task_id), wire.failed_request_to_json())

    def submit_answer(
        self, question_id: str, key: str, source: str, actor_ref: str
    ) -> AnswerResult:
        """`POST /notifier/answers`; returns the admin's verdict.

        Raises:
            AdminQueueError: transport error, non-200, or a malformed verdict.
        """
        body = wire.answer_request_to_json(
            wire.AnswerSubmission(
                question_id=question_id, key=key, source=source, actor_ref=actor_ref
            )
        )
        reply = self._send(
            self._http.build_request("POST", wire.ANSWERS_PATH, json=body), "answers"
        )
        try:
            return wire.parse_answer_result(reply)
        except ValidationError:
            raise AdminQueueError("admin API answers: malformed response") from None

    # --- owner updates (C44, C46, C47; wire/notifier_messages.py) -----------------------

    def submit_message(self, submission: wm.MessageSubmission) -> wm.MessageResult:
        """`POST /notifier/messages`: store one owner text in the inbox (idempotent).

        Raises:
            AdminQueueError: transport error, non-200 (`status` set), or a
                malformed verdict.
        """
        reply = self._post(wm.MESSAGES_PATH, wm.message_request_to_json(submission), "messages")
        try:
            return wm.parse_message_result(reply)
        except ValidationError:
            raise AdminQueueError("admin API messages: malformed response") from None

    def submit_approval_tap(self, submission: wm.ApprovalTapSubmission) -> wm.TapResult:
        """`POST /notifier/approvals`: record one Approve/Deny tap; returns the verdict.

        Raises:
            AdminQueueError: transport error, non-200, or a malformed verdict.
        """
        reply = self._post(
            wm.APPROVALS_PATH, wm.approval_tap_request_to_json(submission), "approvals"
        )
        try:
            return wm.parse_tap_result(reply)
        except ValidationError:
            raise AdminQueueError("admin API approvals: malformed response") from None

    def submit_code(self, submission: wm.CodeSubmission) -> wm.CodeResult:
        """`POST /notifier/codes`: hand one authenticator code to the admin (C47).

        Raises:
            AdminQueueError: transport error, non-200, or a malformed verdict
                (never containing the code).
        """
        reply = self._post(wm.CODES_PATH, wm.code_request_to_json(submission), "codes")
        try:
            return wm.parse_code_result(reply)
        except ValidationError:
            raise AdminQueueError("admin API codes: malformed response") from None

    # --- voice notes (C56; wire/notifier.py) -----------------------------------------------

    def fetch_voice(self, voice_id: str) -> bytes | None:
        """`GET /notifier/voice/{id}`: the stored audio, or None when none waits (404).

        The bytes are checked by the caller (`validate_voice_audio`); here
        only the size is bounded (1 MiB audio cap plus slack).

        Raises:
            ValidationError: `voice_id` is not a ULID.
            AdminQueueError: transport error, wrong content type or another
                non-200 status.
        """
        request = self._http.build_request("GET", wire.voice_path(voice_id))
        status, raw, failure = self._exchange(request, limit=MAX_VOICE_RESPONSE_BYTES)
        if failure is not None:
            raise AdminQueueError(f"admin API voice: request failed ({failure})")
        if status == 404:
            return None
        if status != 200:
            raise AdminQueueError(f"admin API voice: {status}", status=status)
        return raw

    def release_voice(self, voice_id: str) -> None:
        """`POST /notifier/voice/{id}/release`: delete the audio after it was sent.

        Raises:
            ValidationError: `voice_id` is not a ULID.
            AdminQueueError: transport error or a non-200 status.
        """
        self._post(wire.voice_release_path(voice_id), {}, "voice")

    # --- internals ----------------------------------------------------------------------

    def _post(self, path: str, body: dict[str, object], family: str) -> object:
        return self._send(self._http.build_request("POST", path, json=body), family)

    def _reject(self, raw: object) -> None:
        # A task the domain refuses would come back forever: report it failed
        # so the admin's backoff retires it after 8 tries.
        task_id = wire.task_id_of(raw)
        _log.warning("admin sent a malformed task %s; reported failed", task_id or "(no id)")
        if task_id is not None:
            self.failed(task_id)

    def _report(self, path: str, body: dict[str, object]) -> None:
        try:
            self._send(self._http.build_request("POST", path, json=body), "tasks", ok=(200, 204))
        except AdminQueueError as exc:
            if exc.status != 404:
                raise
            _log.warning("task report: task no longer exists; ignored")

    def _send(self, request: httpx.Request, family: str, *, ok: tuple[int, ...] = (200,)) -> object:
        """Send, read at most `MAX_RESPONSE_BYTES`, decode JSON; a status not in `ok` raises."""
        status, raw, failure = self._exchange(request)
        if failure is not None:
            # Raised outside any `except`: nothing chained, only a type name.
            raise AdminQueueError(f"admin API {family}: request failed ({failure})")
        try:
            body = json.loads(raw) if raw else None
        except (ValueError, RecursionError):
            body = None
        if status not in ok:
            fields = body if isinstance(body, dict) else {}
            code = fields.get("error")
            label = code if isinstance(code, str) and _ERROR_CODE_RE.fullmatch(code) else "error"
            raise AdminQueueError(f"admin API {family}: {status} {label}", status=status)
        return body

    def _exchange(
        self, request: httpx.Request, *, limit: int | None = None
    ) -> tuple[int, bytes, str | None]:
        # Read at call time (not a default argument) so the cap can be adjusted in tests.
        cap = MAX_RESPONSE_BYTES if limit is None else limit
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
                if len(body) > cap:
                    return response.status_code, b"", "ResponseTooLarge"
            return response.status_code, bytes(body), None
        except httpx.HTTPError as exc:
            return response.status_code, b"", type(exc).__name__
        finally:
            response.close()
