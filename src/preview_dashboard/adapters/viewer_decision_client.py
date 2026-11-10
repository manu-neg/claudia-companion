"""AdminDecisionClient: the `ApprovalDecider` port over the admin Unix socket (viewer side, F-CL6).

Talks only to `POST /v1/viewer/approvals/{id}/decision` with the scoped
viewer token (ADR 0043), in the format of `wire/viewer_decisions.py`. The
socket is re-checked before every call (`socket_check`, injected by the
composition root: a replaced or foreign socket never gets the token or a
code). The token lives only in the client's default headers (never logged
or repr'd); proxies/env are ignored; responses are size-bounded and parsed
strictly. Any failure is a `StorageUnavailableError` with a fixed message:
the viewer decides nothing on its own (fail closed).
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Final

import httpx

from preview_dashboard.domain.approval_decisions import DecisionCommand, DecisionResult
from preview_dashboard.domain.errors import StorageUnavailableError, ValidationError
from preview_dashboard.wire import viewer_decisions as wire

_BASE_URL: Final = "http://admin.local"
MAX_RESPONSE_BYTES: Final = 4096
# The admin checks one code under its step-up lock; a few seconds at most.
_TIMEOUT: Final = httpx.Timeout(connect=3.0, read=15.0, write=5.0, pool=5.0)
_UNAVAILABLE: Final = "approval decisions are unavailable right now"

_log = logging.getLogger("preview_dashboard.viewer.decisions")


class AdminDecisionClient:
    """Blocking client of the admin's viewer route (thread-safe: one call at a time).

    Args:
        socket_path: the admin Unix socket.
        token: the viewer token (from the C12 file loader).
        socket_check: called with `socket_path` before every request; must
            raise if the socket can't be trusted (production:
            `verify_admin_socket`). None only in tests with a fake transport.
        transport: override the transport (tests); default httpx over UDS.
    """

    def __init__(
        self,
        socket_path: Path,
        token: bytes,
        *,
        socket_check: Callable[[Path], object] | None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._socket_path = socket_path
        self._check = socket_check
        self._http = httpx.Client(
            transport=transport or httpx.HTTPTransport(uds=str(socket_path), trust_env=False),
            base_url=_BASE_URL,
            timeout=_TIMEOUT,
            headers={b"Authorization": b"Bearer " + token, b"Accept-Encoding": b"identity"},
            follow_redirects=False,
            trust_env=False,
        )
        # Serialize: a code is checked once, in order, never interleaved.
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "AdminDecisionClient()"  # never expose headers (the token)

    def close(self) -> None:
        """Close the connection pool. Idempotent."""
        self._http.close()

    def decide(self, command: DecisionCommand) -> DecisionResult:
        """Forward one decision; return the admin's verdict.

        Raises:
            StorageUnavailableError: socket untrusted, transport error,
                non-200, oversized or malformed answer (fixed message, no detail).
        """
        with self._lock:
            if self._check is not None:
                try:
                    self._check(self._socket_path)
                except Exception as exc:
                    _log.warning("admin socket not trusted for decisions (%s)", type(exc).__name__)
                    raise StorageUnavailableError(_UNAVAILABLE) from None
            status, raw = self._exchange(command)
        if status != 200:
            _log.warning("admin refused a dashboard decision: status %d", status)
            raise StorageUnavailableError(_UNAVAILABLE)
        try:
            return wire.parse_decision_result(json.loads(raw))
        except (ValueError, RecursionError, ValidationError):
            _log.warning("admin sent a malformed decision verdict")
            raise StorageUnavailableError(_UNAVAILABLE) from None

    def _exchange(self, command: DecisionCommand) -> tuple[int, bytes]:
        request = self._http.build_request(
            "POST",
            wire.decision_path(command.approval_id),
            json=wire.decision_request_to_json(command),
        )
        try:
            response = self._http.send(request, stream=True)
        except httpx.HTTPError as exc:
            _log.warning("admin unreachable for a dashboard decision (%s)", type(exc).__name__)
            raise StorageUnavailableError(_UNAVAILABLE) from None
        try:
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise StorageUnavailableError(_UNAVAILABLE)
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    raise StorageUnavailableError(_UNAVAILABLE)
            return response.status_code, bytes(body)
        except httpx.HTTPError as exc:
            _log.warning("admin answer for a dashboard decision broke (%s)", type(exc).__name__)
            raise StorageUnavailableError(_UNAVAILABLE) from None
        finally:
            response.close()
