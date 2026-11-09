"""The host's control socket for the risky-action hook (docs/security.md C59, C60).

`ControlSocketServer(gate).start()` binds a Unix socket (mode 0600, in a
directory owned by root and not group/world-writable), accepts only peers
whose `SO_PEERCRED` uid is trusted (root), reads one JSON line per
connection within 5 s and answers with the gate's decision. Oversized,
malformed or slow requests are answered `deny` (or dropped, which the
hook also turns into a deny). Never logs request content.

F-CL3: the same socket carries the `request_approval` tool of the
`claudia-kb` MCP server (`{"v": 1, "approval": {...}}`): the host's approval
flow checks it against the run in progress and answers `pending` + id or
`refused` + a fixed text. Peers are root only, like the hook.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import stat
import struct
import threading
import time
from collections.abc import Collection
from pathlib import Path
from typing import Final, Protocol

from preview_dashboard.application.claudia.approval_flow import ToolAnswer
from preview_dashboard.application.claudia.hook_gate import HookDecision, HookVerdict
from preview_dashboard.interfaces.claudia.hook import (
    DEFAULT_SOCKET_PATH,
    MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
    TIMEOUT_SECONDS,
)

_log = logging.getLogger(__name__)

MAX_CONNECTIONS: Final = 16
_BACKLOG: Final = 16
_UNTRUSTED_DIR_BITS: Final = stat.S_IWGRP | stat.S_IWOTH
_PEERCRED: Final = struct.Struct("3i")
APPROVAL_KEYS: Final = frozenset({"action_kind", "action_target", "reason", "nonce"})
_APPROVAL_FIELD_MAX: Final = 1024


class Decider(Protocol):
    """What the server asks (`HookGate`)."""

    def decide(self, raw: object) -> HookDecision:
        """Answer one forwarded hook call; never raises."""
        ...


class ApprovalRequester(Protocol):
    """What the server asks for `request_approval` (`ApprovalFlow`, F-CL3)."""

    def request_from_tool(
        self, action_kind: object, action_target: object, reason: object, nonce: object
    ) -> ToolAnswer:
        """Open a request for the run in progress, or refuse with a fixed text; never raises.

        `nonce` must be the active run's token (F-CL3b).
        """
        ...


def encode_tool_answer(answer: ToolAnswer) -> bytes:
    """One reply line: `{"result": "pending", "id", "text"}` or `{"result": "refused", "text"}`."""
    body: dict[str, str] = (
        {"result": "pending", "id": answer.approval_id, "text": answer.text}
        if answer.approval_id is not None
        else {"result": "refused", "text": answer.text}
    )
    return (json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8")


_REFUSED_MALFORMED: Final = encode_tool_answer(ToolAnswer(None, "refused: malformed request"))
_REFUSED_OFF: Final = encode_tool_answer(
    ToolAnswer(None, "refused: approvals are not available on this host")
)


def decode_approval(data: dict[str, object]) -> dict[str, object]:
    """The `request_approval` arguments of a decoded request line, incl. the run `nonce`.

    Raises:
        ValueError: not exactly `action_kind`, `action_target`, `reason`, `nonce`
            strings of at most 1024 chars each.
    """
    args = data.get("approval")
    if not isinstance(args, dict) or set(args) != APPROVAL_KEYS:
        raise ValueError("bad approval request")
    if not all(isinstance(v, str) and len(v) <= _APPROVAL_FIELD_MAX for v in args.values()):
        raise ValueError("bad approval request")
    return args


class ControlSocketError(RuntimeError):
    """The socket can't be created safely (untrusted directory, foreign file); refuse."""


def encode_decision(decision: HookDecision) -> bytes:
    """One reply line: `{"decision": "no_decision"}` or `{"decision": "deny", "reason": …}`."""
    if decision.verdict is HookVerdict.NO_DECISION:
        body: dict[str, str] = {"decision": "no_decision"}
    else:
        body = {"decision": "deny", "reason": decision.reason or "denied"}
    return (json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8")


_DENY_MALFORMED: Final = encode_decision(HookDecision.deny("malformed hook request"))


def decode_request(line: bytes) -> object:
    """The forwarded call inside one request line.

    Raises:
        ValueError: not `{"v": 1, "call": {...}}` JSON.
    """
    data = json.loads(line.decode("utf-8"))
    if not isinstance(data, dict) or set(data) != {"v", "call"} or data["v"] != PROTOCOL_VERSION:
        raise ValueError("bad hook request")
    return data["call"]


class ControlSocketServer:
    """Serves hook decisions on a root-only Unix socket (C59).

    Args:
        gate: the decider (`HookGate`).
        path: socket path (the hook's fixed default).
        trusted_uids: peer uids served (root; tests pass their own).
        timeout: per-connection read budget in seconds.
        approvals: answers `request_approval` (F-CL3); None refuses it.
    """

    def __init__(
        self,
        gate: Decider,
        path: Path = DEFAULT_SOCKET_PATH,
        *,
        trusted_uids: Collection[int] = (0,),
        timeout: float = TIMEOUT_SECONDS,
        approvals: ApprovalRequester | None = None,
    ) -> None:
        self._gate = gate
        self._approvals = approvals
        self._path = path
        self._trusted = frozenset(trusted_uids)
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._closed = threading.Event()

    @property
    def path(self) -> Path:
        """Where the socket listens."""
        return self._path

    def start(self) -> None:
        """Bind (0600) and serve in a daemon thread.

        Raises:
            ControlSocketError: the directory is missing or untrusted, or a
                non-socket file sits at `path`.
        """
        self._check_dir()
        self._remove_stale()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)  # no window where the socket is group/world-accessible
        try:
            sock.bind(str(self._path))
        finally:
            os.umask(old)
        os.chmod(self._path, 0o600)
        sock.listen(_BACKLOG)
        self._sock = sock
        self._thread = threading.Thread(target=self._serve, name="claudia-hook-socket", daemon=True)
        self._thread.start()
        _log.info("hook control socket listening")

    def close(self) -> None:
        """Stop serving and remove the socket file."""
        self._closed.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
        with contextlib.suppress(FileNotFoundError):
            if stat.S_ISSOCK(os.lstat(self._path).st_mode):
                os.unlink(self._path)
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _check_dir(self) -> None:
        parent = self._path.parent
        try:
            st = os.lstat(parent)
        except OSError:
            raise ControlSocketError(f"socket directory {parent} is missing") from None
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in self._trusted:
            raise ControlSocketError(f"socket directory {parent} is not trusted")
        if st.st_mode & _UNTRUSTED_DIR_BITS:
            raise ControlSocketError(f"socket directory {parent} is group/world-writable")

    def _remove_stale(self) -> None:
        try:
            st = os.lstat(self._path)
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(st.st_mode):
            raise ControlSocketError(f"{self._path} exists and is not a socket")
        os.unlink(self._path)

    def _serve(self) -> None:
        assert self._sock is not None  # noqa: S101  # nosec B101 - set by start()
        while not self._closed.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                if self._closed.is_set():
                    return
                continue
            if not self._slots.acquire(blocking=False):
                conn.close()  # too many at once: the hook denies on its own
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            with conn:
                if not self._peer_trusted(conn):
                    _log.warning("hook socket: untrusted peer refused")
                    return
                conn.settimeout(self._timeout)
                line = self._read_line(conn)
                reply = _DENY_MALFORMED if line is None else self._answer(line)
                conn.sendall(reply)
        except OSError as exc:
            _log.warning("hook socket: connection failed (%s)", type(exc).__name__)
        finally:
            self._slots.release()

    def _peer_trusted(self, conn: socket.socket) -> bool:
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size)
        except OSError:
            return False
        _pid, uid, _gid = _PEERCRED.unpack(raw)
        return uid in self._trusted

    def _read_line(self, conn: socket.socket) -> bytes | None:
        # One overall budget, so a trickling peer can't hold a slot past it.
        deadline = time.monotonic() + self._timeout
        data = b""
        while b"\n" not in data:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            conn.settimeout(left)
            chunk = conn.recv(65536)
            if not chunk:
                return None
            data += chunk
            if len(data) > MAX_REQUEST_BYTES:
                return None
        line, _, _ = data.partition(b"\n")
        return line

    def _answer(self, line: bytes) -> bytes:
        try:
            data = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return _DENY_MALFORMED
        if isinstance(data, dict) and "approval" in data:
            return self._approval(data)
        try:
            call = decode_request(line)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return _DENY_MALFORMED
        return encode_decision(self._gate.decide(call))

    def _approval(self, data: dict[str, object]) -> bytes:
        """F-CL3 `request_approval`: strict shape, then the flow decides (never raises)."""
        if set(data) != {"v", "approval"} or data["v"] != PROTOCOL_VERSION:
            return _REFUSED_MALFORMED
        try:
            args = decode_approval(data)
        except ValueError:
            return _REFUSED_MALFORMED
        if self._approvals is None:
            return _REFUSED_OFF
        answer = self._approvals.request_from_tool(
            args["action_kind"], args["action_target"], args["reason"], args["nonce"]
        )
        _log.info("request_approval: %s", "pending" if answer.pending else "refused")
        return encode_tool_answer(answer)


__all__ = [
    "APPROVAL_KEYS",
    "ApprovalRequester",
    "ControlSocketError",
    "ControlSocketServer",
    "Decider",
    "decode_approval",
    "decode_request",
    "encode_decision",
    "encode_tool_answer",
]
