"""Client side of Claudia's `request_approval` tool (F-CL3; docs/security.md C46, ADR 0041).

The `claudia-kb` MCP server (caller `claudia` only) exposes the tool and
forwards its three arguments, plus the per-run nonce the host put in the
run's env (`CLAUDIA_RUN_NONCE`, F-CL3b), over the host's root 0600 control
socket (the one the C59 hook uses); the host's approval flow checks them
against the run in progress and opens the request through the admin exactly
like the reply-line path. This module only carries the call: it never creates
a request itself and holds no admin token. Stdlib only.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from preview_dashboard.interfaces.claudia.hook import DEFAULT_SOCKET_PATH, PROTOCOL_VERSION
from preview_dashboard.ports.claudia_host import RUN_NONCE_ENV

# Opening a request is one admin call (prompt queued): longer than a hook decision.
REPLY_TIMEOUT_SECONDS: Final = 20.0
MAX_REPLY_BYTES: Final = 4096
MAX_ARG_CHARS: Final = 1024
HOST_DOWN_TEXT: Final = "refused: the Claudia host could not be reached, so nothing was asked"
BAD_REPLY_TEXT: Final = "refused: the Claudia host answered badly, so nothing was asked"
NO_RUN_TEXT: Final = "refused: this tool only works inside a running Claudia turn"


class ApprovalToolError(Exception):
    """The request was not opened; `text` is what the tool shows her."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


@dataclass(frozen=True, slots=True)
class HostApprovals:
    """Asks the host to open approval requests over its control socket.

    Args:
        socket_path: the host's control socket (fixed default; tests pass their own).
        trusted_uids: owners the socket may have (root).
        timeout: overall budget for one call in seconds.
        environ: where the run's nonce is read from (the server's own env;
            tests pass a dict).
    """

    socket_path: Path = DEFAULT_SOCKET_PATH
    trusted_uids: Collection[int] = (0,)
    timeout: float = REPLY_TIMEOUT_SECONDS
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)

    def request(self, action_kind: str, action_target: str, reason: str) -> str:
        """Ask for one approval; return the host's "pending" text (names the request id).

        Raises:
            ApprovalToolError: the host refused (its fixed text), is down, or
                answered with anything but the two known shapes.
        """
        # The run's token comes from the env the host set for this run (F-CL3b); without
        # it the host would refuse anyway, so fail here with the same fixed kind of text.
        nonce = self.environ.get(RUN_NONCE_ENV, "")
        if not nonce:
            raise ApprovalToolError(NO_RUN_TEXT)
        args = {
            "action_kind": action_kind,
            "action_target": action_target,
            "reason": reason,
            "nonce": nonce,
        }
        if any(len(value) > MAX_ARG_CHARS for value in args.values()):
            raise ApprovalToolError("refused: an argument is too long")
        line = json.dumps({"v": PROTOCOL_VERSION, "approval": args}, separators=(",", ":"))
        reply = self._exchange((line + "\n").encode("utf-8"))
        return read_answer(reply)

    def _exchange(self, payload: bytes) -> bytes:
        self._check_socket()
        deadline = time.monotonic() + self.timeout
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self.timeout)
                conn.connect(str(self.socket_path))
                conn.sendall(payload)
                reply = b""
                while b"\n" not in reply:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise ApprovalToolError(HOST_DOWN_TEXT)
                    conn.settimeout(left)
                    chunk = conn.recv(MAX_REPLY_BYTES)
                    if not chunk:
                        break
                    reply += chunk
                    if len(reply) > MAX_REPLY_BYTES:
                        raise ApprovalToolError(BAD_REPLY_TEXT)
        except OSError:
            raise ApprovalToolError(HOST_DOWN_TEXT) from None
        return reply

    def _check_socket(self) -> None:
        # A socket someone else made could pose as the host (same rule as the hook).
        try:
            st = os.lstat(self.socket_path)
        except OSError:
            raise ApprovalToolError(HOST_DOWN_TEXT) from None
        if not stat.S_ISSOCK(st.st_mode) or st.st_uid not in self.trusted_uids:
            raise ApprovalToolError(HOST_DOWN_TEXT)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ApprovalToolError(HOST_DOWN_TEXT)


def read_answer(reply: bytes) -> str:
    """The pending text of a host answer line.

    Raises:
        ApprovalToolError: `refused` (its text), or anything malformed.
    """
    line, newline, _ = reply.partition(b"\n")
    if not newline:
        raise ApprovalToolError(BAD_REPLY_TEXT)
    try:
        data = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ApprovalToolError(BAD_REPLY_TEXT) from None
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ApprovalToolError(BAD_REPLY_TEXT)
    text = data.get("text")
    if not isinstance(text, str) or not 0 < len(text) <= 1024:
        raise ApprovalToolError(BAD_REPLY_TEXT)
    if set(data) == {"result", "text"} and data["result"] == "refused":
        raise ApprovalToolError(text)
    if set(data) == {"result", "id", "text"} and data["result"] == "pending":
        return text
    raise ApprovalToolError(BAD_REPLY_TEXT)


__all__ = [
    "BAD_REPLY_TEXT",
    "HOST_DOWN_TEXT",
    "REPLY_TIMEOUT_SECONDS",
    "ApprovalToolError",
    "HostApprovals",
    "read_answer",
]
