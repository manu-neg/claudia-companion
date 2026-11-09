"""The PreToolUse hook command `preview-dashboard-claudia-hook` (docs/security.md C59, C60).

Claude Code runs it before every tool call of a Claudia run (matcher `*`;
the host denies tools it does not know), with the hook JSON on stdin. It
forwards a trimmed copy of the call to the host over the root 0600
control socket (5 s budget) and prints only a `deny` answer, or nothing
(exit 0) so the permission guard decides. It never grants. Any failure
(bad input, host down, timeout, odd reply, crash) is a deny: exit 2
(Claude Code blocks on it) plus the deny JSON. Stdlib only, so it starts
fast and cannot break on a heavy import. File content is never forwarded:
only whether it references the dashboard's MCP server / CLI / admin socket
(F-CL1, `dashboard_bypass`).
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import stat
import sys
import time
from collections.abc import Collection, Mapping
from pathlib import Path
from types import FrameType
from typing import BinaryIO, Final, TextIO

DEFAULT_SOCKET_PATH: Final = Path("/run/claudia-host/hook.sock")
PROTOCOL_VERSION: Final = 1
TIMEOUT_SECONDS: Final = 5.0
# Hard stop well under the 10 s hook timeout in the settings file: a hook
# that Claude Code times out counts as a non-blocking error (fail open).
ALARM_SECONDS: Final = 8
MAX_STDIN_BYTES: Final = 64 * 1024 * 1024
MAX_REQUEST_BYTES: Final = 512 * 1024
MAX_REPLY_BYTES: Final = 4096
MAX_COMMAND_CHARS: Final = 256 * 1024
# Only the start of a peer message matters (the prefix check, C60).
MESSAGE_HEAD_CHARS: Final = 512
EXIT_DENY: Final = 2

# Input keys forwarded to the host; large ones (file content) stay here.
FORWARDED_KEYS: Final = frozenset(
    {"command", "file_path", "notebook_path", "to", "message", "item_id", "keep"}
)
_TOP_KEYS: Final = ("session_id", "cwd", "hook_event_name", "tool_name")
_REASON_RE: Final = re.compile(r"[A-Za-z0-9_ :,./()-]{1,160}")
# F-CL1: file content stays here; only whether it references the dashboard's
# MCP server / CLI / venv / admin socket goes to the host. Equal to
# `domain.dashboard_bypass.REFERENCE_PATTERN` (test): this module stays stdlib-only.
CONTENT_REFERENCE_PATTERN: Final = (
    r"preview-dashboard-mcp"
    r"|/opt/preview-dashboard/\.venv/bin\b(?!/preview-dashboard-claudia-hook\b)"
    r"|/run/preview-dashboard\b"
    r"|/etc/preview-dashboard/[\w.-]*\.(?:token|secret)\b"
    r"|\badmin\.sock\b"
    r"|(?:-m\s*|\bimport\s+|\bfrom\s+)preview_dashboard\b"
    r"|\bpreview_dashboard\.interfaces\b"
    r"|\bdashboard_(?:notify|ask|wait_answer|cancel_question)\b"
    r"|preview-dashboard[\"',\s\]]+(?:notify|question|ask)\b"
)
_CONTENT_REFERENCE_RE: Final = re.compile(CONTENT_REFERENCE_PATTERN, re.IGNORECASE)
CONTENT_KEYS: Final = ("content", "new_string", "new_source")
WRITES_REFERENCE_KEY: Final = "writes_dashboard_reference"


def _written_texts(tool_input: Mapping[str, object]) -> list[str]:
    """The texts a file write would put on disk (Write, Edit, NotebookEdit, MultiEdit)."""
    texts = [v for k in CONTENT_KEYS if isinstance(v := tool_input.get(k), str)]
    edits = tool_input.get("edits")  # MultiEdit
    if isinstance(edits, list):
        for edit in edits:
            text = edit.get("new_string") if isinstance(edit, dict) else None
            if isinstance(text, str):
                texts.append(text)
    return texts


REASON_BAD_INPUT: Final = "hook input unreadable"
REASON_HOST_DOWN: Final = "Claudia host unreachable"
REASON_BAD_REPLY: Final = "Claudia host reply unreadable"
REASON_CRASH: Final = "hook failed"


class HookDeniedError(Exception):
    """Internal: stop and deny with this fixed reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def deny_output(reason: str) -> str:
    """The PreToolUse deny JSON (the only decision this hook ever prints)."""
    body = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"Claudia hook: {reason}",
        }
    }
    return json.dumps(body, separators=(",", ":"))


def trim_call(raw: bytes) -> dict[str, object]:
    """Parse the hook input and keep only what the host needs.

    Raises:
        HookDeniedError: not a JSON object, a forwarded value of the wrong
            type, or a command over `MAX_COMMAND_CHARS`.
    """
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise HookDeniedError(REASON_BAD_INPUT) from None
    if not isinstance(data, dict):
        raise HookDeniedError(REASON_BAD_INPUT)
    call: dict[str, object] = {k: data[k] for k in _TOP_KEYS if k in data}
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        raise HookDeniedError(REASON_BAD_INPUT)
    kept: dict[str, object] = {}
    for key in FORWARDED_KEYS & tool_input.keys():
        value = tool_input[key]
        if isinstance(value, bool) or not isinstance(value, str | int):
            raise HookDeniedError(REASON_BAD_INPUT)
        if key == "message" and isinstance(value, str):
            value = value[:MESSAGE_HEAD_CHARS]
        elif isinstance(value, str) and len(value) > MAX_COMMAND_CHARS:
            raise HookDeniedError(REASON_BAD_INPUT)
        kept[key] = value
    # Computed here, never copied from the input (not in FORWARDED_KEYS).
    if any(_CONTENT_REFERENCE_RE.search(text) for text in _written_texts(tool_input)):
        kept[WRITES_REFERENCE_KEY] = True
    call["tool_input"] = kept
    return call


def _check_socket(path: Path, trusted_uids: Collection[int]) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        raise HookDeniedError(REASON_HOST_DOWN) from None
    # A socket someone else made could answer for the host: refuse it.
    if not stat.S_ISSOCK(st.st_mode) or st.st_uid not in trusted_uids:
        raise HookDeniedError(REASON_HOST_DOWN)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise HookDeniedError(REASON_HOST_DOWN)


def ask_host(
    call: Mapping[str, object],
    socket_path: Path,
    *,
    trusted_uids: Collection[int],
    timeout: float = TIMEOUT_SECONDS,
) -> bytes:
    """Send one call to the host and return its raw reply line.

    Raises:
        HookDeniedError: socket untrusted or unreachable, request too big, no
            full reply within `timeout` seconds overall.
    """
    request = json.dumps({"v": PROTOCOL_VERSION, "call": call}, separators=(",", ":")) + "\n"
    payload = request.encode("utf-8")
    if len(payload) > MAX_REQUEST_BYTES:
        raise HookDeniedError(REASON_BAD_INPUT)
    _check_socket(socket_path, trusted_uids)
    deadline = time.monotonic() + timeout
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(str(socket_path))
            conn.sendall(payload)
            reply = b""
            while b"\n" not in reply:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise HookDeniedError(REASON_HOST_DOWN)
                conn.settimeout(left)
                chunk = conn.recv(MAX_REPLY_BYTES)
                if not chunk:
                    break
                reply += chunk
                if len(reply) > MAX_REPLY_BYTES:
                    raise HookDeniedError(REASON_BAD_REPLY)
    except OSError:
        raise HookDeniedError(REASON_HOST_DOWN) from None
    return reply


def read_reply(reply: bytes) -> str | None:
    """None for the host's `no_decision`; else the deny reason.

    Raises:
        HookDeniedError: anything but exactly one of the two known answers.
    """
    line, newline, _ = reply.partition(b"\n")
    if not newline:
        raise HookDeniedError(REASON_BAD_REPLY)
    try:
        data = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise HookDeniedError(REASON_BAD_REPLY) from None
    if data == {"decision": "no_decision"}:
        return None
    if isinstance(data, dict) and set(data) == {"decision", "reason"}:
        reason = data["reason"]
        if data["decision"] == "deny" and isinstance(reason, str) and _REASON_RE.fullmatch(reason):
            return reason
    raise HookDeniedError(REASON_BAD_REPLY)


def run(
    stdin: BinaryIO,
    stdout: TextIO,
    stderr: TextIO,
    *,
    socket_path: Path = DEFAULT_SOCKET_PATH,
    trusted_uids: Collection[int] = (0,),
    timeout: float = TIMEOUT_SECONDS,
) -> int:
    """Run the hook once; return the exit code (0 = no decision, 2 = deny)."""
    try:
        raw = stdin.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            raise HookDeniedError(REASON_BAD_INPUT)
        reply = ask_host(trim_call(raw), socket_path, trusted_uids=trusted_uids, timeout=timeout)
        reason = read_reply(reply)
    except HookDeniedError as denied:
        reason = denied.reason
    except BaseException:
        # Any crash must still block: a non-2 exit would let the call through.
        reason = REASON_CRASH
    if reason is None:
        return 0
    stdout.write(deny_output(reason) + "\n")
    stdout.flush()
    stderr.write(f"Claudia hook: {reason}\n")
    stderr.flush()
    return EXIT_DENY


def _on_alarm(_signum: int, _frame: FrameType | None) -> None:
    raise HookDeniedError(REASON_HOST_DOWN)


def main(argv: list[str] | None = None) -> int:
    """Console-script entry; `--socket PATH` only for tests (the settings file passes none)."""
    try:
        args = sys.argv[1:] if argv is None else argv
        socket_path = DEFAULT_SOCKET_PATH
        if args[:1] == ["--socket"] and len(args) == 2:
            socket_path = Path(args[1])
        elif args:
            raise HookDeniedError(REASON_BAD_INPUT)
        signal.signal(signal.SIGALRM, _on_alarm)
        signal.alarm(ALARM_SECONDS)
        code = run(sys.stdin.buffer, sys.stdout, sys.stderr, socket_path=socket_path)
        signal.alarm(0)
    except BaseException:
        sys.stdout.write(deny_output(REASON_CRASH) + "\n")
        code = EXIT_DENY
    return code


if __name__ == "__main__":
    sys.exit(main())
