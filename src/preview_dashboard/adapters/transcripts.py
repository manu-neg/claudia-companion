"""Transcript reader for the peer audit (C52): `SendMessage` calls from Claude Code's JSONL.

Claude Code (not the model) writes each session to
`<projects>/<cwd slug>/<session id>.jsonl` (V5). This adapter reads only
the bytes appended since an offset, bounded in size, opened `O_NOFOLLOW`
(a planted symlink is "incomplete", never followed), and extracts the
`SendMessage` tool calls. Unreadable or oversized input is reported as
incomplete so the audit fails closed. Nothing read here is logged.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Final

from preview_dashboard.domain.approvals import WindowId, parse_window_id
from preview_dashboard.ports.claudia_host import SendMessageCall, TranscriptSlice

MAX_SLICE_BYTES: Final = 16 * 1024 * 1024
MAX_LINE_BYTES: Final = 1024 * 1024
SEND_MESSAGE_TOOL: Final = "SendMessage"
_SLUG_RE = re.compile(r"[^A-Za-z0-9]")
_OPEN_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def project_slug(cwd: Path) -> str:
    """Claude Code's directory name for a cwd: every non-alphanumeric char becomes `-`."""
    return _SLUG_RE.sub("-", str(cwd))


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    # A structured message is hashed as JSON; it can never carry the prefix check.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def send_message_calls(line: object) -> list[SendMessageCall]:
    """The `SendMessage` tool_use blocks of one parsed transcript line."""
    if not isinstance(line, dict) or line.get("type") != "assistant":
        return []
    message = line.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    stamp = line.get("timestamp")
    calls: list[SendMessageCall] = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        if block.get("name") != SEND_MESSAGE_TOOL:
            continue
        args = block.get("input")
        args = args if isinstance(args, dict) else {}
        calls.append(
            SendMessageCall(
                target=_text(args.get("to", "")),
                text=_text(args.get("message", "")),
                summary=_text(args.get("summary", "")),
                timestamp=stamp if isinstance(stamp, str) else None,
            )
        )
    return calls


def parse_slice(data: bytes, start: int) -> TranscriptSlice:
    """Parse complete lines of `data` (read from offset `start`).

    An unterminated last line is left for the next audit (`end_offset`
    stops before it); a line over 1 MiB or invalid JSON counts as malformed.
    """
    calls: list[SendMessageCall] = []
    malformed = 0
    consumed = 0
    for raw in data.splitlines(keepends=True):
        if not raw.endswith(b"\n"):
            break
        consumed += len(raw)
        body = raw.strip()
        if not body:
            continue
        if len(body) > MAX_LINE_BYTES:
            malformed += 1
            continue
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            malformed += 1
            continue
        calls.extend(send_message_calls(parsed))
    return TranscriptSlice(
        calls=tuple(calls), end_offset=start + consumed, malformed_lines=malformed
    )


class JsonlTranscripts:
    """`TranscriptReader` over Claude Code's project transcripts.

    Args:
        projects_dir: `~/.claude/projects` of the user the host runs as.
        workdir: the runs' cwd (selects the project directory).
    """

    def __init__(self, projects_dir: Path, workdir: Path) -> None:
        self._dir = projects_dir / project_slug(workdir)

    def path(self, window_id: WindowId) -> Path:
        """Transcript path of a window (the id is validated: no traversal)."""
        return self._dir / f"{parse_window_id(window_id)}.jsonl"

    def offset(self, window_id: WindowId) -> int:
        """Current transcript size (0 if missing or not a regular file)."""
        try:
            st = os.lstat(self.path(window_id))
        except OSError:
            return 0
        return st.st_size if stat.S_ISREG(st.st_mode) else 0

    def send_messages(self, window_id: WindowId, since: int) -> TranscriptSlice:
        """`SendMessage` calls after byte `since`; never raises."""
        try:
            fd = os.open(self.path(window_id), _OPEN_FLAGS)
        except FileNotFoundError:
            # No transcript: the run never started a session, so nothing was sent.
            return TranscriptSlice(calls=(), end_offset=since)
        except OSError:
            # ELOOP (a planted symlink), EACCES, ...: can't prove nothing was sent.
            return TranscriptSlice(calls=(), end_offset=since, complete=False)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size < since:
                return TranscriptSlice(calls=(), end_offset=since, complete=False)
            if st.st_size - since > MAX_SLICE_BYTES:
                return TranscriptSlice(calls=(), end_offset=st.st_size, complete=False)
            os.lseek(fd, since, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = st.st_size - since
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except OSError:
            return TranscriptSlice(calls=(), end_offset=since, complete=False)
        finally:
            os.close(fd)
        return parse_slice(b"".join(chunks), since)
