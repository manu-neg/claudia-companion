"""Detects Claudia tool calls that would reach the owner past the host (F-CL1 item 2, C51/C59).

Her only way to the owner is the run's final reply (C56); the dashboard MCP
server's Telegram tools are disallowed (C51). A run that drives the MCP
server over stdio, the `preview-dashboard` CLI, the installed venv's
programs or the admin socket / token files itself would bypass that, so the
hook denies it as `dashboard_bypass` (never approvable). Bash is checked on
the raw command (inline code such as `python -c` included) **and** on each
lexed word (quotes removed: `preview-dash""board`); the CLI counts as a
program in command position or after a launcher/interpreter, never as a
repo slug (`example-org/preview-dashboard`) or a `cd` target. Edit/Write/
NotebookEdit content (a script run later) never reaches the host: the hook
command scans it with the same `REFERENCE_PATTERN` (kept equal by a test)
and forwards only the verdict, `WRITES_REFERENCE_KEY`. A text match:
advisory against a determined obfuscator (the permission guard and C51 stay
the real boundary). Pure; no I/O.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator, Mapping, Sequence
from typing import Final

from preview_dashboard.domain.shell_lex import ShellSyntaxError, parse_script

DASHBOARD_BYPASS_LABEL: Final = "dashboard_bypass"
CLI_NAME: Final = "preview-dashboard"
# Set by the hook command (never taken from the model's input): the written
# content matched `REFERENCE_PATTERN`.
WRITES_REFERENCE_KEY: Final = "writes_dashboard_reference"

# Anywhere in a command or written content (case-insensitive): the MCP server,
# the install's programs and code, the admin socket, the deploy config (token
# files), the package itself, the Telegram tool names (a hand-made JSON-RPC
# call), the CLI followed by a sub-command that talks to the owner.
# Copied verbatim into interfaces/claudia/hook.py (stdlib-only); a test keeps them equal.
# The host settings file and the hook script are left to `settings_edit` (approvable, C59).
REFERENCE_PATTERN: Final = (
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
_REFERENCE_RE: Final = re.compile(REFERENCE_PATTERN, re.IGNORECASE)
# Words after which the next word is the program that runs.
_LAUNCHERS: Final = frozenset(
    {
        *("sudo", "doas", "env", "xargs", "nohup", "timeout", "exec", "command", "builtin"),
        *("nice", "ionice", "setsid", "stdbuf", "time", "flock", "unbuffer", "chronic"),
        *("uv", "uvx", "pipx", "run", "busybox", "watch", "strace", "systemd-run", "run0"),
        *("then", "do", "else", "!", "{", "("),
    }
)
# Shells and interpreters: `python3 /usr/local/bin/preview-dashboard notify …`.
_INTERPRETER_RE: Final = re.compile(
    r"(?:ba|da|z|k|mk|a|fi|c|tc)?sh|(?:python|pypy|perl|ruby|node|php|lua)[0-9.]*"
)
# Tool -> the input fields whose text gets written to disk (MultiEdit: `edits[].new_string`).
CONTENT_FIELDS: Final[Mapping[str, tuple[str, ...]]] = {
    "Write": ("content",),
    "Edit": ("new_string",),
    "MultiEdit": (),
    "NotebookEdit": ("new_source",),
}


def references_dashboard(text: str) -> bool:
    """True if `text` names the MCP server, venv, admin socket, deploy config or a CLI call."""
    return _REFERENCE_RE.search(text) is not None


def _is_assignment(text: str) -> bool:
    name, eq, _ = text.partition("=")
    return bool(eq) and name.isidentifier()


def _launches(word: str) -> bool:
    name = posixpath.basename(word)
    return name in _LAUNCHERS or _INTERPRETER_RE.fullmatch(name) is not None


def _runs_cli(words: Sequence[str]) -> bool:
    """True if a word of one simple command names the CLI as a program.

    In command position (after assignments), right after a launcher or an
    interpreter, or anywhere in a command that starts with a launcher
    (`sudo -u x preview-dashboard …`: its options are not parsed here).
    """
    start = next((i for i, w in enumerate(words) if not _is_assignment(w)), len(words))
    wrapped = start < len(words) and _launches(words[start])
    for i in range(start, len(words)):
        if posixpath.basename(words[i]).casefold() != CLI_NAME:
            continue
        if i == start or wrapped or _launches(words[i - 1]):
            return True
    return False


def _commands(command: str) -> Iterator[list[str]]:
    try:
        parsed = parse_script(command)
    except ShellSyntaxError:
        return  # the raw scan still ran; the classifier makes it `unknown` anyway
    for cmd in parsed:
        yield [word.text for word in cmd.words] + [target.text for _op, target in cmd.redirects]


def bash_bypasses_dashboard(command: str) -> bool:
    """True if a Bash command may run the dashboard's MCP server, CLI, venv or admin socket."""
    if references_dashboard(command):
        return True
    for words in _commands(command):
        if _runs_cli(words) or any(references_dashboard(text) for text in words):
            return True
    return False


def written_texts(tool_name: str, tool_input: Mapping[str, object]) -> Iterator[str]:
    """The texts an Edit/Write/MultiEdit/NotebookEdit call would write (none for other tools)."""
    for field in CONTENT_FIELDS.get(tool_name, ()):
        value = tool_input.get(field)
        if isinstance(value, str):
            yield value
    if tool_name == "MultiEdit":
        edits = tool_input.get("edits")
        if isinstance(edits, list):
            for edit in edits:
                if isinstance(edit, Mapping):
                    text = edit.get("new_string")
                    if isinstance(text, str):
                        yield text


def content_bypasses_dashboard(tool_name: str, tool_input: Mapping[str, object]) -> bool:
    """True if a file write would put a dashboard reference on disk (a script run later).

    Counts the hook's verdict (`WRITES_REFERENCE_KEY`, the content itself is
    not forwarded) and any content present in `tool_input`.
    """
    if tool_name not in CONTENT_FIELDS:
        return False
    if tool_input.get(WRITES_REFERENCE_KEY) is True:
        return True
    return any(references_dashboard(text) for text in written_texts(tool_name, tool_input))


def is_dashboard_bypass(tool_name: str, tool_input: Mapping[str, object]) -> bool:
    """True for a Bash command or a file write that bypasses the host's reply path (F-CL1)."""
    if tool_name == "Bash":
        command = tool_input.get("command")
        return isinstance(command, str) and bash_bypasses_dashboard(command)
    return content_bypasses_dashboard(tool_name, tool_input)


__all__ = [
    "CLI_NAME",
    "CONTENT_FIELDS",
    "DASHBOARD_BYPASS_LABEL",
    "REFERENCE_PATTERN",
    "WRITES_REFERENCE_KEY",
    "bash_bypasses_dashboard",
    "content_bypasses_dashboard",
    "is_dashboard_bypass",
    "references_dashboard",
    "written_texts",
]
