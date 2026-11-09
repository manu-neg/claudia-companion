"""Errors raised by the MCP intake policy, plus safe path display for messages.

`IntakeError` carries a stable machine-readable `code` and a message that is
safe to return to the agent: it names paths relative to their allowed root
(or a basename) and never includes file contents (docs/security.md C10).
"""

from __future__ import annotations

import unicodedata
from enum import StrEnum

from preview_dashboard.domain.errors import DomainError
from preview_dashboard.domain.unicode import BLANK_LOOKALIKES, is_default_ignorable

# Longest path text ever echoed in a message; keeps errors readable and bounded.
_MAX_DISPLAY_CHARS = 300
# Characters that render as nothing or reorder text: escaped so a hostile file
# name can't spoof the error message (bidi overrides, zero-width chars, ...).
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class IntakeErrorCode(StrEnum):
    """Why an intake request was rejected (stable identifiers for MCP mapping)."""

    INVALID_REQUEST = "invalid_request"
    OUTSIDE_ROOTS = "outside_roots"
    DENIED = "denied"
    SYMLINK = "symlink"
    NOT_REGULAR = "not_regular"
    HARDLINK = "hardlink"
    FILESYSTEM_BOUNDARY = "filesystem_boundary"
    NOT_FOUND = "not_found"
    UNREADABLE = "unreadable"
    LIMIT = "limit"
    RELPATH = "relpath"
    DUPLICATE = "duplicate"
    EMPTY = "empty"
    CHANGED = "changed"


class IntakeError(DomainError):
    """An MCP publish request violates the intake policy; nothing is published.

    Attributes:
        code: machine-readable reason (`IntakeErrorCode`).
    """

    def __init__(self, code: IntakeErrorCode, message: str) -> None:
        self.code = code
        super().__init__(message)


def _escape(ch: str) -> str:
    cp = ord(ch)
    return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"


def safe_display(text: str) -> str:
    """Return `text` with invisible/control/bidi characters escaped, truncated.

    Used for every file name echoed in an `IntakeError` message.
    """
    out: list[str] = []
    for ch in text:
        if (
            unicodedata.category(ch) in _ESCAPED_CATEGORIES
            or is_default_ignorable(ch)
            or ch in BLANK_LOOKALIKES
            or ch == "\\"
        ):
            out.append(_escape(ch))
        elif ch == "'":
            # Messages quote names with '...': escape so a name can't close the quote.
            out.append("\\'")
        else:
            out.append(ch)
    shown = "".join(out)
    if len(shown) > _MAX_DISPLAY_CHARS:
        shown = shown[:_MAX_DISPLAY_CHARS] + "..."
    return shown
