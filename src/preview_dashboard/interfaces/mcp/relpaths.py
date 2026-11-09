"""Explain why an intake-derived bundle path fails `validate_relpath`.

The domain validator gives short generic reasons; the publishing agent needs
to know exactly which character or segment broke which rule so it can rename
the file. Names are never auto-renamed: HTML/CSS bundles reference files by
name, so a silent rename would break them.
"""

from __future__ import annotations

import unicodedata

from preview_dashboard.domain.errors import InvalidPathError
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.interfaces.mcp.errors import IntakeError, IntakeErrorCode, safe_display

# Probe wrapper: a lone character is tested between two harmless letters so
# only character-level rules (not segment rules like "only dots") can fire.
_PROBE = "x{}x"
_RENAME_HINT = (
    "Rename it before publishing (files are never renamed automatically, "
    "because other files in the bundle may reference this name)."
)
_NFKC_HINT = (
    " (a compatibility character such as a trademark sign, fullwidth/halfwidth "
    "form or superscript, which some tools silently rewrite)"
)


def _describe_char(ch: str) -> str:
    name = unicodedata.name(ch, "unnamed character")
    shown = safe_display(ch)
    # Only quote the glyph itself when it is visible; the escape is shown otherwise.
    glyph = f" '{shown}'" if shown == ch else ""
    return f"U+{ord(ch):04X} {name}{glyph}"


def _probe(text: str) -> str | None:
    try:
        validate_relpath(text)
    except InvalidPathError as exc:
        return str(exc)
    return None


def explain_relpath_error(relpath: str) -> str | None:
    """Return a human explanation if `relpath` is invalid, else None.

    Order: NFC form, then the first offending character, then the first
    offending segment, then whole-path rules (length, depth).
    """
    overall = _probe(relpath)
    if overall is None:
        return None
    shown = safe_display(relpath)
    if "NFC" in overall:
        return (
            f"path '{shown}' is not NFC-normalized (it uses decomposed accents, "
            "typical of names created on macOS); retype the name with precomposed "
            "characters."
        )
    for ch in relpath:
        if ch == "/":
            continue
        reason = _probe(_PROBE.format(ch))
        if reason is not None:
            hint = _NFKC_HINT if "NFKC" in reason else ""
            return (
                f"path '{shown}' contains {_describe_char(ch)}, "
                f"which is not allowed{hint}: {reason}."
            )
    for segment in relpath.split("/"):
        reason = _probe(segment) if segment else "path has an empty segment"
        if reason is not None:
            return f"path '{shown}': segment '{safe_display(segment)}' is not allowed: {reason}."
    return f"path '{shown}' is not allowed: {overall}."


def check_relpath(relpath: str) -> str:
    """Return `relpath` unchanged if valid; otherwise raise a helpful `IntakeError`.

    Raises:
        IntakeError: code `RELPATH`, naming the rule and character/segment
            that failed and suggesting a rename.
    """
    explanation = explain_relpath_error(relpath)
    if explanation is None:
        return relpath
    raise IntakeError(IntakeErrorCode.RELPATH, f"{explanation} {_RENAME_HINT}")
