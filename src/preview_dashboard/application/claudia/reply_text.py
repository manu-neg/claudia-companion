"""Make Claudia's run output a valid `reply` text before the host posts it (F-CL1 item 4, C56).

The admin refuses (400) a reply over 4096 UTF-16 units, blank, with a
control/invisible char other than a newline, or with a web address
(`application.replies.validate_reply_text`). Her model output can be any of
these (tabs, CRLF, emoji counted twice by Telegram, a GitHub link), so the
host normalizes it here: newlines unified, tabs to spaces, forbidden chars
removed, links defanged (`host[.]tld/…`, scheme dropped), cut to the limit.
The admin's checks are unchanged; this only makes the first attempt pass.
Framework-free; never logs text.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from preview_dashboard.application.replies import REPLY_MAX_CHARS, validate_reply_text
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import utf16_length
from preview_dashboard.domain.text import reject_links, strip_forbidden, trim_cut_end

_KEEP: Final = frozenset({"\n"})
_ELLIPSIS: Final = "\N{HORIZONTAL ELLIPSIS}"
# CR, LINE SEPARATOR, PARAGRAPH SEPARATOR -> newline; TAB -> spaces (code points, not literals).
_NEWLINES: Final = str.maketrans({0x0D: "\n", 0x2028: "\n", 0x2029: "\n", 0x09: "    "})
# Ideographic / fullwidth / halfwidth full stops count as dots for the admin's link check.
_IDEOGRAPHIC_DOTS: Final = str.maketrans({0x3002: ".", 0xFF0E: ".", 0xFF61: "."})
_DEFANG_PASSES: Final = 4
# The admin's link indicators (domain/text.py), each with the spot to break.
_WEB_SCHEME_RE: Final = re.compile(r"https?://", re.IGNORECASE)
_SCHEME_SEP: Final = "://"
_WWW_RE: Final = re.compile(r"www\.", re.IGNORECASE)
_HOST_RE: Final = re.compile(r"([\w-]{1,63})\.([^\W\d_]{2,63}(?::[0-9]{1,5})?/)")
_IPV4_RE: Final = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){2})\.([0-9]{1,3}(?::[0-9]{1,5})?/)")


def _has_link(text: str) -> bool:
    try:
        reject_links(text, name="reply text")
    except ValidationError:
        return True
    return False


def _defang_once(text: str) -> str:
    text = _WEB_SCHEME_RE.sub("", text)  # `https://github.com/x` reads fine as `github[.]com/x`
    text = text.replace(_SCHEME_SEP, ": //")
    text = _WWW_RE.sub(lambda m: m.group(0)[:-1] + "[.]", text)
    text = _HOST_RE.sub(r"\1[.]\2", text)
    return _IPV4_RE.sub(r"\1[.]\2", text)


def defang_links(text: str) -> str:
    """`text` with every web-address shape the admin refuses broken up (`[.]`, no scheme).

    Look-alike forms (fullwidth, ideographic dots) that survive a plain pass
    are NFKC-casefolded first, the way the admin compares them.
    """
    for _ in range(_DEFANG_PASSES):
        if not _has_link(text):
            return text
        text = _defang_once(text)
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_IDEOGRAPHIC_DOTS)
    for _ in range(_DEFANG_PASSES):
        if not _has_link(folded):
            break
        folded = _defang_once(folded)
    return folded


def clip_utf16(text: str, limit: int = REPLY_MAX_CHARS) -> str:
    """Cut `text` to `limit` UTF-16 units (Telegram's count), marking the cut with an ellipsis."""
    if utf16_length(text) <= limit:
        return text
    budget = limit - utf16_length(_ELLIPSIS)
    out: list[str] = []
    used = 0
    for ch in text:
        size = utf16_length(ch)
        if used + size > budget:
            break
        out.append(ch)
        used += size
    # A joiner or selector whose partner was cut off would break the policy.
    return trim_cut_end("".join(out)) + _ELLIPSIS


def prepare_reply_text(raw: str) -> str | None:
    """`raw` made into a text the admin's reply checks accept; None if nothing is left.

    Steps: `\\r\\n`/`\\r`/line separators -> `\\n`, tabs -> spaces, forbidden
    chars removed, links defanged, cut to 4096 UTF-16 units, cleaned again
    (the cut can strand a joiner), then checked with the admin's own rule.
    """
    text = strip_forbidden(raw.replace("\r\n", "\n").translate(_NEWLINES), keep=_KEEP)
    text = strip_forbidden(defang_links(text), keep=_KEEP)  # NFKC may surface new chars
    text = strip_forbidden(clip_utf16(text.strip()), keep=_KEEP).strip()
    if not text:
        return None
    try:
        validate_reply_text(text)
    except ValidationError:
        return None  # not fixable here: the host sends its fixed fallback text
    return text


__all__ = ["clip_utf16", "defang_links", "prepare_reply_text"]
