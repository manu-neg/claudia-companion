"""Sanitizing untrusted display text (item titles and descriptions, alert texts).

Titles/descriptions are published by a semi-trusted source (Claude, which
can be prompt-injected) and shown to the owner, so invisible characters
that can spoof what the owner reads (bidi overrides, zero-width chars,
Hangul fillers) or smuggle hidden data (tag chars, variation selectors) or
break layout (control chars) are removed rather than stored. Text that
leaves the host as an alert must also carry no web address (C35).
"""

from __future__ import annotations

import re
import unicodedata

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.unicode import (
    BLANK_LOOKALIKES,
    JOINERS,
    PRESENTATION_SELECTORS,
    is_default_ignorable,
    is_visible,
    takes_joiner,
    takes_presentation_selector,
)

TITLE_MAX_CHARS = 200
DESCRIPTION_MAX_CHARS = 5000

# Raw input longer than this many times the limit is rejected before any
# work: sanitizing may shrink text, but not by more than invisible padding
# could plausibly account for, and it bounds the cost of cleaning.
_RAW_LENGTH_FACTOR = 4

_REMOVED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})

# Alerts are read on a phone with no way to inspect them: blank look-alikes
# (braille blank ...) go too, although item titles keep them.
_DROP_BLANK_LOOKALIKES = {ord(ch): None for ch in BLANK_LOOKALIKES}

# Link indicators in outgoing alert text (C35), matched on an NFKC-casefolded
# copy so fullwidth / styled look-alikes count too. Ideographic full stops
# are dots to IDNA (and so to clients that linkify), hence folded to ".".
# Bare file names ("app.js") stay allowed; channels defang them anyway.
_IDEOGRAPHIC_DOTS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_LINK_INDICATORS = (
    re.compile(r"://"),
    re.compile(r"www\."),
    # host.tld/..., host.tld:port/..., 1.2.3.4[:port]/... (bounded runs: linear time).
    re.compile(r"[\w-]{1,63}\.[^\W\d_]{2,63}(?::[0-9]{1,5})?/"),
    re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?::[0-9]{1,5})?/"),
)

# A cut line must not end in a joiner/selector whose partner was cut off.
_DANGLING_END = "".join(sorted(JOINERS | PRESENTATION_SELECTORS))


def _strip_invisible(text: str, keep: frozenset[str]) -> str:
    """Remove control/format/separator and Default_Ignorable chars except `keep`.

    ZWJ/ZWNJ carry meaning only in emoji sequences and complex scripts
    (Arabic/Persian, Indic ...): they are kept only between two chars that
    take a joiner (`takes_joiner`; a kept selector counts as its emoji), so
    never inside ASCII/Latin text, where they would split tokens past the
    secret scan or smuggle data. VS15/VS16 are kept only right after an
    emoji base (`takes_presentation_selector`), one per char.
    """
    out: list[str] = []
    for i, ch in enumerate(text):
        if ch in keep:
            out.append(ch)
            continue
        prev = out[-1] if out else ""
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if ch in JOINERS:
            prev_ok = bool(prev) and (takes_joiner(prev) or prev in PRESENTATION_SELECTORS)
            if prev_ok and nxt and takes_joiner(nxt):
                out.append(ch)
            continue
        if ch in PRESENTATION_SELECTORS:
            if prev and takes_presentation_selector(prev, nxt):
                out.append(ch)
            continue
        if is_default_ignorable(ch) or unicodedata.category(ch) in _REMOVED_CATEGORIES:
            continue
        out.append(ch)
    return "".join(out)


def _check_raw_length(raw: str, limit: int, name: str) -> None:
    if len(raw) > _RAW_LENGTH_FACTOR * limit:
        raise ValidationError(f"{name} must be <= {limit} characters")


def sanitize_line(raw: str, *, name: str, max_chars: int) -> str:
    """Return clean single-line display text of 1..`max_chars` chars.

    Line breaks/tabs become spaces, other control, bidi, Default_Ignorable
    and invisible format characters are removed (ZWJ/ZWNJ and VS15/VS16
    kept only inside emoji / complex-script sequences), the result is
    NFC-normalized and trimmed. Shared by
    titles and the short texts of questions/notifications (ADR 0021).

    Args:
        raw: untrusted text.
        name: field name used in error messages.
        max_chars: upper bound after cleaning (raw input is capped at 4x).

    Raises:
        ValidationError: not a string; raw input over 4x the limit; empty,
            longer than `max_chars`, or without any visible character
            (letter, number, punctuation or symbol) after cleaning.
    """
    if not isinstance(raw, str):
        raise ValidationError(f"{name} must be a string")
    _check_raw_length(raw, max_chars, name)
    text = raw.replace("\r\n", " ").translate({ord("\r"): " ", ord("\n"): " ", ord("\t"): " "})
    text = _clean(text, frozenset())
    if not 1 <= len(text) <= max_chars:
        raise ValidationError(f"{name} must be 1..{max_chars} characters")
    if not any(is_visible(ch) for ch in text):
        raise ValidationError(f"{name} must contain a visible character")
    return text


def reject_links(text: str, *, name: str) -> str:
    """Return `text` unchanged unless it contains a web address.

    Rejects `://`, `www.` and `host.tld/path` shapes (also with a port or
    an IPv4 host), after NFKC-casefolding so look-alike forms count too.
    Used for every field of an outgoing alert (docs/security.md C35).

    Raises:
        ValidationError: a link indicator was found. The message names
            `name` only, never the text.
    """
    folded = unicodedata.normalize("NFKC", text).casefold().translate(_IDEOGRAPHIC_DOTS)
    if any(rule.search(folded) for rule in _LINK_INDICATORS):
        raise ValidationError(f"{name} must not contain links or web addresses")
    return text


def reject_invisible(text: str, *, name: str, keep: frozenset[str] = frozenset()) -> str:
    """Return `text` unchanged unless the outgoing-text policy would remove a char of it.

    The check behind already-sanitized alert text (`MessageContent`, rows
    re-read from the outbox): it applies exactly the policy of
    `sanitize_outgoing_line` (control, bidi, Default_Ignorable, invisible
    format chars and blank look-alikes; ZWJ/ZWNJ allowed only between two
    emoji / complex-script chars, VS15/VS16 only right after an emoji
    base) without changing text.

    Args:
        text: text to check.
        name: field name used in error messages.
        keep: chars exempt from the policy (e.g. `"\\n"` in a message).

    Raises:
        ValidationError: a forbidden char was found. The message names
            `name` only, never the text.
    """
    if any(ch in BLANK_LOOKALIKES for ch in text) or _strip_invisible(text, keep) != text:
        raise ValidationError(f"{name} contains a forbidden character")
    return text


def strip_forbidden(text: str, *, keep: frozenset[str] = frozenset()) -> str:
    """Remove every char `reject_invisible` would refuse (blank look-alikes included).

    The cleaning twin of `reject_invisible` for a sender that must pass it on
    the first try (the Claudia host's replies, F-CL1); repeated until stable,
    since a removal can strand a joiner or selector. No NFC, no trimming.
    """
    text = text.translate(_DROP_BLANK_LOOKALIKES)
    for _ in range(8):
        cleaned = _strip_invisible(text, keep)
        if cleaned == text:
            return text
        text = cleaned
    # Still changing after 8 passes (pathological input): drop every joiner/selector.
    return _strip_invisible(text.translate({ord(c): None for c in _DANGLING_END}), keep)


def sanitize_outgoing_line(raw: str, *, name: str, max_chars: int) -> str:
    """`sanitize_line` minus blank look-alikes, then `reject_links`: one clean alert line.

    Raises:
        ValidationError: see `sanitize_line` and `reject_links`.
    """
    if isinstance(raw, str):
        raw = raw.translate(_DROP_BLANK_LOOKALIKES)
    return reject_links(sanitize_line(raw, name=name, max_chars=max_chars), name=name)


def trim_cut_end(text: str) -> str:
    """Return a cut-off piece of clean text without trailing whitespace, joiners or selectors.

    A ZWJ/ZWNJ/VS15/VS16 whose partner was cut away would break the
    outgoing-text policy (`reject_invisible`), so it goes with the cut.
    """
    while True:
        trimmed = text.rstrip().rstrip(_DANGLING_END)
        if trimmed == text:
            return text
        text = trimmed


def sanitize_title(raw: str) -> str:
    """Return a clean single-line title (`sanitize_line` with the 200-char title limit).

    Raises:
        ValidationError: see `sanitize_line`.
    """
    return sanitize_line(raw, name="title", max_chars=TITLE_MAX_CHARS)


def sanitize_description(raw: str) -> str:
    """Return a clean multi-line description (may be empty).

    Line endings are normalized to `\\n`; `\\n` and `\\t` are kept, every
    other control, bidi, Default_Ignorable and invisible format character is
    removed (ZWJ/ZWNJ and VS15/VS16 kept only inside emoji / complex-script
    sequences); the result is NFC-normalized and trimmed.

    Raises:
        ValidationError: not a string; raw input over 4x the limit; or
            longer than 5000 chars after cleaning.
    """
    if not isinstance(raw, str):
        raise ValidationError("description must be a string")
    _check_raw_length(raw, DESCRIPTION_MAX_CHARS, "description")
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    text = _clean(text, frozenset({"\n", "\t"}))
    if len(text) > DESCRIPTION_MAX_CHARS:
        raise ValidationError(f"description must be <= {DESCRIPTION_MAX_CHARS} characters")
    return text


def _clean(text: str, keep: frozenset[str]) -> str:
    # Strip, normalize, then strip again: NFC can merge a mark into its base
    # and change a joiner's neighbours, and trimming can expose a leading
    # joiner; repeating until stable keeps sanitizing idempotent.
    for _ in range(4):
        cleaned = unicodedata.normalize("NFC", _strip_invisible(text, keep)).strip()
        if cleaned == text:
            break
        text = cleaned
    return text
