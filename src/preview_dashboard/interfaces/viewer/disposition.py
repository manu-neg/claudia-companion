"""RFC 6266 `Content-Disposition` values for downloads and inline item bytes (docs/security.md C9).

Filenames come from relpath basenames and item titles, i.e. from untrusted
publishers. The ASCII `filename=` fallback is sanitized so it can never
break out of its quotes or the header (no `"`, `\\`, CR, LF, `;`), and the
real name travels only percent-encoded in `filename*=` (RFC 5987/8187).
"""

from __future__ import annotations

import unicodedata
from typing import Literal
from urllib.parse import quote

DispositionKind = Literal["inline", "attachment"]

FALLBACK_NAME = "download"
MAX_ASCII_NAME = 100
MAX_UTF8_NAME_BYTES = 255
_MAX_EXT = 16
# Printable ASCII that is safe inside a quoted-string and harmless in a file
# name on every OS: no quote/backslash (quoting), no `/` (path), no `;`/`%`
# (header parameter and percent-decoding confusion), no Windows-reserved chars.
_ASCII_UNSAFE = frozenset('"\\/;%:*?<>|')


def _is_unsafe_char(ch: str) -> bool:
    """Control, format (bidi, zero-width), surrogate, private-use or unassigned."""
    return unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _clean_unicode(name: str) -> str:
    """NFC name with separators and invisible/control chars replaced by `_`."""
    name = unicodedata.normalize("NFC", name)
    cleaned = "".join("_" if ch in "/\\" or _is_unsafe_char(ch) else ch for ch in name)
    return cleaned.strip().strip(".")


def _truncate_keep_ext(name: str, limit: int) -> str:
    """Shorten `name` to `limit` characters, keeping a short extension."""
    if len(name) <= limit:
        return name
    dot = name.rfind(".")
    ext = name[dot:] if dot > 0 and len(name) - dot <= _MAX_EXT else ""
    return name[: limit - len(ext)] + ext


def ascii_fallback(filename: str) -> str:
    """Return the sanitized ASCII `filename=` value for `filename`.

    Non-ASCII and unsafe characters become `_`; leading dots and surrounding
    whitespace are dropped (no hidden files); length is bounded to
    `MAX_ASCII_NAME` keeping the extension; never empty (`download`).
    """
    cleaned = _clean_unicode(filename)
    out = "".join(
        ch if 0x20 <= ord(ch) < 0x7F and ch not in _ASCII_UNSAFE else "_" for ch in cleaned
    )
    out = out.strip().lstrip(".").strip()
    out = _truncate_keep_ext(out, MAX_ASCII_NAME)
    return out if out.strip("_") else FALLBACK_NAME


def utf8_name(filename: str) -> str:
    """Return the cleaned Unicode name for `filename*=` (bounded, never empty)."""
    cleaned = _truncate_keep_ext(_clean_unicode(filename).lstrip("."), MAX_UTF8_NAME_BYTES)
    while len(cleaned.encode("utf-8")) > MAX_UTF8_NAME_BYTES:
        cleaned = _truncate_keep_ext(cleaned, len(cleaned) - 1)
    return cleaned or FALLBACK_NAME


def content_disposition(kind: DispositionKind, filename: str) -> str:
    """Return an RFC 6266 `Content-Disposition` header value.

    Example: `attachment; filename="r_sum_.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`.

    Args:
        kind: `inline` or `attachment`.
        filename: the untrusted display name (relpath basename or item title).

    Raises:
        ValueError: `kind` is not `inline`/`attachment`.
    """
    if kind not in ("inline", "attachment"):
        raise ValueError("kind must be 'inline' or 'attachment'")
    # safe="": only ALPHA/DIGIT and "-._~" stay literal, a strict subset of
    # RFC 5987 attr-char, so the value can never contain `"`, `;` or spaces.
    encoded = quote(utf8_name(filename), safe="", encoding="utf-8")
    return f"{kind}; filename=\"{ascii_fallback(filename)}\"; filename*=UTF-8''{encoded}"
