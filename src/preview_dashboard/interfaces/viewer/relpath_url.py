"""Relpath <-> URL-path conversion for preview URLs (docs/security.md C7, C20).

The server percent-decodes the relpath tail of a preview URL **exactly once**,
from the raw (still-encoded) request path — never from Starlette's already
decoded `path`, which would be a second decode — and then re-runs
`validate_relpath`. The inverse, `encode_relpath_url`, percent-encodes each
segment for building preview URLs (the frontend does the same with
`encodeURIComponent` per segment).

`RawPathGuardMiddleware` additionally refuses, for every route of both
apps, a raw path containing an encoded `/`, `\\` or `%` anywhere, so the
router's decoded path parameters (e.g. the item id) can never disagree
with the raw path the relpath is taken from.
"""

from __future__ import annotations

import logging
import re
import string
from urllib.parse import quote

from starlette.types import ASGIApp, Receive, Scope, Send

from preview_dashboard.domain.errors import InvalidPathError
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.interfaces.viewer.errors import send_error
from preview_dashboard.interfaces.viewer.request_id import request_id_of

logger = logging.getLogger("preview_dashboard.viewer")

_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
# RFC 3986 pchar minus nothing: what may appear literally in a raw path.
_RAW_ALLOWED = _UNRESERVED | frozenset("!$&'()*+,;=:@%/")
_HEX = frozenset(string.hexdigits)
# Decoded bytes that must never have arrived percent-encoded: `%` (double
# encoding: `%252e` would otherwise become `%2e`), `/` (a segment can never
# contain one, so `%2F` is always a smuggled separator), `\` (Windows
# separator). Encoded unreserved chars (`%2e` for `.`) are non-canonical:
# no encoder we accept produces them.
_NEVER_ENCODED = frozenset(b"%/\\") | frozenset(c.encode("ascii")[0] for c in _UNRESERVED)


def decode_relpath_tail(raw_tail: str) -> str:
    """Percent-decode a raw relpath URL tail once and validate the result.

    Args:
        raw_tail: the still-encoded tail of the request path, e.g.
            `sub/r%C3%A9sum%C3%A9.html`.

    Returns:
        The validated relpath (`validate_relpath` output).

    Raises:
        InvalidPathError: non-ASCII or disallowed raw characters, malformed
            escapes, encoded `%` / `/` / `\\` / unreserved characters,
            invalid UTF-8, or a decoded path `validate_relpath` rejects.
    """
    if not raw_tail.isascii() or any(ch not in _RAW_ALLOWED for ch in raw_tail):
        raise InvalidPathError("URL path contains a disallowed character")
    out = bytearray()
    i = 0
    while i < len(raw_tail):
        ch = raw_tail[i]
        if ch != "%":
            out.append(ord(ch))
            i += 1
            continue
        pair = raw_tail[i + 1 : i + 3]
        if len(pair) != 2 or not set(pair) <= _HEX:
            raise InvalidPathError("URL path has a malformed percent-escape")
        byte = int(pair, 16)
        if byte in _NEVER_ENCODED:
            raise InvalidPathError("URL path has a forbidden percent-escape")
        out.append(byte)
        i += 3
    try:
        decoded = out.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidPathError("URL path is not valid UTF-8") from None
    return validate_relpath(decoded)


def raw_path_tail(scope: Scope, segments: int) -> str:
    """Return the raw (undecoded) request path after its first `segments` segments.

    For `raw_path=b"/p/01ARZ3/sub/a%20b.png"` and `segments=2` this is
    `sub/a%20b.png`. Routes pass this to `decode_relpath_tail`.

    Raises:
        InvalidPathError: no `raw_path` in the scope (never fall back to the
            decoded `path`), non-ASCII bytes, or too few segments.
    """
    raw = scope.get("raw_path")
    if not isinstance(raw, bytes) or not raw.startswith(b"/"):
        raise InvalidPathError("request has no raw path")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise InvalidPathError("URL path is not ASCII") from None
    parts = text[1:].split("/", segments)
    if len(parts) != segments + 1:
        raise InvalidPathError("URL path is too short")
    return parts[-1]


def relpath_from_scope(scope: Scope, segments: int) -> str:
    """`decode_relpath_tail(raw_path_tail(scope, segments))`: the one entry point for routes."""
    return decode_relpath_tail(raw_path_tail(scope, segments))


def encode_relpath_url(relpath: str) -> str:
    """Percent-encode a relpath for use as a URL tail, one segment at a time.

    Only unreserved characters stay literal; segments are joined with a
    literal `/`. `decode_relpath_tail(encode_relpath_url(p)) == p` for
    every valid `p`.

    Raises:
        InvalidPathError: `relpath` is not a valid relpath.
    """
    validate_relpath(relpath)
    return "/".join(quote(segment, safe="", encoding="utf-8") for segment in relpath.split("/"))


# Encoded separators and percent signs: never needed by any viewer URL.
_SMUGGLED_ESCAPE = re.compile(rb"%(2f|5c|25)", re.IGNORECASE)


def raw_path_is_smuggling(scope: Scope) -> bool:
    """True if the raw request path contains `%2F`, `%5C` or `%25` (any case)."""
    raw = scope.get("raw_path")
    return isinstance(raw, bytes) and _SMUGGLED_ESCAPE.search(raw) is not None


class RawPathGuardMiddleware:
    """Answer 400 to any request whose raw path smuggles `/`, `\\` or `%` encoded."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and raw_path_is_smuggling(scope):
            logger.warning("encoded separator in raw path request_id=%s", request_id_of(scope))
            await send_error(scope, send, 400)
            return
        await self._app(scope, receive, send)
