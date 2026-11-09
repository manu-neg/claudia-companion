"""Conditional-request helpers (ETag / If-None-Match / If-Range) for viewer routes.

Kept tiny and strict: only entity tags we issued can match, so a client
cannot turn a malformed header into a 304 for someone else's resource.
"""

from __future__ import annotations

import hashlib

from starlette.types import Scope

from preview_dashboard.interfaces.viewer._http import DuplicateHeaderError, header_values


def strong_etag(token: str) -> str:
    """Quote `token` (hex/ASCII, no quotes) as a strong entity tag."""
    return f'"{token}"'


def body_etag(body: bytes) -> str:
    """Strong ETag for an in-memory response body (SHA-256 of the bytes)."""
    return strong_etag(hashlib.sha256(body).hexdigest())


def if_none_match(scope: Scope, etag: str) -> bool:
    """True if the request's `If-None-Match` matches `etag` (answer 304).

    Weak comparison per RFC 9110 (`W/` prefix ignored); `*` matches. Several
    header lines are combined; non-ASCII values never match.
    """
    for raw in header_values(scope, b"if-none-match"):
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            return False
        for candidate in text.split(","):
            tag = candidate.strip()
            if tag == "*":
                return True
            tag = tag.removeprefix("W/")
            if tag == etag:
                return True
    return False


def if_range_allows(scope: Scope, etag: str) -> bool:
    """True unless an `If-Range` header is present and is not our strong `etag`.

    A mismatched (or date-based, or duplicated) `If-Range` means "send the
    whole resource", which is always safe.
    """
    values = header_values(scope, b"if-range")
    if not values:
        return True
    if len(values) > 1:
        return False
    try:
        return values[0].decode("ascii").strip() == etag
    except UnicodeDecodeError:
        return False


def single_range_header(scope: Scope) -> str | None:
    """The `Range` value, or None if absent.

    Raises:
        DuplicateHeaderError: more than one `Range` header (answered with 416).
    """
    values = header_values(scope, b"range")
    if len(values) > 1:
        raise DuplicateHeaderError("range")
    if not values:
        return None
    try:
        return values[0].decode("ascii")
    except UnicodeDecodeError:
        # Non-ASCII can never be a valid range; let parse_range reject it.
        return "\x00"
