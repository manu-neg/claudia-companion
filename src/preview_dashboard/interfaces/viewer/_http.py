"""Low-level ASGI header helpers shared by the viewer's security middleware.

Header lookups here are strict on purpose: security decisions must never be
made on an ambiguous request, so a duplicated header is an error, not "first wins".
"""

from __future__ import annotations

from collections.abc import Iterable

from starlette.types import Scope


class DuplicateHeaderError(Exception):
    """A header that must appear at most once was sent more than once."""


def header_values(scope: Scope, name: bytes) -> list[bytes]:
    """Return every raw value of header `name` (lowercase bytes) in `scope`."""
    headers: Iterable[tuple[bytes, bytes]] = scope.get("headers", ())
    return [value for key, value in headers if key == name]


def single_header(scope: Scope, name: bytes) -> bytes | None:
    """Return the only value of header `name`, or None when it is absent.

    Raises:
        DuplicateHeaderError: the header appears more than once.
    """
    values = header_values(scope, name)
    if len(values) > 1:
        raise DuplicateHeaderError(name.decode("latin-1"))
    return values[0] if values else None


def media_type_of(content_type: bytes | None) -> str:
    """Return the lowercase `type/subtype` of a Content-Type value ("" if none)."""
    if not content_type:
        return ""
    return content_type.split(b";", 1)[0].strip().decode("latin-1").lower()


def response_header(headers: Iterable[tuple[bytes, bytes]], name: bytes) -> bytes | None:
    """Return the first value of `name` in a response header list (or None)."""
    for key, value in headers:
        if key.lower() == name:
            return value
    return None
