"""Strict query-string parsing for viewer routes (fail closed on anything odd).

Each route declares the parameters it accepts; unknown or repeated
parameters are a 400 (`ValidationError`), never silently ignored, so there
is exactly one meaning for every URL.
"""

from __future__ import annotations

from collections.abc import Collection
from urllib.parse import parse_qsl

from starlette.types import Scope

from preview_dashboard.domain.errors import ValidationError

_MAX_QUERY_CHARS = 512


def parse_query(scope: Scope, allowed: Collection[str]) -> dict[str, str]:
    """Return the query parameters of `scope` as a dict.

    Raises:
        ValidationError: non-ASCII/oversized query, malformed pairs, a key
            outside `allowed`, or a repeated key.
    """
    raw = scope.get("query_string", b"")
    if not isinstance(raw, bytes) or len(raw) > _MAX_QUERY_CHARS:
        raise ValidationError("invalid query")
    try:
        text = raw.decode("ascii")
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=bool(text))
    except (UnicodeDecodeError, ValueError):
        raise ValidationError("invalid query") from None
    params: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in params:
            raise ValidationError("invalid query")
        params[key] = value
    return params


def flag(params: dict[str, str], name: str) -> bool:
    """True if `name=1` is present; absent is False; any other value is a 400.

    Raises:
        ValidationError: the flag has a value other than `1`.
    """
    value = params.get(name)
    if value is None:
        return False
    if value != "1":
        raise ValidationError("invalid flag")
    return True
