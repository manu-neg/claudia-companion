"""Strict parsing of a single HTTP `Range: bytes=...` request (docs/security.md C9).

Only one byte range is ever honoured (video seeking needs no more).
Multi-range, other units, whitespace, signs, oversized numbers and
unsatisfiable ranges are all rejected with 416 (fail closed) rather than
guessed at.
"""

from __future__ import annotations

from dataclasses import dataclass

# 19 digits covers every size < 2**63 (domain bound) and keeps int() cheap.
_MAX_DIGITS = 19
_PREFIX = "bytes="


class RangeNotSatisfiableError(Exception):
    """The Range header is malformed, multi-range, or outside the resource.

    Attributes:
        size: the resource size, for `Content-Range: bytes */<size>`.
    """

    def __init__(self, size: int) -> None:
        super().__init__("range not satisfiable")
        self.size = size

    @property
    def content_range(self) -> str:
        """The `Content-Range` value a 416 response must carry."""
        return f"bytes */{self.size}"


@dataclass(frozen=True, slots=True)
class ByteRange:
    """An inclusive, validated byte range `[start, end]` within a resource of `size` bytes."""

    start: int
    end: int
    size: int

    @property
    def length(self) -> int:
        """Number of bytes in the range."""
        return self.end - self.start + 1

    @property
    def content_range(self) -> str:
        """The `Content-Range` value for a 206 response."""
        return f"bytes {self.start}-{self.end}/{self.size}"


def _parse_int(text: str) -> int | None:
    """ASCII digits only (no sign, space, `_` or Unicode digits), bounded length."""
    if not text or len(text) > _MAX_DIGITS or not (text.isascii() and text.isdigit()):
        return None
    return int(text)


def parse_range(header: str | None, size: int) -> ByteRange | None:
    """Parse a `Range` header against a resource of `size` bytes.

    Accepted forms: `bytes=a-b`, `bytes=a-`, `bytes=-n` (suffix). `b` past the
    end is clamped to `size - 1`; a suffix longer than the resource means
    the whole resource.

    Args:
        header: the single `Range` header value, or None if absent.
        size: resource size in bytes (>= 0).

    Returns:
        None when there is no Range header (serve the full resource), else
        the validated range.

    Raises:
        RangeNotSatisfiableError: malformed, multi-range, not `bytes`,
            `a > b`, `a >= size`, a zero-length suffix, or an empty resource.
        ValueError: `size` is negative.
    """
    if size < 0:
        raise ValueError("size must be >= 0")
    if header is None:
        return None
    if not header.startswith(_PREFIX):
        raise RangeNotSatisfiableError(size)
    spec = header[len(_PREFIX) :]
    if "," in spec or spec.count("-") != 1 or size == 0:
        raise RangeNotSatisfiableError(size)
    first, last = spec.split("-")
    if first == "":
        suffix = _parse_int(last)
        if suffix is None or suffix == 0:
            raise RangeNotSatisfiableError(size)
        return ByteRange(start=max(0, size - suffix), end=size - 1, size=size)
    start = _parse_int(first)
    end = size - 1 if last == "" else _parse_int(last)
    if start is None or end is None or start > end or start >= size:
        raise RangeNotSatisfiableError(size)
    return ByteRange(start=start, end=min(end, size - 1), size=size)
