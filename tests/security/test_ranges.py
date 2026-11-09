"""Security tests for strict single-`Range` parsing (docs/security.md C9)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from preview_dashboard.interfaces.viewer.ranges import (
    ByteRange,
    RangeNotSatisfiableError,
    parse_range,
)

pytestmark = pytest.mark.security


def test_no_header_means_full_response() -> None:
    assert parse_range(None, 10) is None


@pytest.mark.parametrize(
    ("header", "size", "expected"),
    [
        ("bytes=0-0", 10, (0, 0)),
        ("bytes=0-9", 10, (0, 9)),
        ("bytes=2-5", 10, (2, 5)),
        ("bytes=5-", 10, (5, 9)),
        ("bytes=0-999", 10, (0, 9)),  # end clamped
        ("bytes=-3", 10, (7, 9)),
        ("bytes=-100", 10, (0, 9)),  # suffix longer than the resource
        ("bytes=9-9", 10, (9, 9)),
    ],
)
def test_valid_single_ranges(header: str, size: int, expected: tuple[int, int]) -> None:
    result = parse_range(header, size)
    assert result == ByteRange(expected[0], expected[1], size)
    assert result.length == expected[1] - expected[0] + 1
    assert result.content_range == f"bytes {expected[0]}-{expected[1]}/{size}"


@pytest.mark.parametrize(
    "header",
    [
        "bytes=0-1,2-3",  # multi-range
        "bytes=0-1, 2-3",
        "bytes=0-0,-1",
        "bytes=,0-1",
        "items=0-1",  # other unit
        "Bytes=0-1",
        "bytes = 0-1",
        "bytes=0 -1",
        "bytes= 0-1",
        "bytes=",
        "bytes=-",
        "bytes=--1",
        "bytes=-0",  # zero-length suffix
        "bytes=5-2",  # start > end
        "bytes=10-",  # start == size
        "bytes=10-20",
        "bytes=+1-2",
        "bytes=-+1",
        "bytes=1-+2",
        "bytes=0x1-2",
        "bytes=1_0-20",
        "bytes=\uff11-2",  # fullwidth digit
        "bytes=\u0663-4",  # Arabic-Indic digit
        "bytes=99999999999999999999-",  # > 19 digits
        "bytes=0-99999999999999999999",
        "bytes=1-2-3",
        "bytes=0-1\r\n",
        "garbage",
        "",
    ],
)
def test_invalid_ranges_are_416(header: str) -> None:
    with pytest.raises(RangeNotSatisfiableError) as info:
        parse_range(header, 10)
    assert info.value.content_range == "bytes */10"


def test_empty_resource_has_no_satisfiable_range() -> None:
    for header in ("bytes=0-", "bytes=-1", "bytes=0-0"):
        with pytest.raises(RangeNotSatisfiableError):
            parse_range(header, 0)


def test_negative_size_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="size"):
        parse_range("bytes=0-1", -1)


@given(st.text(max_size=40), st.integers(min_value=0, max_value=2**63 - 1))
def test_result_is_always_within_bounds(header: str, size: int) -> None:
    try:
        result = parse_range(header, size)
    except RangeNotSatisfiableError:
        return
    assert result is not None
    assert 0 <= result.start <= result.end < size
