"""Unit tests for `domain.paths.validate_relpath` rule boundaries.

Adversarial inputs live in `tests/security/test_paths.py` (control C7);
these pin down the exact limits and error types.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from preview_dashboard.domain.errors import InvalidPathError, ValidationError
from preview_dashboard.domain.paths import (
    MAX_DEPTH,
    MAX_PATH_BYTES,
    MAX_SEGMENT_BYTES,
    validate_relpath,
)

pytestmark = pytest.mark.unit


def test_invalid_path_error_is_a_validation_error() -> None:
    assert issubclass(InvalidPathError, ValidationError)


def test_segment_byte_limit_boundary() -> None:
    assert validate_relpath("a" * MAX_SEGMENT_BYTES)
    with pytest.raises(InvalidPathError, match="segment exceeds"):
        validate_relpath("a" * (MAX_SEGMENT_BYTES + 1))


def test_segment_limit_counts_utf8_bytes_not_chars() -> None:
    with pytest.raises(InvalidPathError):
        validate_relpath("é" * 128)  # 128 chars, 256 bytes


def test_total_byte_limit_boundary() -> None:
    ok = "/".join(["a" * 255, "a" * 255, "a" * 255, "a" * 255])  # 1023 bytes
    assert len(ok) == MAX_PATH_BYTES - 1
    assert validate_relpath(ok) == ok
    too_long = ok + "/ab"  # 1026 bytes
    with pytest.raises(InvalidPathError, match="exceeds 1024"):
        validate_relpath(too_long)


def test_depth_limit_boundary() -> None:
    assert validate_relpath("/".join(["d"] * MAX_DEPTH))
    with pytest.raises(InvalidPathError, match="deeper"):
        validate_relpath("/".join(["d"] * (MAX_DEPTH + 1)))


@pytest.mark.parametrize("raw", ["x~", "a/~b", "a~"])
def test_tilde_allowed_when_not_leading(raw: str) -> None:
    assert validate_relpath(raw) == raw


@pytest.mark.parametrize(
    ("raw", "fragment"), [("", "empty"), ("/a", "relative"), ("a//b", "empty")]
)
def test_error_messages_are_specific(raw: str, fragment: str) -> None:
    with pytest.raises(InvalidPathError, match=fragment):
        validate_relpath(raw)


@given(st.text(alphabet=st.characters(codec="utf-8"), max_size=50))
def test_valid_paths_are_returned_unchanged(raw: str) -> None:
    with contextlib.suppress(InvalidPathError):
        assert validate_relpath(raw) == raw
