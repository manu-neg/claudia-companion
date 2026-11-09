"""Unit tests for RegexSecretScanner's session mechanics and constructor checks.

Rule coverage, chunking independence and ReDoS live in
`tests/security/test_secret_scan.py` (docs/security.md C15).
"""

from __future__ import annotations

import pytest

from preview_dashboard.adapters.secret_scan import (
    DEFAULT_RULES,
    MAX_MATCH_BYTES,
    RegexSecretScanner,
)
from preview_dashboard.domain.errors import DomainError, SecretDetectedError
from preview_dashboard.ports.scanner import ContentScanner

pytestmark = pytest.mark.unit


def test_satisfies_port() -> None:
    scanner: ContentScanner = RegexSecretScanner()
    scanner.new_session().finish()


def test_rule_names_in_priority_order() -> None:
    assert RegexSecretScanner().rule_names == tuple(n for n, _ in DEFAULT_RULES)


def test_clean_stream_passes() -> None:
    session = RegexSecretScanner().new_session()
    session.feed(b"")
    session.feed(b"just some text")
    session.finish()


def test_finished_session_cannot_be_reused() -> None:
    session = RegexSecretScanner().new_session()
    session.finish()
    with pytest.raises(RuntimeError):
        session.feed(b"x")
    with pytest.raises(RuntimeError):
        session.finish()


def test_session_closes_after_detection() -> None:
    scanner = RegexSecretScanner(rules=(("demo", rb"MARK"),))
    session = scanner.new_session()
    with pytest.raises(SecretDetectedError):
        session.feed(b"x" * 300_000 + b"MARK" + b"y")
    with pytest.raises(RuntimeError):
        session.feed(b"more")


def test_sessions_are_independent() -> None:
    scanner = RegexSecretScanner(rules=(("demo", rb"MARK"),))
    a = scanner.new_session()
    b = scanner.new_session()
    a.feed(b"MA")
    b.feed(b"RK")
    a.finish()
    b.finish()


def test_custom_rules() -> None:
    scanner = RegexSecretScanner(rules=(("demo rule", rb"X{3}"),))
    session = scanner.new_session()
    session.feed(b"aXX")
    with pytest.raises(SecretDetectedError) as info:
        session.feed(b"Xb")
        session.finish()
    assert info.value.rule == "demo rule"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"rules": ()},
        {"rules": (("", rb"x"),)},
        {"rules": (("bad\nlabel", rb"x"),)},
        {"overlap_bytes": MAX_MATCH_BYTES},
        {"block_bytes": 0},
    ],
)
def test_invalid_constructor_args(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        RegexSecretScanner(**kwargs)  # type: ignore[arg-type]


def test_secret_detected_error_shape() -> None:
    err = SecretDetectedError("AWS access key id", "dir/a.txt")
    assert isinstance(err, DomainError)
    assert err.rule == "AWS access key id"
    assert err.relpath == "dir/a.txt"
    assert "AWS access key id" in str(err)
    assert "dir/a.txt" in str(err)
    assert "in " not in str(SecretDetectedError("r"))


# --- window trim keeps lookbehind context -------------------------------------------------


def _aws_like() -> bytes:
    return b"AK" + b"IA" + b"Q" * 16  # assembled so gitleaks never sees a literal


@pytest.mark.parametrize("shift", range(-4, 5))
def test_trim_keeps_boundary_char_so_glued_token_is_not_a_false_positive(shift: int) -> None:
    # A token glued to a preceding letter is not a secret (boundary lookbehind).
    # If a window trim cut exactly between that letter and the token, the
    # next window would see the token "at the start" and wrongly flag it.
    overlap, block = MAX_MATCH_BYTES + 3, 20_000
    at = block - overlap + shift  # around the old trim edge
    data = bytearray(b"." * block)
    data[at - 1 : at + 20] = b"X" + _aws_like()
    session = RegexSecretScanner(overlap_bytes=overlap, block_bytes=block).new_session()
    session.feed(bytes(data))  # one full block: scan, then trim
    session.feed(b" more text")
    session.finish()


def test_trimmed_window_still_detects_token_at_its_start() -> None:
    overlap, block = MAX_MATCH_BYTES + 3, 20_000
    data = b"." * (block - 5) + _aws_like()[:5]  # token cut by the block edge
    session = RegexSecretScanner(overlap_bytes=overlap, block_bytes=block).new_session()
    session.feed(data)
    with pytest.raises(SecretDetectedError):
        session.feed(_aws_like()[5:] + b" ")
        session.finish()
