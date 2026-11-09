"""Security tests for `Content-Disposition` building (docs/security.md C9).

Untrusted file names and titles must never break out of the header or the
quoted fallback, and must round-trip (cleaned) through `filename*`.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

import pytest
from hypothesis import given
from hypothesis import strategies as st

from preview_dashboard.interfaces.viewer.disposition import (
    FALLBACK_NAME,
    MAX_ASCII_NAME,
    MAX_UTF8_NAME_BYTES,
    ascii_fallback,
    content_disposition,
    utf8_name,
)

pytestmark = pytest.mark.security

_SHAPE = re.compile(
    r"^(inline|attachment); filename=\"([^\"\\]*)\"; filename\*=UTF-8''([A-Za-z0-9%._~-]+)$"
)


def _parts(value: str) -> tuple[str, str, str]:
    match = _SHAPE.fullmatch(value)
    assert match, value
    return match.group(1), match.group(2), unquote(match.group(3), errors="strict")


def test_plain_name() -> None:
    assert content_disposition("attachment", "report.pdf") == (
        "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
    )
    assert content_disposition("inline", "a.png").startswith("inline; ")


@pytest.mark.parametrize(
    ("name", "fallback"),
    [
        ('a"b.txt', "a_b.txt"),
        ("a\\b.txt", "a_b.txt"),
        ("a\r\nSet-Cookie: x=1.txt", "a__Set-Cookie_ x=1.txt"),
        ("a;b.txt", "a_b.txt"),
        ("100%.txt", "100_.txt"),
        ("../../etc/passwd", "_.._etc_passwd"),
        ("sub/dir/x.html", "sub_dir_x.html"),
        ("résumé.pdf", "r_sum_.pdf"),
        (".env", "env"),
        ("...hidden", "hidden"),
        ("  spaced.txt  ", "spaced.txt"),
        ("evil\u202egnp.exe", "evil_gnp.exe"),
        ("zero\u200bwidth.txt", "zero_width.txt"),
        ("tab\there.txt", "tab_here.txt"),
        ("C:evil.txt", "C_evil.txt"),
    ],
)
def test_ascii_fallback_sanitization(name: str, fallback: str) -> None:
    assert ascii_fallback(name) == fallback
    kind, quoted, _ = _parts(content_disposition("attachment", name))
    assert kind == "attachment" and quoted == fallback


@pytest.mark.parametrize("name", ["", "   ", "...", "日本語", "\u202e", '"""'])
def test_never_empty(name: str) -> None:
    value = content_disposition("attachment", name)
    _, quoted, decoded = _parts(value)
    assert quoted and quoted.strip("_")
    assert decoded


def test_all_non_ascii_falls_back_to_download_but_keeps_utf8() -> None:
    _, quoted, decoded = _parts(content_disposition("attachment", "日本語"))
    assert quoted == FALLBACK_NAME
    assert decoded == "日本語"


def test_utf8_name_round_trips_through_filename_star() -> None:
    _, _, decoded = _parts(content_disposition("attachment", "Größe \u2013 café.pdf"))
    assert decoded == "Größe \u2013 café.pdf"


def test_filename_star_strips_controls_and_separators() -> None:
    _, _, decoded = _parts(content_disposition("attachment", "a/b\\c\r\n\u202ed.txt"))
    assert decoded == "a_b_c___d.txt"


def test_long_names_are_bounded_and_keep_extension() -> None:
    name = "x" * 500 + ".tar.gz"
    assert len(ascii_fallback(name)) == MAX_ASCII_NAME
    assert ascii_fallback(name).endswith(".gz")
    assert utf8_name(name).endswith(".gz")
    wide = "é" * 400 + ".pdf"
    assert len(utf8_name(wide).encode()) <= MAX_UTF8_NAME_BYTES
    assert utf8_name(wide).endswith(".pdf")


def test_invalid_kind_is_rejected() -> None:
    with pytest.raises(ValueError, match="kind"):
        content_disposition("form-data", "x")  # type: ignore[arg-type]


@given(st.text(max_size=300), st.sampled_from(["inline", "attachment"]))
def test_header_value_is_always_safe(name: str, kind: str) -> None:
    value = content_disposition(kind, name)  # type: ignore[arg-type]
    assert value.isascii()
    assert all(0x20 <= ord(c) < 0x7F for c in value)
    _parts(value)  # exactly the expected shape: no parameter injection
