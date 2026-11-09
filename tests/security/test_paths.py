"""Security tests for control C7: bundle-relative path validation.

Covers traversal, absolute/drive/UNC paths, separators, control and bidi
characters, Unicode normalization and compatibility look-alikes (WorstFit),
Default_Ignorable characters, Windows reserved names and chars, URL
metacharacters and size/depth limits, plus Hypothesis properties that no
accepted path can escape its root or carry an invisible/look-alike char.
"""

from __future__ import annotations

import posixpath
import unicodedata
from pathlib import PurePosixPath

import pytest
from hypothesis import given
from hypothesis import strategies as st

from preview_dashboard.domain.errors import InvalidPathError
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.domain.unicode import is_default_ignorable

pytestmark = pytest.mark.security

ROOT = PurePosixPath("/srv/root")

ADVERSARIAL = [
    # traversal
    "..",
    ".",
    "../x",
    "a/../../x",
    "a/./b",
    "a/..",
    "...",
    "a/.../b",
    # absolute / home / drive / UNC / Windows separators and streams
    "/etc/passwd",
    "//server/share",
    "~/x",
    "~root/.ssh/id_rsa",
    "C:",
    "C:/x",
    "c:x",
    "a.txt:stream",
    "\\\\server\\share",
    "a\\..\\..\\x",
    "..\\x",
    # empty segments / trailing slash
    "",
    "a//b",
    "a/",
    "a/b/",
    # control characters (C0 incl. CR/LF, DEL, C1)
    "a\x00b",
    "a\x00/../x",
    "a\nb",
    "a\rb",
    "a\tb",
    "a\x1bb",
    "a\x7fb",
    "a\x85b",
    "a\x9bb",
    # bidi overrides/isolates and invisible format chars
    "evil\u202egpj.exe",
    "a\u202ab",
    "a\u202db",
    "a\u2066b",
    "a\u2067b",
    "a\u2068b",
    "a\u2069b",
    "a\u200bb",
    "a\ufeffb",
    "a\u2028b",
    # normalization tricks (decomposed 'é' is not NFC)
    "cafe\u0301.txt",
    "e\u0301/x",
    # trailing dot / leading/trailing whitespace in a segment
    "a.",
    "dir./x",
    "a ",
    " a",
    "a /b",
    "a\u00a0",
    # lone surrogate
    "a\ud800b",
    # compatibility look-alikes (NFKC-unstable): fullwidth dot/solidus/
    # reverse solidus/colon/percent fold to ASCII in NFKC tools and Windows
    # "best fit" code pages (WorstFit)
    "\uff0e\uff0e\uff3c\uff0e\uff0e\uff3cevil.exe",
    "\uff0e\uff0e/x",
    "\uff0e\uff0e",
    "a\uff0fb",
    # NFKC-stable separator look-alikes that Windows best-fit code pages
    # still map to '/', '\\' or ':' (WorstFit; '¥'/'₩' are 0x5C in cp932/cp949)
    "a\u2215b",
    "a\u2044b",
    "a\u2216b",
    "a\u29f5b",
    "..\u00a5..\u00a5evil.exe",
    "..\u20a9x",
    "C\u2236x",
    "a\ua789b",
    "a\uff3cb",
    "a\uff1ab",
    "C\uff1a/x",
    "\uff05\uff12\uff45",
    "\ufe52\ufe52/x",  # SMALL FULL STOP
    "\u2024\u2024/x",  # ONE DOT LEADER
    "\u2025/x",  # TWO DOT LEADER -> '..'
    "file\ufb01.txt",  # 'ﬁ' ligature
    "COM\u00b9",
    "LPT\u00b2.txt",
    "\u2126.txt",  # OHM SIGN (NFC-unstable)
    "\u212a.txt",  # KELVIN SIGN
    "a\u3000b",  # IDEOGRAPHIC SPACE
    "\uff41.txt",  # fullwidth 'a'
    # Windows reserved / URL metacharacters
    "a%2e%2e",
    "%2e%2e/x",
    "..%2fx",
    "100%.txt",
    "a?b",
    "a#b",
    "a;b",
    'a"b',
    "a<b",
    "a>b",
    "a|b",
    "a*b",
    # Windows reserved device names (any case, any extension)
    "CON",
    "con",
    "Con.txt",
    "PRN",
    "AUX.tar.gz",
    "NUL",
    "nul.txt",
    "NUL .txt",
    "dir/nul",
    "COM0",
    "com1",
    "COM9.log",
    "LPT0",
    "lpt5.txt",
    "LPT9",
    "CONIN$",
    "conout$.x",
    # Default_Ignorable and blank look-alikes
    "a\u115fb",
    "a\u1160b",
    "\u3164",
    "a\u3164b",
    "a\uffa0b",
    "a\u2800b",
    "\u2800",
    "a\u034fb",
    "a\u17b4b",
    "a\u17b5b",
    "a\u180bb",
    "a\u180eb",
    "a\u00adb",
    "a\u061cb",
    "a\u200cb",
    "a\u200db",
    "a\u2060b",
    "a\u2065b",
    "a\ufe00b",
    "a\ufe0fb",
    "a\U000e0100b",
    "a\U000e01efb",
    "a\U000e0041b",  # TAG LATIN CAPITAL A (hidden text)
    "a\U0001d173b",
    "a\U0001bca0b",
    "a\ufff0b",
    # limits
    "a" * 256,
    "/".join(["a" * 200] * 6),
    "/".join(["d"] * 17),
]


@pytest.mark.parametrize("raw", ADVERSARIAL)
def test_adversarial_paths_are_rejected(raw: str) -> None:
    with pytest.raises(InvalidPathError):
        validate_relpath(raw)


@pytest.mark.parametrize("raw", [None, b"a.txt", 1])
def test_non_string_is_rejected(raw: object) -> None:
    with pytest.raises(InvalidPathError):
        validate_relpath(raw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "raw",
    [
        "index.html",
        ".hidden",
        "assets/app.js",
        "a/b/c/d.txt",
        "..a",
        "a..b",
        "café.txt",
        "日本語/ファイル.md",
        "x~backup.txt",
        "it's.txt",
        "a+b=c&d@e!f$g(h)[i]{j},k'l.txt",
        "CONFIG",
        "console.log",
        "com10",
        "lpt",
        "auxiliary.txt",
        "nul_",
        "icon.con",
        "Straße.txt",
        "\u0130stanbul.txt",
        "emoji\U0001f600.txt",
        "/".join(["d"] * 16),
        "é" * 127,  # 254 bytes
        "/".join(["a" * 255] * 4),  # 1023 bytes
    ],
)
def test_safe_paths_are_accepted_unchanged(raw: str) -> None:
    assert validate_relpath(raw) == raw


def _escapes(root: PurePosixPath, rel: str) -> bool:
    """Lexically resolve `root/rel` (no filesystem) and test containment."""
    joined = PurePosixPath(posixpath.normpath(str(root / rel)))
    return joined == root or root not in joined.parents


_PATH_ALPHABET = st.sampled_from(
    [
        *("a", "b", ".", "..", "/", "\\", ":", "~", " ", "\x00", "\n", "\u202e"),
        *("e\u0301", "é", "C:", "'"),
        # compatibility look-alikes of '.', '/', '\\', ':', '%'
        *("\uff0e", "\uff0f", "\uff3c", "\uff1a", "\uff05", "\u2215", "\u00a5", "\u2025"),
        # URL / Windows metacharacters and reserved names
        *("%", "%2e", "%2f", "?", "#", ";", '"', "<", ">", "|", "*"),
        *("CON", "nul", "COM1", "lpt9", "COM\u00b9", ".txt"),
        # Default_Ignorable and blank look-alikes
        *("\u3164", "\u115f", "\uffa0", "\u2800", "\u034f", "\u17b4", "\ufe0f"),
        *("\U000e0100", "\U000e0041", "\u200d", "\u00ad"),
    ]
)

_FORBIDDEN_IN_ACCEPTED = frozenset('\\:%?#;"<>|*')


def _assert_canonical(result: str) -> None:
    """Invariants every accepted path satisfies, beyond root containment."""
    assert not _escapes(ROOT, result)
    assert not any(is_default_ignorable(ch) for ch in result)
    assert not _FORBIDDEN_IN_ACCEPTED.intersection(result)
    for segment in result.split("/"):
        assert unicodedata.normalize("NFKC", segment) == segment
        assert segment.split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL"}
    assert validate_relpath(result) == result  # idempotent


@given(st.lists(_PATH_ALPHABET, max_size=12).map("".join))
def test_property_adversarial_alphabet_never_escapes_root(raw: str) -> None:
    try:
        result = validate_relpath(raw)
    except InvalidPathError:
        return
    _assert_canonical(result)
    # Even after NFKC folding (what a careless tool might apply), the path
    # still cannot traverse: accepted paths are NFKC-stable, so this is a no-op.
    assert unicodedata.normalize("NFKC", result) == result


@given(st.text(max_size=300))
def test_property_any_text_is_rejected_or_contained(raw: str) -> None:
    try:
        result = validate_relpath(raw)
    except InvalidPathError:
        return
    _assert_canonical(result)
    assert ".." not in PurePosixPath(result).parts
