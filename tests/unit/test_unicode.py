"""Unit tests for `domain.unicode`: Default_Ignorable set, visibility, joiner/selector bases,
caseless key."""

from __future__ import annotations

import sys
import unicodedata

import pytest

from preview_dashboard.domain.unicode import (
    BLANK_LOOKALIKES,
    caseless_key,
    is_default_ignorable,
    is_visible,
    remove_default_ignorables,
    takes_joiner,
    takes_presentation_selector,
)

pytestmark = pytest.mark.unit

# Cf characters that are *not* Default_Ignorable by the UCD derivation:
# prepended concatenation marks, interlinear annotation controls and
# Egyptian hieroglyph format controls.
_CF_NOT_IGNORABLE = {
    *range(0x0600, 0x0606),
    0x06DD,
    0x070F,
    0x0890,
    0x0891,
    0x08E2,
    *range(0xFFF9, 0xFFFC),
    0x110BD,
    0x110CD,
    *range(0x13430, 0x13440),
}


@pytest.mark.parametrize(
    "ch",
    [
        "\u00ad",
        "\u034f",
        "\u061c",
        "\u115f",
        "\u1160",
        "\u17b4",
        "\u17b5",
        "\u180b",
        "\u180e",
        "\u180f",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u202e",
        "\u2060",
        "\u2065",
        "\u2069",
        "\u206f",
        "\u3164",
        "\ufe00",
        "\ufe0f",
        "\ufeff",
        "\uffa0",
        "\ufff0",
        "\ufff8",
        "\U0001bca0",
        "\U0001d173",
        "\U0001d17a",
        "\U000e0000",
        "\U000e0041",
        "\U000e0100",
        "\U000e01ef",
        "\U000e0fff",
    ],
)
def test_default_ignorable_members(ch: str) -> None:
    assert is_default_ignorable(ch)
    assert not is_visible(ch)


@pytest.mark.parametrize(
    "ch",
    ["a", " ", "\u00ac", "\u034e", "\u0350", "\u115e", "\u1161", "\u2800", "\ufff9", "\U000e1000"],
)
def test_default_ignorable_non_members(ch: str) -> None:
    assert not is_default_ignorable(ch)


def test_default_ignorable_matches_ucd_derivation_for_format_chars() -> None:
    # Derivation: Cf + Variation_Selector + Other_DI - exclusions. Check the
    # Cf part exhaustively against the stdlib's category data.
    for cp in range(sys.maxunicode + 1):
        ch = chr(cp)
        if unicodedata.category(ch) == "Cf":
            assert is_default_ignorable(ch) is (cp not in _CF_NOT_IGNORABLE), hex(cp)


@pytest.mark.parametrize(
    "ch", ["a", "Z", "\u65e5", "7", "\u0663", "!", "\u00ab", "$", "\U0001f600"]
)
def test_visible(ch: str) -> None:
    assert is_visible(ch)


@pytest.mark.parametrize("ch", [" ", "\u3000", "\u2800", "\u3164", "\u115f", "\u0301", "\x00"])
def test_not_visible(ch: str) -> None:
    assert not is_visible(ch)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("\u015a", "\u017f\u0301"),  # '\u015a' vs long-s + combining acute
        ("\u0130", "i\u0307"),  # '\u0130' vs 'i' + combining dot above
        ("Stra\u00dfe", "STRASSE"),
        ("\u1fbc", "\u1fb3"),  # '\u1fbc' vs '\u1fb3' (both fold to '\u03b1\u03b9')
        ("\u03a3", "\u03c2"),
        ("\u212b", "\u00e5"),  # ANGSTROM SIGN vs '\u00e5'
        ("\ufb01", "FI"),  # '\ufb01' ligature (compatibility)
        ("A.txt", "a.TXT"),
    ],
)
def test_caseless_key_matches_equivalents(a: str, b: str) -> None:
    assert caseless_key(a) == caseless_key(b)


@pytest.mark.parametrize(
    ("a", "b"), [("a", "b"), ("\u00e9", "e"), ("\u0131", "i"), ("a.txt", "a.txt ")]
)
def test_caseless_key_distinguishes_different_strings(a: str, b: str) -> None:
    assert caseless_key(a) != caseless_key(b)


# --- blank look-alikes, joiner/selector bases (G4) -------------------------------------

_BLANKS = ["\u2800", "\ufffc", "\U00016fe4", "\U0001d159"]
_HANGUL_FILLERS = ["\u115f", "\u1160", "\u3164", "\uffa0"]


@pytest.mark.parametrize("ch", _BLANKS)
def test_blank_lookalikes_are_listed_and_never_visible(ch: str) -> None:
    assert ch in BLANK_LOOKALIKES
    assert not is_default_ignorable(ch)  # else the set above would be redundant
    assert not is_visible(ch)
    assert not takes_joiner(ch)


@pytest.mark.parametrize("ch", _HANGUL_FILLERS)
def test_hangul_fillers_are_covered_as_default_ignorable(ch: str) -> None:
    assert is_default_ignorable(ch)
    assert not is_visible(ch)


@pytest.mark.parametrize(
    "ch",
    [
        *("\U0001f525", "\u2764", "\u2640", "\U0001f3fd"),  # emoji, sign, skin tone (Sk)
        *("\u0915", "\u094d", "\u0645", "\u06cc", "\u0dca", "\u05d0", "\u65e5"),
    ],
)
def test_takes_joiner_emoji_and_complex_scripts(ch: str) -> None:
    assert takes_joiner(ch)


@pytest.mark.parametrize(
    "ch",
    [
        *("a", "Z", "0", "-", "^", " ", "\n"),  # ASCII
        *("\u00e9", "\u00a9", "\u0301", "\u03b1", "\u0436", "\u0561"),  # Latin-1 .. Armenian
        *("\u1e9e", "\u1f00", "\ua7c0", "\uff21", "\U0001d400", "\u20e3"),  # extensions
        *("\u200d", "\ufe0f", "\u00ad", "\U000e0041"),  # Default_Ignorable
        *("\u2026", "\u3000"),  # punctuation, space
    ],
)
def test_takes_joiner_refuses_latin_like_and_invisible(ch: str) -> None:
    assert not takes_joiner(ch)


@pytest.mark.parametrize(
    ("ch", "following"),
    [
        ("\u2764", ""),
        ("\u00a9", "x"),
        ("\u203c", ""),
        ("\u2139", ""),
        ("\u2194", ""),
        ("\U0001f3f3", "\u200d"),
        *((d, "\u20e3") for d in "#*0123456789"),
    ],
)
def test_presentation_selector_bases(ch: str, following: str) -> None:
    assert takes_presentation_selector(ch, following)


@pytest.mark.parametrize(
    ("ch", "following"),
    [
        ("Y", "e"),
        ("1", ""),
        ("1", "x"),
        ("a", "\u20e3"),
        ("\u00e9", ""),
        ("\u0915", ""),
        ("\ufe0f", ""),
        ("\u2800", ""),
        ("\u0301", ""),
    ],
)
def test_presentation_selector_non_bases(ch: str, following: str) -> None:
    assert not takes_presentation_selector(ch, following)


def test_remove_default_ignorables_rejoins_split_tokens() -> None:
    split = "AK" + chr(0x200D) + "IA" + chr(0xFE0F) + "Q" + chr(0x200B) + chr(0xE0041) + "Z"
    assert remove_default_ignorables(split) == "AKIAQZ"
    assert remove_default_ignorables("\u2764\u2800x") == "\u2764\u2800x"
