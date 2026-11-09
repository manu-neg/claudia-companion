"""Unicode helpers shared by path validation and display-text sanitizing.

Holds the Default_Ignorable_Code_Point set (invisible characters used for
filename/title spoofing and hidden-data smuggling), blank look-alikes, the
"visible character" test, where ZWJ/ZWNJ and emoji presentation selectors
are meaningful, and the canonical caseless fold used to detect colliding
file names. Stdlib only: `unicodedata` exposes neither Default_Ignorable
nor Script, so the ranges are spelled out here from the Unicode Character
Database.
"""

from __future__ import annotations

import unicodedata
from bisect import bisect_right

# Default_Ignorable_Code_Point, from DerivedCoreProperties.txt (Unicode 15.1;
# unchanged in 16.0). Inclusive (first, last) ranges, sorted, non-overlapping.
_DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),  # SOFT HYPHEN
    (0x034F, 0x034F),  # COMBINING GRAPHEME JOINER
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x115F, 0x1160),  # HANGUL CHOSEONG/JUNGSEONG FILLER
    (0x17B4, 0x17B5),  # KHMER VOWEL INHERENT AQ/AA
    (0x180B, 0x180F),  # MONGOLIAN FVS1..3, VOWEL SEPARATOR, FVS4
    (0x200B, 0x200F),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    (0x202A, 0x202E),  # bidi embeddings/overrides
    (0x2060, 0x206F),  # WORD JOINER, invisible operators, bidi isolates, deprecated
    (0x3164, 0x3164),  # HANGUL FILLER
    (0xFE00, 0xFE0F),  # VARIATION SELECTOR-1..16
    (0xFEFF, 0xFEFF),  # ZERO WIDTH NO-BREAK SPACE (BOM)
    (0xFFA0, 0xFFA0),  # HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),  # unassigned specials
    (0x1BCA0, 0x1BCA3),  # SHORTHAND FORMAT controls
    (0x1D173, 0x1D17A),  # MUSICAL SYMBOL BEGIN/END BEAM etc.
    (0xE0000, 0xE0FFF),  # TAG chars, VARIATION SELECTOR-17..256, reserved
)
_RANGE_STARTS: tuple[int, ...] = tuple(start for start, _ in _DEFAULT_IGNORABLE_RANGES)

ZWNJ = "\u200c"
ZWJ = "\u200d"
JOINERS = frozenset({ZWNJ, ZWJ})
VS15 = "\ufe0e"  # text presentation selector
VS16 = "\ufe0f"  # emoji presentation selector
PRESENTATION_SELECTORS = frozenset({VS15, VS16})
COMBINING_KEYCAP = "\u20e3"
# Keycap emoji are ASCII + VS16 + U+20E3 ("1\ufe0f\u20e3"): the only place a
# selector may follow an ASCII char.
_KEYCAP_BASES = frozenset("#*0123456789")

# Visible-looking-blank characters that are *not* Default_Ignorable (so the
# set above misses them) yet render as nothing: never count as visible text.
# (The Hangul fillers U+115F/U+1160/U+3164/U+FFA0 are Default_Ignorable.)
BLANK_LOOKALIKES = frozenset(
    {
        "\u2800",  # BRAILLE PATTERN BLANK (So)
        "\ufffc",  # OBJECT REPLACEMENT CHARACTER (So)
        "\U00016fe4",  # KHITAN SMALL SCRIPT FILLER (Mn)
        "\U0001d159",  # MUSICAL SYMBOL NULL NOTEHEAD (So)
    }
)

# Letters and marks of scripts that shape without ZWJ/ZWNJ (Latin, Greek,
# Cyrillic, Armenian, their extension and compatibility blocks, generic
# combining marks): a joiner next to them only hides data or splits tokens.
# Inclusive, sorted, non-overlapping; everything >= U+0590 not listed counts
# as a complex script (Hebrew, Arabic, Indic, Southeast Asian, CJK ...).
_JOINERLESS_LETTER_RANGES: tuple[tuple[int, int], ...] = (
    (0x0000, 0x058F),  # Basic Latin .. Armenian (incl. IPA, diacritics, Greek, Cyrillic)
    (0x1C80, 0x1C8F),  # Cyrillic Extended-C
    (0x1D00, 0x1FFF),  # Phonetic Ext (+ Suppl.), diacritics Suppl., Latin Ext Additional, Greek Ext
    (0x20D0, 0x214F),  # combining marks for symbols, letterlike symbols
    (0x2C60, 0x2C7F),  # Latin Extended-C
    (0x2DE0, 0x2DFF),  # Cyrillic Extended-A
    (0xA640, 0xA69F),  # Cyrillic Extended-B
    (0xA720, 0xA7FF),  # Latin Extended-D
    (0xAB30, 0xAB6F),  # Latin Extended-E
    (0xFB00, 0xFB17),  # Latin/Armenian ligatures
    (0xFE20, 0xFE2F),  # Combining Half Marks
    (0xFF00, 0xFFEF),  # Halfwidth and Fullwidth Forms
    (0x10780, 0x107BF),  # Latin Extended-F
    (0x1D400, 0x1D7FF),  # Mathematical Alphanumeric Symbols
    (0x1DF00, 0x1DFFF),  # Latin Extended-G
    (0x1E030, 0x1E08F),  # Cyrillic Extended-D
)
_JOINERLESS_STARTS: tuple[int, ...] = tuple(start for start, _ in _JOINERLESS_LETTER_RANGES)

# Emoji and their modifiers are symbols (So/Sk) from U+2000 up; lower ones
# (ASCII, Latin-1) never take part in ZWJ sequences.
_EMOJI_SYMBOL_MIN = 0x2000

# Categories that put ink on screen: letters, numbers, punctuation, symbols.
_VISIBLE_CATEGORY_PREFIXES = ("L", "N", "P", "S")


def _in_ranges(cp: int, starts: tuple[int, ...], ranges: tuple[tuple[int, int], ...]) -> bool:
    i = bisect_right(starts, cp) - 1
    return i >= 0 and cp <= ranges[i][1]


def is_default_ignorable(ch: str) -> bool:
    """True if `ch` has the Unicode Default_Ignorable_Code_Point property."""
    return _in_ranges(ord(ch), _RANGE_STARTS, _DEFAULT_IGNORABLE_RANGES)


def remove_default_ignorables(text: str) -> str:
    """Return `text` without any Default_Ignorable char (joiners, selectors, ZWSP, tags ...).

    For secret scanning: a token split by invisible chars is whole again.
    """
    return "".join(ch for ch in text if not is_default_ignorable(ch))


def is_visible(ch: str) -> bool:
    """True if `ch` renders visibly on its own (category L/N/P/S, not ignorable/blank).

    Hangul fillers are category Lo but Default_Ignorable, hence the extra checks.
    """
    return (
        unicodedata.category(ch).startswith(_VISIBLE_CATEGORY_PREFIXES)
        and not is_default_ignorable(ch)
        and ch not in BLANK_LOOKALIKES
    )


def takes_joiner(ch: str) -> bool:
    """True if a ZWJ/ZWNJ next to `ch` can be meaningful: an emoji or a complex-script char.

    Emoji-range symbols (So/Sk from U+2000 up, incl. skin-tone modifiers)
    and letters/marks outside the Latin/Greek/Cyrillic/Armenian blocks
    (Arabic ZWNJ, Indic conjuncts ...) qualify. Never ASCII, a
    Default_Ignorable char or a blank look-alike.
    """
    if is_default_ignorable(ch) or ch in BLANK_LOOKALIKES:
        return False
    cp, category = ord(ch), unicodedata.category(ch)
    if category in ("So", "Sk"):
        return cp >= _EMOJI_SYMBOL_MIN
    if category[0] in ("L", "M"):
        return not _in_ranges(cp, _JOINERLESS_STARTS, _JOINERLESS_LETTER_RANGES)
    return False


def takes_presentation_selector(ch: str, following: str) -> bool:
    """True if VS15/VS16 right after `ch` can be meaningful (`following`: the char after it).

    Emoji bases are non-ASCII symbols/punctuation (e.g. U+2764, U+00A9,
    U+203C) or U+2139; an ASCII char only as a keycap base (`#`, `*`,
    digits) directly followed by U+20E3.
    """
    if ch in _KEYCAP_BASES:
        return following == COMBINING_KEYCAP
    if ord(ch) < 0x80 or not is_visible(ch):
        return False
    return unicodedata.category(ch)[0] in ("S", "P") or ch == "\u2139"


def caseless_key(text: str) -> str:
    """Return the compatibility caseless-match key of `text` (Unicode 3.13, D146).

    `NFKD(casefold(NFKD(casefold(NFD(text)))))`: two strings map to the same
    key iff they are equal ignoring case and compatibility/canonical
    variants (e.g. U+015A vs U+017F U+0301, U+0130 vs 'i' U+0307, sharp s vs
    'SS'). A plain `casefold()` misses several of these, letting two bundle
    files alias on case-insensitive filesystems.
    """
    once = unicodedata.normalize("NFKD", unicodedata.normalize("NFD", text).casefold())
    return unicodedata.normalize("NFKD", once.casefold())
