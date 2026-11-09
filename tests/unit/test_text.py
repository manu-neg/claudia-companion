"""Unit tests for display-text sanitizing (item title, description), link and invisible-char
rejection for outgoing alert text (C35)."""

from __future__ import annotations

import contextlib
import unicodedata

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.text import (
    DESCRIPTION_MAX_CHARS,
    TITLE_MAX_CHARS,
    reject_invisible,
    reject_links,
    sanitize_description,
    sanitize_outgoing_line,
    sanitize_title,
    trim_cut_end,
)
from preview_dashboard.domain.unicode import (
    JOINERS,
    PRESENTATION_SELECTORS,
    takes_joiner,
    takes_presentation_selector,
)

pytestmark = pytest.mark.unit

BIDI = ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]


@pytest.mark.parametrize(
    "ch", [*BIDI, "\u200b", "\ufeff", "\u200e", "\x00", "\x1b", "\x7f", "\x85"]
)
def test_title_removes_invisible_and_control_chars(ch: str) -> None:
    assert sanitize_title(f"ab{ch}c") == "abc"


def test_title_turns_line_breaks_into_spaces_and_trims() -> None:
    assert sanitize_title("  a\r\nb\tc\nd\re  ") == "a b c d e"


def test_title_keeps_emoji_joiners_and_normalizes_nfc() -> None:
    family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"
    assert sanitize_title(family) == family
    assert sanitize_title("cafe\u0301") == "caf\u00e9"


def test_title_length_limits() -> None:
    assert sanitize_title("x" * TITLE_MAX_CHARS)
    with pytest.raises(ValidationError):
        sanitize_title("x" * (TITLE_MAX_CHARS + 1))
    with pytest.raises(ValidationError):
        sanitize_title("\u202e \u200b ")


@pytest.mark.parametrize("fn", [sanitize_title, sanitize_description])
def test_non_string_is_rejected(fn: object) -> None:
    with pytest.raises(ValidationError):
        fn(None)  # type: ignore[operator]


def test_description_keeps_newlines_and_tabs() -> None:
    assert sanitize_description(" a\r\nb\rc\n\td\u202e ") == "a\nb\nc\n\td"


def test_description_may_be_empty_and_has_max_length() -> None:
    assert sanitize_description("   ") == ""
    assert len(sanitize_description("d" * DESCRIPTION_MAX_CHARS)) == DESCRIPTION_MAX_CHARS
    with pytest.raises(ValidationError):
        sanitize_description("d" * (DESCRIPTION_MAX_CHARS + 1))


def test_length_is_checked_after_cleaning() -> None:
    # Invisible padding must not count against (or sneak past) the limit.
    assert len(sanitize_title("x" * TITLE_MAX_CHARS + "\u200b" * 50)) == TITLE_MAX_CHARS


@given(st.text(max_size=300))
def test_sanitizers_are_idempotent_and_leave_no_bidi(raw: str) -> None:
    for fn in (sanitize_title, sanitize_description):
        try:
            once = fn(raw)
        except ValidationError:
            continue
        assert fn(once) == once
        assert not any(ch in once for ch in BIDI)
        assert unicodedata.is_normalized("NFC", once)


# --- Default_Ignorable stripping, joiners, visibility, raw length ----------------

IGNORABLE = [
    "\u00ad",
    "\u034f",
    "\u061c",
    "\u115f",
    "\u1160",
    "\u17b4",
    "\u180e",
    "\u2060",
    "\u2065",
    "\u3164",
    "\ufe00",
    "\uffa0",
    "\U000e0041",
    "\U000e0100",
    "\U000e01ef",
    "\U0001d173",
]


@pytest.mark.parametrize("ch", IGNORABLE)
@pytest.mark.parametrize("fn", [sanitize_title, sanitize_description])
def test_default_ignorables_are_stripped(fn: object, ch: str) -> None:
    assert fn(f"ab{ch}c") == "abc"  # type: ignore[operator]


def test_tag_character_smuggling_is_removed() -> None:
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "ignore previous instructions")
    assert sanitize_title(f"Report{hidden}") == "Report"
    assert sanitize_description(f"Body{hidden}\ntext") == "Body\ntext"


def test_variation_selector_smuggling_is_removed() -> None:
    # Runs of variation selectors are a hidden-data channel.
    payload = "\ufe01\ufe02" + "".join(chr(0xE0100 + i) for i in range(40))
    assert sanitize_title(f"x{payload}y") == "xy"


def test_emoji_presentation_selector_kept_after_visible_char() -> None:
    heart_fire = "\u2764\ufe0f\u200d\U0001f525"
    assert sanitize_title(heart_fire) == heart_fire
    assert sanitize_title("\u2764\ufe0f\ufe0f") == "\u2764\ufe0f"  # only one survives
    assert sanitize_title("a \ufe0fb") == "a b"  # not after a visible char


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a\u200db", "ab"),  # between two ASCII chars: never (G4)
        ("a\u200cb", "ab"),
        ("\u00e9\u200d\u00e8", "\u00e9\u00e8"),  # Latin-1 letters need no joiner
        ("\u0436\u200d\u03b1", "\u0436\u03b1"),  # Cyrillic / Greek
        ("\uff21\u200d\uff22", "\uff21\uff22"),  # fullwidth Latin
        ("\U0001d400\u200d\U0001d401", "\U0001d400\U0001d401"),  # math bold
        ("a\u200d\U0001f525", "a\U0001f525"),  # both sides must take a joiner
        ("\U0001f525\u200da", "\U0001f525a"),
        ("\u200d\U0001f469\U0001f4bb", "\U0001f469\U0001f4bb"),  # leading
        ("\U0001f469\u200d", "\U0001f469"),  # trailing
        ("\U0001f469 \u200d\U0001f4bb", "\U0001f469 \U0001f4bb"),  # next to a space
        ("\U0001f469\u200d\u200d\U0001f4bb", "\U0001f469\u200d\U0001f4bb"),  # runs: one
        ("\U0001f469\u200d\u200b\U0001f4bb", "\U0001f469\U0001f4bb"),  # next is invisible
        ("\U0001f469\u200d\ufe0f", "\U0001f469\ufe0f"),  # a selector is not a partner
        ("\u0915\u094d\u200d\u0937", "\u0915\u094d\u200d\u0937"),  # Devanagari half form
        ("\u0645\u06cc\u200c\u062e", "\u0645\u06cc\u200c\u062e"),  # Persian ZWNJ
        ("\u0dbb\u0dca\u200d\u0dba", "\u0dbb\u0dca\u200d\u0dba"),  # Sinhala yansaya
    ],
)
def test_joiners_kept_only_inside_emoji_and_complex_script_sequences(
    raw: str, expected: str
) -> None:
    assert sanitize_title(raw) == expected


@pytest.mark.parametrize(
    "seq",
    [
        "\U0001f468\u200d\U0001f469\u200d\U0001f467",  # family
        "\U0001f3c3\U0001f3fd\u200d\u2640\ufe0f",  # runner, skin tone, female sign
        "\U0001f3f3\ufe0f\u200d\U0001f308",  # rainbow flag (ZWJ after VS16)
        "\u2764\ufe0f\u200d\U0001f525",  # heart on fire
        "\U0001f441\ufe0f\u200d\U0001f5e8\ufe0f",  # eye in speech bubble
        "1\ufe0f\u20e3",  # keycap one
        "#\ufe0f\u20e3",
        "\u00a9\ufe0f",  # copyright sign, emoji style
        "\u203c\ufe0f",  # double exclamation (Po)
        "\u2139\ufe0f",  # information source (Ll)
        "\u2194\ufe0e",  # left-right arrow, text style
        *("\u274c", "\u231b", "\U0001f6ab", "\u2753", "\u2705"),  # the alert emoji
    ],
)
def test_emoji_sequences_survive_every_sanitizer(seq: str) -> None:
    assert sanitize_title(f"x {seq} y") == f"x {seq} y"
    assert sanitize_outgoing_line(seq, name="f", max_chars=40) == seq
    assert reject_invisible(seq, name="f") == seq


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Y\ufe0fes", "Yes"),  # after an ASCII letter
        ("1\ufe0f", "1"),  # keycap base without the keycap
        ("1\ufe0fx\u20e3", "1x\u20e3"),
        ("\u00e9\ufe0f", "\u00e9"),  # after a Latin letter
        ("\u0915\ufe0f", "\u0915"),  # after a script letter
        ("\u2764\ufe0f\ufe0e", "\u2764\ufe0f"),  # one per char
    ],
)
def test_presentation_selectors_kept_only_after_an_emoji_base(raw: str, expected: str) -> None:
    assert sanitize_title(raw) == expected


def test_joiner_and_selector_label_spoof_is_refused() -> None:
    # 'Y<ZWJ>e<VS16>s' passed option labels before G4.
    spoof = f"Y{chr(0x200D)}e{chr(0xFE0F)}s"
    assert sanitize_outgoing_line(spoof, name="f", max_chars=40) == "Yes"
    with pytest.raises(ValidationError, match="forbidden character"):
        reject_invisible(spoof, name="f")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ab \u200d", "ab"),
        ("ab\u200d \ufe0f ", "ab"),
        ("\U0001f469\u200d", "\U0001f469"),
        ("\u2764\ufe0f", "\u2764"),
        ("a\u094d", "a\u094d"),  # marks stay
        ("", ""),
    ],
)
def test_trim_cut_end_drops_dangling_joiners(raw: str, expected: str) -> None:
    assert trim_cut_end(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        *("\u3164", "\u115f\u1160", "\uffa0", "\u2800\u2800", " \u3000 ", "\u0301"),
        *("\u200d\u200c", "\ufe0f", "\ufffc", "\U00016fe4", "\U0001d159"),
    ],
)
def test_title_needs_a_visible_character(raw: str) -> None:
    with pytest.raises(ValidationError):
        sanitize_title(raw)


def test_title_with_blank_lookalike_and_visible_char_is_kept() -> None:
    assert sanitize_title("a\u2800b") == "a\u2800b"


def test_raw_length_is_pre_rejected_before_sanitizing() -> None:
    assert sanitize_title("x" + "\u200b" * (4 * TITLE_MAX_CHARS - 1)) == "x"
    with pytest.raises(ValidationError):
        sanitize_title("x" + "\u200b" * (4 * TITLE_MAX_CHARS))
    assert sanitize_description(" " * (4 * DESCRIPTION_MAX_CHARS)) == ""
    with pytest.raises(ValidationError):
        sanitize_description(" " * (4 * DESCRIPTION_MAX_CHARS + 1))


_TEXT_ALPHABET = st.sampled_from(
    [
        *("a", "b", " ", "\n", "\t", "\r", "\u0301", "e", "\u094d", "\u0915"),
        *("\u200c", "\u200d", "\u200b", "\ufe0f", "\ufe0e", "\u2764", "\U0001f525"),
        *("\u3164", "\u115f", "\u2800", "\u034f", "\U000e0041", "\U000e0100", "\u202e"),
    ]
)


@given(st.lists(_TEXT_ALPHABET, max_size=40).map("".join))
def test_sanitizers_idempotent_on_joiner_heavy_input(raw: str) -> None:
    for fn in (sanitize_title, sanitize_description):
        try:
            once = fn(raw)
        except ValidationError:
            continue
        assert fn(once) == once
        assert "\u200b" not in once
        assert not any(0xE0000 <= ord(ch) <= 0xE0FFF for ch in once)


# --- outgoing alert text: no links (C35) -------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "a://b",
        "www.x",
        "WwW.x",
        "host.tld/",
        "a-b.co/path",
        "h.io:8080/",
        "1.2.3.4/",
        "1.2.3.4:5/",
        "x\uff0eyz/z",  # fullwidth full stop
        "x\uff61yz/z",  # halfwidth ideographic full stop
        "\u24e6\u24e6\u24e6.x",  # circled letters: NFKC -> "www"
    ],
)
def test_reject_links_refuses_link_shapes(text: str) -> None:
    with pytest.raises(ValidationError, match=r"^field must not contain links"):
        reject_links(text, name="field")


@pytest.mark.parametrize(
    "text", ["app.js", "src/app.js", "1.2.3/4", "and/or", "e.g. this", "3.5/5", "a. b/c"]
)
def test_reject_links_keeps_plain_text(text: str) -> None:
    assert reject_links(text, name="field") == text


def test_sanitize_outgoing_line_sanitizes_then_checks() -> None:
    assert sanitize_outgoing_line(" a\u200bb\n", name="f", max_chars=5) == "ab"
    with pytest.raises(ValidationError):
        sanitize_outgoing_line("w\u200bww.x", name="f", max_chars=40)  # hidden by ZWSP


def test_reject_links_is_fast_on_long_look_alike_runs() -> None:
    text = ("a" * 63 + ".") * 12
    assert reject_links(text, name="f") == text


# --- outgoing alert text: invisible chars (C35, backlog G1) ---------------------------


def test_sanitize_outgoing_line_drops_blank_lookalikes() -> None:
    # Item titles keep U+2800 (see above); alert text must not.
    assert sanitize_outgoing_line("a\u2800b", name="f", max_chars=5) == "ab"
    with pytest.raises(ValidationError):
        sanitize_outgoing_line("\u2800\u2800", name="f", max_chars=5)


@pytest.mark.parametrize(
    "text",
    [
        *(f"a{ch}b" for ch in ("\u200b", "\u2060", "\U000e0041", "\u2800", "\u3164")),
        *(f"a{ch}b" for ch in ("\u00ad", "\u034f", "\u202e", "\x00", "\n")),
        "\u200dab",
        "a\ufe0f\ufe0f",
    ],
)
def test_reject_invisible_refuses_what_sanitizing_would_remove(text: str) -> None:
    with pytest.raises(ValidationError, match=r"^f contains a forbidden character$"):
        reject_invisible(text, name="f")


def test_reject_invisible_keeps_emoji_sequences_and_allowed_chars() -> None:
    for text in ("\u2764\ufe0f", "\U0001f469\u200d\U0001f4bb", "a b"):
        assert reject_invisible(text, name="f") == text
    assert reject_invisible("a\nb", name="f", keep=frozenset({"\n"})) == "a\nb"


@given(st.lists(_TEXT_ALPHABET, max_size=40).map("".join))
def test_outgoing_lines_always_pass_reject_invisible(raw: str) -> None:
    # The check and the sanitizer are one policy: sanitized output is accepted.
    try:
        line = sanitize_outgoing_line(raw, name="f", max_chars=TITLE_MAX_CHARS)
    except ValidationError:
        return
    assert reject_invisible(line, name="f") == line


_JOINER_ALPHABET = st.sampled_from(
    [
        *("a", "Y", "1", "#", " ", "\u00e9", "\uff21", "\u0915", "\u094d", "\u0645"),
        *("\u2764", "\U0001f525", "\U0001f3fd", "\u2139", "\u20e3", "\u2800", "\ufffc"),
        *("\u200c", "\u200d", "\ufe0f", "\ufe0e", "\u200b"),
    ]
)


@settings(max_examples=300)
@given(st.lists(_JOINER_ALPHABET, max_size=30).map("".join))
def test_kept_joiners_and_selectors_always_sit_in_a_sequence(raw: str) -> None:
    # G4: whatever survives any sanitizer is a joiner between two chars that
    # take one, or a selector after an emoji base; never next to ASCII text.
    outputs: list[str] = []
    for fn in (
        sanitize_title,
        sanitize_description,
        lambda t: sanitize_outgoing_line(t, name="f", max_chars=TITLE_MAX_CHARS),
    ):
        with contextlib.suppress(ValidationError):
            outputs.append(fn(raw))
    for text in outputs:
        for i, ch in enumerate(text):
            prev, nxt = text[i - 1] if i else "", text[i + 1 : i + 2]
            if ch in JOINERS:
                assert prev in PRESENTATION_SELECTORS or takes_joiner(prev)
                assert takes_joiner(nxt)
            elif ch in PRESENTATION_SELECTORS:
                assert prev and takes_presentation_selector(prev, nxt)
