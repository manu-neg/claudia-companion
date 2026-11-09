"""F-CL1 item 4 (C56): the host's first reply attempt passes the admin's reply checks.

Her model output may hold tabs, CRLF, invisible chars, web addresses or more
than 4096 UTF-16 units (emoji count twice); `prepare_reply_text` normalizes
it so `validate_reply_text` and the rendered `MessageContent` accept it on the
first try. The admin's checks themselves are unchanged (still refuse raw).
"""

from __future__ import annotations

import pytest

from preview_dashboard.application.claudia.reply_text import (
    clip_utf16,
    defang_links,
    prepare_reply_text,
)
from preview_dashboard.application.claudia.runs import REPLY_REFUSED_TEXT
from preview_dashboard.application.replies import REPLY_MAX_CHARS, validate_reply_text
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import MessageContent, utf16_length
from preview_dashboard.ports.claudia_host import RunOutcome
from tests.claudia_host_support import FakeRunner, host_rig, message

pytestmark = pytest.mark.security

ZWSP = "\N{ZERO WIDTH SPACE}"
ZWNJ = "\N{ZERO WIDTH NON-JOINER}"
ZWJ = "\N{ZERO WIDTH JOINER}"
GRIN = "\N{GRINNING FACE}"


def _fullwidth(text: str) -> str:
    """ASCII -> fullwidth look-alikes (built, so the source holds no confusables)."""
    return "".join(chr(ord(c) + 0xFEE0) for c in text)


RAW_REPLIES = [
    "Hecho.\tTodo bien.",
    "Line one\r\nLine two\rLine three",
    "Mira https://github.com/example-org/preview-dashboard/commit/abc123 ahora",
    "See github.com/example-org/preview-dashboard/pulls and www.example.com",
    "Docs at HTTPS://Example.ORG/x and ftp://files.example.net/y",
    "Server 192.168.1.10:8080/status is up",
    f"Fullwidth {_fullwidth('github.com')}/x and ideographic example\N{IDEOGRAPHIC FULL STOP}com/x",
    f"zero{ZWSP}width and bidi \N{RIGHT-TO-LEFT OVERRIDE}evil\N{POP DIRECTIONAL FORMATTING} ok",
    "Line\N{LINE SEPARATOR}separator and para\N{PARAGRAPH SEPARATOR}separator",
    f"emoji {GRIN}" * 900,
    "x" * 5000,
    "a\N{BELL}bell and \N{ESCAPE}[31mcolour",
    f"\N{MAN}{ZWJ}\N{WOMAN}{ZWJ}\N{GIRL} family and \N{HEAVY BLACK HEART}"
    "\N{VARIATION SELECTOR-16} heart",
]


@pytest.mark.parametrize("raw", RAW_REPLIES)
def test_fcl1_prepared_reply_passes_the_admin_checks(raw: str) -> None:
    text = prepare_reply_text(raw)
    assert text is not None
    validate_reply_text(text)  # the admin's own rule (application/replies.py)
    MessageContent(text=text, long_form=True)  # the rendered reply (events/reply.py)
    assert utf16_length(text) <= REPLY_MAX_CHARS


@pytest.mark.parametrize("raw", RAW_REPLIES[:9])
def test_fcl1_admin_still_refuses_the_raw_forms(raw: str) -> None:
    # The fix is host-side only: admin validation is not weakened.
    with pytest.raises(ValidationError):
        validate_reply_text(raw)


def test_fcl1_links_are_defanged_readably() -> None:
    out = defang_links("Mira https://github.com/example-org/x/commit/abc ahora")
    assert out == "Mira github[.]com/example-org/x/commit/abc ahora"


def test_fcl1_plain_text_is_unchanged() -> None:
    raw = "Hola! Todo listo.\nTres commits nuevos: abc123, def456.\n- Claudia " + GRIN
    assert prepare_reply_text(raw) == raw


def test_fcl1_clip_counts_utf16_units() -> None:
    clipped = clip_utf16(GRIN * 3000)
    assert utf16_length(clipped) <= REPLY_MAX_CHARS
    assert clipped.endswith("\N{HORIZONTAL ELLIPSIS}")


@pytest.mark.parametrize("raw", ["", "   ", ZWSP + ZWSP, "\t\r\n"])
def test_fcl1_nothing_left_is_none(raw: str) -> None:
    assert prepare_reply_text(raw) is None


def test_fcl1_host_sends_a_valid_first_attempt() -> None:
    raw = (
        "Listo:\thttps://github.com/example-org/preview-dashboard/commits\r\n" + ZWSP + "ok " * 2000
    )
    rig = host_rig(runner=FakeRunner(outcome=RunOutcome(exit_code=0, result_text=raw)))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert len(rig.admin.replies) == 1  # no fallback needed
    sent = rig.admin.replies[0][0]
    validate_reply_text(sent)
    assert sent != REPLY_REFUSED_TEXT


def test_fcl1_unsendable_reply_never_posts_invalid_text() -> None:
    rig = host_rig(runner=FakeRunner(outcome=RunOutcome(exit_code=0, result_text=ZWSP + ZWNJ)))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.admin.replies
    for text, _mid in rig.admin.replies:
        validate_reply_text(text)
