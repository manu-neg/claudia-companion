"""Security tests for C35 hardening (F-A): no links, required session, scan what leaves.

Every outgoing field (prompt, option labels, session label, notification
title) rejects web addresses; the Telegram channel defangs whatever could
still be auto-linked; the alert as rendered is secret-scanned, NFKC-folded
so fullwidth look-alikes are caught; the session label is mandatory.
"""

from __future__ import annotations

import sys
import unicodedata
from datetime import timedelta
from typing import Any

import pytest

from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.adapters.telegram.channel import TelegramChannel, defang
from preview_dashboard.application.notify import scan_texts
from preview_dashboard.application.questions import AskCommand
from preview_dashboard.domain.errors import SecretDetectedError, ValidationError
from preview_dashboard.domain.notifications import DeliveryPayload, MessageButton, MessageContent
from preview_dashboard.domain.questions import Question, QuestionOption
from tests.builders import T0
from tests.fakes import FAKE_SECRET, FakeContentScanner
from tests.notify_support import (
    DASHBOARD,
    NotifyHarness,
    build_harness,
    make_notification,
    make_question,
    qid,
)
from tests.telegram_support import OWNER, FakeBotApi, message, ok

pytestmark = pytest.mark.security

OPTIONS = [("a", "Yes"), ("b", "No")]


def _fullwidth(text: str) -> str:
    """ASCII -> fullwidth forms (NFKC folds them back)."""
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


LINKS = [
    "see https://evil.example",
    "hxxps://evil.example",
    "tg://resolve?domain=evil",
    "go to www.evil.example",
    "WWW.Evil.Example",
    "login at evil.example/login",
    "t.me/evil_bot",
    "EVIL.EXAMPLE/X",
    "evil.example:8443/x",
    "10.0.0.1/admin",
    "10.0.0.1:80/admin",
    "evil\u3002example/x",  # ideographic full stop: a dot to IDNA
    _fullwidth("evil.example/x"),
    _fullwidth("https://x"),
    "evil\u2024example/x",  # one dot leader: NFKC -> "."
]

ALLOWED = [
    "Deploy app.js and README.md?",
    "Bump to v1.2.3 or 2.0?",
    "Merge src/app.js into main?",
    "Keep 3.5/5 rating and/or retry",
    "Use e.g. SQLite",
]


@pytest.fixture
def h() -> NotifyHarness:
    return build_harness()


# --- domain: no link in any outgoing field ---------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    ("field", "build"),
    [
        ("prompt", lambda text: make_question(prompt=text)),
        ("option label", lambda text: QuestionOption(key="a", label=text[:40])),
        ("session label", lambda text: make_question(session_label=text[:40])),
        ("title", lambda text: make_notification(title=text)),
    ],
)
def test_c35_links_are_rejected_in_every_outgoing_field(field: str, build: Any, link: str) -> None:
    with pytest.raises(ValidationError) as err:
        build(link)
    message_text = str(err.value)
    assert field in message_text
    assert link not in message_text and "evil" not in message_text  # never echoes the value


@pytest.mark.parametrize("text", ALLOWED)
def test_c35_file_names_and_plain_text_stay_allowed(text: str) -> None:
    assert make_question(prompt=text).prompt == text
    assert make_notification(title=text).title == text


def test_c35_links_are_refused_by_ask_and_notify_before_anything_is_stored(
    h: NotifyHarness,
) -> None:
    for cmd in (
        AskCommand(prompt="open evil.example/x", options=OPTIONS, session_label="s1"),
        AskCommand(prompt="p", options=[("a", "www.evil.example"), ("b", "no")], session_label="s"),
        AskCommand(prompt="p", options=OPTIONS, session_label="https://x"),
    ):
        with pytest.raises(ValidationError):
            h.questions.ask(cmd)
    with pytest.raises(ValidationError):
        h.notify.notify("done", "shipped: evil.example/release")
    assert h.repo.count() == 0
    assert h.outbox.notifications == {}


def test_c35_message_content_rejects_links_too() -> None:
    # The notifier re-validates every task through MessageContent (wire).
    with pytest.raises(ValidationError):
        MessageContent(text="❓ open https://evil.example")


# --- session label: required, shown on every alert --------------------------------------


@pytest.mark.parametrize("label", [None, "", " \u200b "])
def test_c35_session_label_is_required(h: NotifyHarness, label: str | None) -> None:
    with pytest.raises(ValidationError):
        h.questions.ask(AskCommand(prompt="p", options=OPTIONS, session_label=label))  # type: ignore[arg-type]
    assert h.repo.count() == 0


def test_c35_every_question_alert_names_its_session(h: NotifyHarness) -> None:
    h.questions.ask(AskCommand(prompt="Ship?", options=OPTIONS, session_label="repo: dash"))
    (pending,) = h.outbox_service.pending(20)
    assert pending.payload.content.text.splitlines()[1] == "Session: repo: dash"


# --- scan what leaves: rendered text, NFKC-folded ----------------------------------------


def test_c35_rendered_alert_is_scanned() -> None:
    # Only the rendered text ("Session: " prefix + label) contains the marker.
    markers = {b"Session: sneaky": "rendered marker", "\u2705 sneaky".encode(): "rendered marker"}
    h = build_harness(scanner=FakeContentScanner(markers))
    with pytest.raises(SecretDetectedError):
        h.questions.ask(AskCommand(prompt="p", options=OPTIONS, session_label="sneaky"))
    with pytest.raises(SecretDetectedError):
        h.notify.notify("done", "sneaky")
    assert h.repo.count() == 0
    assert h.outbox.notifications == {}


def test_c35_fullwidth_secret_is_caught(h: NotifyHarness) -> None:
    wide = _fullwidth(FAKE_SECRET.decode())
    assert unicodedata.normalize("NFC", wide) == wide  # sanitizing alone would not fold it
    with pytest.raises(SecretDetectedError):
        h.questions.ask(AskCommand(prompt=f"use {wide}?", options=OPTIONS, session_label="s1"))
    with pytest.raises(SecretDetectedError):
        h.notify.notify("failed", wide)


def test_c35_fullwidth_telegram_bot_token_is_caught_by_the_real_scanner() -> None:
    # Built at runtime: no token-shaped literal in the repository.
    token = "1234" + "56789" + ":" + "AA" + "x" * 33
    for text in (token, _fullwidth(token)):
        with pytest.raises(SecretDetectedError) as err:
            scan_texts(RegexSecretScanner(), [f"deploy with {text}"])
        assert err.value.rule == "Telegram bot token"
        assert token not in str(err.value)


# --- joiners/selectors cannot split secrets or spoof labels (G4) ----------------------

_ZWJ, _ZWNJ, _VS16 = chr(0x200D), chr(0x200C), chr(0xFE0F)
_AWS_KEY = "AK" + "IA" + "Q" * 16  # built at runtime: no key-shaped literal in the repo


def _split(text: str, sep: str) -> str:
    return sep.join(text)


@pytest.mark.parametrize("sep", [_ZWJ, _ZWNJ, _VS16, _ZWJ + _VS16])
def test_c35_joiner_split_secret_is_refused_by_content_and_caught_by_the_scan(sep: str) -> None:
    split = _split(_AWS_KEY, sep)
    with pytest.raises(ValidationError, match="forbidden character"):
        MessageContent(text=f"key {split}")
    with pytest.raises(ValidationError):
        MessageButton(key="a", label=_split("AKIA", sep))
    # The scan also sees a copy with every joiner/selector removed (C35).
    for text in (split, _fullwidth(split)):
        with pytest.raises(SecretDetectedError) as err:
            scan_texts(RegexSecretScanner(), [f"deploy with {text}"])
        assert err.value.rule == "AWS access key id"
        assert _AWS_KEY not in str(err.value)


def test_c35_joiner_split_secret_never_leaves_via_ask_or_notify(h: NotifyHarness) -> None:
    split = _split(FAKE_SECRET.decode(), _ZWJ)
    with pytest.raises(SecretDetectedError):
        h.questions.ask(AskCommand(prompt=f"use {split}?", options=OPTIONS, session_label="s1"))
    with pytest.raises(SecretDetectedError):
        h.questions.ask(AskCommand(prompt="p", options=OPTIONS, session_label=split))
    with pytest.raises(SecretDetectedError):
        h.notify.notify("done", split)
    assert h.repo.count() == 0
    assert h.outbox.notifications == {}


def test_c35_joiner_spoofed_label_is_cleaned_and_relayed_copy_refused(h: NotifyHarness) -> None:
    spoof = f"Y{_ZWJ}e{_VS16}s"  # rendered "Yes"; passed labels before G4
    h.questions.ask(AskCommand(prompt="p", options=[("a", spoof), ("b", "No")], session_label="s"))
    (pending,) = h.outbox_service.pending(20)
    assert pending.payload.content.buttons[0].label == "Yes"
    with pytest.raises(ValidationError):
        MessageButton(key="a", label=spoof)


_BLANK_LOOKALIKES = [chr(cp) for cp in (0x2800, 0x1D159, 0x16FE4, 0xFFFC)]
_HANGUL_FILLERS = [chr(cp) for cp in (0x3164, 0x115F, 0x1160, 0xFFA0)]


@pytest.mark.parametrize("ch", _BLANK_LOOKALIKES + _HANGUL_FILLERS)
def test_c35_fields_made_only_of_blank_lookalikes_are_refused(h: NotifyHarness, ch: str) -> None:
    blank = ch * 3
    with pytest.raises(ValidationError):
        QuestionOption(key="a", label=blank)
    with pytest.raises(ValidationError):
        h.questions.ask(AskCommand(prompt=blank, options=OPTIONS, session_label="s1"))
    with pytest.raises(ValidationError):
        h.questions.ask(AskCommand(prompt="p", options=OPTIONS, session_label=blank))
    with pytest.raises(ValidationError):
        h.notify.notify("done", blank)
    with pytest.raises(ValidationError):
        MessageContent(text=f"a{ch}b")
    with pytest.raises(ValidationError):
        MessageButton(key="a", label=f"a{ch}b")
    # Mixed with visible text they are dropped from every outgoing field.
    assert QuestionOption(key="a", label=f"Y{ch}es").label == "Yes"
    assert h.repo.count() == 0


# --- Telegram: defang what could still be auto-linked ----------------------------------


def test_c35_telegram_defangs_hostnames_in_text_and_labels() -> None:
    payload = DeliveryPayload(
        content=MessageContent(
            text="❓ Ship evil.example build of app.js? ping @evil_bot\nSession: s1",
            buttons=(
                MessageButton(key="a", label="yes, 10.0.0.1"),
                MessageButton(key="b", label="mail me@evil.example"),
            ),
        ),
        question_id=qid(1),
    )
    api = FakeBotApi()
    api.script("sendMessage", ok(message(5)))
    TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD).send(payload)
    body = api.calls[0].body
    shown = [
        body["text"],
        *(b["text"] for row in body["reply_markup"]["inline_keyboard"] for b in row),
    ]
    for text in shown:
        assert "evil.example" not in text and "10.0.0.1" not in text and "@evil" not in text
    assert "evil\u2024example" in body["text"] and "app\u2024js" in body["text"]
    assert body["link_preview_options"] == {"is_disabled": True}
    assert "parse_mode" not in body


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("evil.example", "evil\u2024example"),
        ("a\u3002b", "a\u2024b"),
        ("me@host", "me\uff20host"),
        ("x://y", "x:\u2215\u2215y"),
        ("end. Next", "end. Next"),
        ("3.14", "3\u202414"),
    ],
)
def test_c35_defang_keeps_length_and_readability(raw: str, expected: str) -> None:
    assert defang(raw) == expected
    assert len(defang(raw)) == len(raw)


def _nfkc_dots() -> list[str]:
    # Every char that folds to a dot separator (IDNA maps U+3002 to "." too).
    return [
        chr(cp)
        for cp in range(sys.maxunicode + 1)
        if unicodedata.normalize("NFKC", chr(cp)) in {".", "。"}
    ]


def test_c35_defang_covers_every_nfkc_dot_like() -> None:
    dots = _nfkc_dots()
    assert {"\ufe12", "\ufe52", "\uff0e", "\u3002", "\uff61", "\u2024"} <= set(dots)
    for dot in [".", *dots]:
        assert defang(f"evil{dot}example") == "evil\u2024example", hex(ord(dot))


def test_c35_question_field_validation_also_guards_stored_rows() -> None:
    # Rows are rebuilt through the constructors, so a URL planted in the DB fails closed.
    with pytest.raises(ValidationError):
        Question(
            id=qid(1),
            prompt="evil.example/x",
            options=(QuestionOption(key="a", label="A"), QuestionOption(key="b", label="B")),
            created_at=T0,
            expires_at=T0 + timedelta(hours=1),
            updated_at=T0,
        )
