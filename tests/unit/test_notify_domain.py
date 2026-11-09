"""Unit tests for `domain/notifications.py`: messages, links, notifications, delivery tasks."""

from __future__ import annotations

import itertools
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.notifications import (
    MAX_DELIVERY_ATTEMPTS,
    DashboardLinks,
    DeliveryAction,
    DeliveryPayload,
    DeliveryState,
    DeliveryTask,
    MessageButton,
    MessageContent,
    PendingTask,
    backoff_delay,
    dashboard_origin,
    is_dashboard_link,
    parse_task_id,
    validate_message_ref,
)
from preview_dashboard.domain.questions import QuestionOption, QuestionState, sanitize_option_label
from preview_dashboard.domain.text import TITLE_MAX_CHARS, sanitize_outgoing_line
from preview_dashboard.events import default_event_registry
from preview_dashboard.events.base import RenderContext
from tests.builders import T0, ulid
from tests.notify_support import DASHBOARD, make_content, make_notification, make_task, qid, tid

pytestmark = pytest.mark.unit

# Invisible/control characters built from code points (never literal in source).
RLO = chr(0x202E)
LRI = chr(0x2066)
NUL = chr(0)
BEL = chr(7)
LSEP = chr(0x2028)


# --- MessageContent -------------------------------------------------------------


def test_message_content_happy() -> None:
    content = MessageContent(
        text="line 1\nline 2",
        buttons=(MessageButton(key="a", label="A"),),
        link=f"{DASHBOARD}/#/item/{ulid(1)}",
    )
    assert content.buttons[0].key == "a"


@pytest.mark.parametrize(
    "text", ["", "x" * 301, f"a{RLO}b", f"a{LRI}b", f"a{NUL}b", f"a{BEL}b", f"a{LSEP}b", "a\rb"]
)
def test_message_text_rejected(text: str) -> None:
    with pytest.raises(ValidationError):
        MessageContent(text=text)


def test_message_text_allows_300_chars_and_emoji() -> None:
    assert len(MessageContent(text="❓" + "x" * 299).text) == 300


def test_buttons_bounded_and_unique() -> None:
    nine = tuple(MessageButton(key=f"k{i}", label="x") for i in range(9))
    with pytest.raises(ValidationError):
        MessageContent(text="x", buttons=nine)
    dup = (MessageButton(key="a", label="x"), MessageButton(key="a", label="y"))
    with pytest.raises(ValidationError):
        MessageContent(text="x", buttons=dup)
    with pytest.raises(ValidationError):
        MessageContent(text="x", buttons=(("a", "b"),))  # type: ignore[arg-type]


def test_button_label_must_already_be_sanitized() -> None:
    # A relayed/stored label is checked, never silently cleaned (C35).
    assert MessageButton(key="a", label="Yes").label == "Yes"
    for label in (f" Ye{RLO}s ", " Yes", "Ye\u200bs"):
        with pytest.raises(ValidationError):
            MessageButton(key="a", label=label)


# Invisible chars from the Copilot review of PR #1 (backlog G1), plus
# misplaced emoji joiners: every one is refused in text and labels.
INVISIBLE = [
    "\u200b",  # ZERO WIDTH SPACE
    "\u2060",  # WORD JOINER
    "\U000e0041",  # TAG LATIN CAPITAL LETTER A
    "\u2800",  # BRAILLE PATTERN BLANK
    "\u3164",  # HANGUL FILLER
    "\u00ad",  # SOFT HYPHEN
    "\u034f",  # COMBINING GRAPHEME JOINER
    # G4: joiners/selectors between ASCII chars, more blank look-alikes.
    "\u200d",  # ZERO WIDTH JOINER
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\ufe0f",  # VARIATION SELECTOR-16
    "\ufffc",  # OBJECT REPLACEMENT CHARACTER
    "\U00016fe4",  # KHITAN SMALL SCRIPT FILLER
    "\U0001d159",  # MUSICAL SYMBOL NULL NOTEHEAD
]


@pytest.mark.parametrize("ch", INVISIBLE)
def test_invisible_chars_rejected_in_text_and_labels(ch: str) -> None:
    with pytest.raises(ValidationError, match="forbidden character"):
        MessageContent(text=f"a{ch}b")
    with pytest.raises(ValidationError):
        MessageButton(key="a", label=f"a{ch}b")


@pytest.mark.parametrize(
    "text",
    [
        "\u200dx",  # ZWJ without a visible char before it
        "x\u200d\n",  # ZWJ before a line break
        "x\ufe0f\ufe0f",  # a run of VS16 (hidden-data channel)
        "\ufe0fx",  # VS16 with nothing to modify
    ],
)
def test_misplaced_emoji_joiners_rejected(text: str) -> None:
    with pytest.raises(ValidationError):
        MessageContent(text=text)


@pytest.mark.parametrize(
    "text",
    [
        "❤\ufe0f done",  # heart + VS16
        "\U0001f469\u200d\U0001f4bb deployed",  # woman technologist (ZWJ sequence)
        "❓ Which DB?\nSession: s1\n⌛ Expired",
        "क\u094d\u200dष",  # Devanagari half form (virama + ZWJ)
    ],
)
def test_emoji_and_script_sequences_still_accepted(text: str) -> None:
    label = text.split(" ")[0].split("\n")[0]
    content = MessageContent(text=text, buttons=(MessageButton(key="a", label=label),))
    assert content.text == text and content.buttons[0].label == label


_ALERT_ALPHABET = st.sampled_from(
    [
        *("a", "b", " ", "\n", "\u0301", "\u094d", "क", "❤", "\U0001f525", "x" * 30),
        *("\u200c", "\u200d", "\u200b", "\ufe0f", "\u2800", "\u3164", "\U000e0041", "\u00ad"),
    ]
)


@settings(max_examples=300)
@given(
    title=st.lists(_ALERT_ALPHABET, max_size=12).map("".join),
    label=st.lists(_ALERT_ALPHABET, max_size=6).map("".join),
    event=st.sampled_from(["question", "done", "failed"]),
    final_state=st.sampled_from([None, QuestionState.ANSWERED, QuestionState.EXPIRED]),
)
def test_any_sanitized_alert_renders_to_valid_content(
    title: str, label: str, event: str, final_state: QuestionState | None
) -> None:
    # Sanitizer and MessageContent share one policy, so whatever the services
    # accept (incl. the title cut in compose_text) always renders.
    try:
        clean_title = sanitize_outgoing_line(title, name="t", max_chars=TITLE_MAX_CHARS)
        clean_label = sanitize_option_label(label)
    except ValidationError:
        return
    ctx = RenderContext(
        title=clean_title,
        session_label="s" * 40,  # long lines force the title cut (with "…")
        options=(QuestionOption(key="a", label=clean_label), QuestionOption(key="b", label="No")),
        final_state=final_state if event == "question" else None,
        answer_label=clean_label,
    )
    content = default_event_registry().get(event).render(ctx)
    assert all(b.label in (clean_label, "No") for b in content.buttons)


@pytest.mark.parametrize(
    "link",
    [
        "http://dash.example/",
        "javascript:alert(1)",
        "https://dash.example",  # no path
        "https://Dash.example/",
        "https://dash.example/a b",
        "https://dash.example/?q=1",
        "https://user@dash.example/",
        "https://dash.example/" + "a" * 201,
        "",
    ],
)
def test_links_rejected(link: str) -> None:
    with pytest.raises(ValidationError):
        MessageContent(text="x", link=link)


# --- DashboardLinks ---------------------------------------------------------------


def test_dashboard_links() -> None:
    links = DashboardLinks(DASHBOARD)
    assert links.link_for(None) == f"{DASHBOARD}/"
    assert links.link_for(ulid(3)) == f"{DASHBOARD}/#/item/{ulid(3)}"  # type: ignore[arg-type]
    assert DashboardLinks().link_for(ulid(3)) is None  # type: ignore[arg-type]
    assert DashboardLinks("https://h.example:8443").link_for(None) == "https://h.example:8443/"


def test_dashboard_link_never_embeds_an_unvalidated_id() -> None:
    with pytest.raises(ValidationError):
        DashboardLinks(DASHBOARD).link_for("../../evil")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "base", ["http://h.example", "https://h.example/", "https://H.example", "h.example", ""]
)
def test_dashboard_base_rejected(base: str) -> None:
    with pytest.raises(ValidationError):
        DashboardLinks(base)


def test_dashboard_origin_is_the_first_allowed_host() -> None:
    assert dashboard_origin(frozenset({"b.example", "a.example"})) == "https://a.example"
    assert dashboard_origin(()) is None
    with pytest.raises(ValidationError):
        dashboard_origin(["Evil.example"])


@pytest.mark.parametrize(
    "link",
    [f"{DASHBOARD}/", f"{DASHBOARD}/#/item/{ulid(1)}", f"{DASHBOARD}/a/b"],
)
def test_is_dashboard_link_accepts_the_origin_only(link: str) -> None:
    assert is_dashboard_link(link, DASHBOARD)
    assert not is_dashboard_link(link, None)  # no origin: fail closed
    assert not is_dashboard_link(link, "https://other.example")


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/login",  # Copilot's case: queryless foreign link
        f"{DASHBOARD}.evil.example/",
        f"{DASHBOARD}@evil.example/",
        f"{DASHBOARD}:8443/",
        f"{DASHBOARD}:443/",
        DASHBOARD.replace("https://", "http://") + "/",
        DASHBOARD,  # no path
        f"{DASHBOARD}/?next=x",
        f"{DASHBOARD}/" + "a" * 600,
    ],
)
def test_is_dashboard_link_rejects_look_alikes(link: str) -> None:
    assert not is_dashboard_link(link, DASHBOARD)


def test_is_dashboard_link_rejects_a_malformed_origin() -> None:
    assert not is_dashboard_link(f"{DASHBOARD}/", f"{DASHBOARD}/")
    assert not is_dashboard_link(None, DASHBOARD)  # type: ignore[arg-type]


# --- backoff -------------------------------------------------------------------------


def test_backoff_grows_and_caps() -> None:
    delays = [backoff_delay(n).total_seconds() for n in range(1, 9)]
    assert delays[:4] == [5, 20, 80, 320]
    assert delays[-1] == 1800
    assert all(a <= b for a, b in itertools.pairwise(delays))
    assert backoff_delay(10_000) == timedelta(minutes=30)
    with pytest.raises(ValueError):
        backoff_delay(0)


# --- Notification ----------------------------------------------------------------------


def test_notification_title_sanitized() -> None:
    assert make_notification(title=f" Deploy{RLO} done\n").title == "Deploy done"


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_type": "Done"},
        {"title": ""},
        {"title": "x" * 201},
        {"item_id": "x"},
        {"question_id": "x"},
        {"id": "x"},
    ],
)
def test_notification_invalid(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_notification(**overrides)


# --- DeliveryTask ------------------------------------------------------------------------


def test_new_send_and_resolve() -> None:
    send = DeliveryTask.new_send(
        id=tid(1),
        notification_id=make_notification().id,
        channel="fake",
        content=make_content(),
        now=T0,
    )
    assert (send.state, send.attempts, send.next_attempt_at) == (DeliveryState.PENDING, 0, T0)
    resolve = DeliveryTask.new_resolve(
        id=tid(2),
        notification_id=make_notification().id,
        channel="fake",
        content=make_content(),
        final_state=QuestionState.CANCELLED,
        now=T0,
    )
    assert resolve.action is DeliveryAction.RESOLVE


@pytest.mark.parametrize(
    "overrides",
    [
        {"channel": "Fake"},
        {"attempts": -1},
        {"attempts": MAX_DELIVERY_ATTEMPTS + 1},
        {"attempts": True},
        {"message_ref": "msg-1"},  # PENDING with a ref
        {"state": DeliveryState.DONE, "message_ref": "has space"},
        {"state": DeliveryState.DONE, "message_ref": "x" * 65},
        {"final_state": QuestionState.ANSWERED},  # SEND with a final state
        {"action": DeliveryAction.RESOLVE, "final_state": None},
        {"action": DeliveryAction.RESOLVE, "final_state": QuestionState.OPEN},
        {
            "action": DeliveryAction.RESOLVE,
            "content": make_content(buttons=[("a", "A")]),
        },
        {"content": "text"},
        {"state": "lost"},
    ],
)
def test_delivery_task_invalid(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        make_task(**overrides)


def test_done_records_ref() -> None:
    task = make_task().done("12:34")
    assert (task.state, task.message_ref) == (DeliveryState.DONE, "12:34")
    with pytest.raises(InvalidStateError):
        task.done("x")


def test_failed_attempts_back_off_then_fail_for_good() -> None:
    task = make_task()
    now = T0
    for attempt in range(1, MAX_DELIVERY_ATTEMPTS):
        task = task.failed_attempt(now)
        assert task.state is DeliveryState.PENDING
        assert task.attempts == attempt
        assert task.next_attempt_at == now + backoff_delay(attempt)
        now = task.next_attempt_at
    task = task.failed_attempt(now)
    assert (task.state, task.attempts) == (DeliveryState.FAILED, MAX_DELIVERY_ATTEMPTS)
    with pytest.raises(InvalidStateError):
        task.failed_attempt(now)


def test_dropped() -> None:
    task = make_task(action=DeliveryAction.RESOLVE).dropped()
    assert (task.state, task.attempts) == (DeliveryState.FAILED, 0)
    with pytest.raises(InvalidStateError):
        task.dropped()


def test_message_ref_and_task_id_validators() -> None:
    assert validate_message_ref("-100123:42") == "-100123:42"
    for bad in ("", "a b", "é", "x" * 65, None):
        with pytest.raises(ValidationError):
            validate_message_ref(bad)
    with pytest.raises(ValidationError):
        parse_task_id("nope")


# --- DTOs -----------------------------------------------------------------------------------


def test_payload_rules() -> None:
    buttons = make_content(buttons=[("a", "A")])
    assert DeliveryPayload(content=buttons, question_id=qid(1)).question_id == qid(1)
    with pytest.raises(ValidationError):
        DeliveryPayload(content=buttons)  # buttons answer a question
    with pytest.raises(ValidationError):
        DeliveryPayload(content=make_content(), final_state=QuestionState.EXPIRED)
    with pytest.raises(ValidationError):
        DeliveryPayload(content=make_content(), question_id=qid(1), final_state=QuestionState.OPEN)
    with pytest.raises(ValidationError):
        DeliveryPayload(content=make_content(), question_id="x")  # type: ignore[arg-type]


def test_pending_task_rules() -> None:
    plain = DeliveryPayload(content=make_content())
    resolved = DeliveryPayload(
        content=make_content(), question_id=qid(1), final_state=QuestionState.ANSWERED
    )
    assert PendingTask(id=tid(1), channel="fake", action=DeliveryAction.SEND, payload=plain)
    assert PendingTask(
        id=tid(1),
        channel="fake",
        action=DeliveryAction.RESOLVE,
        payload=resolved,
        message_ref="msg-1",
    )
    bad = [
        {"action": DeliveryAction.RESOLVE, "payload": resolved},  # no ref
        {"action": DeliveryAction.RESOLVE, "payload": plain, "message_ref": "m"},  # no state
        {"action": DeliveryAction.SEND, "payload": plain, "message_ref": "m"},
        {"action": DeliveryAction.SEND, "payload": resolved},
        {"action": "poke", "payload": plain},
    ]
    for fields in bad:
        with pytest.raises(ValidationError):
            PendingTask(id=tid(1), channel="fake", **fields)  # type: ignore[arg-type]
