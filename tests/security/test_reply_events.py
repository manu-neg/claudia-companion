"""Security tests for the `reply` and `voice` events (M2 parts of C56).

Reply text: <= 4096 UTF-16 units, multi-line, same outgoing policy as C35
(no invisible chars, no web address), plain text + defang on Telegram, only
the pinned dashboard link button, never via `notify`, never logged. Voice:
only checked Ogg/Opus (<= 1 MiB, <= 60 s), uploaded as a file to the
owner's chat (never by URL), without a caption.
"""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.adapters.telegram.client import TelegramError
from preview_dashboard.application.delivery import DeliveryService
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    MessageButton,
    MessageContent,
    PendingTask,
)
from preview_dashboard.events import REPLY_EVENT, VOICE_EVENT, RenderContext, default_event_registry
from preview_dashboard.events.voice import VOICE_MAX_BYTES, validate_voice_audio
from preview_dashboard.wire import notifier as wire
from tests.notify_support import DASHBOARD, build_harness, qid, tid
from tests.owner_updates_support import ogg_opus
from tests.telegram_support import (
    FAKE_NOTIFIER_TOKEN,
    OWNER,
    FakeBotApi,
    FakeNotifierAdmin,
    error,
    message,
    ok,
)

pytestmark = pytest.mark.security

LINK = f"{DASHBOARD}/#/item/{qid(9)}"
REPLY_TEXT = "Claro! I merged nothing yet.\nThe review is running."


def _render(event: str, body: str | None, link: str | None = None) -> MessageContent:
    return (
        default_event_registry()
        .get(event)
        .render(RenderContext(title="Claudia", body=body, link=link))
    )


# --- reply text ----------------------------------------------------------------------------


@pytest.mark.parametrize("event", [REPLY_EVENT, VOICE_EVENT])
def test_c56_reply_renders_the_body_verbatim_with_the_link(event: str) -> None:
    content = _render(event, REPLY_TEXT, LINK)
    assert content.text == REPLY_TEXT
    assert content.link == LINK
    assert content.buttons == ()


@pytest.mark.parametrize(
    "body", ["x" * 4096, "\U0001f525" * 2048, "line\n" * 800 + "end", "\u00e9" * 4096]
)
def test_c56_reply_up_to_4096_utf16_units_is_accepted(body: str) -> None:
    assert _render(REPLY_EVENT, body).text == body


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("x" * 4097, id="4097-chars"),
        pytest.param("\U0001f525" * 2049, id="4098-utf16-units"),
        pytest.param("", id="empty"),
        pytest.param("see https://evil.example/x", id="url"),
        pytest.param("go to www.evil.example", id="www"),
        pytest.param("open evil.example/login now", id="host-path"),
        pytest.param(
            "\uff48\uff54\uff54\uff50\uff53\uff1a\uff0f\uff0fevil.example", id="fullwidth-url"
        ),
        pytest.param("hi\u200bthere", id="zwsp"),
        pytest.param("abc\u202edef", id="bidi"),
        pytest.param("tab\there", id="tab"),
        pytest.param("cr\rhere", id="cr"),
        pytest.param("\u2800\u2800", id="blank-lookalike"),
    ],
)
def test_c56_reply_breaking_the_outgoing_policy_is_refused(body: str) -> None:
    with pytest.raises(ValidationError):
        _render(REPLY_EVENT, body)


def test_c56_a_long_form_reply_cannot_carry_answer_buttons() -> None:
    with pytest.raises(ValidationError):
        MessageContent(text="x", buttons=(MessageButton(key="a", label="A"),), long_form=True)


def test_c35_alerts_keep_the_300_char_cap() -> None:
    # Only reply/voice declare a longer limit; every other content stays <= 300.
    registry = default_event_registry()
    assert registry.get(REPLY_EVENT).max_chars == registry.get(VOICE_EVENT).max_chars == 4096  # type: ignore[attr-defined]
    for long_text in ("x" * 301, "\U0001f525" * 301):
        with pytest.raises(ValidationError):
            MessageContent(text=long_text)
        with pytest.raises(ValidationError):
            MessageContent(text=long_text, buttons=(MessageButton(key="a", label="A"),))
    assert MessageContent(text="x" * 300).long_form is False


@pytest.mark.parametrize("event", ["question", "done", "failed"])
def test_c35_a_301_char_alert_body_is_refused(event: str) -> None:
    # A forged or tampered task can't use the reply limit for an alert.
    kind = default_event_registry().get(event)
    content = kind.render(RenderContext(title="t" * 200, session_label="s"))
    assert len(content.text) <= 300 and content.long_form is False
    body = {
        "id": tid(1),
        "channel": "telegram",
        "action": "send",
        "payload": {
            "text": "x" * 301,
            "buttons": [{"key": "a", "label": "A"}] if event == "question" else [],
            "link": None,
            "question_id": qid(1) if event == "question" else None,
        },
    }
    with pytest.raises(ValidationError):
        wire.parse_task(body)


@pytest.mark.parametrize("flag", [1, "true", None, False])
def test_c35_long_form_flag_must_be_exactly_true_to_lift_the_cap(flag: object) -> None:
    body = {
        "id": tid(1),
        "channel": "telegram",
        "action": "send",
        "payload": {"text": "x" * 301, "buttons": [], "link": None, "long_form": flag},
    }
    with pytest.raises(ValidationError):
        wire.parse_task(body)


def test_c35_alert_payload_json_is_unchanged() -> None:
    payload = DeliveryPayload(content=MessageContent(text="✅ done"))
    assert "long_form" not in wire.payload_to_json(payload)


@pytest.mark.parametrize("event", [REPLY_EVENT, VOICE_EVENT])
def test_c56_reply_events_cannot_be_sent_through_notify(event: str) -> None:
    # Only the Claudia host posts replies (its own token + budget, M3).
    h = build_harness()
    with pytest.raises(ValidationError):
        h.notify.notify(event, "Looks like a reply")
    assert h.outbox.tasks == {}
    assert h.outbox.notifications == {}


def test_c56_long_reply_task_round_trips_the_wire() -> None:
    body = "a\n" * 2000 + "end"
    payload = DeliveryPayload(content=MessageContent(text=body, link=LINK, long_form=True))
    task = PendingTask(id=tid(1), channel="telegram", action=DeliveryAction.SEND, payload=payload)
    assert wire.parse_task(wire.task_to_json(task)).payload.content.text == body


def test_c56_reply_is_plain_text_defanged_with_only_the_pinned_link() -> None:
    api = FakeBotApi()
    api.script("sendMessage", ok(message(9)))
    channel = TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD)
    body = "Done: see app.js and ping @someone\n" + "x" * 3000
    channel.send(DeliveryPayload(content=MessageContent(text=body, link=LINK, long_form=True)))
    [call] = api.calls
    assert "parse_mode" not in call.body
    assert call.body["link_preview_options"] == {"is_disabled": True}
    assert "app\u2024js" in call.body["text"]
    assert "\uff20someone" in call.body["text"]
    assert len(call.body["text"]) == len(body)
    assert call.body["reply_markup"] == {
        "inline_keyboard": [[{"text": "Open dashboard", "url": LINK}]]
    }


def test_c56_reply_text_is_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    private_words = "the owner's private reply words"
    admin = FakeNotifierAdmin()
    task = PendingTask(
        id=tid(1),
        channel="telegram",
        action=DeliveryAction.SEND,
        payload=DeliveryPayload(content=MessageContent(text=private_words)),
    )
    admin.route("GET", wire.TASKS_PATH, httpx.Response(200, json=wire.tasks_to_json([task])))
    admin.route("POST", wire.task_failed_path(tid(1)), httpx.Response(204))
    api = FakeBotApi()
    api.script("sendMessage", error(400, f"Bad Request: can't parse {private_words}"))
    service = DeliveryService(
        queue=AdminDeliveryQueue(Path("/x.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport()),
        channels=[TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD)],
    )
    with caplog.at_level(logging.DEBUG):
        assert service.run_once_deliveries() == 0
    assert "private reply" not in caplog.text


# --- voice ----------------------------------------------------------------------------------------


def test_c56_voice_audio_within_the_caps_is_accepted() -> None:
    audio = ogg_opus(59.5)
    checked = validate_voice_audio(audio)
    assert checked.data == audio
    assert 59 < checked.seconds <= 60


@pytest.mark.parametrize(
    "audio",
    [
        pytest.param(ogg_opus(60.5), id="over-60s"),
        pytest.param(ogg_opus(2.0) + b"\x00" * VOICE_MAX_BYTES, id="over-1MiB"),
        pytest.param(b"", id="empty"),
        pytest.param(b"ID3\x04" + b"\x00" * 100, id="mp3"),
        pytest.param(ogg_opus(2.0)[:-10], id="truncated"),
        pytest.param(ogg_opus(2.0).replace(b"OpusHead", b"VorbisHd"), id="not-opus"),
        pytest.param(ogg_opus(2.0) + ogg_opus(2.0), id="two-streams"),
        pytest.param(ogg_opus(2.0)[: -(27 + 1 + 200)], id="no-eos"),  # last page dropped
        pytest.param("not bytes", id="str"),
    ],
)
def test_c56_voice_audio_outside_the_caps_is_refused(audio: object) -> None:
    with pytest.raises(ValidationError):
        validate_voice_audio(audio)


def test_c56_voice_is_uploaded_as_a_file_to_the_owner_chat_without_caption() -> None:
    api = FakeBotApi()
    api.script("sendVoice", ok(message(31)))
    channel = TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD)
    audio = ogg_opus(3.0)
    assert channel.send_voice(audio) == f"{OWNER}:31"
    [call] = api.calls
    assert call.method == "sendVoice"
    assert str(call.request.url).startswith("https://api.telegram.org/bot")
    content_type = call.request.headers["content-type"]
    assert content_type.startswith("multipart/form-data")
    raw = call.request.content
    assert f'name="chat_id"\r\n\r\n{OWNER}\r\n'.encode() in raw
    assert b'name="voice"; filename="voice.ogg"' in raw
    assert b"Content-Type: audio/ogg" in raw
    assert audio in raw
    assert b'name="caption"' not in raw


def test_c56_bad_voice_audio_never_reaches_telegram() -> None:
    api = FakeBotApi()
    channel = TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD)
    with pytest.raises(ValidationError):
        channel.send_voice(ogg_opus(61.0))
    assert api.calls == []


def test_c56_voice_cannot_be_sent_by_url_or_file_id() -> None:
    # As JSON, sendVoice would let Telegram fetch audio from any URL.
    with pytest.raises(ValueError, match="unsupported"):
        FakeBotApi().client().call("sendVoice", {"chat_id": OWNER, "voice": "https://x/y.ogg"})


def test_c56_voice_reply_from_another_chat_is_refused() -> None:
    api = FakeBotApi()
    api.script("sendVoice", ok(message(31, chat_id=OWNER + 1)))
    channel = TelegramChannel(api.client(), OWNER, dashboard_origin=DASHBOARD)
    with pytest.raises(TelegramError):
        channel.send_voice(ogg_opus(1.0))
