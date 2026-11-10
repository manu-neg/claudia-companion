"""Security tests for owner voice/photo intake on the notifier side and its config (C61).

One test per control point: only the owner's private chat (checked before
anything else), switch off = dropped plus one fixed notice per hour,
Telegram metadata caps checked before any download, the largest photo
size within the caps, documents / albums refused, bounded download on the
same Telegram host (byte cap, reported size, validated `file_path`, token
never logged), retry/drop rules, captions redacted and never logged, and
the fail-closed config switches.
"""

from __future__ import annotations

import base64
import logging
import os
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from preview_dashboard.adapters.telegram.client import BASE_URL, validate_file_path
from preview_dashboard.adapters.telegram.updates import MediaSwitches, OwnerMedia, accept_message
from preview_dashboard.config import Settings
from preview_dashboard.domain.owner_messages import CODE_REDACTED
from preview_dashboard.interfaces.notifier.commands import media_switches
from preview_dashboard.interfaces.notifier.owner_updates import (
    MEDIA_NOTICE_INTERVAL_SECONDS,
    InboxUnavailableError,
)
from preview_dashboard.wire import notifier_messages as wm
from preview_dashboard.wire.notifier_media import MEDIA_PATH
from tests.owner_updates_support import Harness, jpeg, ogg_opus, result
from tests.telegram_support import (
    FAKE_BOT_SECRET,
    FAKE_BOT_TOKEN,
    OWNER,
    STRANGER,
    message_update,
    ok,
)

pytestmark = pytest.mark.security

ON = MediaSwitches(voice=True, photo=True)
OFF_TEXT = wm.OWNER_NOTICE_TEXTS[wm.OwnerNotice.MEDIA_OFF]
REFUSED_TEXT = wm.OWNER_NOTICE_TEXTS[wm.OwnerNotice.MEDIA_REFUSED]
CAPTION = "Zebra-caption-words"


def voice_meta(data: bytes | None = None, **overrides: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "file_id": "VoiceFile_1",
        "file_unique_id": "U1",
        "duration": 5,
        "mime_type": "audio/ogg",
        "file_size": len(data) if data is not None else 1000,
    }
    meta.update(overrides)
    return meta


def photo_sizes(data: bytes | None = None) -> list[dict[str, Any]]:
    big = len(data) if data is not None else 50_000
    return [
        {"file_id": "Small", "file_unique_id": "s", "width": 90, "height": 67, "file_size": 900},
        {"file_id": "Large", "file_unique_id": "l", "width": 1280, "height": 960, "file_size": big},
    ]


def voice_update(update_id: int = 1, data: bytes | None = None, **extra: Any) -> dict[str, Any]:
    return message_update(update_id, None, voice=voice_meta(data), **extra)


def photo_update(update_id: int = 1, data: bytes | None = None, **extra: Any) -> dict[str, Any]:
    return message_update(update_id, None, photo=photo_sizes(data), **extra)


def _route(h: Harness, *batch: dict[str, Any]) -> None:
    h.updates(*batch)
    h.router.poll(50)


# --- who may send (C44 first) ------------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [
        pytest.param({"sender": STRANGER, "chat": STRANGER}, id="foreign-user"),
        pytest.param({"sender": OWNER, "chat": STRANGER}, id="foreign-chat"),
        pytest.param({"chat": -100123, "chat_type": "supergroup"}, id="group"),
        pytest.param({"chat_type": "group"}, id="group-type"),
        pytest.param({"is_bot": True}, id="bot"),
    ],
)
@pytest.mark.parametrize("build", [voice_update, photo_update], ids=["voice", "photo"])
def test_c61_non_owner_media_is_dropped_without_any_reply(build: Any, who: dict[str, Any]) -> None:
    h = Harness(media=ON)
    _route(h, build(1, **who))
    assert h.api.methods() == ["getUpdates"]  # no getFile, no notice: no oracle
    assert h.posted(MEDIA_PATH) == []


@pytest.mark.parametrize("build", [voice_update, photo_update], ids=["voice", "photo"])
def test_c61_media_not_typed_by_the_owner_is_ignored(build: Any) -> None:
    h = Harness(media=ON)
    _route(h, build(1, via_bot={"id": 5, "is_bot": True}), build(2, sender_chat={"id": -1001}))
    assert h.api.methods() == ["getUpdates"]


# --- switches -------------------------------------------------------------------------------


def test_c61_switch_off_drops_with_one_notice_per_hour() -> None:
    h = Harness()  # both switches off
    _route(h, voice_update(1), photo_update(2), voice_update(3))
    assert h.sent_texts() == [OFF_TEXT]
    assert h.posted(MEDIA_PATH) == []
    assert "getFile" not in h.api.methods()
    h.now += MEDIA_NOTICE_INTERVAL_SECONDS - 1
    _route(h, voice_update(4))
    assert h.sent_texts() == [OFF_TEXT]
    h.now += 2
    _route(h, photo_update(5))
    assert h.sent_texts() == [OFF_TEXT, OFF_TEXT]


def test_c61_each_kind_has_its_own_switch() -> None:
    data = ogg_opus(3.0)
    h = Harness(media=MediaSwitches(voice=True, photo=False))
    h.serve_file(data)
    _route(h, photo_update(1), voice_update(2, data))
    assert h.sent_texts() == [OFF_TEXT]
    posted = h.posted(MEDIA_PATH)
    assert [p["kind"] for p in posted] == ["voice"]


def test_c61_switches_need_claudia_and_exact_true() -> None:
    def cfg(**values: object) -> object:
        return SimpleNamespace(**values)

    on = {"claudia_voice_input_enabled": True, "claudia_photo_input_enabled": True}
    assert media_switches(cfg(claudia_enabled=True, **on)) == MediaSwitches(True, True)
    assert media_switches(cfg(claudia_enabled=False, **on)) == MediaSwitches()
    assert media_switches(cfg(**on)) == MediaSwitches()  # no claudia_enabled at all
    odd = {"claudia_voice_input_enabled": "true", "claudia_photo_input_enabled": 1}
    assert media_switches(cfg(claudia_enabled=True, **odd)) == MediaSwitches()


# --- metadata caps, before any download -------------------------------------------------------


@pytest.mark.parametrize(
    "update",
    [
        pytest.param(message_update(1, None, voice=voice_meta(duration=121)), id="voice-121s"),
        pytest.param(
            message_update(1, None, voice=voice_meta(file_size=2 * 1024 * 1024 + 1)),
            id="voice-over-2mib",
        ),
        pytest.param(
            message_update(
                1, None, voice={k: v for k, v in voice_meta().items() if k != "file_size"}
            ),
            id="voice-no-size",
        ),
        pytest.param(message_update(1, None, voice=voice_meta(mime_type="audio/mpeg")), id="mp3"),
        pytest.param(message_update(1, None, voice=voice_meta(file_id="a/../b")), id="bad-file-id"),
        pytest.param(
            message_update(
                1,
                None,
                photo=[{"file_id": "X", "width": 5000, "height": 300, "file_size": 9000}],
            ),
            id="photo-side-over-4096",
        ),
        pytest.param(
            message_update(
                1,
                None,
                photo=[{"file_id": "X", "width": 800, "height": 600, "file_size": 11 * 2**20}],
            ),
            id="photo-over-10mib",
        ),
        pytest.param(photo_update(1, media_group_id="album-1"), id="album"),
        pytest.param(photo_update(1, document={"file_id": "D"}), id="photo-plus-document"),
        pytest.param(message_update(1, "hi", voice=voice_meta()), id="text-plus-voice"),
        pytest.param(voice_update(1, caption="x" * 4097), id="caption-over-4096"),
        pytest.param(voice_update(1, caption="a\x00b"), id="caption-nul"),
    ],
)
def test_c61_metadata_over_the_caps_is_refused_before_any_download(
    update: dict[str, Any],
) -> None:
    h = Harness(media=ON)
    _route(h, update)
    assert "getFile" not in h.api.methods()
    assert h.downloads() == []
    assert h.posted(MEDIA_PATH) == []
    assert h.sent_texts() == [REFUSED_TEXT]


def test_c61_photo_sent_as_a_document_is_not_media() -> None:
    h = Harness(media=ON)
    _route(h, message_update(1, None, document={"file_id": "D", "mime_type": "image/jpeg"}))
    assert h.api.methods() == ["getUpdates"]  # ignored like any other non-text message
    assert h.posted(MEDIA_PATH) == []


def test_c61_largest_photo_size_within_the_caps_is_fetched() -> None:
    data = jpeg()
    h = Harness(media=ON)
    h.serve_file(data, path="photos/file_9.jpg")
    sizes = [
        *photo_sizes(data),
        {"file_id": "Huge", "width": 5120, "height": 3840, "file_size": 30_000},
    ]
    _route(h, message_update(1, None, photo=sizes))
    get_file = [c.body for c in h.api.calls if c.method == "getFile"]
    assert get_file == [{"file_id": "Large"}]
    assert h.posted(MEDIA_PATH)[0]["kind"] == "photo"


# --- download -------------------------------------------------------------------------------------


def test_c61_voice_is_downloaded_from_the_same_host_and_posted() -> None:
    data = ogg_opus(4.0)
    h = Harness(media=ON)
    h.serve_file(data)
    _route(h, voice_update(7, data, caption="call me, code 123456 ok", message_id=70))
    assert h.downloads() == [f"{BASE_URL}/file/bot{FAKE_BOT_TOKEN}/voice/file_1.oga"]
    (body,) = h.posted(MEDIA_PATH)
    assert base64.b64decode(body["data"]) == data
    assert body["kind"] == "voice"
    assert (body["update_id"], body["message_id"], body["sender_id"]) == (7, 70, OWNER)
    assert body["caption"] == f"call me, code {CODE_REDACTED} ok"
    assert h.sent_texts() == []


def test_c61_download_is_aborted_past_the_cap() -> None:
    h = Harness(media=ON)
    h.api.script("getFile", ok({"file_id": "F", "file_path": "voice/file_1.oga"}))  # no size
    h.api.script("file_1.oga", httpx.Response(200, content=b"\x00" * (2 * 1024 * 1024 + 1)))
    _route(h, voice_update(1))
    assert len(h.downloads()) == 1
    assert h.posted(MEDIA_PATH) == []
    assert h.sent_texts() == [REFUSED_TEXT]


def test_c61_reported_size_over_the_cap_is_never_downloaded() -> None:
    h = Harness(media=ON)
    h.api.script(
        "getFile", ok({"file_id": "F", "file_path": "voice/file_1.oga", "file_size": 3 * 2**20})
    )
    _route(h, voice_update(1))
    assert h.downloads() == []
    assert h.sent_texts() == [REFUSED_TEXT]


@pytest.mark.parametrize(
    "path",
    ["../secret", "/etc/passwd", "voice/../../x", "voice/file?x=1", "voice//f", "voice/f#x", "f"],
)
def test_c61_unsafe_file_path_is_never_requested(path: str) -> None:
    with pytest.raises(ValueError):
        validate_file_path(path)
    h = Harness(media=ON)
    h.api.script("getFile", ok({"file_id": "F", "file_path": path, "file_size": 10}))
    _route(h, voice_update(1))
    assert h.downloads() == []
    assert h.sent_texts() == [REFUSED_TEXT]


def test_c61_token_caption_and_file_id_are_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    h = Harness(media=ON)
    h.api.script("getFile", ok({"file_id": "F", "file_path": "voice/file_1.oga", "file_size": 9}))
    h.api.script("file_1.oga", httpx.Response(500, json={"description": FAKE_BOT_TOKEN}))
    with pytest.raises(InboxUnavailableError):
        _route(h, voice_update(1, caption=CAPTION))
    for secret in (FAKE_BOT_SECRET, CAPTION, "VoiceFile_1", "file_1.oga"):
        assert secret not in caplog.text


def test_c61_transient_download_failure_is_fetched_again() -> None:
    data = ogg_opus(2.0)
    h = Harness(media=ON)
    h.api.script("getFile", ok({"file_id": "F", "file_path": "voice/file_1.oga", "file_size": 9}))
    h.api.script("file_1.oga", httpx.Response(502, content=b"bad gateway"))
    with pytest.raises(InboxUnavailableError):
        _route(h, voice_update(5, data))
    assert h.source._offset == 5  # rewound: the same update comes again
    h.serve_file(data)
    _route(h, voice_update(5, data))
    assert len(h.posted(MEDIA_PATH)) == 1
    assert h.sent_texts() == []


def test_c61_media_the_admin_refuses_is_dropped_with_a_notice() -> None:
    data = ogg_opus(2.0)
    h = Harness(media=ON)
    h.admin.route("POST", MEDIA_PATH, httpx.Response(422, json={"error": "unsupported"}))
    h.serve_file(data)
    _route(h, voice_update(1, data))
    assert len(h.posted(MEDIA_PATH)) == 1  # tried once, not retried
    assert h.sent_texts() == [REFUSED_TEXT]


def test_c61_duplicate_media_is_posted_with_the_same_key() -> None:
    data = ogg_opus(2.0)
    h = Harness(media=ON)
    h.admin.route("POST", MEDIA_PATH, result("stored"), result("duplicate"))
    for _ in range(2):
        h.serve_file(data)
        _route(h, voice_update(9, data, message_id=90))
    keys = [(b["update_id"], b["message_id"]) for b in h.posted(MEDIA_PATH)]
    assert keys == [(9, 90), (9, 90)]


def test_c61_submission_never_reprs_caption_or_bytes() -> None:
    data = ogg_opus(2.0)
    event = accept_message(voice_update(1, data, caption=CAPTION)["message"], 1, OWNER, ON)
    assert isinstance(event, OwnerMedia)
    assert CAPTION not in repr(event)
    assert "VoiceFile_1" not in repr(event)
    submission = event.submission(data)
    assert CAPTION not in repr(submission)
    assert "data=" not in repr(submission)


# --- config (fail closed) ----------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    for key in list(os.environ):
        if key.startswith("PDASH_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PDASH_CONFIG", "/nonexistent/preview-dashboard-test.toml")
    yield monkeypatch


def _toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(body)
    monkeypatch.setenv("PDASH_CONFIG", str(path))


CLAUDIA_ON = "notify_enabled = true\nnotify_owner_chat_id = 4242\nclaudia_enabled = true\n"


def test_c61_config_defaults_on_with_claudia_and_read_only(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    # Owner decision 2026-11-09: both switches default on, photo tools read-only.
    settings = Settings()
    assert settings.claudia_voice_input_enabled is True
    assert settings.claudia_photo_input_enabled is True
    assert settings.claudia_photo_turn_tools == "read_only"
    # Still nothing without Claudia (claudia_enabled defaults off).
    assert (settings.voice_input_active, settings.photo_input_active) == (False, False)
    _toml(tmp_path, clean_env, CLAUDIA_ON)
    on = Settings()
    assert (on.voice_input_active, on.photo_input_active) == (True, True)


def test_c61_explicit_false_turns_each_input_off(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    _toml(tmp_path, clean_env, CLAUDIA_ON + "claudia_voice_input_enabled = false\n")
    settings = Settings()
    assert (settings.voice_input_active, settings.photo_input_active) == (False, True)
    _toml(tmp_path, clean_env, CLAUDIA_ON + "claudia_photo_input_enabled = false\n")
    settings = Settings()
    assert (settings.voice_input_active, settings.photo_input_active) == (True, False)
    clean_env.setenv("PDASH_CLAUDIA_VOICE_INPUT_ENABLED", "false")
    settings = Settings()
    assert (settings.voice_input_active, settings.photo_input_active) == (False, False)


def test_c61_switches_take_effect_only_with_claudia(clean_env: pytest.MonkeyPatch) -> None:
    alone = Settings(claudia_voice_input_enabled=True, claudia_photo_input_enabled=True)
    assert (alone.voice_input_active, alone.photo_input_active) == (False, False)


def test_c61_switches_on_from_toml(tmp_path: Path, clean_env: pytest.MonkeyPatch) -> None:
    _toml(
        tmp_path,
        clean_env,
        CLAUDIA_ON
        + "claudia_voice_input_enabled = true\nclaudia_photo_input_enabled = false\n"
        + 'claudia_photo_turn_tools = "full"\n',
    )
    settings = Settings()
    assert (settings.voice_input_active, settings.photo_input_active) == (True, False)
    assert settings.claudia_photo_turn_tools == "full"


@pytest.mark.parametrize(
    "line",
    [
        "claudia_voice_input_enabled = 1",
        'claudia_photo_input_enabled = "maybe"',
        'claudia_photo_turn_tools = "FULL"',
        'claudia_photo_turn_tools = "all"',
        "claudia_photo_turn_tools = true",
    ],
)
def test_c61_invalid_values_refuse_to_start(
    tmp_path: Path, clean_env: pytest.MonkeyPatch, line: str
) -> None:
    _toml(tmp_path, clean_env, CLAUDIA_ON + line + "\n")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize("name", ["CLAUDIA_VOICE_INPUT_ENABLED", "CLAUDIA_PHOTO_INPUT_ENABLED"])
def test_c61_env_can_turn_media_off_but_never_on(
    tmp_path: Path, clean_env: pytest.MonkeyPatch, name: str
) -> None:
    # Off in the config: env can't turn it back on.
    _toml(tmp_path, clean_env, CLAUDIA_ON + f"{name.lower()} = false\n")
    clean_env.setenv(f"PDASH_{name}", "true")
    with pytest.raises(SettingsError, match="may only turn"):
        Settings()
    _toml(tmp_path, clean_env, CLAUDIA_ON + f"{name.lower()} = true\n")
    clean_env.setenv(f"PDASH_{name}", "false")
    assert getattr(Settings(), name.lower()) is False


def test_c61_env_can_narrow_photo_tools_but_never_widen(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    _toml(tmp_path, clean_env, CLAUDIA_ON)
    clean_env.setenv("PDASH_CLAUDIA_PHOTO_TURN_TOOLS", "full")
    with pytest.raises(SettingsError, match="only select read_only"):
        Settings()
    _toml(tmp_path, clean_env, CLAUDIA_ON + 'claudia_photo_turn_tools = "full"\n')
    clean_env.setenv("PDASH_CLAUDIA_PHOTO_TURN_TOOLS", "read_only")
    assert Settings().claudia_photo_turn_tools == "read_only"
