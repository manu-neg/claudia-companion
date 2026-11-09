"""Security tests for Claudia's voice replies (unit M10): the voice parts of C56.

Only text that passed the reply policy and the secret scan is spoken; a long
reply gets a short spoken summary and keeps its full text; the audio obeys
the size/duration caps and is deleted when delivered or given up; the voice
route takes the claudia token only and spends the reply budget.
"""

from __future__ import annotations

import base64
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.piper_tts import PiperTextToSpeech
from preview_dashboard.adapters.voice_store import FsVoiceStore
from preview_dashboard.application.claudia.voice import (
    MAX_SPOKEN_CHARS,
    VoiceComposer,
    VoiceService,
    VoiceToggle,
    detect_language,
    spoken_summary,
)
from preview_dashboard.domain.errors import (
    ConflictError,
    LimitExceededError,
    SecretDetectedError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.events.voice import VOICE_MAX_BYTES
from preview_dashboard.wire.claudia_voice import (
    VoiceRequest,
    parse_voice_request,
    voice_request_to_json,
)
from tests.claudia_admin_support import claudia_app, message_body
from tests.fakes import FAKE_SECRET, FakeContentScanner
from tests.notify_admin_support import bearer
from tests.owner_updates_support import _page, ogg_opus


def big_ogg(size: int) -> bytes:
    """A well-formed 2 s Ogg/Opus stream of at least `size` bytes (many audio pages)."""
    stub = ogg_opus(2.0, audio_bytes=1)
    data, seq = stub[:-29], 2  # drop the one-byte audio page: header 27 + lacing 1 + body 1
    granule = 312 + 2 * 48_000
    while len(data) < size:
        data += _page(b"\x00" * 60_000, granule=0, seq=seq, flags=0)
        seq += 1
    return data + _page(b"\x00", granule=granule, seq=seq, flags=0x04)


pytestmark = pytest.mark.security

ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
SECRET_TEXT = "the key is " + FAKE_SECRET.decode()
AWS_KEY_ID = "AKIA" + "Q" * 16
_WORDS = re.compile(r"\w+")


class FakeTts:
    """Records what it was asked to speak; returns canned Ogg/Opus."""

    def __init__(self, *, seconds: float = 3.0, long_seconds: float | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._seconds = seconds
        self._long = long_seconds

    def synthesize(self, text: str, language: str) -> bytes:
        self.calls.append((text, language))
        # A summary is at most 280 chars + the pointer; anything longer is "the full text".
        if self._long is not None and len(text) > 330:
            return ogg_opus(self._long)
        return ogg_opus(self._seconds)


def composer(tts: FakeTts) -> VoiceComposer:
    return VoiceComposer(tts=tts, scanner=FakeContentScanner())


# --- language -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "language"),
    [
        ("¡Hola! Claro que sí, lo hago ahora.", "es"),
        ("El build está listo y los tests pasan.", "es"),
        ("The build is ready and all tests pass.", "en"),
        ("Done", "en"),
        ("", "en"),
    ],
)
def test_c56_voice_language_follows_the_message(text, language):
    assert detect_language(text) == language


def test_c56_voice_uses_the_voice_of_the_detected_language():
    tts = FakeTts()
    es = composer(tts).compose("¡Hola! Claro que sí, lo hago ahora.")
    en = composer(tts).compose("The build is ready and all tests pass.")
    assert (es.language, en.language) == ("es", "en")
    assert [lang for _text, lang in tts.calls] == ["es", "en"]


# --- only scanned text is spoken --------------------------------------------------------------


def test_c56_secret_text_is_never_spoken():
    tts = FakeTts()
    with pytest.raises(SecretDetectedError):
        composer(tts).compose(SECRET_TEXT)
    assert tts.calls == []


@pytest.mark.parametrize(
    "text", ["see https://evil.example/x", "hidden\u200bjoiner", "bell\x07", "  ", "x" * 4097]
)
def test_c56_text_breaking_the_reply_policy_is_never_spoken(text):
    tts = FakeTts()
    with pytest.raises(ValidationError):
        composer(tts).compose(text)
    assert tts.calls == []


def test_c56_the_scanner_sees_the_text_before_the_engine_does():
    scanner = FakeContentScanner()
    tts = FakeTts()
    VoiceComposer(tts=tts, scanner=scanner).compose("All good now.")
    assert scanner.sessions == 1 and scanner.fed_bytes > 0 and scanner.finished == 1
    assert len(tts.calls) == 1


def test_c56_spoken_words_come_only_from_the_scanned_text():
    tts = FakeTts()
    text = "First sentence here. " * 80
    note = composer(tts).compose(text)
    spoken = tts.calls[-1][0]
    assert note.summarized
    allowed = set(_WORDS.findall(text.lower())) | {"full", "text", "is", "in", "the", "message"}
    assert set(_WORDS.findall(spoken.lower())) <= allowed


# --- length caps ------------------------------------------------------------------------------


def test_c56_short_text_is_spoken_whole():
    tts = FakeTts()
    note = composer(tts).compose("All checks passed.")
    assert not note.summarized and tts.calls == [("All checks passed.", "en")]
    assert note.text == "All checks passed."


def test_c56_long_text_gets_a_summary_and_keeps_the_full_text():
    tts = FakeTts()
    text = ("The deployment finished without errors. " * 40).strip()
    assert len(text) > MAX_SPOKEN_CHARS
    note = composer(tts).compose(text)
    assert note.summarized and note.text == text
    assert len(tts.calls) == 1 and len(tts.calls[0][0]) < 400
    assert tts.calls[0][0].endswith("The full text is in the message.")


def test_c56_spanish_summary_uses_the_spanish_pointer():
    assert spoken_summary("El build está listo. " * 60, "es").endswith(
        "El texto completo está en el mensaje."
    )


def test_c56_audio_over_sixty_seconds_falls_back_to_the_summary():
    tts = FakeTts(seconds=3.0, long_seconds=70.0)
    note = composer(tts).compose("Short enough in characters but " + "slow " * 90)
    assert note.summarized and len(tts.calls) == 2
    assert note.audio.seconds <= 60


def test_c56_audio_that_never_fits_is_refused():
    with pytest.raises(ValidationError):
        composer(FakeTts(seconds=90.0)).compose("Anything to say.")


def test_c56_audio_over_one_mib_is_refused():
    class Big:
        def synthesize(self, text: str, language: str) -> bytes:
            return big_ogg(VOICE_MAX_BYTES + 10)

    with pytest.raises(ValidationError):
        VoiceComposer(tts=Big(), scanner=FakeContentScanner()).compose("Anything.")


def test_c56_toggle_flips_and_starts_off():
    toggle = VoiceToggle()
    assert toggle.enabled is False
    assert toggle.toggle() is True and toggle.enabled
    assert toggle.toggle() is False


# --- audio is deleted -------------------------------------------------------------------------


def test_c56_audio_file_is_private_and_deleted_after_delivery(tmp_path):
    store = FsVoiceStore(tmp_path / "voice")
    store.save(ULID, ogg_opus())
    path = tmp_path / "voice" / f"{ULID}.ogg"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert store.load(ULID) == ogg_opus()
    store.discard(ULID)
    assert store.load(ULID) is None and not path.exists()
    store.discard(ULID)  # absent: fine


def test_c56_audio_given_up_is_swept_by_age(tmp_path):
    store = FsVoiceStore(tmp_path / "voice")
    store.save(ULID, ogg_opus())
    stale = tmp_path / "voice" / f"{ULID}.ogg"
    old = time.time() - 7200
    os.utime(stale, (old, old))
    store.save("01ARZ3NDEKTSV4RRFFQ69G5FAW", ogg_opus())
    assert store.purge_older_than(3600) == 1
    assert store.load(ULID) is None and store.load("01ARZ3NDEKTSV4RRFFQ69G5FAW") is not None


def test_c56_store_refuses_bad_ids_duplicates_and_floods(tmp_path):
    store = FsVoiceStore(tmp_path / "voice", max_waiting=1)
    for bad in ("../x", "short", ULID.lower(), ""):
        with pytest.raises(ValidationError):
            store.save(bad, b"x")
        assert store.load(bad) is None
    store.save(ULID, b"x")
    with pytest.raises(ConflictError):
        store.save(ULID, b"y")
    with pytest.raises(LimitExceededError):
        store.save("01ARZ3NDEKTSV4RRFFQ69G5FAW", b"y")
    assert not list((tmp_path / "voice").glob("*.tmp"))


# --- the admin service ------------------------------------------------------------------------


class RecordingReplies:
    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(
        self,
        text: str,
        *,
        message_id: str | None,
        item_id: str | None,
        before_visible: Any = None,
    ) -> str:
        if before_visible is not None:
            before_visible(ULID)
        self.sent.append(text)
        return ULID


class FetchingReplies(RecordingReplies):
    """Plays the notifier fetching the audio the moment the reply becomes visible."""

    def __init__(self, store: FsVoiceStore, *, fail: bool = False) -> None:
        super().__init__()
        self.store, self.fail = store, fail
        self.fetched: bytes | None = None

    def send(self, text: str, **kw: Any) -> str:
        reply_id = super().send(text, **kw)
        self.fetched = self.store.load(reply_id)
        if self.fail:
            raise StorageUnavailableError("outbox down")
        return reply_id


def test_c56_voice_1_audio_is_saved_before_the_reply_is_visible(tmp_path):
    store = FsVoiceStore(tmp_path)
    replies = FetchingReplies(store)
    VoiceService(replies=replies, store=store).send("hi", ogg_opus(), message_id=None, item_id=None)
    assert replies.fetched == ogg_opus()


def test_c56_voice_1_audio_is_dropped_when_queueing_fails(tmp_path):
    store = FsVoiceStore(tmp_path)
    replies = FetchingReplies(store, fail=True)
    with pytest.raises(StorageUnavailableError):
        VoiceService(replies=replies, store=store).send(
            "hi", ogg_opus(), message_id=None, item_id=None
        )
    assert store.load(ULID) is None


def test_c56_voice_2_unreadable_voice_dir_sweeps_nothing(tmp_path, monkeypatch):
    store = FsVoiceStore(tmp_path)

    def boom(self: Path) -> Any:
        raise PermissionError("unreadable")

    monkeypatch.setattr(Path, "iterdir", boom)
    assert store.purge_older_than(0) == 0


def test_c56_bad_audio_spends_no_reply_budget(tmp_path):
    replies = RecordingReplies()
    service = VoiceService(replies=replies, store=FsVoiceStore(tmp_path))
    for audio in (b"", b"RIFF" + b"0" * 40, ogg_opus(61.0), ogg_opus(2.0)[:-5]):
        with pytest.raises(ValidationError):
            service.send("hi", audio, message_id=None, item_id=None)
    assert replies.sent == []


def test_c56_text_is_kept_when_the_audio_cannot_be_stored(tmp_path):
    replies = RecordingReplies()
    store = FsVoiceStore(tmp_path, max_waiting=0)
    assert (
        VoiceService(replies=replies, store=store).send(
            "hi", ogg_opus(), message_id=None, item_id=None
        )
        == ULID
    )
    assert replies.sent == ["hi"] and store.load(ULID) is None


def test_c56_service_fetch_and_release(tmp_path):
    service = VoiceService(replies=RecordingReplies(), store=FsVoiceStore(tmp_path))
    service.send("hi", ogg_opus(), message_id=None, item_id=None)
    assert service.fetch(ULID) == ogg_opus()
    service.release(ULID)
    assert service.fetch(ULID) is None


# --- the engine adapter -----------------------------------------------------------------------


def test_c56_piper_refuses_unknown_language_and_missing_model(tmp_path):
    engine = PiperTextToSpeech(tmp_path)
    with pytest.raises(ValidationError):
        engine.synthesize("hola", "fr")
    with pytest.raises(ValidationError):
        engine.synthesize("   ", "es")
    # Neither the optional extra nor the models are present: fail closed, no download.
    with pytest.raises(StorageUnavailableError):
        engine.synthesize("hola", "es")


# --- wire -------------------------------------------------------------------------------------


def test_c56_wire_roundtrip_and_strictness():
    audio = ogg_opus()
    wire = voice_request_to_json(VoiceRequest(text="hi", audio=audio, message_id=None))
    assert parse_voice_request(wire).audio == audio
    bad_bodies: list[object] = [
        {"text": "hi"},
        {"text": "hi", "audio": "!!!notbase64"},
        {"text": "hi", "audio": "QUJD", "extra": 1},
        {"text": 5, "audio": "QUJD"},
        {"text": "hi", "audio": "A" * (VOICE_MAX_BYTES * 2)},
        [],
    ]
    for bad in bad_bodies:
        with pytest.raises(ValidationError):
            parse_voice_request(bad)


# --- the route --------------------------------------------------------------------------------


def _voice(
    client: TestClient,
    rig: Any,
    *,
    text: str = "All good.",
    audio: bytes | None = None,
    **extra: Any,
) -> Any:
    body = {"text": text, "audio": base64.b64encode(audio or ogg_opus()).decode(), **extra}
    return client.post("/v1/claudia/voice", json=body, headers=bearer(rig.claudia_token))


def _inbox_message(client: TestClient, rig: Any) -> str:
    client.post("/v1/notifier/messages", json=message_body(), headers=bearer(rig.notifier_token))
    return str(rig.claudia.inbox.unhandled(1)[0].id)


def test_c56_route_queues_the_text_and_keeps_the_audio(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        before = len(rig.core.outbox.pending(20))
        response = _voice(client, rig, text="¡Hola! Todo listo.")
        assert response.status_code == 201, response.text
        voice_id = response.json()["id"]
        tasks = rig.core.outbox.pending(20)[before:]
        assert [t.payload.content.text for t in tasks] == ["¡Hola! Todo listo."]
        assert rig.claudia.voice.fetch(voice_id) == ogg_opus()
        rig.claudia.voice.release(voice_id)
        assert rig.claudia.voice.fetch(voice_id) is None


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"text": f"key {AWS_KEY_ID}"}, 422),
        ({"text": "see https://evil.example/x"}, 400),
        ({"audio": ogg_opus(61.0)}, 400),
        ({"audio": b"not audio"}, 400),
    ],
)
def test_c56_route_refuses_unsafe_voice_without_queueing(tmp_path, kwargs, status):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        before = len(rig.core.outbox.pending(20))
        response = _voice(client, rig, **kwargs)
        assert response.status_code == status
        assert AWS_KEY_ID not in response.text
        assert len(rig.core.outbox.pending(20)) == before
        assert not list(tmp_path.rglob("*.ogg"))


def test_c56_route_body_over_the_cap_is_refused(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        response = _voice(client, rig, audio=big_ogg(VOICE_MAX_BYTES + 10))
        assert response.status_code in (400, 413)


def test_c56_voice_shares_the_reply_budget(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        mid = _inbox_message(client, rig)
        reply = client.post(
            "/v1/claudia/replies",
            json={"text": "one", "message_id": mid},
            headers=bearer(rig.claudia_token),
        )
        statuses = [reply.status_code]
        statuses += [_voice(client, rig, message_id=mid).status_code for _ in range(3)]
        assert statuses == [201, 201, 201, 429]


@pytest.mark.parametrize("token", ["admin_token", "notifier_token"])
def test_c56_voice_route_refuses_the_other_tokens(tmp_path, token):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        body = {"text": "hi", "audio": base64.b64encode(ogg_opus()).decode()}
        response = client.post("/v1/claudia/voice", json=body, headers=bearer(getattr(rig, token)))
        assert response.status_code == 403
        assert rig.claudia.voice.fetch(ULID) is None


def test_c56_voice_text_and_audio_are_never_logged(tmp_path, caplog):
    caplog.set_level("DEBUG")
    marker = "Quokka-private-voice-words"
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        assert _voice(client, rig, text=marker).status_code == 201
    assert marker not in caplog.text


def test_c56_data_dir_layout(tmp_path: Path) -> None:
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        voice_id = _voice(client, rig).json()["id"]
        files = list(tmp_path.rglob(f"{voice_id}.ogg"))
        assert len(files) == 1 and files[0].parent.name == "voice"
