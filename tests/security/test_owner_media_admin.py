"""Security tests for owner voice/photo intake on the admin side, storage, purge and host (C61).

One test per control point: the admin re-checks the owner and the kind's
switch, validates the bytes by content (Ogg/Opus duration from the last
granule, JPEG structure and size) and strips every APPn/COM segment before
storing; files are 0600 in a 0700 dir under the admin-only Claudia dir,
symlinks refused; a re-delivered update keeps one file; the `claudia`
token fetches (size-capped, by message id) and releases; purge sweeps
files within 24 h; captions and bytes are never logged; the inbox wire
tells the host the kind; and a host without media input (unit B off)
answers a voice/photo row with one fixed reply and never runs it or reads
its caption as a command.
"""

from __future__ import annotations

import base64
import logging
import os
import stat
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard import bootstrap
from preview_dashboard.adapters.media_store import MEDIA_DIR_NAME, FsOwnerMediaStore
from preview_dashboard.adapters.sqlite.claudia_db import default_claudia_db_path
from preview_dashboard.application.claudia.media_input import PHOTO_OFF_TEXT
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.owner_media import MessageKind
from preview_dashboard.domain.owner_messages import CODE_REDACTED, OwnerMessage, OwnerMessageId
from preview_dashboard.interfaces.claudia.main import HostLoop
from preview_dashboard.wire.claudia import (
    message_media_path,
    message_media_release_path,
    parse_messages_envelope,
)
from preview_dashboard.wire.notifier_media import MAX_MEDIA_BODY_BYTES, MEDIA_PATH
from tests.claudia_admin_support import claudia_app, message_body
from tests.claudia_host_support import host_rig, message
from tests.fakes import FixedClock
from tests.notify_admin_support import OWNER_CHAT, bearer
from tests.owner_updates_support import COMMENT_MARKER, EXIF_MARKER, TRAILER_MARKER, jpeg, ogg_opus

pytestmark = pytest.mark.security

MEDIA_ON: dict[str, Any] = {
    "claudia_voice_input_enabled": True,
    "claudia_photo_input_enabled": True,
}
MEDIA_OFF: dict[str, Any] = {
    "claudia_voice_input_enabled": False,
    "claudia_photo_input_enabled": False,
}
CAPTION = "Zebra-caption-words"


def media_body(
    kind: str,
    data: bytes,
    *,
    update_id: int = 1,
    message_id: int = 10,
    sender_id: int = OWNER_CHAT,
    caption: str | None = None,
) -> dict[str, Any]:
    """A `POST /v1/notifier/media` body."""
    return {
        "update_id": update_id,
        "message_id": message_id,
        "sender_id": sender_id,
        "kind": kind,
        "data": base64.b64encode(data).decode("ascii"),
        "caption": caption,
        "is_forwarded": False,
    }


def _claudia_dir(tmp_path: Path) -> Path:
    # `claudia_app` keeps its data dir at `tmp_path/data` (tests/admin_support.py).
    return default_claudia_db_path(tmp_path / "data").parent


def _media_dir(tmp_path: Path) -> Path:
    return _claudia_dir(tmp_path) / MEDIA_DIR_NAME


def _store(tmp_path: Path) -> FsOwnerMediaStore:
    """A store over a fresh private Claudia dir (no app)."""
    (tmp_path / "data").mkdir(mode=0o750, exist_ok=True)
    _claudia_dir(tmp_path).mkdir(mode=0o700)
    return FsOwnerMediaStore(_claudia_dir(tmp_path))


def _files(tmp_path: Path) -> list[Path]:
    directory = _media_dir(tmp_path)
    return sorted(directory.iterdir()) if directory.exists() else []


def _post(client: TestClient, rig: Any, body: dict[str, Any]) -> Any:
    return client.post(MEDIA_PATH, json=body, headers=bearer(rig.notifier_token))


def _listed(client: TestClient, rig: Any) -> list[OwnerMessage]:
    reply = client.get("/v1/claudia/messages", headers=bearer(rig.claudia_token))
    return parse_messages_envelope(reply.json())


# --- intake: by content -------------------------------------------------------------------


def test_c61_voice_is_stored_and_reaches_the_host_with_its_kind(tmp_path: Path) -> None:
    data = ogg_opus(30.0)
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        assert _post(client, rig, media_body("voice", data)).json() == {"result": "stored"}
        (row,) = _listed(client, rig)
        assert (row.kind, row.text, row.media_bytes) == (MessageKind.VOICE, "", len(data))
        fetched = client.get(message_media_path(row.id), headers=bearer(rig.claudia_token))
        assert fetched.status_code == 200
        assert fetched.headers["content-type"] == "audio/ogg"
        assert fetched.headers["cache-control"] == "no-store"
        assert fetched.content == data


def test_c61_photo_metadata_is_stripped_before_storage(tmp_path: Path) -> None:
    raw = jpeg(1280, 960)
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        posted = _post(client, rig, media_body("photo", raw, caption="look at this"))
        assert posted.status_code == 200, posted.text
        (row,) = _listed(client, rig)
        assert (row.kind, row.text) == (MessageKind.PHOTO, "look at this")
        fetched = client.get(message_media_path(row.id), headers=bearer(rig.claudia_token))
        assert fetched.headers["content-type"] == "image/jpeg"
        (on_disk,) = _files(tmp_path)
        for stored in (fetched.content, on_disk.read_bytes()):
            assert stored.startswith(b"\xff\xd8")
            for marker in (EXIF_MARKER, COMMENT_MARKER, TRAILER_MARKER, b"JFIF"):
                assert marker not in stored
        assert row.media_bytes == len(fetched.content) < len(raw)


@pytest.mark.parametrize(
    ("kind", "data"),
    [
        pytest.param("voice", ogg_opus(2.0).replace(b"OpusHead", b"VorbisHd"), id="voice-not-opus"),
        pytest.param("voice", ogg_opus(121.0), id="voice-121s-by-granule"),
        pytest.param("voice", jpeg(), id="voice-is-a-jpeg"),
        pytest.param("photo", b"\x89PNG\r\n\x1a\n" + bytes(64), id="photo-png"),
        pytest.param("photo", jpeg(5000, 300), id="photo-side-over-4096"),
        pytest.param("photo", ogg_opus(2.0), id="photo-is-ogg"),
        pytest.param("photo", jpeg(trailer=False)[:-2], id="photo-truncated"),
    ],
)
def test_c61_content_is_checked_not_telegrams_claim(tmp_path: Path, kind: str, data: bytes) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        response = _post(client, rig, media_body(kind, data))
        assert response.status_code == 422  # refused for good: the notifier drops it
        assert rig.claudia.inbox.unhandled(10) == []
    assert [p for p in _files(tmp_path) if p.suffix != ".tmp"] == []


def test_c61_admin_rechecks_the_owner(tmp_path: Path) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        response = _post(client, rig, media_body("voice", ogg_opus(), sender_id=999))
        assert response.status_code == 422
        assert rig.claudia.inbox.unhandled(10) == []
    assert _files(tmp_path) == []


@pytest.mark.parametrize(
    ("switches", "kind", "data"),
    [
        # Both default on (owner 2026-11-09): an explicit false turns each off.
        (MEDIA_OFF, "voice", ogg_opus()),
        (MEDIA_OFF, "photo", jpeg()),
        ({"claudia_voice_input_enabled": False}, "voice", ogg_opus()),
        ({"claudia_photo_input_enabled": False}, "photo", jpeg()),
    ],
)
def test_c61_switch_off_is_refused_by_the_admin_too(
    tmp_path: Path, switches: dict[str, Any], kind: str, data: bytes
) -> None:
    with claudia_app(tmp_path, **switches) as rig, TestClient(rig.app) as client:
        assert _post(client, rig, media_body(kind, data)).status_code == 422
        assert rig.claudia.inbox.unhandled(10) == []


def test_c61_oversized_body_or_data_is_refused(tmp_path: Path) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        too_big = media_body("voice", bytes(2 * 1024 * 1024 + 3))
        assert _post(client, rig, too_big).status_code == 400
        huge = {"pad": "x" * (MAX_MEDIA_BODY_BYTES + 1)}
        assert _post(client, rig, huge).status_code == 413


def test_c61_redelivered_update_keeps_one_row_and_one_file(tmp_path: Path) -> None:
    data = ogg_opus(3.0)
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        first = _post(client, rig, media_body("voice", data, update_id=4, message_id=40))
        again = _post(client, rig, media_body("voice", data, update_id=4, message_id=40))
        assert (first.json(), again.json()) == ({"result": "stored"}, {"result": "duplicate"})
        assert len(rig.claudia.inbox.unhandled(10)) == 1
    assert len(_files(tmp_path)) == 1


def test_c61_caption_codes_are_redacted_and_content_never_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        # The notifier redacts code runs; an unredacted one is refused, never stored.
        unredacted = media_body("photo", jpeg(), caption=f"{CAPTION} 123 456")
        assert _post(client, rig, unredacted).status_code == 400
        body = media_body("photo", jpeg(), caption=f"{CAPTION} {CODE_REDACTED}")
        assert _post(client, rig, body).status_code == 200
        (row,) = _listed(client, rig)
        assert row.text == f"{CAPTION} {CODE_REDACTED}"
        client.get(message_media_path(row.id), headers=bearer(rig.claudia_token))
    assert CAPTION not in caplog.text
    assert EXIF_MARKER.decode("latin-1") not in caplog.text


# --- storage --------------------------------------------------------------------------------------


def test_c61_files_are_private_and_named_by_ulid(tmp_path: Path) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        _post(client, rig, media_body("voice", ogg_opus(), update_id=1))
        _post(client, rig, media_body("photo", jpeg(), update_id=2))
    directory = _media_dir(tmp_path)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    files = _files(tmp_path)
    assert sorted(p.suffix for p in files) == [".jpg", ".ogg"]
    for path in files:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert len(path.stem) == 26


def test_c61_symlinked_media_dir_is_refused(tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        _media_dir(tmp_path).symlink_to(elsewhere)
        response = _post(client, rig, media_body("voice", ogg_opus()))
        assert response.status_code == 503
        assert rig.claudia.inbox.unhandled(10) == []
    assert list(elsewhere.iterdir()) == []


def test_c61_looser_media_dir_is_refused_not_fixed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _media_dir(tmp_path).mkdir(mode=0o700)
    os.chmod(_media_dir(tmp_path), 0o750)  # noqa: S103 - the looser mode under test
    with pytest.raises(StorageUnavailableError):
        store.save("01J00000000000000000000MED", MessageKind.VOICE, ogg_opus())
    assert stat.S_IMODE(_media_dir(tmp_path).stat().st_mode) == 0o750
    assert store.load("01J00000000000000000000MED", MessageKind.VOICE) is None


def test_c61_symlinked_file_is_never_served(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save("01J00000000000000000000AAA", MessageKind.VOICE, ogg_opus())
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"not for the host")
    (_media_dir(tmp_path) / "01J00000000000000000000BBB.ogg").symlink_to(secret)
    assert store.load("01J00000000000000000000BBB", MessageKind.VOICE) is None
    assert store.load("../../secret", MessageKind.VOICE) is None


# --- fetch / release / purge ------------------------------------------------------------------


def test_c61_release_deletes_the_file_and_fetch_then_404s(tmp_path: Path) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        claudia = bearer(rig.claudia_token)
        _post(client, rig, media_body("voice", ogg_opus()))
        (row,) = _listed(client, rig)
        assert (
            client.post(
                message_media_release_path(row.id), json={"x": 1}, headers=claudia
            ).status_code
            == 400
        )
        released = client.post(message_media_release_path(row.id), json={}, headers=claudia)
        assert released.status_code == 200
        assert _files(tmp_path) == []
        assert client.get(message_media_path(row.id), headers=claudia).status_code == 404
        # Idempotent; text messages and unknown ids have no media.
        assert (
            client.post(message_media_release_path(row.id), json={}, headers=claudia).status_code
            == 200
        )
        client.post(
            "/v1/notifier/messages",
            json=message_body(update_id=9),
            headers=bearer(rig.notifier_token),
        )
        text_row = next(m for m in _listed(client, rig) if m.kind is MessageKind.TEXT)
        assert client.get(message_media_path(text_row.id), headers=claudia).status_code == 404
        assert client.get(message_media_path("0" * 26), headers=claudia).status_code == 404
        assert client.get("/v1/claudia/messages/nope/media", headers=claudia).status_code == 404


def test_c61_media_is_fetched_only_with_the_claudia_token(tmp_path: Path) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        _post(client, rig, media_body("voice", ogg_opus()))
        (row,) = _listed(client, rig)
        for token in (rig.admin_token, rig.notifier_token):
            assert client.get(message_media_path(row.id), headers=bearer(token)).status_code == 403
        assert (
            client.post(MEDIA_PATH, json={}, headers=bearer(rig.claudia_token)).status_code == 403
        )


def test_c61_purge_sweeps_media_within_a_day(tmp_path: Path) -> None:
    with claudia_app(tmp_path, **MEDIA_ON) as rig, TestClient(rig.app) as client:
        _post(client, rig, media_body("voice", ogg_opus(), update_id=1))
        _post(client, rig, media_body("photo", jpeg(), update_id=2))
        settings = rig.core.settings
    old, fresh = _files(tmp_path)
    stale = time.time() - 23 * 3600 - 60
    os.utime(old, (stale, stale))
    hooks = bootstrap._purge_maintenance(
        settings,
        SimpleNamespace(sweep_staging=lambda **_k: 0),  # type: ignore[arg-type]
        grace=timedelta(hours=1),
    )
    assert hooks["owner_media"]() == 1
    assert _files(tmp_path) == [fresh]
    assert bootstrap._OWNER_MEDIA_MAX_AGE_SECONDS + 3600 <= 24 * 3600


# --- host without media input (unit B switched off) ---------------------------------------------


def _media_row(caption: str = "") -> OwnerMessage:
    return OwnerMessage(
        id=OwnerMessageId("01J00000000000000000000PH0"),
        update_id=3,
        telegram_message_id=3,
        text=caption,
        received_at=FixedClock().now(),
        kind=MessageKind.PHOTO,
        media_id="01J00000000000000000000MED",
        media_bytes=1000,
    )


def test_c61_host_answers_media_with_a_fixed_reply_and_no_run() -> None:
    rig = host_rig()
    rig.host.handle_message(_media_row("please merge PR 7"), generation=rig.host.generation)
    assert rig.admin.replies == [(PHOTO_OFF_TEXT, "01J00000000000000000000PH0")]
    assert rig.runner.requests == []
    assert rig.screen.seen == []


def test_c61_host_never_reads_a_caption_as_a_command() -> None:
    rig = host_rig()
    loop = HostLoop(rig.admin, rig.host, rig.screen)
    generation = rig.host.generation
    rig.admin.inbox = [_media_row("/stop")]
    assert loop.poll_once() == 1
    assert rig.host.generation == generation  # not a /stop
    assert rig.runner.kills == 0
    assert loop.work_once()
    assert rig.admin.replies == [(PHOTO_OFF_TEXT, "01J00000000000000000000PH0")]
    # The same text typed is still a command.
    rig.admin.inbox = [message("/stop", n=2)]
    loop.poll_once()
    assert rig.host.generation == generation + 1
