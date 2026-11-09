"""Security tests for delivering Claudia's voice notes (unit M10b): the delivery part of C56.

The audio leaves the admin's private store only through the notifier-token
routes; the notifier checks size and format again, sends the text before the
voice, releases the audio only after it was sent, and the purge job removes
audio nobody collected. Also: the WAL checkpoint of the Claudia database
after purge deletes (C24, C44).
"""

from __future__ import annotations

import base64
import os
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.admin_queue import (
    MAX_VOICE_RESPONSE_BYTES,
    AdminDeliveryQueue,
    AdminQueueError,
)
from preview_dashboard.adapters.sqlite.claudia_db import (
    compact_claudia,
    connect_claudia,
    default_claudia_db_path,
)
from preview_dashboard.adapters.voice_store import FsVoiceStore
from preview_dashboard.application.delivery import DeliveryService
from preview_dashboard.application.purge import InboxHousekeeping, PurgeService
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    MessageContent,
    PendingTask,
    TaskId,
)
from preview_dashboard.domain.questions import AnswerResult
from preview_dashboard.interfaces.notifier.voice import VoiceDeliveries
from preview_dashboard.wire import notifier as wire
from tests.builders import T0
from tests.claudia_admin_support import claudia_app
from tests.fakes import (
    FixedClock,
    InMemoryApprovalStore,
    InMemoryBlobStore,
    InMemoryItemRepository,
    InMemoryOwnerMessageStore,
)
from tests.notify_support import nid, tid
from tests.owner_updates_support import ogg_opus
from tests.telegram_support import FAKE_NOTIFIER_TOKEN, FakeNotifierAdmin

pytestmark = pytest.mark.security

AUDIO = ogg_opus()


def _reply_task(n: int = 1, *, voice: bool = True) -> PendingTask:
    return PendingTask(
        id=tid(n),
        channel="fake",
        action=DeliveryAction.SEND,
        payload=DeliveryPayload(
            content=MessageContent(text="All good.", long_form=True),
            voice_id=nid(n) if voice else None,
        ),
    )


# --- admin routes: the audio goes only to the notifier token ----------------------------------


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _post_voice(client: TestClient, rig: Any) -> str:
    body = {"text": "All good.", "audio": base64.b64encode(AUDIO).decode()}
    response = client.post("/v1/claudia/voice", json=body, headers=_bearer(rig.claudia_token))
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def test_c56_notifier_token_fetches_then_releases_the_audio(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        voice_id = _post_voice(client, rig)
        fetched = client.get(wire.voice_path(voice_id), headers=_bearer(rig.notifier_token))
        assert fetched.status_code == 200
        assert fetched.content == AUDIO
        assert fetched.headers["content-type"] == "audio/ogg"
        assert fetched.headers["cache-control"] == "no-store"
        released = client.post(
            wire.voice_release_path(voice_id), json={}, headers=_bearer(rig.notifier_token)
        )
        assert released.status_code == 200
        gone = client.get(wire.voice_path(voice_id), headers=_bearer(rig.notifier_token))
        assert gone.status_code == 404
        assert not list(tmp_path.rglob("*.ogg"))
        # Releasing twice is fine (idempotent).
        again = client.post(
            wire.voice_release_path(voice_id), json={}, headers=_bearer(rig.notifier_token)
        )
        assert again.status_code == 200


@pytest.mark.parametrize("token", ["admin_token", "claudia_token"])
def test_c56_other_tokens_cannot_fetch_or_release_audio(tmp_path, token):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        voice_id = _post_voice(client, rig)
        headers = _bearer(getattr(rig, token))
        assert client.get(wire.voice_path(voice_id), headers=headers).status_code == 403
        released = client.post(wire.voice_release_path(voice_id), json={}, headers=headers)
        assert released.status_code == 403
        assert len(list(tmp_path.rglob("*.ogg"))) == 1
        assert client.get(wire.voice_path(voice_id)).status_code == 401


@pytest.mark.parametrize("bad", ["abc", "../../etc/passwd", "0" * 25, "z" * 26])
def test_c56_voice_routes_refuse_ids_that_are_not_ulids(tmp_path, bad):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        headers = _bearer(rig.notifier_token)
        # 403: a normalised `..` path leaves the notifier family (never reaches the store).
        refused = (400, 403, 404)
        assert client.get(f"/v1/notifier/voice/{bad}", headers=headers).status_code in refused
        released = client.post(f"/v1/notifier/voice/{bad}/release", json={}, headers=headers)
        assert released.status_code in refused


def test_c56_release_body_must_be_empty(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        voice_id = _post_voice(client, rig)
        response = client.post(
            wire.voice_release_path(voice_id),
            json={"extra": 1},
            headers=_bearer(rig.notifier_token),
        )
        assert response.status_code == 400
        assert len(list(tmp_path.rglob("*.ogg"))) == 1


def test_c56_pending_reply_task_carries_the_voice_id(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        voice_id = _post_voice(client, rig)
        (task,) = [t for t in rig.core.outbox.pending(20) if t.payload.voice_id]
        assert task.payload.voice_id == voice_id
        # And it survives the wire round trip the notifier parses.
        assert wire.parse_task(wire.task_to_json(task)).payload.voice_id == voice_id


# --- wire ------------------------------------------------------------------------------------


def test_c56_wire_voice_paths_validate_the_id():
    assert wire.voice_path(nid(1)) == f"/v1/notifier/voice/{nid(1)}"
    assert wire.voice_release_path(nid(1)) == f"/v1/notifier/voice/{nid(1)}/release"
    for bad in ("", "../x", nid(1) + "/..", "short"):
        with pytest.raises(ValidationError):
            wire.voice_path(bad)
        with pytest.raises(ValidationError):
            wire.voice_release_path(bad)


def test_c56_only_a_long_form_reply_can_carry_a_voice_id():
    with pytest.raises(ValidationError):
        DeliveryPayload(content=MessageContent(text="alert"), voice_id=nid(1))
    bad = wire.task_to_json(_reply_task())
    bad["payload"] = {**wire.payload_to_json(_reply_task().payload), "voice_id": None}
    with pytest.raises(ValidationError):
        wire.parse_task(bad)  # null is refused like any non-ULID
    alert = wire.task_to_json(_reply_task(voice=False))
    assert "voice_id" not in alert["payload"]  # type: ignore[operator]


# --- the notifier's admin client -------------------------------------------------------------


def _client(admin: FakeNotifierAdmin) -> AdminDeliveryQueue:
    return AdminDeliveryQueue(
        Path("/nonexistent.sock"), FAKE_NOTIFIER_TOKEN, transport=admin.transport()
    )


def test_c56_client_fetches_with_the_notifier_token_only():
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.voice_path(nid(1)), httpx.Response(200, content=AUDIO))
    assert _client(admin).fetch_voice(nid(1)) == AUDIO
    (call,) = admin.calls
    assert call.request.headers["authorization"] == f"Bearer {FAKE_NOTIFIER_TOKEN.decode()}"
    assert str(call.request.url.path) == wire.voice_path(nid(1))


def test_c56_client_treats_404_as_no_voice_and_other_errors_as_errors():
    admin = FakeNotifierAdmin()
    admin.route("GET", wire.voice_path(nid(1)), httpx.Response(404, json={"error": "not_found"}))
    admin.route("GET", wire.voice_path(nid(2)), httpx.Response(500, json={}))
    queue = _client(admin)
    assert queue.fetch_voice(nid(1)) is None
    with pytest.raises(AdminQueueError):
        queue.fetch_voice(nid(2))
    with pytest.raises(ValidationError):
        queue.fetch_voice("../etc/passwd")


def test_c56_client_refuses_audio_over_the_size_cap():
    admin = FakeNotifierAdmin()
    big = b"\x00" * (MAX_VOICE_RESPONSE_BYTES + 1)
    admin.route("GET", wire.voice_path(nid(1)), httpx.Response(200, content=big))
    with pytest.raises(AdminQueueError, match="ResponseTooLarge"):
        _client(admin).fetch_voice(nid(1))


def test_c56_client_release_posts_to_the_release_route():
    admin = FakeNotifierAdmin()
    admin.route("POST", wire.voice_release_path(nid(1)), httpx.Response(200, json={}))
    _client(admin).release_voice(nid(1))
    assert [c.method for c in admin.calls] == ["POST"]


# --- delivery order and release --------------------------------------------------------------


class _Inner:
    """A scripted `DeliveryQueue` that logs into the shared event list."""

    def __init__(self, events: list[str], tasks: list[PendingTask]) -> None:
        self._events, self._tasks = events, tasks

    def pending(self, wait: float) -> list[PendingTask]:
        return list(self._tasks)

    def done(self, task_id: TaskId, message_ref: str | None) -> None:
        self._events.append("done")

    def failed(self, task_id: TaskId) -> None:
        self._events.append("failed")

    def submit_answer(
        self, question_id: str, key: str, source: str, actor_ref: str
    ) -> AnswerResult:
        raise AssertionError("not used")


class _Source:
    def __init__(self, events: list[str], audio: bytes | None) -> None:
        self._events, self._audio = events, audio
        self.fetched: list[str] = []

    def fetch_voice(self, voice_id: str) -> bytes | None:
        self.fetched.append(voice_id)
        self._events.append("fetch")
        return self._audio

    def release_voice(self, voice_id: str) -> None:
        self._events.append("release")


class _Sender:
    def __init__(self, events: list[str], *, fail: bool = False) -> None:
        self._events, self._fail = events, fail
        self.sent: list[bytes] = []

    def send_voice(self, audio: bytes) -> str:
        self._events.append("voice")
        if self._fail:
            raise ConnectionError("upload down")
        self.sent.append(audio)
        return "1:2"


class _TextChannel:
    name = "fake"

    def __init__(self, events: list[str]) -> None:
        self._events = events

    def send(self, payload: DeliveryPayload) -> str | None:
        self._events.append("text")
        return None

    def resolve(self, message_ref: str, payload: DeliveryPayload) -> None:
        raise AssertionError("not used")


def _round(
    tasks: list[PendingTask], audio: bytes | None, *, fail_send: bool = False
) -> tuple[list[str], _Source, _Sender]:
    events: list[str] = []
    source, sender = _Source(events, audio), _Sender(events, fail=fail_send)
    queue = VoiceDeliveries(_Inner(events, tasks), source, sender)
    service = DeliveryService(queue=queue, channels=[_TextChannel(events)])
    service.run_once_deliveries()
    return events, source, sender


def test_c56_text_is_sent_before_the_voice_and_release_comes_last():
    events, source, sender = _round([_reply_task()], AUDIO)
    assert events == ["text", "done", "fetch", "voice", "release"]
    assert sender.sent == [AUDIO]
    assert source.fetched == [nid(1)]


def test_c56_a_plain_reply_without_audio_sends_no_voice():
    events, _source, sender = _round([_reply_task()], None)
    assert events == ["text", "done", "fetch"]
    assert sender.sent == []


def test_c56_tasks_without_a_voice_id_never_ask_for_audio():
    events, source, _sender = _round([_reply_task(voice=False)], AUDIO)
    assert events == ["text", "done"]
    assert source.fetched == []


@pytest.mark.parametrize("bad", [b"not audio", b"", b"OggS" + b"\x00" * 40])
def test_c56_invalid_audio_is_never_uploaded_and_is_released(bad):
    events, _source, sender = _round([_reply_task()], bad)
    assert sender.sent == []
    assert "voice" not in events
    assert events[-1] == "release"


def test_c56_audio_over_the_size_cap_is_never_uploaded():
    from preview_dashboard.events.voice import VOICE_MAX_BYTES

    events, _source, sender = _round([_reply_task()], AUDIO + b"\x00" * VOICE_MAX_BYTES)
    assert sender.sent == []
    assert "voice" not in events


def test_c56_failed_upload_keeps_the_audio_and_never_resends_the_text():
    events, _source, sender = _round([_reply_task()], AUDIO, fail_send=True)
    assert events == ["text", "done", "fetch", "voice"]  # no release, no second text
    assert sender.sent == []


def test_c56_failed_text_sends_no_voice():
    events: list[str] = []

    class _DownChannel(_TextChannel):
        def send(self, payload: DeliveryPayload) -> str | None:
            raise ConnectionError("down")

    source, sender = _Source(events, AUDIO), _Sender(events)
    queue = VoiceDeliveries(_Inner(events, [_reply_task()]), source, sender)
    DeliveryService(queue=queue, channels=[_DownChannel(events)]).run_once_deliveries()
    assert events == ["failed"]
    assert source.fetched == []


def test_c56_voice_failures_are_logged_by_type_only(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    _round([_reply_task()], AUDIO, fail_send=True)
    assert "ConnectionError" in caplog.text
    assert "upload down" not in caplog.text


# --- purge: stale audio and the Claudia WAL ---------------------------------------------------


def test_c56_purge_removes_audio_nobody_collected(tmp_path: Path) -> None:
    store = FsVoiceStore(tmp_path / "voice")
    fresh_id, stale_id = nid(1), nid(2)
    store.save(fresh_id, AUDIO)
    store.save(stale_id, AUDIO)
    old = time.time() - 48 * 3600
    os.utime(tmp_path / "voice" / f"{stale_id}.ogg", (old, old))
    from preview_dashboard.bootstrap import _VOICE_MAX_AGE_SECONDS

    service = PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(),
        clock=FixedClock(T0),
        retention=timedelta(days=30),
        orphan_grace=timedelta(hours=1),
        maintenance={"voice": lambda: store.purge_older_than(_VOICE_MAX_AGE_SECONDS)},
    )
    assert service.run().maintenance == {"voice": 1}
    assert store.load(fresh_id) == AUDIO
    assert store.load(stale_id) is None


def _inbox_purge(compact: Callable[[], object], *, with_old_message: bool) -> PurgeService:
    from tests.contracts.owner_message_store import make_message

    messages = InMemoryOwnerMessageStore()
    if with_old_message:
        messages.add(make_message(1))
    return PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(),
        clock=FixedClock(T0 + timedelta(days=31)),
        retention=timedelta(days=30),
        orphan_grace=timedelta(hours=1),
        inbox=InboxHousekeeping(
            messages=messages, approvals=InMemoryApprovalStore(), compact=compact
        ),
    )


def test_c44_purge_checkpoints_the_claudia_db_after_deleting_rows() -> None:
    calls: list[int] = []
    report = _inbox_purge(lambda: calls.append(1), with_old_message=True).run()
    assert report.inbox_deleted == 1
    assert calls == [1]


def test_c44_purge_skips_the_checkpoint_when_nothing_changed() -> None:
    calls: list[int] = []
    _inbox_purge(lambda: calls.append(1), with_old_message=False).run()
    assert calls == []


def test_c44_a_failing_checkpoint_never_undoes_the_purge(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken() -> None:
        raise RuntimeError("message text must not be logged")

    report = _inbox_purge(broken, with_old_message=True).run()
    assert report.inbox_deleted == 1
    assert "RuntimeError" in caplog.text
    assert "message text" not in caplog.text


def test_c44_compact_claudia_truncates_the_wal(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir(mode=0o700)
    path = default_claudia_db_path(tmp_path / "data")
    conn = connect_claudia(path)
    wal = Path(f"{path}-wal")
    try:
        conn.execute(
            "INSERT INTO owner_messages (id, update_id, telegram_message_id, text, received_us,"
            " is_forwarded, state) VALUES ('m1', 1, 1, 'secret words', 0, 0, 'received')"
        )
        conn.execute("DELETE FROM owner_messages")
        assert wal.stat().st_size > 0  # page images of the deleted text sit in the WAL
        assert compact_claudia(lambda: connect_claudia(path, create=False)) is True
        assert wal.stat().st_size == 0
    finally:
        conn.close()


def test_c44_compact_claudia_validates_its_bounds_and_retries_while_busy(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        compact_claudia(lambda: None, attempts=0)  # type: ignore[arg-type, return-value]
    (tmp_path / "data").mkdir(mode=0o700)
    path = default_claudia_db_path(tmp_path / "data")
    writer = connect_claudia(path)
    reader = connect_claudia(path, create=False)
    sleeps: list[float] = []
    try:
        writer.execute(
            "INSERT INTO owner_messages (id, update_id, telegram_message_id, text, received_us,"
            " is_forwarded, state) VALUES ('m1', 1, 1, 'x', 0, 0, 'received')"
        )
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM owner_messages").fetchall()  # holds a snapshot
        writer.execute("UPDATE owner_messages SET text = 'y'")
        done = compact_claudia(
            lambda: connect_claudia(path, create=False),
            attempts=3,
            delay_seconds=0.01,
            sleep=sleeps.append,
        )
        assert done is False
        assert len(sleeps) == 2
    finally:
        reader.close()
        writer.close()
