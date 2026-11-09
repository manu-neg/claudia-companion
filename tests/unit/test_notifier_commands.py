"""Unit tests for the notifier command functions: fail-closed startup, `pair`, `notify test`."""

from __future__ import annotations

import io
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.bootstrap import dashboard_base_url
from preview_dashboard.domain.notifications import dashboard_origin
from preview_dashboard.interfaces.mcp.admin_socket import AdminSocketTrustError
from preview_dashboard.interfaces.notifier import commands
from preview_dashboard.interfaces.notifier.commands import (
    NotifierError,
    NotifierParts,
    build_notifier,
    notify_test_body,
    pair,
    send_test,
    serve_notifier,
)
from tests.admin_support import make_settings
from tests.notify_support import qid
from tests.telegram_support import (
    FAKE_BOT_SECRET,
    FAKE_BOT_TOKEN,
    FAKE_NOTIFIER_TOKEN,
    OWNER,
    FakeBotApi,
    error,
    ok,
)

pytestmark = pytest.mark.unit


@dataclass(frozen=True)
class Config:
    admin_socket: Path
    notifier_token_file: Path
    telegram_token_file: Path
    notify_enabled: bool = True
    notify_owner_chat_id: int | None = OWNER
    allowed_hosts: frozenset[str] = frozenset({"dash.example.ts.net"})
    claudia_enabled: bool = False


def write_secret(path: Path, data: bytes, mode: int = 0o600) -> Path:
    path.write_bytes(data)
    os.chmod(path, mode)
    return path


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        admin_socket=tmp_path / "admin.sock",
        notifier_token_file=write_secret(tmp_path / "notifier.token", FAKE_NOTIFIER_TOKEN),
        telegram_token_file=write_secret(tmp_path / "telegram.token", FAKE_BOT_TOKEN.encode()),
    )


def build(config: Config, **kwargs: object) -> NotifierParts:
    return build_notifier(config, verify_socket=lambda _p: 0, **kwargs)  # type: ignore[arg-type]


def test_build_wires_telegram_and_the_queue(config: Config) -> None:
    parts = build(config)
    channel = parts.service._channels["telegram"]
    assert isinstance(channel, TelegramChannel)
    # Pinned to the same origin the admin builds links from (C35).
    assert channel._origin == "https://dash.example.ts.net"
    parts.close()


def test_build_reads_owner_messages_only_when_asked(config: Config) -> None:
    from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
    from preview_dashboard.interfaces.notifier.owner_updates import OwnerUpdateRouter

    default, claudia = build(config), build(config, owner_messages=True)
    assert isinstance(default.service._answers, TelegramAnswerSource)
    router = claudia.service._answers
    assert isinstance(router, OwnerUpdateRouter)
    # Codes are deleted through the same pinned channel that sends alerts.
    assert id(router._chat) == id(claudia.service._channels["telegram"])
    default.close()
    claudia.close()


def test_build_without_allowed_hosts_sends_no_link_buttons(
    config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("WARNING"):
        parts = build(Config(**{**config.__dict__, "allowed_hosts": frozenset()}))
    channel = parts.service._channels["telegram"]
    assert isinstance(channel, TelegramChannel) and channel._origin is None
    assert "without dashboard link buttons" in caplog.text
    parts.close()


def test_notifier_and_admin_derive_the_same_origin(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, allowed_hosts=frozenset({"b.example", "a.example"}))
    assert dashboard_origin(settings.allowed_hosts) == dashboard_base_url(settings)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"notify_enabled": False}, "disabled"),
        ({"notify_owner_chat_id": None}, "notify pair"),
        ({"notify_owner_chat_id": -100}, "positive integer"),
    ],
)
def test_build_fails_closed_on_config(
    config: Config, change: dict[str, object], message: str
) -> None:
    bad = Config(**{**config.__dict__, **change})
    with pytest.raises(NotifierError, match=message):
        build(bad)


def test_build_refuses_unsafe_token_files(config: Config) -> None:
    os.chmod(config.telegram_token_file, 0o644)
    with pytest.raises(NotifierError, match="telegram token"):
        build(config)
    os.chmod(config.telegram_token_file, 0o600)
    os.chmod(config.notifier_token_file, 0o606)  # noqa: S103 - the unsafe mode under test
    with pytest.raises(NotifierError, match="notifier token"):
        build(config)


def test_build_refuses_a_malformed_bot_token_without_echoing_it(config: Config) -> None:
    bogus = b"not-a-bot-token-but-long-enough-0123456789abcdefghijk"
    write_secret(config.telegram_token_file, bogus)
    with pytest.raises(NotifierError) as info:
        build(config)
    assert bogus.decode() not in str(info.value)


def test_build_verifies_the_admin_socket_before_using_the_token(config: Config) -> None:
    def untrusted(_path: Path) -> int:
        raise AdminSocketTrustError("admin socket x has an untrusted owner")

    with pytest.raises(NotifierError, match="untrusted owner"):
        build_notifier(config, verify_socket=untrusted)


def test_serve_runs_until_stopped_and_closes(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeRunner:
        def __init__(self, service: object) -> None:
            pass

        def install_signal_handlers(self) -> None:
            pass

        def run(self) -> bool:
            return True

    monkeypatch.setattr(commands, "NotifierRunner", FakeRunner)
    parts_holder: list[NotifierParts] = []

    def tracking_build(cfg: object, *, token_groups: object) -> NotifierParts:
        parts = build(config)
        parts_holder.append(parts)
        return parts

    assert serve_notifier(config, build=tracking_build) == 0
    assert parts_holder[0].queue._http.is_closed and parts_holder[0].telegram._http.is_closed


def _serve_and_capture(
    config: object, monkeypatch: pytest.MonkeyPatch, cfg_build: Config
) -> NotifierParts:
    """Run `serve_notifier` with a stub runner; return the parts it built."""

    class FakeRunner:
        def __init__(self, service: object) -> None:
            pass

        def install_signal_handlers(self) -> None:
            pass

        def run(self) -> bool:
            return True

    monkeypatch.setattr(commands, "NotifierRunner", FakeRunner)
    built: list[NotifierParts] = []

    def wrapped(cfg: object, **kwargs: object) -> NotifierParts:
        parts = build(cfg_build, **kwargs)
        built.append(parts)
        return parts

    assert serve_notifier(config, build=wrapped) == 0  # type: ignore[arg-type]
    return built[0]


def test_claudia_off_notifier_has_no_owner_intake(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
    from preview_dashboard.interfaces.notifier.voice import VoiceDeliveries

    # Default, a missing flag and a non-True value all behave as before Claudia.
    class Odd:
        claudia_enabled = "yes"

    for cfg in (config, object(), Odd()):
        parts = _serve_and_capture(cfg, monkeypatch, config)
        assert isinstance(parts.service._answers, TelegramAnswerSource)
        assert not isinstance(parts.service._queue, VoiceDeliveries)


def test_claudia_on_notifier_wires_intake_and_voice(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    from preview_dashboard.interfaces.notifier.owner_updates import OwnerUpdateRouter
    from preview_dashboard.interfaces.notifier.voice import VoiceDeliveries

    on = replace(config, claudia_enabled=True)
    parts = _serve_and_capture(on, monkeypatch, on)
    assert isinstance(parts.service._answers, OwnerUpdateRouter)
    assert isinstance(parts.service._queue, VoiceDeliveries)


def test_pair_prints_code_and_chat_id(config: Config) -> None:
    api = FakeBotApi()
    start = {
        "update_id": 3,
        "message": {
            "from": {"id": OWNER},
            "chat": {"id": OWNER, "type": "private"},
            "text": "/start CODE2345",
        },
    }
    api.script("getUpdates", ok([start]))
    out = io.StringIO()
    code = pair(config.telegram_token_file, out, transport=api.transport(), code="CODE2345")
    assert code == 0
    text = out.getvalue()
    assert "/start CODE2345" in text
    assert f"notify_owner_chat_id = {OWNER}" in text
    assert FAKE_BOT_SECRET not in text
    confirm = api.calls[-1]
    assert confirm.method == "sendMessage" and confirm.body["chat_id"] == OWNER
    assert "parse_mode" not in confirm.body


def test_pair_reports_a_running_notifier(config: Config) -> None:
    api = FakeBotApi()
    api.script("getUpdates", error(409, "Conflict: terminated by other getUpdates request"))
    with pytest.raises(NotifierError, match="stop preview-dashboard-notifier"):
        pair(config.telegram_token_file, io.StringIO(), transport=api.transport(), code="X")


def test_pair_times_out(config: Config) -> None:
    with pytest.raises(NotifierError, match="timed out"):
        pair(
            config.telegram_token_file, io.StringIO(), transport=FakeBotApi().transport(), timeout=0
        )


def test_pair_telegram_errors_are_scrubbed(config: Config) -> None:
    api = FakeBotApi()
    api.script("getUpdates", httpx.ConnectError(f"cannot reach bot{FAKE_BOT_TOKEN}"))
    with pytest.raises(NotifierError) as info:
        pair(config.telegram_token_file, io.StringIO(), transport=api.transport(), code="X")
    assert FAKE_BOT_SECRET not in str(info.value)


def test_send_test_asks_a_two_option_question() -> None:
    sent: list[dict[str, object]] = []

    def ask(body: dict[str, object]) -> Mapping[str, object]:
        sent.append(body)
        return {"question": {"id": qid(1), "state": "open"}}

    out = io.StringIO()
    assert send_test(ask, out) == 0
    assert sent == [notify_test_body()]
    options = notify_test_body()["options"]
    assert isinstance(options, list) and len(options) == 2
    line = json.loads(out.getvalue())
    assert line == {
        "id": qid(1),
        "state": "open",
        "wait_command": f"preview-dashboard question wait {qid(1)}",
    }


def test_send_test_accepts_a_flat_question_reply() -> None:
    out = io.StringIO()
    send_test(lambda _b: {"id": qid(2), "state": "open"}, out)
    assert json.loads(out.getvalue())["id"] == qid(2)


def test_send_test_refuses_a_reply_without_a_valid_id() -> None:
    with pytest.raises(NotifierError):
        send_test(lambda _b: {"question": {"id": "x; rm -rf /"}}, io.StringIO())
