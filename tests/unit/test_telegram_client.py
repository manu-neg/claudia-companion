"""Unit tests for the Telegram Bot API client: fixed URL, bounded replies, token hygiene (C36)."""

from __future__ import annotations

import logging

import httpx
import pytest

from preview_dashboard.adapters.telegram import client as client_mod
from preview_dashboard.adapters.telegram.client import (
    BASE_URL,
    BotToken,
    TelegramBotClient,
    TelegramConfigError,
    TelegramError,
    validate_chat_id,
)
from tests.telegram_support import FAKE_BOT_SECRET, FAKE_BOT_TOKEN, FakeBotApi, error, ok

pytestmark = pytest.mark.unit


def test_call_posts_json_to_the_fixed_base_url() -> None:
    api = FakeBotApi()
    api.script("getMe", ok({"id": 1}))
    assert api.client().call("getMe", {"a": 1}) == {"id": 1}
    (call,) = api.calls
    assert call.url == f"{BASE_URL}/bot{FAKE_BOT_TOKEN}/getMe"
    assert call.request.method == "POST"
    assert call.body == {"a": 1}


def test_unknown_methods_are_refused_before_any_request() -> None:
    api = FakeBotApi()
    with pytest.raises(ValueError, match="unsupported"):
        api.client().call("../../evil", {})
    with pytest.raises(ValueError):
        api.client().call("setWebhook", {})
    assert api.calls == []


def test_http_client_ignores_env_and_verifies_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    client = TelegramBotClient(BotToken(FAKE_BOT_TOKEN))
    http = client._http
    assert http.trust_env is False
    assert http.follow_redirects is False
    # No proxy mounted despite HTTPS_PROXY in the environment.
    assert not any(m is not None for m in http._mounts.values())
    client.close()


def test_telegram_error_reply_raises_with_scrubbed_description() -> None:
    api = FakeBotApi()
    api.script("sendMessage", error(400, f"Bad Request: token {FAKE_BOT_TOKEN} \x1b[31m"))
    with pytest.raises(TelegramError) as info:
        api.client().call("sendMessage", {"chat_id": 1, "text": "x"})
    exc = info.value
    assert exc.status == 400
    assert FAKE_BOT_SECRET not in str(exc) and FAKE_BOT_SECRET not in exc.description
    assert "\x1b" not in exc.description
    assert "<redacted>" in exc.description


def test_retry_after_is_parsed_and_capped() -> None:
    api = FakeBotApi()
    api.script("sendMessage", error(429, "Too Many Requests", retry_after=99999))
    with pytest.raises(TelegramError) as info:
        api.client().call("sendMessage", {})
    assert info.value.status == 429 and info.value.retry_after == 3600


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json=[1, 2]),
        httpx.Response(200, json={"ok": True}),
        httpx.Response(502, content=b"<html>bad gateway</html>"),
    ],
)
def test_unusable_replies_raise(response: httpx.Response) -> None:
    api = FakeBotApi()
    api.script("getMe", response)
    with pytest.raises(TelegramError):
        api.client().call("getMe", {})


def test_oversized_reply_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_mod, "MAX_RESPONSE_BYTES", 100)
    api = FakeBotApi()
    api.script("getMe", ok("x" * 500))
    with pytest.raises(TelegramError, match="ResponseTooLarge"):
        api.client().call("getMe", {})


def test_compressed_reply_is_refused() -> None:
    api = FakeBotApi()
    api.script(
        "getMe", httpx.Response(200, content=b"\x1f\x8b", headers={"Content-Encoding": "gzip"})
    )
    with pytest.raises(TelegramError, match="UnexpectedEncoding"):
        api.client().call("getMe", {})


def test_transport_errors_carry_only_the_type_name() -> None:
    api = FakeBotApi()
    url_error = httpx.ConnectError(f"failed for {BASE_URL}/bot{FAKE_BOT_TOKEN}/getMe")
    api.script("getMe", url_error)
    with pytest.raises(TelegramError) as info:
        api.client().call("getMe", {})
    assert str(info.value) == "telegram getMe: request failed (ConnectError)"
    # Nothing chained that could print the URL in a traceback.
    assert info.value.__cause__ is None and info.value.__context__ is None


def test_long_poll_read_timeout_is_applied() -> None:
    api = FakeBotApi()
    api.client().call("getUpdates", {"timeout": 50}, read_timeout=65.0)
    assert api.calls[0].request.extensions["timeout"]["read"] == 65.0


def test_token_is_not_in_reprs() -> None:
    token = BotToken(FAKE_BOT_TOKEN)
    client = TelegramBotClient(token, transport=FakeBotApi().transport())
    for text in (repr(token), str(token), repr(client), f"{token}"):
        assert FAKE_BOT_SECRET not in text


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "nocolon",
        "123:short",
        "abc:" + "x" * 35,
        f"{FAKE_BOT_TOKEN}/getMe",
        "1:" + "x" * 35 + "?",
    ],
)
def test_bot_token_shape_is_checked(raw: str) -> None:
    with pytest.raises(TelegramConfigError) as info:
        BotToken(raw)
    assert raw not in str(info.value) or raw == ""


def test_bot_token_accepts_bytes() -> None:
    assert BotToken(FAKE_BOT_TOKEN.encode()).reveal() == FAKE_BOT_TOKEN


@pytest.mark.parametrize("raw", [0, -5, True, "42", 2**53, None, 1.5])
def test_chat_id_must_be_a_positive_int(raw: object) -> None:
    with pytest.raises(TelegramConfigError):
        validate_chat_id(raw)


def test_constructing_a_client_silences_http_loggers() -> None:
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.DEBUG)
    TelegramBotClient(BotToken(FAKE_BOT_TOKEN), transport=FakeBotApi().transport())
    for name in ("httpx", "httpcore"):
        assert logging.getLogger(name).getEffectiveLevel() >= logging.WARNING
