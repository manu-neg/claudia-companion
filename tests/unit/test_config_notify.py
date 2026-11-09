"""Unit tests for the notification settings (ADR 0021; docs/security.md C16, C33, C34, C36, C37).

Defaults (off), fail-closed validation (owner chat id required when on,
distinct token files, TTL/rate bounds) and the env rules: env may turn
notifications off, lower the alert rate, but never turn them on or pick
the owner's chat.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from preview_dashboard.config import Settings

pytestmark = pytest.mark.unit

ENABLED = "notify_enabled = true\nnotify_owner_chat_id = 4242\n"


@pytest.fixture(autouse=True)
def _clean_pdash_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in list(os.environ):
        if key.startswith("PDASH_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PDASH_CONFIG", "/nonexistent/preview-dashboard-test.toml")
    yield


def _use_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(body)
    monkeypatch.setenv("PDASH_CONFIG", str(config_file))


def test_defaults_are_off() -> None:
    settings = Settings()
    assert settings.notify_enabled is False
    assert settings.notify_owner_chat_id is None
    assert settings.notify_rate_per_hour == 20
    assert settings.question_ttl_seconds == 86400
    assert settings.notifier_token_file == Path("/etc/preview-dashboard/notifier.token")
    assert settings.telegram_token_file == Path("/etc/preview-dashboard/telegram.token")


def test_enabled_from_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(tmp_path, monkeypatch, ENABLED)
    settings = Settings()
    assert (settings.notify_enabled, settings.notify_owner_chat_id) == (True, 4242)


def test_enabled_requires_the_owner_chat_id() -> None:
    with pytest.raises(ValidationError, match="notify_owner_chat_id is required"):
        Settings(notify_enabled=True)


@pytest.mark.parametrize("chat_id", [0, -5, True, "4242", 2**53, 1.5])
def test_owner_chat_id_must_be_a_positive_int(chat_id: object) -> None:
    with pytest.raises(ValidationError, match="notify_owner_chat_id"):
        Settings(notify_owner_chat_id=chat_id)


@pytest.mark.parametrize("ttl", [59, 604801, 0])
def test_question_ttl_bounds(ttl: int) -> None:
    with pytest.raises(ValidationError, match="question_ttl_seconds"):
        Settings(question_ttl_seconds=ttl)


def test_rate_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Settings(notify_rate_per_hour=0)


@pytest.mark.parametrize(
    "overrides",
    [
        {"notifier_token_file": Path("/etc/preview-dashboard/admin.token")},
        {"telegram_token_file": Path("/etc/preview-dashboard/admin.token")},
        {"telegram_token_file": Path("/etc/preview-dashboard/notifier.token")},
    ],
)
def test_token_files_must_differ(overrides: dict[str, Path]) -> None:
    with pytest.raises(ValidationError, match="must differ"):
        Settings(**overrides)  # type: ignore[arg-type]


@pytest.mark.parametrize("path", ["relative.token", "//etc/x.token", "/etc/../x.token"])
def test_token_paths_must_be_absolute_and_normalized(path: str) -> None:
    with pytest.raises(ValidationError):
        Settings(notifier_token_file=Path(path))
    with pytest.raises(ValidationError):
        Settings(telegram_token_file=Path(path))


def test_intake_root_may_not_contain_the_notifier_token_dir() -> None:
    with pytest.raises(ValidationError, match="overlaps"):
        Settings(
            notifier_token_file=Path("/srv/secrets/notifier.token"),
            intake_allowed_roots=(Path("/srv"),),
        )


# --- env rules (C16) ----------------------------------------------------------------


@pytest.mark.parametrize("value", ["true", "1", "yes", "on"])
def test_env_cannot_turn_notifications_on(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PDASH_NOTIFY_ENABLED", value)
    with pytest.raises(SettingsError, match="only turn notifications off"):
        Settings()


def test_env_can_turn_notifications_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(tmp_path, monkeypatch, ENABLED)
    monkeypatch.setenv("PDASH_NOTIFY_ENABLED", "false")
    assert Settings().notify_enabled is False


def test_env_may_repeat_an_enabled_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(tmp_path, monkeypatch, ENABLED)
    monkeypatch.setenv("PDASH_NOTIFY_ENABLED", "true")
    assert Settings().notify_enabled is True


def test_env_can_never_set_the_owner_chat(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(tmp_path, monkeypatch, ENABLED)
    monkeypatch.setenv("PDASH_NOTIFY_OWNER_CHAT_ID", "999")
    with pytest.raises(SettingsError, match="only be set in the config file"):
        Settings()


def test_env_may_only_lower_the_alert_rate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_NOTIFY_RATE_PER_HOUR", "5")
    assert Settings().notify_rate_per_hour == 5
    monkeypatch.setenv("PDASH_NOTIFY_RATE_PER_HOUR", "21")
    with pytest.raises(SettingsError, match="tighten"):
        Settings()


def test_env_may_only_shorten_the_question_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_QUESTION_TTL_SECONDS", "600")
    assert Settings().question_ttl_seconds == 600
    monkeypatch.setenv("PDASH_QUESTION_TTL_SECONDS", "90000")
    with pytest.raises(SettingsError, match="tighten"):
        Settings()
