"""Repo-wide pytest fixtures: keep every test hermetic against host state.

`Settings` (pydantic-settings) reads real env vars and
`/etc/preview-dashboard/config.toml` unless told otherwise (config.py
`settings_customise_sources`). Several test modules already isolate this
per-module (test_config.py, test_config_notify.py, intake_support.py); this
autouse fixture applies the same isolation everywhere else so a real,
live-deployed host (stray PDASH_* env, a real config.toml with
notify_enabled/owner login set) can never leak into a "default" assertion.
PDASH_CONFIG points at an *empty* secure TOML file, not a missing one: a
named-but-missing config file refuses to start (I6, `verify_config`).
Tests that need a specific TOML/env still set it themselves, after this
fixture runs (backlog.md G3).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.config_support import write_empty_config


@pytest.fixture(scope="session")
def _empty_config(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_empty_config(tmp_path_factory.mktemp("pdash-config"))


@pytest.fixture(autouse=True)
def _isolate_pdash_env(monkeypatch: pytest.MonkeyPatch, _empty_config: Path) -> Iterator[None]:
    """Strip PDASH_* env vars and point PDASH_CONFIG at an empty, secure TOML file."""
    for key in list(os.environ):
        if key.startswith("PDASH_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PDASH_CONFIG", str(_empty_config))
    yield
