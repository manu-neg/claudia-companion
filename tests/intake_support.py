"""Shared helpers for MCP intake tests: isolated Settings and policy builders.

Settings are built from constructor kwargs only (trusted, not env-narrowed);
the autouse-able fixture strips PDASH_* env and any real config file so the
host environment cannot leak into intake tests.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from preview_dashboard.config import Settings
from preview_dashboard.interfaces.mcp.intake import IntakeBundle, IntakePolicy


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove PDASH_* env vars and point PDASH_CONFIG at a missing file."""
    for key in list(os.environ):
        if key.startswith("PDASH_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PDASH_CONFIG", "/nonexistent/preview-dashboard-test.toml")
    yield


def make_policy(*roots: Path, **overrides: Any) -> IntakePolicy:
    """Build an `IntakePolicy` via `Settings` with the given roots and overrides."""
    settings = Settings(intake_allowed_roots=tuple(roots), **overrides)
    return IntakePolicy.from_settings(settings)


def read_all(bundle: IntakeBundle) -> dict[str, bytes]:
    """Read every file of `bundle` into memory, keyed by relpath."""
    out: dict[str, bytes] = {}
    for f in bundle.files:
        with f.open_reader(chunk_size=3) as chunks:
            out[f.relpath] = b"".join(chunks)
    return out


def open_fd_count() -> int:
    """Number of fds currently open in this process (Linux /proc)."""
    return len(os.listdir("/proc/self/fd"))
