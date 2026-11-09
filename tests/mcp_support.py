"""Shared helpers for MCP server/client tests: a real admin API on a tmp Unix socket.

Builds the real admin core and app over a tmp data dir (tests/admin_support),
serves it with the production uvicorn config on a real Unix socket in a
thread, and writes a private token file, so `AdminClient` is exercised
end to end exactly as in production.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from preview_dashboard.bootstrap import build_core
from preview_dashboard.config import Settings
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.mcp.client import AdminClient
from preview_dashboard.interfaces.mcp.intake import IntakePolicy
from tests.admin_support import make_settings, running_admin_server, write_token


@dataclass(frozen=True)
class LiveAdmin:
    """A running admin API plus what a client needs to reach it."""

    settings: Settings
    token: str
    outbox: Path

    def client(self) -> AdminClient:
        """A production-configured client (token loaded from the file)."""
        return AdminClient.from_settings(self.settings)

    def intake(self) -> IntakePolicy:
        """The intake policy for these settings."""
        return IntakePolicy.from_settings(self.settings)


@contextmanager
def live_admin(tmp_path: Path, **overrides: Any) -> Iterator[LiveAdmin]:
    """Serve a fresh admin API on `tmp_path/run/admin.sock` for the block."""
    outbox = tmp_path / "outbox"
    outbox.mkdir(exist_ok=True)
    settings = make_settings(tmp_path, intake_allowed_roots=(outbox,), **overrides)
    token = write_token(settings.admin_token_file)
    with build_core(settings, role="admin") as core:
        app = build_admin_app(core, token=token.encode("ascii"))
        with running_admin_server(app, settings.admin_socket):
            yield LiveAdmin(settings=settings, token=token, outbox=outbox)


def write_file(path: Path, data: bytes | str = b"hello") -> Path:
    """Create `path` (and parents) with `data`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def fake_aws_key() -> str:
    """An AWS-access-key-shaped string, assembled so no literal key sits in the repo."""
    return "AK" + "IA" + "QZ7XW4B2" + "MLKH3VDN"


def strip_pdash_env() -> dict[str, str]:
    """A copy of os.environ without any PDASH_* variable."""
    return {k: v for k, v in os.environ.items() if not k.startswith("PDASH_")}
