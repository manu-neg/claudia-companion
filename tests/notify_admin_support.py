"""Helpers for the admin question/notifier route tests (unit N3): both tokens, both families.

`notify_app(tmp_path)` builds the real admin core (SQLite, notifications on
by default) and the real admin app with an admin **and** a notifier token;
`asgi_client(app, peer=...)` is an async httpx client over ASGI (optionally
tagged with Unix-peer credentials, as the socket server does), so tests can
run many long-polls concurrently. `live_notify_admin` serves the same app on
a real Unix socket with both token files written, for CLI/MCP/notifier
end-to-end tests.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI
from starlette.types import ASGIApp

from preview_dashboard.bootstrap import AdminCore, build_core
from preview_dashboard.config import Settings
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.auth import PeerCredentials, PeerCredentialsApp
from tests.admin_support import make_settings, running_admin_server, write_token

OWNER_CHAT = 424242
ASGI_BASE = "http://admin.local"


def notify_settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Settings with notifications on, token files under `tmp_path/secrets`."""
    options: dict[str, Any] = {
        "notify_enabled": True,
        "notify_owner_chat_id": OWNER_CHAT,
        "notifier_token_file": tmp_path / "secrets" / "notifier.token",
        "telegram_token_file": tmp_path / "secrets" / "telegram.token",
        **overrides,
    }
    return make_settings(tmp_path, **options)


@dataclass(frozen=True)
class NotifyApp:
    """An admin app with both tokens, plus its core."""

    app: ASGIApp
    core: AdminCore
    admin_token: str
    notifier_token: str

    def app_state(self) -> Any:
        """The inner FastAPI app's `state` (waiter slots), under the middleware stack."""
        app: Any = self.app
        while not isinstance(app, FastAPI):
            app = app._app
        return app.state


@contextmanager
def notify_app(
    tmp_path: Path,
    *,
    with_notifier_token: bool = True,
    allowed_peer_uids: Sequence[int] = (),
    notifier_peer_uids: Sequence[int] = (),
    **overrides: Any,
) -> Iterator[NotifyApp]:
    """Yield a fresh admin app (real core) with an admin and a notifier token."""
    settings = notify_settings(tmp_path, **overrides)
    admin_token = secrets.token_urlsafe(32)
    notifier_token = secrets.token_urlsafe(32)
    with build_core(settings, role="admin") as core:
        app = build_admin_app(
            core,
            token=admin_token.encode(),
            notifier_token=notifier_token.encode() if with_notifier_token else None,
            allowed_peer_uids=allowed_peer_uids,
            notifier_peer_uids=notifier_peer_uids,
        )
        yield NotifyApp(app=app, core=core, admin_token=admin_token, notifier_token=notifier_token)


def asgi_client(
    app: ASGIApp, *, peer: PeerCredentials | None = None, timeout: float = 30.0
) -> httpx.AsyncClient:
    """Async client calling `app` in-process; `peer` is attached like `SO_PEERCRED`."""
    target: ASGIApp = PeerCredentialsApp(app, peer) if peer is not None else app
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=target), base_url=ASGI_BASE, timeout=timeout
    )


def bearer(token: str) -> dict[str, str]:
    """Authorization header for `token`."""
    return {"Authorization": f"Bearer {token}"}


def ask_body(**overrides: Any) -> dict[str, Any]:
    """A valid `POST /v1/questions` body."""
    body: dict[str, Any] = {
        "prompt": "Which database should the prototype use?",
        "options": [{"key": "a", "label": "SQLite"}, {"key": "b", "label": "Postgres"}],
        "session_label": "db-choice task",
    }
    body.update(overrides)
    return body


def answer_body(question_id: str, key: str = "a", source: str = "telegram") -> dict[str, str]:
    """A `POST /v1/notifier/answers` body."""
    return {"question_id": question_id, "key": key, "source": source, "actor_ref": "424242"}


@dataclass(frozen=True)
class LiveNotifyAdmin:
    """A running admin API (real socket) with both token files written."""

    settings: Settings
    core: AdminCore
    admin_token: str
    notifier_token: str


@contextmanager
def live_notify_admin(tmp_path: Path, **overrides: Any) -> Iterator[LiveNotifyAdmin]:
    """Serve the notifier-enabled admin app on `tmp_path/run/admin.sock` for the block."""
    settings = notify_settings(tmp_path, **overrides)
    admin_token = write_token(settings.admin_token_file)
    notifier_token = write_token(settings.notifier_token_file)
    with build_core(settings, role="admin") as core:
        app = build_admin_app(
            core, token=admin_token.encode(), notifier_token=notifier_token.encode()
        )
        with running_admin_server(app, settings.admin_socket):
            yield LiveNotifyAdmin(
                settings=settings,
                core=core,
                admin_token=admin_token,
                notifier_token=notifier_token,
            )


def cli_env(settings: Settings) -> dict[str, str]:
    """`PDASH_*` env pointing the CLI at `settings` (PDASH_CONFIG: conftest's empty TOML)."""
    return {
        "PDASH_DATA_DIR": str(settings.data_dir),
        "PDASH_ADMIN_TOKEN_FILE": str(settings.admin_token_file),
        "PDASH_ADMIN_SOCKET": str(settings.admin_socket),
        "PDASH_NOTIFIER_TOKEN_FILE": str(settings.notifier_token_file),
        "PDASH_TELEGRAM_TOKEN_FILE": str(settings.telegram_token_file),
    }
