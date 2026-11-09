"""Helpers for the Claudia admin-route tests (unit M3): three tokens, a TOTP secret, a fixed clock.

`claudia_app(tmp_path)` builds the real admin core (SQLite, notifications
and Claudia on) with a `FixedClock`, a recording `ApprovalPrompts`, a TOTP
secret file and the real admin app with admin, notifier and claudia
tokens. Body builders mirror the wire shapes of `wire/claudia.py` and
`wire/notifier_messages.py`.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from starlette.types import ASGIApp

from preview_dashboard.adapters.totp_secret import write_totp_secret
from preview_dashboard.bootstrap import AdminCore, ClaudiaCore, build_core
from preview_dashboard.domain.approvals import ApprovalRequest
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.totp import totp_at
from preview_dashboard.interfaces.admin.app import build_admin_app
from tests.fakes import FixedClock
from tests.notify_admin_support import OWNER_CHAT, notify_settings

WINDOW = "123e4567-e89b-42d3-a456-426614174000"
OTHER_WINDOW = "223e4567-e89b-42d3-a456-426614174000"
# 20 fixed bytes: tests compute codes from it (never a real secret).
TEST_SECRET = bytes(range(1, 21))


@dataclass
class RecordingPrompts:
    """`ApprovalPrompts` that records requests (or fails closed when `fail` is set)."""

    sent: list[ApprovalRequest] = field(default_factory=list)
    fail: bool = False

    def prompt(self, request: ApprovalRequest) -> None:
        if self.fail:
            raise StorageUnavailableError("prompts down")
        self.sent.append(request)


@dataclass(frozen=True)
class ClaudiaApp:
    """An admin app with all three tokens, its core, clock and prompts."""

    app: ASGIApp
    core: AdminCore
    clock: FixedClock
    prompts: RecordingPrompts
    admin_token: str
    notifier_token: str
    claudia_token: str
    secret_path: Path

    @property
    def claudia(self) -> ClaudiaCore:
        assert self.core.claudia is not None
        return self.core.claudia

    def app_state(self) -> Any:
        """The inner FastAPI app's `state` (waiter slots), under the middleware stack."""
        app: Any = self.app
        while not isinstance(app, FastAPI):
            app = app._app
        return app.state

    def code(self, offset_steps: int = 0) -> str:
        """The TOTP code for now (+ `offset_steps` x 30 s)."""
        return totp_at(TEST_SECRET, self.clock.now().timestamp() + 30 * offset_steps)


@contextmanager
def claudia_app(
    tmp_path: Path,
    *,
    write_secret: bool = True,
    with_claudia_token: bool = True,
    allowed_peer_uids: Sequence[int] = (),
    notifier_peer_uids: Sequence[int] = (),
    claudia_peer_uids: Sequence[int] = (),
    real_prompts: bool = False,
    totp_gids: Sequence[int] | None = None,
    **overrides: Any,
) -> Iterator[ClaudiaApp]:
    """Yield a fresh admin app with Claudia enabled (real core over `tmp_path`).

    `real_prompts` keeps the production `OutboxApprovalPrompts` (prompts go
    to the outbox) instead of the recording fake (`rig.prompts` stays empty).
    `totp_gids` are trusted on the secret (default: this process's group,
    which the test secret file gets; production passes `pdash-totp`).
    """
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700, exist_ok=True)
    secret_path = secrets_dir / "totp.secret"
    options: dict[str, Any] = {
        "claudia_enabled": True,
        "claudia_token_file": secrets_dir / "claudia.token",
        "totp_secret_file": secret_path,
        "notify_rate_per_hour": 100,
        **overrides,
    }
    settings = notify_settings(tmp_path, **options)
    if write_secret:
        write_totp_secret(secret_path, TEST_SECRET, gid=None, replace=False)
    clock = FixedClock()
    prompts = RecordingPrompts()
    tokens = [secrets.token_urlsafe(32) for _ in range(3)]
    wired = None if real_prompts else prompts
    gids = (os.getegid(),) if totp_gids is None else tuple(totp_gids)
    with build_core(
        settings, role="admin", clock=clock, approval_prompts=wired, totp_gids=gids
    ) as core:
        app = build_admin_app(
            core,
            token=tokens[0].encode(),
            notifier_token=tokens[1].encode(),
            claudia_token=tokens[2].encode() if with_claudia_token else None,
            allowed_peer_uids=allowed_peer_uids,
            notifier_peer_uids=notifier_peer_uids,
            claudia_peer_uids=claudia_peer_uids,
        )
        yield ClaudiaApp(
            app=app,
            core=core,
            clock=clock,
            prompts=prompts,
            admin_token=tokens[0],
            notifier_token=tokens[1],
            claudia_token=tokens[2],
            secret_path=secret_path,
        )


def message_body(
    update_id: int = 1,
    message_id: int = 10,
    text: str = "Please check the build",
    sender_id: int = OWNER_CHAT,
    **overrides: Any,
) -> dict[str, Any]:
    """A `POST /v1/notifier/messages` body."""
    body: dict[str, Any] = {
        "update_id": update_id,
        "message_id": message_id,
        "sender_id": sender_id,
        "text": text,
        "is_forwarded": False,
    }
    body.update(overrides)
    return body


def approval_body(**overrides: Any) -> dict[str, Any]:
    """A valid `POST /v1/claudia/approvals` body (kind `action`, PR merge)."""
    body: dict[str, Any] = {
        "window_id": WINDOW,
        "kind": "action",
        "action_text": "Merge PR 31 into main",
        "action_kind": "pr_merge",
        "action_target": "example-org/example-repo#31",
    }
    body.update(overrides)
    return body


def tap_body(request_id: str, decision: str = "approve") -> dict[str, Any]:
    """A `POST /v1/notifier/approvals` body."""
    return {
        "request_id": request_id,
        "decision": decision,
        "source": "telegram",
        "actor_ref": str(OWNER_CHAT),
    }


def code_body(
    code: str, update_id: int = 100, sender_id: int = OWNER_CHAT, *, message_id: int = 5
) -> dict[str, Any]:
    """A `POST /v1/notifier/codes` body."""
    return {"update_id": update_id, "message_id": message_id, "sender_id": sender_id, "code": code}
