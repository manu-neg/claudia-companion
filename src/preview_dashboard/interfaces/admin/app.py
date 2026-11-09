"""Builds the admin ASGI app: FastAPI routes inside a fixed security middleware stack.

Order (outermost first): request id → access log → catch-all 500 → peer
uid policy → bearer token (admin, notifier or claudia, scoped per route family) →
FastAPI (no docs/OpenAPI, no debug, no slash redirects). Authentication runs
before routing, so without a token even 404s are indistinguishable from
401s (docs/security.md C12, C19, C26, C33, C34).
"""

from __future__ import annotations

from collections.abc import Collection

from fastapi import FastAPI
from starlette.types import ASGIApp

from preview_dashboard.bootstrap import AdminCore, dashboard_base_url
from preview_dashboard.config import Settings
from preview_dashboard.interfaces.admin import (
    claudia_api,
    cleanup_api,
    folders_api,
    notifier_api,
    questions_api,
)
from preview_dashboard.interfaces.admin.api import router
from preview_dashboard.interfaces.admin.auth import (
    BearerAuthMiddleware,
    PeerPolicyMiddleware,
    TokenVerifier,
)
from preview_dashboard.interfaces.admin.errors import (
    AccessLogMiddleware,
    CatchAllMiddleware,
    RequestIdMiddleware,
    register_exception_handlers,
)
from preview_dashboard.interfaces.admin.longpoll import (
    MAX_APPROVAL_WAITERS,
    MAX_CLAUDIA_POLLERS,
    MAX_NOTIFIER_POLLERS,
    MAX_QUESTION_WAITERS,
    WaiterSlots,
)
from preview_dashboard.interfaces.admin.multipart import PublishFormLimits


def viewer_base_url(settings: Settings) -> str | None:
    """The dashboard origin used in `viewer_url`s (see `bootstrap.dashboard_base_url`)."""
    return dashboard_base_url(settings)


def build_admin_app(
    core: AdminCore,
    *,
    token: bytes,
    notifier_token: bytes | None = None,
    allowed_peer_uids: Collection[int] | None = None,
    notifier_peer_uids: Collection[int] | None = None,
    form_limits: PublishFormLimits | None = None,
    claudia_token: bytes | None = None,
    claudia_peer_uids: Collection[int] | None = None,
) -> ASGIApp:
    """Build the admin API app around an admin core.

    Args:
        core: the admin role's services (`bootstrap.build_core(role="admin")`).
        token: the admin bearer token (from `auth.load_admin_token`), >= 43
            chars; valid on every route except `/v1/notifier/*` and `/v1/claudia/*`.
        notifier_token: the notifier token, valid only on `/v1/notifier/*`
            (None: those routes accept no token at all).
        allowed_peer_uids: Unix-socket peer uids allowed on the admin routes.
        notifier_peer_uids: peer uids allowed on `/v1/notifier/*`. If any
            peer list is non-empty, all are enforced (403 otherwise, including
            unknown peers); if all are empty, socket permissions decide.
        form_limits: publish request limits; default derived from settings
            (tests pass tighter timeouts).
        claudia_token: the Claudia host's token, valid only on `/v1/claudia/*`
            (None: those routes accept no token at all; C45).
        claudia_peer_uids: peer uids allowed on `/v1/claudia/*` (the host's).

    Raises:
        ValueError: a token is too short or too low-variety, or two tokens
            are the same.
    """
    inner = FastAPI(
        debug=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        swagger_ui_oauth2_redirect_url=None,
        redirect_slashes=False,
    )
    inner.state.core = core
    inner.state.viewer_base = viewer_base_url(core.settings)
    inner.state.publish_limits = form_limits or PublishFormLimits.for_settings(core.settings)
    inner.state.question_slots = WaiterSlots(MAX_QUESTION_WAITERS)
    inner.state.notifier_gate = WaiterSlots(MAX_NOTIFIER_POLLERS)
    inner.state.claudia_gate = WaiterSlots(MAX_CLAUDIA_POLLERS)
    inner.state.approval_slots = WaiterSlots(MAX_APPROVAL_WAITERS)
    register_exception_handlers(inner)
    inner.include_router(router)
    inner.include_router(folders_api.router)
    inner.include_router(cleanup_api.router)
    inner.include_router(questions_api.router)
    inner.include_router(notifier_api.router)
    inner.include_router(claudia_api.router)
    app: ASGIApp = BearerAuthMiddleware(
        inner,
        verifier=TokenVerifier(token),
        notifier_verifier=None if notifier_token is None else TokenVerifier(notifier_token),
        claudia_verifier=None if claudia_token is None else TokenVerifier(claudia_token),
    )
    app = PeerPolicyMiddleware(
        app,
        allowed_uids=allowed_peer_uids,
        notifier_uids=notifier_peer_uids,
        claudia_uids=claudia_peer_uids,
    )
    app = CatchAllMiddleware(app)
    app = AccessLogMiddleware(app)
    return RequestIdMiddleware(app)
