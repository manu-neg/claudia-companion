"""Builds the two viewer ASGI apps: dashboard (UI + JSON) and preview (item bytes).

Each app is a FastAPI app with docs/OpenAPI off and generic errors, wrapped
in a fixed stack of pure ASGI security middleware (docs/security.md C2-C6,
C19, C21, C22, C31). The stack wraps the *whole* FastAPI app, so even
Starlette's own error responses get the security headers.
"""

from __future__ import annotations

from fastapi import FastAPI
from starlette.types import ASGIApp, Receive, Scope, Send

from preview_dashboard.config import Settings
from preview_dashboard.interfaces.viewer.csrf import CsrfMiddleware
from preview_dashboard.interfaces.viewer.errors import (
    CatchAllMiddleware,
    register_exception_handlers,
)
from preview_dashboard.interfaces.viewer.fetch_metadata import (
    DashboardFetchMetadataMiddleware,
    PreviewFetchMetadataMiddleware,
)
from preview_dashboard.interfaces.viewer.headers import (
    DashboardHeaderPolicy,
    HeaderPolicy,
    PreviewHeaderPolicy,
    SecurityHeadersMiddleware,
)
from preview_dashboard.interfaces.viewer.identity import IdentityMiddleware
from preview_dashboard.interfaces.viewer.knowledge import Knowledge
from preview_dashboard.interfaces.viewer.limits import (
    DASHBOARD_MAX_BODY_BYTES,
    BodyLimitMiddleware,
    MethodAllowlistMiddleware,
)
from preview_dashboard.interfaces.viewer.origins import ViewerOrigins
from preview_dashboard.interfaces.viewer.relpath_url import RawPathGuardMiddleware
from preview_dashboard.interfaces.viewer.renderer_page import RendererPage
from preview_dashboard.interfaces.viewer.request_id import RequestIdMiddleware
from preview_dashboard.interfaces.viewer.routes import dashboard as dashboard_routes
from preview_dashboard.interfaces.viewer.routes import kb as kb_routes
from preview_dashboard.interfaces.viewer.routes import preview as preview_routes
from preview_dashboard.interfaces.viewer.service_worker import ServiceWorkerGuardMiddleware
from preview_dashboard.interfaces.viewer.services import ViewerOptions, ViewerServices
from preview_dashboard.interfaces.viewer.static_assets import StaticAssets, default_static_dir

__all__ = ["SecuredApp", "ViewerServices", "build_dashboard_app", "build_preview_app"]


class SecuredApp:
    """An ASGI app: the security middleware stack around a FastAPI app.

    Attributes:
        inner: the wrapped FastAPI app (routes, state, exception handlers).
        origins: the trust values the stack was built with.
    """

    def __init__(self, stack: ASGIApp, inner: FastAPI, origins: ViewerOrigins) -> None:
        self._stack = stack
        self.inner = inner
        self.origins = origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._stack(scope, receive, send)


def _fastapi(settings: Settings, services: ViewerServices, origins: ViewerOrigins) -> FastAPI:
    """A FastAPI app with no docs/OpenAPI, no debug, no slash redirects (C21)."""
    app = FastAPI(
        debug=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        swagger_ui_oauth2_redirect_url=None,
        redirect_slashes=False,
    )
    app.state.services = services
    app.state.origins = origins
    app.state.options = ViewerOptions.from_settings(settings, origins.preview_origin)
    register_exception_handlers(app)
    return app


def _outer(app: ASGIApp, policy: HeaderPolicy) -> ASGIApp:
    """Layers shared by both apps, outermost last-applied (runs first)."""
    app = CatchAllMiddleware(app)
    app = SecurityHeadersMiddleware(app, policy=policy)
    return RequestIdMiddleware(app)


def build_dashboard_app(
    settings: Settings,
    services: ViewerServices,
    *,
    static_assets: StaticAssets | None = None,
    knowledge: Knowledge | None = None,
) -> SecuredApp:
    """Build the dashboard app (UI + JSON, local `viewer_port`, served on 443).

    Request order: request id → security headers → catch-all → service-worker
    guard → Host + owner identity → raw-path guard → fetch metadata → CSRF
    (POST only; 405 for other unsafe methods) → 1 KiB body cap → routes.

    Args:
        static_assets: UI files to serve; default: the packaged `static/`
            directory, read into memory once here.
        knowledge: knowledge-map services (C57); default None = the map is off
            and the approvals list confirms nothing (fail closed).

    Raises:
        ConfigError: owner/hosts/preview origin unset or invalid (fail closed).
        StaticAssetError: the static directory is unsafe.
    """
    origins = ViewerOrigins.from_settings(settings)
    inner = _fastapi(settings, services, origins)
    inner.state.static_assets = (
        static_assets if static_assets is not None else StaticAssets.load(default_static_dir())
    )
    inner.state.knowledge = knowledge
    inner.include_router(dashboard_routes.router)
    # Dashboard app only: the preview app never gets KB routes (C57, I2).
    inner.include_router(kb_routes.router)
    app: ASGIApp = BodyLimitMiddleware(inner, max_bytes=DASHBOARD_MAX_BODY_BYTES)
    app = CsrfMiddleware(app, dashboard_origins=origins.dashboard_origins)
    app = DashboardFetchMetadataMiddleware(app)
    app = RawPathGuardMiddleware(app)
    app = IdentityMiddleware(
        app, owner_login=origins.owner_login, allowed_hosts=origins.dashboard_hosts
    )
    app = ServiceWorkerGuardMiddleware(app)
    return SecuredApp(_outer(app, DashboardHeaderPolicy(origins)), inner, origins)


def build_preview_app(
    settings: Settings,
    services: ViewerServices,
    *,
    renderer_page: RendererPage | None = None,
) -> SecuredApp:
    """Build the preview app (item bytes only, local `preview_port`, served on 8443).

    Request order: request id → security headers (per-file CSP) → catch-all
    → service-worker guard → Host + owner identity → raw-path guard →
    GET/HEAD only → no request body → fetch metadata (request and response
    phase) → routes.

    Args:
        renderer_page: the `/r/` text renderer (inlined assets); default:
            built once here from the packaged `static/` directory.

    Raises:
        ConfigError: owner/hosts/preview origin unset or invalid (fail closed).
        StaticAssetError: the renderer assets are missing or unsafe to inline.
    """
    origins = ViewerOrigins.from_settings(settings)
    inner = _fastapi(settings, services, origins)
    inner.state.renderer_page = (
        renderer_page if renderer_page is not None else RendererPage.load(default_static_dir())
    )
    inner.include_router(preview_routes.router)
    app: ASGIApp = PreviewFetchMetadataMiddleware(inner, preview_origin=origins.preview_origin)
    app = BodyLimitMiddleware(app, max_bytes=0)
    app = MethodAllowlistMiddleware(app, methods=("GET", "HEAD"))
    app = RawPathGuardMiddleware(app)
    app = IdentityMiddleware(
        app, owner_login=origins.owner_login, allowed_hosts=(origins.preview_host,)
    )
    app = ServiceWorkerGuardMiddleware(app)
    return SecuredApp(_outer(app, PreviewHeaderPolicy(origins)), inner, origins)
