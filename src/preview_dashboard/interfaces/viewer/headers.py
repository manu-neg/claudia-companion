"""Security response headers for the dashboard and preview apps (docs/security.md C5, C6, C19, C22).

`SecurityHeadersMiddleware` wraps every response of an app (errors included)
and replaces whatever security headers a route set with the app's policy:
routes cannot weaken them. `csp_for` is the pure per-file preview CSP rule;
`dashboard_csp` the dashboard page policy (Trusted Types: ADR 0011).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Protocol

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from preview_dashboard.interfaces.viewer._http import media_type_of, response_header
from preview_dashboard.interfaces.viewer.errors import error_body
from preview_dashboard.interfaces.viewer.hints import bundle_referer_bound, get_preview_hints
from preview_dashboard.interfaces.viewer.origins import ViewerOrigins
from preview_dashboard.interfaces.viewer.request_id import request_id_of
from preview_dashboard.kinds.base import PreviewMode

logger = logging.getLogger("preview_dashboard.viewer")

PDF_MEDIA_TYPE = "application/pdf"

# Browser features nobody on either origin needs. Denying them on the
# preview origin keeps hostile HTML from even prompting for them.
_DENIED_FEATURES: tuple[str, ...] = (
    "accelerometer",
    "autoplay",
    "bluetooth",
    "camera",
    "clipboard-read",
    "clipboard-write",
    "display-capture",
    "encrypted-media",
    "geolocation",
    "gyroscope",
    "hid",
    "identity-credentials-get",
    "idle-detection",
    "local-fonts",
    "magnetometer",
    "microphone",
    "midi",
    "otp-credentials",
    "payment",
    "publickey-credentials-create",
    "publickey-credentials-get",
    "screen-wake-lock",
    "serial",
    "storage-access",
    "usb",
    "web-share",
    "window-management",
    "xr-spatial-tracking",
)
PREVIEW_PERMISSIONS_POLICY = ", ".join(
    f"{f}=()" for f in sorted((*_DENIED_FEATURES, "fullscreen", "picture-in-picture"))
)
# The dashboard itself plays previewed video, so it keeps fullscreen/PiP.
DASHBOARD_PERMISSIONS_POLICY = ", ".join(
    [f"{f}=()" for f in _DENIED_FEATURES] + ["fullscreen=(self)", "picture-in-picture=(self)"]
)

# Headers the middleware owns: removed from every route response, then set
# from policy. Cookies/CORS are removed *and* logged, because a route
# emitting one is a bug that breaks I1/C19.
_FORBIDDEN_EXACT = frozenset({b"set-cookie", b"set-cookie2"})
_FORBIDDEN_PREFIX = b"access-control-"
_OWNED = frozenset(
    {
        b"cache-control",
        b"content-security-policy",
        b"content-security-policy-report-only",
        b"cross-origin-embedder-policy",
        b"cross-origin-opener-policy",
        b"cross-origin-resource-policy",
        b"feature-policy",
        b"link",  # could preload/prefetch or (historically) register a service worker
        b"nel",
        b"origin-agent-cluster",
        b"permissions-policy",
        b"referrer-policy",
        b"refresh",  # header-driven navigation
        b"report-to",
        b"reporting-endpoints",
        b"server",
        b"service-worker-allowed",
        b"timing-allow-origin",
        b"x-content-type-options",
        b"x-dns-prefetch-control",
        b"x-frame-options",
        b"x-permitted-cross-domain-policies",
        b"x-powered-by",
        b"x-xss-protection",
    }
)


def _join(directives: Sequence[str]) -> str:
    return "; ".join(directives)


def sandbox_csp(frame_ancestors: Sequence[str]) -> str:
    """Return the full sandboxed preview CSP (C5) framed only by `frame_ancestors`."""
    return _join(
        (
            "sandbox allow-scripts",
            "default-src 'none'",
            "script-src 'unsafe-inline' 'self'",
            "style-src 'unsafe-inline' 'self'",
            "img-src 'self' data: blob:",
            "media-src 'self' blob:",
            "font-src 'self' data:",
            "connect-src 'none'",
            "worker-src 'none'",
            "form-action 'none'",
            "base-uri 'none'",
            f"frame-ancestors {' '.join(frame_ancestors)}",
        )
    )


def pdf_csp(frame_ancestors: Sequence[str]) -> str:
    """Return the PDF exception CSP: no `sandbox` (Chrome refuses sandboxed PDFs)."""
    return _join(
        (
            "default-src 'none'",
            "object-src 'none'",
            "form-action 'none'",
            "base-uri 'none'",
            f"frame-ancestors {' '.join(frame_ancestors)}",
        )
    )


def csp_for(
    media_type: str,
    preview_mode: PreviewMode | None,
    *,
    frame_ancestors: Sequence[str],
) -> str:
    """Return the CSP for one preview-origin response, decided per file.

    Every response gets the full sandbox CSP, with one exception: a file
    whose media type is exactly `application/pdf` served for an item whose
    kind's preview mode is `DOCUMENT`. A PDF inside a bundle or a DOWNLOAD
    item, an SVG, an HTML bundle member and every error stay sandboxed.

    Args:
        media_type: lowercase `type/subtype` of the response ("" if none).
        preview_mode: the item kind's preview mode, or None when unknown.
        frame_ancestors: dashboard origins allowed to frame the response.
    """
    if not frame_ancestors:
        raise ValueError("frame_ancestors must not be empty")
    if media_type == PDF_MEDIA_TYPE and preview_mode is PreviewMode.DOCUMENT:
        return pdf_csp(frame_ancestors)
    return sandbox_csp(frame_ancestors)


def dashboard_csp(preview_origin: str) -> str:
    """Return the dashboard page CSP (C6), with the Trusted Types backstop (ADR 0011).

    `trusted-types 'none'`: the dashboard renders no HTML from data and
    loads no DOMPurify (text is formatted on the preview origin, ADR 0018),
    so no Trusted Types policy may be created at all — every HTML/script
    sink refuses strings outright.
    """
    return _join(
        (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            f"img-src 'self' data: {preview_origin}",
            f"media-src {preview_origin}",
            f"frame-src {preview_origin}",
            "connect-src 'self'",
            "font-src 'self'",
            "manifest-src 'self'",
            "worker-src 'none'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types 'none'",
        )
    )


def cache_control(route_value: bytes | None, default: str) -> str:
    """Return the Cache-Control to send: the route's if private/no-store, else `default`.

    Nothing the viewer serves may be stored by a shared cache, so a route
    value is kept only if it says `private` or `no-store` and not `public`.
    """
    if route_value:
        tokens = {
            t.strip().split("=", 1)[0] for t in route_value.decode("latin-1").lower().split(",")
        }
        if "public" not in tokens and "s-maxage" not in tokens and tokens & {"private", "no-store"}:
            return route_value.decode("latin-1")
    return default


class HeaderPolicy(Protocol):
    """Decides an app's security headers for one response."""

    def headers_for(
        self, scope: Scope, status: int, route_headers: Sequence[tuple[bytes, bytes]]
    ) -> list[tuple[str, str]]:
        """Return the headers to add, given the route's original headers."""
        ...


_COMMON: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Origin-Agent-Cluster", "?1"),
    ("X-DNS-Prefetch-Control", "off"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
)


class DashboardHeaderPolicy:
    """Headers for the dashboard app (UI + JSON): never framable, never cached."""

    def __init__(self, origins: ViewerOrigins) -> None:
        self._csp = dashboard_csp(origins.preview_origin)

    def headers_for(
        self, scope: Scope, status: int, route_headers: Sequence[tuple[bytes, bytes]]
    ) -> list[tuple[str, str]]:
        return [
            *_COMMON,
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", self._csp),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("X-Frame-Options", "DENY"),
            ("Permissions-Policy", DASHBOARD_PERMISSIONS_POLICY),
            (
                "Cache-Control",
                cache_control(response_header(route_headers, b"cache-control"), "no-store"),
            ),
        ]


class PreviewHeaderPolicy:
    """Headers for the preview app (item bytes only), decided per file.

    CSP comes from `csp_for` (response Content-Type + route hints). CORP is
    `same-site` (the dashboard is same-site: same host, other port), except
    `cross-origin` for successful HTML-bundle sub-resources whose `Referer`
    binds them to their own bundle (`bundle_referer_bound`): their
    opaque-origin sandboxed document could not load them otherwise (ADR
    0012). Bundle sub-resources vary on `Referer` so a cached copy is never
    reused with the wrong CORP. Successful SANDBOXED (HTML bundle) responses
    use `Referrer-Policy: same-origin` so the bundle's own loads carry that
    Referer (it never leaves the preview origin); everything else sends none.
    No `X-Frame-Options`: the dashboard must frame previews; `frame-ancestors`
    restricts who may.
    """

    def __init__(self, origins: ViewerOrigins) -> None:
        self._ancestors = origins.dashboard_origins
        self._preview_origin = origins.preview_origin

    def headers_for(
        self, scope: Scope, status: int, route_headers: Sequence[tuple[bytes, bytes]]
    ) -> list[tuple[str, str]]:
        hints = get_preview_hints(scope)
        media_type = media_type_of(response_header(route_headers, b"content-type"))
        success = 200 <= status < 300 or status == 304
        bound = success and bundle_referer_bound(scope, hints, self._preview_origin)
        corp = "cross-origin" if bound else "same-site"
        referrer = (
            "same-origin"
            if success and hints.preview_mode is PreviewMode.SANDBOXED
            else "no-referrer"
        )
        cache_default = "private, no-cache" if success else "no-store"
        route_cache = response_header(route_headers, b"cache-control") if success else None
        extra = [("Vary", "Referer")] if success and hints.bundle_subresource else []
        return [
            *_COMMON,
            ("Referrer-Policy", referrer),
            *extra,
            (
                "Content-Security-Policy",
                csp_for(media_type, hints.preview_mode, frame_ancestors=self._ancestors),
            ),
            ("Cross-Origin-Resource-Policy", corp),
            ("Permissions-Policy", PREVIEW_PERMISSIONS_POLICY),
            ("Cache-Control", cache_control(route_cache, cache_default)),
        ]


def _is_owned(name: bytes) -> bool:
    return name in _OWNED or name in _FORBIDDEN_EXACT or name.startswith(_FORBIDDEN_PREFIX)


# A response with two of these is ambiguous (which type/disposition does the
# browser use?), so it is never delivered.
_SINGLE_RESPONSE_HEADERS = (b"content-type", b"content-disposition")


def has_ambiguous_headers(headers: Sequence[tuple[bytes, bytes]]) -> bool:
    """True if a response carries more than one Content-Type or Content-Disposition."""
    names = [bytes(k).lower() for k, _ in headers]
    return any(names.count(name) > 1 for name in _SINGLE_RESPONSE_HEADERS)


class _ResponseReplacedError(Exception):
    """Internal: the route's response was replaced by a 500; abort its body."""


class SecurityHeadersMiddleware:
    """Replace every response's security headers with `policy`'s (C19, C22).

    Strips cookies, CORS, `Server`, `Service-Worker-Allowed` and every header
    the policy owns, whatever the route or an inner middleware set, then
    appends the policy's values. Wrap it around everything else so error
    responses from inner middleware are covered too.
    """

    def __init__(self, app: ASGIApp, *, policy: HeaderPolicy) -> None:
        self._app = app
        self._policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                original: list[tuple[bytes, bytes]] = [
                    (bytes(k).lower(), bytes(v)) for k, v in message.get("headers", ())
                ]
                if has_ambiguous_headers(original):
                    logger.error(
                        "duplicate content-type/disposition replaced by 500 request_id=%s",
                        request_id_of(scope),
                    )
                    await self._send_500(scope, send)
                    raise _ResponseReplacedError
                for name, _ in original:
                    if name in _FORBIDDEN_EXACT or name.startswith(_FORBIDDEN_PREFIX):
                        # Name only: the value may be sensitive (C29).
                        logger.error(
                            "stripped forbidden response header %s request_id=%s",
                            name.decode("latin-1"),
                            request_id_of(scope),
                        )
                kept = [(k, v) for k, v in original if not _is_owned(k)]
                added = self._policy.headers_for(scope, message["status"], original)
                message = {
                    **message,
                    "headers": kept
                    + [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in added],
                }
            await send(message)

        await self._app(scope, receive, send_with_headers)

    async def _send_500(self, scope: Scope, send: Send) -> None:
        body = error_body(500, request_id_of(scope))
        base = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        added = self._policy.headers_for(scope, 500, base)
        headers = base + [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in added]
        await send({"type": "http.response.start", "status": 500, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})
