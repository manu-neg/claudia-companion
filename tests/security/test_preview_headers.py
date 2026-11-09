"""Security tests for preview-origin response headers (docs/security.md C5, C19, C22).

Every preview response — SVG items, bundle members, nested bundle HTML,
errors from every layer — carries the full sandbox CSP, decided per file;
the only exception is `application/pdf` for a DOCUMENT-mode item. No
response ever carries cookies, CORS or `Service-Worker-Allowed`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from fastapi import Request
from fastapi.responses import Response

from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from preview_dashboard.interfaces.viewer.disposition import content_disposition
from preview_dashboard.interfaces.viewer.hints import PreviewHints, set_preview_hints
from preview_dashboard.kinds.base import PreviewMode
from tests.viewer_support import (
    DASH_ORIGIN,
    OWNER,
    PREVIEW_HOST,
    call_asgi,
    owner_headers,
    preview_app,
    preview_client,
)

if TYPE_CHECKING:
    # starlette.testclient returns httpx2 responses (httpx is its deprecated fallback).
    from httpx2 import Response as ClientResponse

pytestmark = pytest.mark.security

SANDBOX_CSP = (
    "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'self'; "
    "style-src 'unsafe-inline' 'self'; img-src 'self' data: blob:; "
    "media-src 'self' blob:; font-src 'self' data:; connect-src 'none'; "
    "worker-src 'none'; form-action 'none'; base-uri 'none'; "
    f"frame-ancestors {DASH_ORIGIN}"
)
PDF_CSP = (
    "default-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'; "
    f"frame-ancestors {DASH_ORIGIN}"
)

BUNDLE_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"

# (path, media type, hints, extra route headers)
ROUTES: dict[str, tuple[str, PreviewHints | None, dict[str, str]]] = {
    "/svg-item": ("image/svg+xml", PreviewHints(PreviewMode.MEDIA), {}),
    "/bundle/icon.svg": (
        "image/svg+xml",
        PreviewHints(PreviewMode.SANDBOXED, True, item_id=BUNDLE_ID, revision="1"),
        {},
    ),
    "/bundle/sub/x.html": ("text/html", PreviewHints(PreviewMode.SANDBOXED, True), {}),
    "/bundle/index.html": ("text/html", PreviewHints(PreviewMode.SANDBOXED), {}),
    "/bundle/doc.pdf": ("application/pdf", PreviewHints(PreviewMode.SANDBOXED, True), {}),
    "/image": ("image/png", PreviewHints(PreviewMode.MEDIA), {}),
    "/video": ("video/mp4", PreviewHints(PreviewMode.MEDIA), {}),
    "/text": ("text/plain", PreviewHints(PreviewMode.TEXT), {}),
    "/pdf": ("application/pdf", PreviewHints(PreviewMode.DOCUMENT), {}),
    "/pdf-no-hints": ("application/pdf", None, {}),
    "/pdf-download": (
        "application/pdf",
        PreviewHints(PreviewMode.DOWNLOAD),
        {"Content-Disposition": content_disposition("attachment", "a.pdf")},
    ),
    "/pdf-with-params": ("application/pdf; charset=binary", PreviewHints(PreviewMode.DOCUMENT), {}),
    "/html-as-document-mode": ("text/html", PreviewHints(PreviewMode.DOCUMENT), {}),
    "/download": (
        "application/octet-stream",
        PreviewHints(PreviewMode.DOWNLOAD),
        {"Content-Disposition": content_disposition("attachment", "x.bin")},
    ),
    "/hostile": (
        "text/html",
        PreviewHints(PreviewMode.SANDBOXED),
        {
            "Set-Cookie": "sid=1",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Content-Security-Policy": "default-src *",
            "Service-Worker-Allowed": "/",
            "Server": "leaky/1.0",
            "X-Frame-Options": "ALLOWALL",
            "Cache-Control": "public, max-age=31536000",
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Link": "</sw.js>; rel=serviceworker",
            "Refresh": "0; url=https://evil.example",
        },
    ),
}

# Fetch metadata of the request each route is meant for (C31); the header
# tests send the matching one so only headers are under test here.
DEST = {
    "/svg-item": ("image", "same-site"),
    "/bundle/icon.svg": ("image", "cross-site"),
    "/bundle/sub/x.html": ("iframe", "same-site"),  # denied (403): still sandboxed
    "/bundle/index.html": ("iframe", "same-site"),
    "/bundle/doc.pdf": ("iframe", "same-site"),
    "/image": ("image", "same-site"),
    "/video": ("video", "same-site"),
    "/text": ("iframe", "same-site"),
    "/pdf": ("document", "same-site"),
    "/pdf-no-hints": ("document", "same-site"),
    "/pdf-download": ("document", "same-site"),
    "/pdf-with-params": ("document", "same-site"),
    "/html-as-document-mode": ("iframe", "same-site"),
    "/download": ("document", "same-site"),
    "/hostile": ("iframe", "same-site"),
}


@pytest.fixture
def prev() -> SecuredApp:
    app = preview_app()
    for path, (media_type, hints, extra) in ROUTES.items():

        def endpoint(
            request: Request,
            media_type: str = media_type,
            hints: PreviewHints | None = hints,
            extra: dict[str, str] = extra,
        ) -> Response:
            if hints is not None:
                set_preview_hints(request.scope, hints)
            return Response(b"<x/>", headers=dict(extra), media_type=media_type)

        app.inner.add_api_route(path, endpoint, methods=["GET"])

    @app.inner.get("/boom")
    def boom(request: Request) -> Response:
        set_preview_hints(request.scope, PreviewHints(PreviewMode.DOCUMENT))
        raise RuntimeError("secret detail /var/lib/preview-dashboard")

    return app


def _get(app: SecuredApp, path: str, **extra: str) -> ClientResponse:
    dest, site = DEST.get(path, ("document", "same-site"))
    headers = owner_headers({"Sec-Fetch-Dest": dest, "Sec-Fetch-Site": site, **extra})
    return preview_client(app).get(path, headers=headers)


SANDBOXED_PATHS = [p for p in ROUTES if p not in {"/pdf", "/pdf-with-params"}]


@pytest.mark.parametrize("path", SANDBOXED_PATHS)
def test_every_non_pdf_document_response_is_fully_sandboxed(prev: SecuredApp, path: str) -> None:
    response = _get(prev, path)
    assert response.headers["content-security-policy"] == SANDBOX_CSP


def test_required_cases_from_review(prev: SecuredApp) -> None:
    """svg item, bundle .svg and nested sub/x.html are sandboxed (unit 3 review)."""
    for path in ("/svg-item", "/bundle/icon.svg", "/bundle/sub/x.html"):
        csp = _get(prev, path).headers["content-security-policy"]
        assert csp.startswith("sandbox allow-scripts;")
        assert "connect-src 'none'" in csp


@pytest.mark.parametrize("path", ["/pdf", "/pdf-with-params"])
def test_pdf_document_is_the_only_exception(prev: SecuredApp, path: str) -> None:
    response = _get(prev, path)
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert csp == PDF_CSP
    assert "sandbox" not in csp and "script-src" not in csp


def test_csp_header_is_single_and_route_value_is_replaced(prev: SecuredApp) -> None:
    response = _get(prev, "/hostile")
    assert response.headers.get_list("content-security-policy") == [SANDBOX_CSP]


@pytest.mark.parametrize(
    "path_or_case",
    ["/nope", "identity", "host", "method", "body", "boom", "sw", "fetch-dest"],
)
async def test_error_responses_are_sandboxed_too(prev: SecuredApp, path_or_case: str) -> None:
    headers = [
        (b"host", PREVIEW_HOST.encode()),
        (b"tailscale-user-login", OWNER.encode()),
    ]
    method, path = "GET", "/image"
    if path_or_case == "/nope":
        path = "/nope"
    elif path_or_case == "identity":
        headers[1] = (b"tailscale-user-login", b"nobody")
    elif path_or_case == "host":
        headers[0] = (b"host", b"evil.example")
    elif path_or_case == "method":
        method = "POST"
    elif path_or_case == "body":
        headers.append((b"content-length", b"5"))
    elif path_or_case == "boom":
        path = "/boom"
    elif path_or_case == "sw":
        headers.append((b"service-worker", b"script"))
    elif path_or_case == "fetch-dest":
        headers.append((b"sec-fetch-dest", b"embed"))
        headers.append((b"sec-fetch-site", b"same-site"))
    result = await call_asgi(prev, method=method, path=path, headers=headers)
    assert result.status is not None and result.status >= 400
    assert result.header("content-security-policy") == SANDBOX_CSP
    assert result.header("cache-control") == "no-store"
    assert result.header("x-content-type-options") == "nosniff"
    assert b"secret detail" not in result.body and b"Traceback" not in result.body


def test_500_body_is_generic(prev: SecuredApp) -> None:
    response = _get(prev, "/boom")
    assert response.status_code == 500
    assert response.json() == {
        "error": "internal_error",
        "request_id": response.headers["x-request-id"],
    }


def test_hostile_route_headers_are_stripped(prev: SecuredApp) -> None:
    response = _get(prev, "/hostile")
    lowered = {k.lower() for k in response.headers}
    assert "set-cookie" not in lowered
    assert not any(k.startswith("access-control-") for k in lowered)
    assert "service-worker-allowed" not in lowered
    assert "server" not in lowered
    assert "x-frame-options" not in lowered
    assert "link" not in lowered and "refresh" not in lowered
    assert response.headers["cache-control"] == "private, no-cache"
    assert response.headers["cross-origin-resource-policy"] == "same-site"


@pytest.mark.parametrize("path", [*ROUTES, "/nope", "/boom"])
def test_no_cookies_or_cors_on_any_preview_response(prev: SecuredApp, path: str) -> None:
    response = _get(prev, path, Origin="https://evil.example")
    lowered = {k.lower() for k in response.headers}
    assert "set-cookie" not in lowered
    assert not any(k.startswith("access-control-") for k in lowered)
    assert "service-worker-allowed" not in lowered


def test_common_preview_headers(prev: SecuredApp) -> None:
    headers = _get(prev, "/image").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-site"
    assert headers["origin-agent-cluster"] == "?1"
    assert headers["cache-control"] == "private, no-cache"
    assert "x-frame-options" not in headers  # the dashboard must be able to frame previews
    policy = headers["permissions-policy"]
    for feature in ("camera", "microphone", "geolocation", "usb", "payment", "fullscreen"):
        assert f"{feature}=()" in policy


def test_bundle_subresource_gets_cross_origin_corp_only_when_bound(prev: SecuredApp) -> None:
    """Opaque-origin bundle documents can't load same-site CORP resources (ADR 0012),
    so bound sub-resources get `cross-origin`; unbound ones stay `same-site`."""
    own = {"Referer": f"https://{PREVIEW_HOST}/i/{BUNDLE_ID}/1/index.html"}
    other = {"Referer": f"https://{PREVIEW_HOST}/i/{OTHER_ID}/1/index.html"}
    foreign = {"Referer": "https://evil.example/i/" + BUNDLE_ID + "/1/index.html"}
    # Same item, another revision: a different bundle (ADR 0019).
    other_rev = {"Referer": f"https://{PREVIEW_HOST}/i/{BUNDLE_ID}/2/index.html"}
    client = preview_client(prev)

    def corp(extra: dict[str, str]) -> ClientResponse:
        return client.get("/bundle/icon.svg", headers=owner_headers(extra))

    bound = corp(own)
    assert bound.headers["cross-origin-resource-policy"] == "cross-origin"
    assert bound.headers["vary"] == "Referer"
    for extra in ({}, other, foreign, other_rev):
        response = corp(extra)
        assert response.headers["cross-origin-resource-policy"] == "same-site"
        assert response.headers["vary"] == "Referer"
    assert _get(prev, "/svg-item").headers["cross-origin-resource-policy"] == "same-site"
    assert "vary" not in _get(prev, "/svg-item").headers


def test_bundle_pages_send_same_origin_referrer(prev: SecuredApp) -> None:
    """Bundle pages must emit a Referer for their own loads; nothing else does."""
    assert _get(prev, "/bundle/index.html").headers["referrer-policy"] == "same-origin"
    nested = preview_client(prev).get("/bundle/sub/x.html", headers=owner_headers())
    assert nested.headers["referrer-policy"] == "same-origin"
    assert _get(prev, "/image").headers["referrer-policy"] == "no-referrer"
    assert _get(prev, "/pdf").headers["referrer-policy"] == "no-referrer"


def test_multiple_dashboard_hosts_all_listed_as_frame_ancestors() -> None:
    app = preview_app(allowed_hosts=frozenset({"b.example.ts.net", "dash.example.ts.net"}))

    @app.inner.get("/x")
    def x() -> Response:
        return Response(b"", media_type="image/png")

    response = preview_client(app).get(
        "/x", headers=owner_headers({"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site"})
    )
    assert response.headers["content-security-policy"].endswith(
        "frame-ancestors https://b.example.ts.net https://dash.example.ts.net"
    )
