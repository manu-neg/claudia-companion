"""Security tests for dashboard-app response headers (docs/security.md C6, C19, C22).

The dashboard page CSP (with the Trusted Types backstop, ADR 0011) and the
common hardening headers are present on every response, including errors,
and routes cannot weaken them or emit cookies/CORS.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.responses import JSONResponse, Response

from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from tests.viewer_support import (
    DASH_HOST,
    PREVIEW_ORIGIN,
    call_asgi,
    csrf_headers,
    dashboard_app,
    dashboard_client,
    owner_headers,
)

pytestmark = pytest.mark.security

DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    f"img-src 'self' data: {PREVIEW_ORIGIN}; media-src {PREVIEW_ORIGIN}; "
    f"frame-src {PREVIEW_ORIGIN}; connect-src 'self'; font-src 'self'; "
    "manifest-src 'self'; worker-src 'none'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'; "
    "require-trusted-types-for 'script'; trusted-types 'none'"
)


@pytest.fixture
def dash() -> SecuredApp:
    app = dashboard_app()

    @app.inner.get("/api/feed")
    def feed() -> JSONResponse:
        return JSONResponse({"items": []})

    @app.inner.get("/hostile")
    def hostile() -> Response:
        return Response(
            b"{}",
            media_type="application/json",
            headers={
                "Set-Cookie": "sid=secret-cookie-value",
                "Access-Control-Allow-Origin": "*",
                "Content-Security-Policy": "default-src *",
                "X-Frame-Options": "SAMEORIGIN",
                "Cache-Control": "public, max-age=600",
                "Server": "x",
                "Service-Worker-Allowed": "/",
            },
        )

    @app.inner.get("/cached")
    def cached() -> Response:
        headers = {"Cache-Control": "private, max-age=60"}
        return Response(b"x", media_type="text/css", headers=headers)

    @app.inner.post("/api/x")
    def post() -> JSONResponse:
        return JSONResponse({})

    return app


def test_dashboard_csp_is_exact(dash: SecuredApp) -> None:
    response = dashboard_client(dash).get("/api/feed", headers=owner_headers())
    assert response.headers.get_list("content-security-policy") == [DASHBOARD_CSP]


def test_trusted_types_backstop_allows_no_policy(dash: SecuredApp) -> None:
    csp = (
        dashboard_client(dash)
        .get("/api/feed", headers=owner_headers())
        .headers["content-security-policy"]
    )
    assert "require-trusted-types-for 'script'" in csp
    # No policy at all: the dashboard never turns a string into HTML (ADR 0011 amendment).
    assert "trusted-types 'none'" in csp
    assert "dompurify" not in csp
    assert "'allow-duplicates'" not in csp and " default" not in csp.split("trusted-types")[1]


def test_no_inline_or_remote_script_allowed(dash: SecuredApp) -> None:
    csp = (
        dashboard_client(dash)
        .get("/api/feed", headers=owner_headers())
        .headers["content-security-policy"]
    )
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "https:" not in csp.replace(PREVIEW_ORIGIN, "")


def test_common_dashboard_headers(dash: SecuredApp) -> None:
    headers = dashboard_client(dash).get("/api/feed", headers=owner_headers()).headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["x-frame-options"] == "DENY"
    assert headers["origin-agent-cluster"] == "?1"
    assert headers["cache-control"] == "no-store"
    policy = headers["permissions-policy"]
    for feature in ("camera", "microphone", "geolocation", "usb", "payment"):
        assert f"{feature}=()" in policy
    assert "fullscreen=(self)" in policy


@pytest.mark.parametrize(
    "case", ["not-found", "identity", "host", "csrf", "method", "body", "service-worker"]
)
async def test_error_responses_carry_all_headers(dash: SecuredApp, case: str) -> None:
    headers = [(k.lower().encode(), v.encode()) for k, v in owner_headers().items()]
    headers.insert(0, (b"host", DASH_HOST.encode()))
    method, path, body = "GET", "/api/feed", b""
    if case == "not-found":
        path = "/missing"
    elif case == "identity":
        headers = [(b"host", DASH_HOST.encode())]
    elif case == "host":
        headers[0] = (b"host", b"evil.example")
    elif case == "csrf":
        method, path = "POST", "/api/x"
    elif case == "method":
        method = "DELETE"
    elif case == "body":
        method, path, body = "POST", "/api/x", b"x" * 2048
        headers = [(b"host", DASH_HOST.encode())] + [
            (k.lower().encode(), v.encode()) for k, v in csrf_headers().items()
        ]
        headers.append((b"content-length", b"2048"))
    elif case == "service-worker":
        headers.append((b"service-worker", b"script"))
    result = await call_asgi(dash, method=method, path=path, headers=headers, body=body)
    assert result.status is not None and result.status >= 400
    assert result.header("content-security-policy") == DASHBOARD_CSP
    assert result.header("x-frame-options") == "DENY"
    assert result.header("cache-control") == "no-store"
    assert result.header("content-type") == "application/json"


def test_route_cannot_weaken_or_leak(dash: SecuredApp, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR)
    response = dashboard_client(dash).get("/hostile", headers=owner_headers())
    lowered = {k.lower() for k in response.headers}
    assert "set-cookie" not in lowered
    assert not any(k.startswith("access-control-") for k in lowered)
    assert "server" not in lowered and "service-worker-allowed" not in lowered
    assert response.headers.get_list("content-security-policy") == [DASHBOARD_CSP]
    assert response.headers.get_list("x-frame-options") == ["DENY"]
    assert response.headers["cache-control"] == "no-store"
    # The stripping is logged by header name, never by value.
    assert "set-cookie" in caplog.text
    assert "secret-cookie-value" not in caplog.text


def test_private_cache_control_from_route_is_kept(dash: SecuredApp) -> None:
    response = dashboard_client(dash).get("/cached", headers=owner_headers())
    assert response.headers["cache-control"] == "private, max-age=60"


def test_request_id_is_random_and_client_value_ignored(dash: SecuredApp) -> None:
    client = dashboard_client(dash)
    first = client.get("/api/feed", headers=owner_headers({"X-Request-Id": "forged\r\nx"}))
    second = client.get("/api/feed", headers=owner_headers())
    assert first.headers["x-request-id"] != "forged\r\nx"
    assert first.headers["x-request-id"] != second.headers["x-request-id"]
    assert len(first.headers["x-request-id"]) == 16
