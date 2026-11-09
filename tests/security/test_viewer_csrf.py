"""Security tests for the dashboard CSRF matrix and method/body limits (docs/security.md C4, C19).

A dummy JSON POST route stands in for trash/restore; every row of the
matrix removes or corrupts exactly one requirement of a legitimate request.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from tests.viewer_support import (
    DASH_HOST,
    DASH_ORIGIN,
    OWNER,
    PREVIEW_ORIGIN,
    call_asgi,
    csrf_headers,
    dashboard_app,
    dashboard_client,
    owner_headers,
)

pytestmark = pytest.mark.security


@pytest.fixture
def dash() -> SecuredApp:
    app = dashboard_app()

    @app.inner.post("/api/csrf-probe")
    async def trash(request: Request) -> JSONResponse:
        body = await request.body()
        return JSONResponse({"ok": True, "len": len(body)})

    @app.inner.get("/api/feed")
    def feed() -> JSONResponse:
        return JSONResponse({"items": []})

    return app


def _post(
    app: SecuredApp, headers: dict[str, str], body: bytes = b"{}"
) -> tuple[int, dict[str, str]]:
    response = dashboard_client(app).post("/api/csrf-probe", headers=headers, content=body)
    return response.status_code, dict(response.headers)


def test_legitimate_post_passes(dash: SecuredApp) -> None:
    status, _ = _post(dash, csrf_headers())
    assert status == 200


def test_get_needs_no_csrf_headers(dash: SecuredApp) -> None:
    assert dashboard_client(dash).get("/api/feed", headers=owner_headers()).status_code == 200


@pytest.mark.parametrize(
    ("header", "value"),
    [
        # Content-Type: only exact application/json.
        ("Content-Type", "text/plain"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Content-Type", "multipart/form-data; boundary=x"),
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Type", "Application/JSON"),
        ("Content-Type", "application/json "),
        ("Content-Type", "text/plain; application/json"),
        # Origin: exactly the dashboard origin.
        ("Origin", "null"),
        ("Origin", PREVIEW_ORIGIN),
        ("Origin", f"{DASH_ORIGIN}/"),
        ("Origin", f"{DASH_ORIGIN}:443"),
        (
            "Origin",
            f"http://{DASH_HOST}",
        ),
        ("Origin", "https://evil.example"),
        ("Origin", f"https://{DASH_HOST}.evil.example"),
        ("Origin", "HTTPS://DASH.EXAMPLE.TS.NET"),
        # Sec-Fetch-Site: exactly same-origin.
        ("Sec-Fetch-Site", "same-site"),
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Site", "none"),
        ("Sec-Fetch-Site", "SAME-ORIGIN"),
        # Custom header: exactly "1".
        ("X-PDash-CSRF", "0"),
        ("X-PDash-CSRF", "true"),
        ("X-PDash-CSRF", "11"),
        ("X-PDash-CSRF", ""),
    ],
)
def test_each_wrong_value_is_rejected(dash: SecuredApp, header: str, value: str) -> None:
    status, headers = _post(dash, csrf_headers({header: value}))
    assert status == 403
    assert not any(k.startswith("access-control-") for k in headers)


@pytest.mark.parametrize("missing", ["Content-Type", "Origin", "Sec-Fetch-Site", "X-PDash-CSRF"])
def test_each_missing_header_is_rejected(dash: SecuredApp, missing: str) -> None:
    headers = csrf_headers()
    del headers[missing]
    if missing == "Content-Type":
        # httpx would otherwise add none; make sure nothing sneaks in.
        assert "Content-Type" not in headers
    status, _ = _post(dash, headers)
    assert status == 403


@pytest.mark.parametrize("dup", [b"origin", b"content-type", b"x-pdash-csrf", b"sec-fetch-site"])
async def test_duplicated_csrf_header_is_rejected(dash: SecuredApp, dup: bytes) -> None:
    base = {k.lower().encode(): v.encode() for k, v in csrf_headers().items()}
    headers = [(b"host", DASH_HOST.encode()), *base.items(), (dup, base[dup])]
    result = await call_asgi(dash, method="POST", path="/api/csrf-probe", headers=headers)
    assert result.status == 403


def test_origin_must_match_request_host() -> None:
    # Two dashboard hosts: an Origin of one with the Host of the other fails.
    app = dashboard_app(allowed_hosts=frozenset({DASH_HOST, "other.example.ts.net"}))

    @app.inner.post("/p")
    def p() -> JSONResponse:
        return JSONResponse({})

    client = dashboard_client(app)
    ok = client.post("/p", headers=csrf_headers(), content=b"{}")
    assert ok.status_code == 200
    crossed = client.post(
        "/p", headers=csrf_headers({"Origin": "https://other.example.ts.net"}), content=b"{}"
    )
    assert crossed.status_code == 403


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"])
def test_other_methods_are_405_without_cors(dash: SecuredApp, method: str) -> None:
    headers = csrf_headers(
        {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "x-pdash-csrf"}
    )
    response = dashboard_client(dash).request(method, "/api/csrf-probe", headers=headers)
    assert response.status_code == 405
    assert response.headers["allow"] == "GET, HEAD, POST"
    assert not any(k.lower().startswith("access-control-") for k in response.headers)


def test_body_at_limit_passes(dash: SecuredApp) -> None:
    body = b'{"a":"' + b"x" * (1024 - 8) + b'"}'
    assert len(body) == 1024
    status, _ = _post(dash, csrf_headers(), body)
    assert status == 200


def test_body_over_limit_is_413(dash: SecuredApp) -> None:
    status, _ = _post(dash, csrf_headers(), b"{" + b" " * 1024 + b"}")
    assert status == 413


def test_chunked_body_over_limit_is_413(dash: SecuredApp) -> None:
    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b" " * 200

    response = dashboard_client(dash).post(
        "/api/csrf-probe", headers=csrf_headers(), content=chunks()
    )
    assert response.status_code == 413


async def test_lying_content_length_is_still_capped(dash: SecuredApp) -> None:
    headers = [
        (b"host", DASH_HOST.encode()),
        *((k.lower().encode(), v.encode()) for k, v in csrf_headers().items()),
        (b"content-length", b"2"),
    ]
    result = await call_asgi(
        dash, method="POST", path="/api/csrf-probe", headers=headers, body=b" " * 2000
    )
    assert result.status == 413


@pytest.mark.parametrize("value", [b"-1", b"1e3", b"abc", b" 12", b"99999999999999999999"])
async def test_malformed_content_length_is_400(dash: SecuredApp, value: bytes) -> None:
    headers = [
        (b"host", DASH_HOST.encode()),
        *((k.lower().encode(), v.encode()) for k, v in csrf_headers().items()),
        (b"content-length", value),
    ]
    result = await call_asgi(dash, method="POST", path="/api/csrf-probe", headers=headers)
    assert result.status == 400


def test_sandboxed_preview_post_is_rejected(dash: SecuredApp) -> None:
    """A sandboxed preview has an opaque origin: Origin null, cross-site."""
    headers = csrf_headers({"Origin": "null", "Sec-Fetch-Site": "cross-site"})
    status, _ = _post(dash, headers)
    assert status == 403


def test_identity_still_required_for_valid_csrf(dash: SecuredApp) -> None:
    headers = csrf_headers({"Tailscale-User-Login": "x" + OWNER})
    status, _ = _post(dash, headers)
    assert status == 403
