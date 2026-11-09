"""Security tests for the viewer apps' attack surface (docs/security.md C21, C5).

No docs/OpenAPI, no debug output, generic bodies with a request id, the
preview app accepts only body-less GET/HEAD, and the app split holds.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.responses import JSONResponse
from starlette.testclient import TestClient

from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from tests.viewer_support import (
    dashboard_app,
    dashboard_client,
    owner_headers,
    preview_app,
    preview_client,
    route_paths,
)

pytestmark = pytest.mark.security

AppClient = tuple[SecuredApp, TestClient]


@pytest.fixture(params=["dashboard", "preview"])
def app_and_client(request: pytest.FixtureRequest) -> AppClient:
    if request.param == "dashboard":
        app = dashboard_app()
        return app, dashboard_client(app)
    app = preview_app()
    return app, preview_client(app)


@pytest.mark.parametrize(
    "path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/api/nope"]
)
def test_no_docs_or_openapi(app_and_client: AppClient, path: str) -> None:
    _, client = app_and_client
    response = client.get(path, headers=owner_headers())
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_factory_settings(app_and_client: AppClient) -> None:
    app, _ = app_and_client
    assert isinstance(app, SecuredApp)
    assert app.inner.debug is False
    assert app.inner.docs_url is None and app.inner.redoc_url is None
    assert app.inner.openapi_url is None


def test_404_does_not_echo_path(app_and_client: AppClient) -> None:
    _, client = app_and_client
    response = client.get("/marker-<script>alert(1)</script>", headers=owner_headers())
    assert response.status_code == 404
    assert "marker" not in response.text and "script" not in response.text


def test_validation_errors_are_generic_400() -> None:
    app = dashboard_app()

    @app.inner.get("/api/items")
    def items(limit: int) -> JSONResponse:
        return JSONResponse({"limit": limit})

    response = dashboard_client(app).get(
        "/api/items", params={"limit": "echo-marker"}, headers=owner_headers()
    )
    assert response.status_code == 400
    assert "echo-marker" not in response.text
    assert set(response.json()) == {"error", "request_id"}


def test_unhandled_exception_is_generic_500() -> None:
    app = dashboard_app()

    @app.inner.get("/api/boom")
    def boom() -> JSONResponse:
        raise RuntimeError("internal-detail-marker")

    response = dashboard_client(app).get("/api/boom", headers=owner_headers())
    assert response.status_code == 500
    assert "internal-detail-marker" not in response.text
    assert "Traceback" not in response.text
    assert response.json()["request_id"] == response.headers["x-request-id"]


def test_no_trailing_slash_redirects() -> None:
    app = dashboard_app()

    @app.inner.get("/api/feed")
    def feed() -> JSONResponse:
        return JSONResponse({})

    response = dashboard_client(app).get(
        "/api/feed/", headers=owner_headers(), follow_redirects=False
    )
    assert response.status_code == 404
    assert "location" not in response.headers


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_preview_accepts_only_get_and_head(method: str) -> None:
    response = preview_client(preview_app()).request(method, "/x", headers=owner_headers())
    assert response.status_code == 405
    assert response.headers["allow"] == "GET, HEAD"


def test_preview_rejects_request_bodies() -> None:
    client = preview_client(preview_app())
    assert client.request("GET", "/x", headers=owner_headers(), content=b"x").status_code == 413

    def gen() -> Iterator[bytes]:
        yield b"x"

    assert client.request("GET", "/x", headers=owner_headers(), content=gen()).status_code == 413


def test_preview_has_no_api_routes() -> None:
    app = preview_app()
    paths = route_paths(app)
    assert paths  # guards against the scan silently finding nothing
    assert not any(p.startswith("/api") for p in paths)
