"""Security tests for the service-worker guard (docs/security.md C5, C31).

No service worker can ever be registered on either viewer origin: the
script fetch is refused and `Service-Worker-Allowed` is never sent.
"""

from __future__ import annotations

import pytest
from fastapi.responses import Response
from starlette.testclient import TestClient

from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from preview_dashboard.interfaces.viewer.service_worker import is_service_worker_request
from tests.viewer_support import (
    dashboard_app,
    dashboard_client,
    owner_headers,
    preview_app,
    preview_client,
)

pytestmark = pytest.mark.security


def _with_script_route(app: SecuredApp) -> SecuredApp:
    @app.inner.get("/sw.js")
    def script() -> Response:
        return Response(
            b"self.addEventListener('fetch', e => {})",
            media_type="text/javascript",
            headers={"Service-Worker-Allowed": "/"},
        )

    return app


@pytest.fixture(params=["dashboard", "preview"])
def client(request: pytest.FixtureRequest) -> TestClient:
    if request.param == "dashboard":
        return dashboard_client(_with_script_route(dashboard_app()))
    return preview_client(_with_script_route(preview_app()))


@pytest.mark.parametrize("value", ["script", "SCRIPT", "", "anything"])
def test_service_worker_header_is_403(client: TestClient, value: str) -> None:
    response = client.get("/sw.js", headers=owner_headers({"Service-Worker": value}))
    assert response.status_code == 403
    assert "service-worker-allowed" not in {k.lower() for k in response.headers}


def test_serviceworker_fetch_dest_is_403(client: TestClient) -> None:
    response = client.get("/sw.js", headers=owner_headers({"Sec-Fetch-Dest": "serviceworker"}))
    assert response.status_code == 403


def test_service_worker_allowed_is_never_sent(client: TestClient) -> None:
    # A plain (non-SW) fetch of the same route: header stripped even on 200.
    response = client.get("/sw.js", headers=owner_headers())
    assert "service-worker-allowed" not in {k.lower() for k in response.headers}


def test_guard_runs_before_identity() -> None:
    client = preview_client(preview_app())
    response = client.get("/sw.js", headers={"Service-Worker": "script"})
    assert response.status_code == 403


def test_detector_ignores_normal_requests() -> None:
    scope = {"type": "http", "headers": [(b"sec-fetch-dest", b"script")]}
    assert not is_service_worker_request(scope)
    assert is_service_worker_request({"type": "http", "headers": [(b"service-worker", b"script")]})
