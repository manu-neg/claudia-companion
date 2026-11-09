"""Security tests: ambiguous responses are never delivered (8a review fix 2).

A response with two `Content-Type` or two `Content-Disposition` headers could
be read differently by the browser and by our CSP / fetch-metadata logic
(e.g. "PDF" for us, HTML for the browser), so both apps replace it with a
generic 500 and the preview's fetch-metadata check denies it (403).
"""

from __future__ import annotations

import pytest
from fastapi import Request
from starlette.responses import Response

from preview_dashboard.interfaces.viewer.headers import has_ambiguous_headers, sandbox_csp
from preview_dashboard.interfaces.viewer.hints import PreviewHints, set_preview_hints
from preview_dashboard.kinds.base import PreviewMode
from tests.viewer_support import (
    DASH_ORIGIN,
    dashboard_app,
    dashboard_client,
    owner_headers,
    preview_app,
    preview_client,
)

pytestmark = pytest.mark.security

_DOUBLE_TYPE = [(b"content-type", b"application/pdf"), (b"content-type", b"text/html")]
_DOUBLE_DISPOSITION = [
    (b"content-type", b"application/pdf"),
    (b"content-disposition", b"inline"),
    (b"content-disposition", b"attachment"),
]


def test_has_ambiguous_headers() -> None:
    assert has_ambiguous_headers(_DOUBLE_TYPE)
    assert has_ambiguous_headers(_DOUBLE_DISPOSITION)
    assert has_ambiguous_headers([(b"Content-Type", b"a/b"), (b"content-type", b"a/b")])
    assert not has_ambiguous_headers([(b"content-type", b"application/pdf")])


def _hostile_route(raw_headers: list[tuple[bytes, bytes]], status: int = 200) -> object:
    def endpoint(request: Request) -> Response:
        set_preview_hints(request.scope, PreviewHints(PreviewMode.DOCUMENT))
        response = Response(b"%PDF-1.7 <script>x</script>", status_code=status)
        response.raw_headers = [
            (k, v) for k, v in response.raw_headers if k != b"content-type"
        ] + raw_headers
        return response

    return endpoint


@pytest.mark.parametrize("raw_headers", [_DOUBLE_TYPE, _DOUBLE_DISPOSITION])
@pytest.mark.parametrize("status", [200, 404])
@pytest.mark.parametrize("fetch_metadata", [True, False])
def test_preview_never_delivers_ambiguous_response(
    raw_headers: list[tuple[bytes, bytes]], status: int, fetch_metadata: bool
) -> None:
    app = preview_app()
    app.inner.add_api_route("/x", _hostile_route(raw_headers, status), methods=["GET"])  # type: ignore[arg-type]
    extra = {"Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "same-site"} if fetch_metadata else {}
    response = preview_client(app).get("/x", headers=owner_headers(extra))
    # 2xx with fetch metadata: denied by the fetch-metadata check (403);
    # otherwise the header middleware replaces it with a 500.
    assert response.status_code in {403, 500}
    assert b"<script>" not in response.content
    assert response.headers.get_list("content-type") == ["application/json"]
    assert "content-disposition" not in response.headers
    assert response.headers["content-security-policy"] == sandbox_csp([DASH_ORIGIN])


@pytest.mark.parametrize("raw_headers", [_DOUBLE_TYPE, _DOUBLE_DISPOSITION])
def test_dashboard_never_delivers_ambiguous_response(
    raw_headers: list[tuple[bytes, bytes]],
) -> None:
    app = dashboard_app()
    app.inner.add_api_route("/api/x", _hostile_route(raw_headers), methods=["GET"])  # type: ignore[arg-type]
    response = dashboard_client(app).get("/api/x", headers=owner_headers())
    assert response.status_code == 500
    assert b"<script>" not in response.content
    assert response.json()["error"] == "internal_error"
    assert response.headers["x-frame-options"] == "DENY"
