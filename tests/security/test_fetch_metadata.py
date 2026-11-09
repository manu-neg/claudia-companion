"""Security tests for fetch-metadata resource isolation (docs/security.md C31, ADR 0012).

The pure policy is tested as a matrix; the middleware is tested end to end
(central enforcement, early rejection, aborted body streams).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import Request
from fastapi.responses import Response, StreamingResponse

from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from preview_dashboard.interfaces.viewer.disposition import content_disposition
from preview_dashboard.interfaces.viewer.fetch_metadata import (
    FetchMetadata,
    dashboard_request_allowed,
    preview_request_allowed,
    preview_response_allowed,
)
from preview_dashboard.interfaces.viewer.hints import PreviewHints, set_preview_hints
from preview_dashboard.kinds.base import PreviewMode
from tests.viewer_support import (
    DASH_HOST,
    OWNER,
    PREVIEW_HOST,
    call_asgi,
    dashboard_app,
    dashboard_client,
    make_env,
    owner_headers,
    preview_app,
    preview_client,
)

pytestmark = pytest.mark.security

AppCounter = tuple[SecuredApp, list[int]]

M = PreviewMode


def meta(dest: str, site: str = "same-site", mode: str = "no-cors") -> FetchMetadata:
    return FetchMetadata(site=site, dest=dest, mode=mode)


def allowed(
    m: FetchMetadata,
    media_type: str,
    mode: PreviewMode | None,
    *,
    attachment: bool = False,
    bundle: bool = False,
    bound: bool | None = None,
) -> bool:
    """`bound` defaults to `bundle`: a bundle sub-resource whose Referer binds it."""
    return preview_response_allowed(
        m,
        media_type=media_type,
        preview_mode=mode,
        attachment=attachment,
        bundle_subresource=bundle,
        bundle_bound=bundle if bound is None else bound,
    )


# --- preview policy matrix ----------------------------------------------------


@pytest.mark.parametrize(
    ("dest", "site", "media_type", "mode", "attachment", "bundle", "expected"),
    [
        # SVG: only ever as an image.
        ("image", "same-site", "image/svg+xml", M.MEDIA, False, False, True),
        ("document", "same-site", "image/svg+xml", M.MEDIA, False, False, False),
        ("iframe", "same-site", "image/svg+xml", M.MEDIA, False, False, False),
        ("document", "none", "image/svg+xml", M.MEDIA, False, False, False),
        ("image", "cross-site", "image/svg+xml", M.MEDIA, False, False, False),
        ("image", "cross-site", "image/svg+xml", M.SANDBOXED, False, True, True),
        # HTML: iframe from the dashboard only.
        ("iframe", "same-site", "text/html", M.SANDBOXED, False, False, True),
        ("iframe", "cross-site", "text/html", M.SANDBOXED, False, False, False),
        ("document", "same-site", "text/html", M.SANDBOXED, False, False, False),
        ("document", "none", "text/html", M.SANDBOXED, False, False, False),
        ("iframe", "cross-site", "text/html", M.SANDBOXED, False, True, False),
        ("iframe", "same-site", "text/html", M.SANDBOXED, False, True, False),
        ("image", "same-site", "text/html", M.SANDBOXED, False, False, False),
        # PDF documents: document or iframe, from the dashboard or user.
        ("document", "same-site", "application/pdf", M.DOCUMENT, False, False, True),
        ("document", "none", "application/pdf", M.DOCUMENT, False, False, True),
        ("document", "cross-site", "application/pdf", M.DOCUMENT, False, False, False),
        ("iframe", "same-site", "application/pdf", M.DOCUMENT, False, False, True),
        ("document", "same-site", "application/pdf", M.SANDBOXED, False, True, False),
        ("document", "same-site", "application/pdf", None, False, False, False),
        # Downloads: top-level navigation or a download fetch, never embedded.
        ("document", "same-site", "application/octet-stream", M.DOWNLOAD, True, False, True),
        ("document", "none", "application/zip", None, True, False, True),
        ("empty", "same-site", "application/octet-stream", M.DOWNLOAD, True, False, True),
        ("document", "cross-site", "application/octet-stream", M.DOWNLOAD, True, False, False),
        ("empty", "cross-site", "application/octet-stream", M.DOWNLOAD, True, False, False),
        ("iframe", "same-site", "text/plain", M.TEXT, True, False, False),
        ("image", "same-site", "image/png", M.MEDIA, True, False, False),
        ("empty", "same-site", "text/plain", M.TEXT, False, False, False),
        # Media.
        ("image", "same-site", "image/png", M.MEDIA, False, False, True),
        ("image", "same-origin", "image/png", M.MEDIA, False, False, True),
        ("video", "same-site", "video/mp4", M.MEDIA, False, False, True),
        ("audio", "same-site", "audio/mpeg", M.MEDIA, False, False, True),
        ("video", "same-site", "audio/mpeg", M.MEDIA, False, False, True),
        ("video", "same-site", "image/png", M.MEDIA, False, False, False),
        ("image", "same-site", "video/mp4", M.MEDIA, False, False, False),
        ("video", "cross-site", "video/mp4", M.MEDIA, False, False, False),
        ("image", "none", "image/png", M.MEDIA, False, False, False),
        # TEXT kinds render sandboxed in an iframe.
        ("iframe", "same-site", "text/plain", M.TEXT, False, False, True),
        ("iframe", "same-site", "application/json", M.TEXT, False, False, True),
        ("document", "same-site", "text/plain", M.TEXT, False, False, False),
        # Bundle-only destinations.
        ("script", "cross-site", "text/javascript", M.SANDBOXED, False, True, True),
        ("style", "cross-site", "text/css", M.SANDBOXED, False, True, True),
        ("track", "cross-site", "text/vtt", M.SANDBOXED, False, True, True),
        ("script", "same-site", "text/plain", M.TEXT, False, False, False),
        ("script", "cross-site", "text/javascript", M.SANDBOXED, False, False, False),
        ("style", "none", "text/css", M.SANDBOXED, False, True, False),
        ("font", "cross-site", "font/woff2", M.SANDBOXED, False, True, False),
        # Never.
        ("embed", "same-site", "application/pdf", M.DOCUMENT, False, False, False),
        ("object", "same-site", "application/pdf", M.DOCUMENT, False, False, False),
        ("worker", "same-site", "text/javascript", M.SANDBOXED, False, True, False),
        ("serviceworker", "same-origin", "text/javascript", M.SANDBOXED, False, True, False),
        ("manifest", "same-site", "application/json", M.TEXT, False, False, False),
        ("image", "bogus-site", "image/png", M.MEDIA, False, False, False),
    ],
)
def test_preview_policy_matrix(
    dest: str,
    site: str,
    media_type: str,
    mode: PreviewMode | None,
    attachment: bool,
    bundle: bool,
    expected: bool,
) -> None:
    assert allowed(meta(dest, site), media_type, mode, attachment=attachment, bundle=bundle) is (
        expected
    )


@pytest.mark.parametrize(
    ("dest", "media_type"),
    [("image", "image/png"), ("script", "text/javascript"), ("style", "text/css")],
)
def test_unbound_bundle_subresource_is_denied_cross_site(dest: str, media_type: str) -> None:
    """Review fix 1: cross-site bundle loads need the bundle's own Referer."""
    m = meta(dest, "cross-site")
    assert not allowed(m, media_type, M.SANDBOXED, bundle=True, bound=False)
    assert allowed(m, media_type, M.SANDBOXED, bundle=True, bound=True)
    # Same-site loads (the dashboard) don't depend on the binding.
    assert allowed(meta(dest, "same-site"), media_type, M.SANDBOXED, bundle=True, bound=False)


def test_missing_fetch_metadata_is_allowed_for_compatibility() -> None:
    assert allowed(FetchMetadata(), "image/svg+xml", M.MEDIA)
    assert preview_request_allowed(FetchMetadata())
    assert dashboard_request_allowed(FetchMetadata(), "GET")


def test_partial_fetch_metadata_is_denied() -> None:
    assert not allowed(FetchMetadata(site="same-site"), "image/png", M.MEDIA)
    assert not preview_request_allowed(FetchMetadata(site="same-site"))
    assert not dashboard_request_allowed(FetchMetadata(mode="navigate"), "GET")


# --- dashboard policy -----------------------------------------------------------


@pytest.mark.parametrize(
    ("site", "dest", "mode", "method", "expected"),
    [
        ("same-origin", "empty", "cors", "GET", True),
        ("same-origin", "script", "no-cors", "GET", True),
        ("none", "document", "navigate", "GET", True),
        ("cross-site", "document", "navigate", "GET", True),  # a link to the dashboard
        ("cross-site", "document", "navigate", "POST", False),  # cross-site form post
        ("cross-site", "empty", "no-cors", "GET", False),  # evil fetch()
        ("cross-site", "script", "no-cors", "GET", False),  # <script src=/api/feed>
        ("cross-site", "image", "no-cors", "GET", False),
        ("cross-site", "iframe", "navigate", "GET", False),
        ("same-site", "document", "navigate", "GET", True),  # link from a PDF preview
        ("same-site", "empty", "cors", "GET", False),
        ("same-site", "iframe", "navigate", "GET", False),
        ("weird", "document", "navigate", "GET", False),
    ],
)
def test_dashboard_policy_matrix(
    site: str, dest: str, mode: str, method: str, expected: bool
) -> None:
    assert dashboard_request_allowed(FetchMetadata(site, dest, mode), method) is expected


def test_dashboard_middleware_blocks_cross_site_api_read() -> None:
    app = dashboard_app()

    @app.inner.get("/api/feed")
    def feed() -> Response:
        return Response(b"{}", media_type="application/json")

    client = dashboard_client(app)
    evil = owner_headers(
        {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors"}
    )
    assert client.get("/api/feed", headers=evil).status_code == 403
    own = owner_headers(
        {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors"}
    )
    assert client.get("/api/feed", headers=own).status_code == 200


# --- preview middleware -----------------------------------------------------------


@pytest.fixture
def prev_and_counter() -> AppCounter:
    app = preview_app()
    produced: list[int] = []

    @app.inner.get("/svg")
    def svg(request: Request) -> Response:
        set_preview_hints(request.scope, PreviewHints(PreviewMode.MEDIA))
        return Response(b"<svg/>", media_type="image/svg+xml")

    @app.inner.get("/big.bin")
    def big(request: Request) -> StreamingResponse:
        set_preview_hints(request.scope, PreviewHints(PreviewMode.DOWNLOAD))

        def chunks() -> Iterator[bytes]:
            for i in range(1000):
                produced.append(i)
                yield b"x" * 1024

        return StreamingResponse(
            chunks(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": content_disposition("attachment", "big.bin")},
        )

    @app.inner.get("/missing")
    def missing(request: Request) -> Response:
        return Response(b"{}", status_code=404, media_type="application/json")

    return app, produced


def test_svg_as_document_is_403_and_as_image_is_200(prev_and_counter: AppCounter) -> None:
    app, _ = prev_and_counter
    client = preview_client(app)
    as_doc = owner_headers({"Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "same-site"})
    as_img = owner_headers({"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site"})
    denied = client.get("/svg", headers=as_doc)
    assert denied.status_code == 403
    assert b"<svg" not in denied.content
    assert client.get("/svg", headers=as_img).status_code == 200
    assert client.get("/svg", headers=owner_headers()).status_code == 200  # no metadata


def test_denied_stream_is_aborted_not_drained(prev_and_counter: AppCounter) -> None:
    app, produced = prev_and_counter
    headers = owner_headers({"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site"})
    response = preview_client(app).get("/big.bin", headers=headers)
    assert response.status_code == 403
    assert len(response.content) < 200
    assert len(produced) < 5


def test_allowed_download_streams(prev_and_counter: AppCounter) -> None:
    app, _ = prev_and_counter
    headers = owner_headers({"Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "same-site"})
    response = preview_client(app).get("/big.bin", headers=headers)
    assert response.status_code == 200
    assert len(response.content) == 1000 * 1024


def test_error_statuses_are_not_rewritten(prev_and_counter: AppCounter) -> None:
    app, _ = prev_and_counter
    headers = owner_headers({"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site"})
    assert preview_client(app).get("/missing", headers=headers).status_code == 404


@pytest.mark.parametrize("dest", [b"embed", b"object", b"worker", b"sharedworker", b"report"])
async def test_forbidden_destinations_rejected_before_route(
    prev_and_counter: AppCounter, dest: bytes
) -> None:
    app, _ = prev_and_counter
    result = await call_asgi(
        app,
        path="/svg",
        headers=[
            (b"host", PREVIEW_HOST.encode()),
            (b"tailscale-user-login", OWNER.encode()),
            (b"sec-fetch-site", b"same-site"),
            (b"sec-fetch-dest", dest),
        ],
    )
    assert result.status == 403


@pytest.mark.parametrize(
    "extra",
    [
        [(b"sec-fetch-dest", b"image"), (b"sec-fetch-dest", b"image")],
        [(b"sec-fetch-site", b"same-site"), (b"sec-fetch-site", b"same-site")],
        [(b"sec-fetch-dest", b"im\xe1ge"), (b"sec-fetch-site", b"same-site")],
    ],
)
async def test_malformed_fetch_metadata_is_403(extra: list[tuple[bytes, bytes]]) -> None:
    for app, host in ((preview_app(), PREVIEW_HOST), (dashboard_app(), DASH_HOST)):
        result = await call_asgi(
            app,
            path="/x",
            headers=[(b"host", host.encode()), (b"tailscale-user-login", OWNER.encode()), *extra],
        )
        assert result.status == 403


# --- 304 is a delivery too: same policy as 2xx (a cached copy is released) --------


def _fm(dest: str, site: str) -> dict[str, str]:
    mode = "navigate" if dest in {"document", "iframe"} else "no-cors"
    return {"Sec-Fetch-Dest": dest, "Sec-Fetch-Site": site, "Sec-Fetch-Mode": mode}


@pytest.mark.parametrize(
    ("files", "path", "dest", "site"),
    [
        ({"a.svg": b"<svg/>"}, "/i/{id}/1/a.svg", "document", "cross-site"),
        ({"a.svg": b"<svg/>"}, "/i/{id}/1/a.svg", "document", "same-site"),
        ({"a.svg": b"<svg/>"}, "/i/{id}/1/a.svg", "iframe", "same-site"),
        ({"index.html": b"<p>x</p>"}, "/i/{id}/1/index.html", "iframe", "cross-site"),
        ({"index.html": b"<p>x</p>"}, "/i/{id}/1/index.html", "document", "same-site"),
        ({"index.html": b"<p>", "b.js": b"1"}, "/i/{id}/1/b.js", "script", "cross-site"),
        ({"notes.md": b"# hi"}, "/i/{id}/1/notes.md", "script", "same-site"),
        ({"notes.md": b"# hi"}, "/t/{id}/1/notes.md", "script", "cross-site"),
    ],
)
def test_denied_context_gets_403_even_with_matching_if_none_match(
    files: dict[str, bytes], path: str, dest: str, site: str
) -> None:
    env = make_env()
    item = env.publish(files, title="T")
    url = path.format(id=item.id)
    client = env.preview_client()
    fresh = client.get(url, headers=owner_headers())  # no fetch metadata: allowed
    assert fresh.status_code == 200
    etag = fresh.headers["etag"]
    response = client.get(url, headers=owner_headers({"If-None-Match": etag, **_fm(dest, site)}))
    assert response.status_code == 403, (url, dest, site)
    assert "etag" not in response.headers


@pytest.mark.parametrize(
    ("files", "path", "dest"),
    [
        ({"a.svg": b"<svg/>"}, "/i/{id}/1/a.svg", "image"),
        ({"index.html": b"<p>x</p>"}, "/i/{id}/1/index.html", "iframe"),
        ({"index.html": b"<p>", "b.js": b"1"}, "/i/{id}/1/b.js", "script"),
        ({"notes.md": b"# hi"}, "/t/{id}/1/notes.md", "iframe"),
    ],
)
def test_allowed_context_still_gets_304(files: dict[str, bytes], path: str, dest: str) -> None:
    env = make_env()
    item = env.publish(files, title="T")
    url = path.format(id=item.id)
    client = env.preview_client()
    etag = client.get(url, headers=owner_headers()).headers["etag"]
    headers = owner_headers({"If-None-Match": etag, **_fm(dest, "same-site")})
    assert client.get(url, headers=headers).status_code == 304
