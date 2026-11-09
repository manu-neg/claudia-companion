"""Security tests: per-kind Content-Type, CSP, disposition and nosniff on real preview routes.

(docs/security.md C5, C8, C22, C31; ADR 0005, 0012.) One item per registered
kind is published through the real PublishService and fetched from the
real preview routes. Covers: registry type + nosniff on every file; sandbox
CSP everywhere except DOCUMENT-mode PDFs; SVG and nested bundle HTML
sandboxed; bundle sub-resources bound to their bundle via `Referer`;
tampered stored media types served as octet-stream attachments; the TEXT
render endpoint never using the original type.
"""

from __future__ import annotations

import dataclasses

import pytest

from preview_dashboard.domain.models import Item, ItemFile
from preview_dashboard.interfaces.viewer.headers import pdf_csp, sandbox_csp
from preview_dashboard.kinds import default_registry
from preview_dashboard.kinds.base import PreviewMode
from tests.viewer_support import DASH_ORIGIN, PREVIEW_ORIGIN, ViewerEnv, make_env, owner_headers

pytestmark = pytest.mark.security

SANDBOX = sandbox_csp([DASH_ORIGIN])
PDF = pdf_csp([DASH_ORIGIN])
REGISTRY = default_registry()


def _sample_name(kind_name: str) -> str:
    if kind_name == "progress":  # the one kind with a fixed file name (ADR 0029)
        return "progress.json"
    kind = REGISTRY.get(kind_name)
    ext = sorted(kind.extensions)[0] if kind.extensions else ".bin"
    return f"sample{ext}"


@pytest.fixture(scope="module")
def env() -> ViewerEnv:
    env = make_env()
    for kind in REGISTRY.all():
        env.publish({_sample_name(kind.name): b"sample bytes"}, title=kind.name, kind=kind.name)
    return env


def _item(env: ViewerEnv, title: str) -> Item:
    return next(i for i in env.items if i.title == title)


@pytest.mark.parametrize("kind_name", [k.name for k in REGISTRY.all()])
def test_inline_headers_per_kind(env: ViewerEnv, kind_name: str) -> None:
    kind = REGISTRY.get(kind_name)
    item = _item(env, kind_name)
    relpath = _sample_name(kind_name)
    response = env.preview_client().get(f"/i/{item.id}/1/{relpath}", headers=owner_headers())
    assert response.status_code == 200
    expected = kind.media_type(relpath)
    assert response.headers["content-type"].split(";")[0] == expected
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-resource-policy"] == "same-site"
    is_pdf_doc = expected == "application/pdf" and kind.preview_mode is PreviewMode.DOCUMENT
    assert response.headers["content-security-policy"] == (PDF if is_pdf_doc else SANDBOX)
    disposition = response.headers["content-disposition"]
    if kind.preview_mode is PreviewMode.DOWNLOAD:
        assert disposition.startswith("attachment;")
    else:
        assert disposition.startswith("inline;")
    assert "set-cookie" not in response.headers


def test_text_types_carry_utf8_charset_but_html_does_not(env: ViewerEnv) -> None:
    client = env.preview_client()
    text = _item(env, "text")
    html = _item(env, "html")
    got = client.get(f"/i/{text.id}/1/{_sample_name('text')}", headers=owner_headers())
    assert got.headers["content-type"] == "text/plain; charset=utf-8"
    got = client.get(f"/i/{html.id}/1/{_sample_name('html')}", headers=owner_headers())
    assert got.headers["content-type"] == "text/html"


def test_svg_is_sandboxed_and_only_an_image(env: ViewerEnv) -> None:
    svg = _item(env, "svg")
    url = f"/i/{svg.id}/1/{_sample_name('svg')}"
    client = env.preview_client()
    as_image = client.get(
        url, headers=owner_headers({"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site"})
    )
    assert as_image.status_code == 200
    assert as_image.headers["content-type"] == "image/svg+xml"
    assert as_image.headers["content-security-policy"] == SANDBOX
    for dest in ("document", "iframe"):
        denied = client.get(
            url, headers=owner_headers({"Sec-Fetch-Dest": dest, "Sec-Fetch-Site": "same-site"})
        )
        assert denied.status_code == 403, dest


def test_pdf_exception_only_for_document_pdfs_and_304_keeps_it(env: ViewerEnv) -> None:
    pdf = _item(env, "pdf")
    url = f"/i/{pdf.id}/1/{_sample_name('pdf')}"
    client = env.preview_client()
    first = client.get(url, headers=owner_headers())
    assert first.headers["content-security-policy"] == PDF
    assert first.headers["etag"] == f'"{pdf.files[0].sha256}"'
    again = client.get(url, headers=owner_headers({"If-None-Match": first.headers["etag"]}))
    assert again.status_code == 304
    assert again.content == b""
    assert again.headers["content-type"] == "application/pdf"
    assert again.headers["content-security-policy"] == PDF


@pytest.fixture(scope="module")
def bundle_env() -> tuple[ViewerEnv, Item, Item]:
    env = make_env()
    files = {
        "index.html": b"<script src=app.js></script>",
        "app.js": b"1",
        "icon.svg": b"<svg/>",
        "sub/x.html": b"<p>nested</p>",
        "doc.pdf": b"%PDF-1.7",
    }
    bundle = env.publish(files, title="Bundle")
    other = env.publish({"index.html": b"<p>other</p>", "a.js": b"2"}, title="Other")
    return env, bundle, other


def test_bundle_members_are_sandboxed(bundle_env: tuple[ViewerEnv, Item, Item]) -> None:
    env, bundle, _ = bundle_env
    client = env.preview_client()
    for relpath in ("index.html", "sub/x.html", "icon.svg", "app.js", "doc.pdf"):
        response = client.get(f"/i/{bundle.id}/1/{relpath}", headers=owner_headers())
        assert response.status_code == 200, relpath
        assert response.headers["content-security-policy"] == SANDBOX, relpath
    entry = client.get(f"/i/{bundle.id}/1/index.html", headers=owner_headers())
    assert entry.headers["referrer-policy"] == "same-origin"
    assert entry.headers["cross-origin-resource-policy"] == "same-site"


def test_bundle_subresource_bound_to_own_bundle(bundle_env: tuple[ViewerEnv, Item, Item]) -> None:
    """Review fix 1: cross-site sub-resource loads need the bundle's own Referer."""
    env, bundle, other = bundle_env
    url = f"/i/{bundle.id}/1/app.js"
    own = f"{PREVIEW_ORIGIN}/i/{bundle.id}/1/index.html"
    ok = env.preview_client().get(
        url,
        headers=owner_headers(
            {"Sec-Fetch-Dest": "script", "Sec-Fetch-Site": "cross-site", "Referer": own}
        ),
    )
    assert ok.status_code == 200
    assert ok.headers["cross-origin-resource-policy"] == "cross-origin"
    assert ok.headers["vary"] == "Referer"
    for referer in (
        None,  # attacker page with Referrer-Policy: no-referrer
        "https://evil.example/page",
        f"{PREVIEW_ORIGIN}/i/{other.id}/1/index.html",  # another bundle
        f"{PREVIEW_ORIGIN}/i/{bundle.id}/1",  # no trailing slash: not a page of the bundle
        f"https://dash.example.ts.net/i/{bundle.id}/1/index.html",  # wrong origin
    ):
        extra = {"Sec-Fetch-Dest": "script", "Sec-Fetch-Site": "cross-site"}
        if referer is not None:
            extra["Referer"] = referer
        denied = env.preview_client().get(url, headers=owner_headers(extra))
        assert denied.status_code == 403, referer
    # Without fetch metadata (old browser) the response is served, but with
    # CORP same-site, so the browser itself blocks a cross-site embed.
    legacy = env.preview_client().get(url, headers=owner_headers())
    assert legacy.status_code == 200
    assert legacy.headers["cross-origin-resource-policy"] == "same-site"


def test_nested_bundle_html_is_never_an_iframe_document(
    bundle_env: tuple[ViewerEnv, Item, Item],
) -> None:
    env, bundle, _ = bundle_env
    response = env.preview_client().get(
        f"/i/{bundle.id}/1/sub/x.html",
        headers=owner_headers({"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "same-site"}),
    )
    assert response.status_code == 403
    assert response.headers["content-security-policy"] == SANDBOX


# --- tamper defense: stored media type re-checked against the registry -------------


def _tamper(env: ViewerEnv, item: Item, **changes: object) -> Item:
    first = dataclasses.replace(item.files[0], **changes)  # type: ignore[arg-type]
    tampered = dataclasses.replace(item, files=(first, *item.files[1:]))
    env.services.repo.delete(item.id)
    env.services.repo.add(tampered)
    return tampered


@pytest.mark.parametrize(
    ("kind", "files", "fake_type"),
    [
        ("text", {"notes.txt": b"<script>alert(1)</script>"}, "text/html"),
        ("image", {"a.png": b"<svg onload=alert(1)>"}, "image/svg+xml"),
        ("markdown", {"a.md": b"%PDF-1.7"}, "application/pdf"),  # would dodge the sandbox
        ("code", {"a.js": b"alert(1)"}, "text/javascript"),
    ],
)
def test_tampered_media_type_is_served_as_octet_stream_attachment(
    kind: str, files: dict[str, bytes], fake_type: str
) -> None:
    env = make_env()
    item = _tamper(env, env.publish(files, kind=kind), media_type=fake_type)
    relpath = item.files[0].relpath
    for url in (f"/i/{item.id}/1/{relpath}", f"/d/{item.id}/1/{relpath}"):
        response = env.preview_client().get(url, headers=owner_headers())
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        assert response.headers["content-disposition"].startswith("attachment;")
        assert response.headers["content-security-policy"] == SANDBOX


def test_unknown_kind_is_served_as_octet_stream_attachment() -> None:
    env = make_env()
    item = env.publish({"a.txt": b"hi"}, kind="text")
    env.services.repo.delete(item.id)
    env.services.repo.add(dataclasses.replace(item, kind="mystery"))
    response = env.preview_client().get(f"/i/{item.id}/1/a.txt", headers=owner_headers())
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith("attachment;")


# --- TEXT render endpoint ----------------------------------------------------------


@pytest.mark.parametrize("kind_name", [k.name for k in REGISTRY.all() if k.render_capped])
def test_render_endpoint_is_always_utf8_text_plain(env: ViewerEnv, kind_name: str) -> None:
    item = _item(env, kind_name)
    response = env.preview_client().get(
        f"/t/{item.id}/1/{_sample_name(kind_name)}", headers=owner_headers()
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.headers["content-security-policy"] == SANDBOX
    assert response.headers["content-disposition"].startswith("inline;")
    assert "x-pdash-truncated" not in response.headers


@pytest.mark.parametrize("kind_name", [k.name for k in REGISTRY.all() if not k.render_capped])
def test_render_endpoint_refuses_non_text_kinds(env: ViewerEnv, kind_name: str) -> None:
    item = _item(env, kind_name)
    response = env.preview_client().get(
        f"/t/{item.id}/1/{_sample_name(kind_name)}", headers=owner_headers()
    )
    assert response.status_code == 404


def test_item_file_media_type_of_every_kind_is_the_registry_type(env: ViewerEnv) -> None:
    """Sanity: publish stored exactly what the registry says (the tamper check's baseline)."""
    for kind in REGISTRY.all():
        stored: ItemFile = _item(env, kind.name).files[0]
        assert stored.media_type == kind.media_type(stored.relpath)


_PARITY_HEADERS = ("content-type", "content-disposition", "content-security-policy", "etag")


@pytest.mark.parametrize("prefix", ["i", "t", "r", "d"])
@pytest.mark.parametrize("kind_name", [k.name for k in REGISTRY.all()])
def test_304_carries_the_same_type_and_disposition_as_200(
    env: ViewerEnv, kind_name: str, prefix: str
) -> None:
    # A cached preview keeps its 200 headers only if the 304 repeats them:
    # type/disposition decide how the browser treats the cached bytes (C5, C31).
    item = _item(env, kind_name)
    url = f"/{prefix}/{item.id}/1/{_sample_name(kind_name)}"
    client = env.preview_client()
    first = client.get(url, headers=owner_headers())
    if first.status_code == 404:  # /t and /r serve render-capped kinds only
        assert prefix in {"t", "r"} and not REGISTRY.get(kind_name).render_capped
        return
    assert first.status_code == 200
    again = client.get(url, headers=owner_headers({"If-None-Match": first.headers["etag"]}))
    assert again.status_code == 304
    for name in _PARITY_HEADERS:
        assert again.headers.get(name) == first.headers.get(name), name
