"""Security tests for the preview-origin text renderer route `/r/{id}/1/{relpath}`.

(docs/security.md C5, C7, C20, C22, C23, C31; docs/frontend.md.) The page is
served from the preview app with the full sandbox CSP; the untrusted text is
embedded as escaped JSON that can never close its `<script>` block; only
render-capped kinds are served; trashed items need `?t=1`; top-level or
cross-site loads are refused by fetch metadata. Traversal matrices for `/r`
live in `test_fs_confinement.py` (shared with `/i`, `/t`, `/d`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.headers import sandbox_csp
from preview_dashboard.interfaces.viewer.renderer_page import (
    TEXT_RENDERERS,
    RendererPage,
    embed_json,
)
from preview_dashboard.interfaces.viewer.static_assets import StaticAssetError, default_static_dir
from preview_dashboard.kinds import default_registry
from tests.viewer_support import DASH_ORIGIN, ViewerEnv, make_env, owner_headers

pytestmark = pytest.mark.security

REGISTRY = default_registry()
TEXT_KINDS = [k for k in REGISTRY.all() if k.render_capped]
OTHER_KINDS = [k for k in REGISTRY.all() if not k.render_capped]
HOSTILE = "</script><script>alert(1)</script> <!-- <script> \u2028\u2029 & </SCRIPT > \"'"
IFRAME_FROM_DASHBOARD = {
    "Sec-Fetch-Site": "same-site",
    "Sec-Fetch-Dest": "iframe",
    "Sec-Fetch-Mode": "navigate",
}
DATA_BLOCK = re.compile(
    rb'<script type="application/json" id="pdash-data">(.*?)</script>', re.DOTALL
)


def _name(kind_name: str) -> str:
    if kind_name == "progress":  # the one kind with a fixed file name (ADR 0029)
        return "progress.json"
    extensions = sorted(REGISTRY.get(kind_name).extensions)
    return f"sample{extensions[0] if extensions else '.bin'}"


@pytest.fixture(scope="module")
def env() -> ViewerEnv:
    env = make_env(render_cap_bytes=4096)
    for kind in REGISTRY.all():
        env.publish({_name(kind.name): HOSTILE.encode()}, title=kind.name, kind=kind.name)
    return env


def _item_id(env: ViewerEnv, title: str) -> str:
    return next(i.id for i in env.items if i.title == title)


def _data(body: bytes) -> dict[str, object]:
    blocks = DATA_BLOCK.findall(body)
    assert len(blocks) == 1
    parsed: dict[str, object] = json.loads(blocks[0])
    return parsed


@pytest.mark.parametrize("kind_name", [k.name for k in TEXT_KINDS])
def test_render_page_headers_per_text_kind(env: ViewerEnv, kind_name: str) -> None:
    item_id = _item_id(env, kind_name)
    response = env.preview_client().get(
        f"/r/{item_id}/1/{_name(kind_name)}", headers=owner_headers(IFRAME_FROM_DASHBOARD)
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["content-security-policy"] == sandbox_csp([DASH_ORIGIN])
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-resource-policy"] == "same-site"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "private, no-cache"
    assert "set-cookie" not in response.headers
    assert "access-control-allow-origin" not in response.headers
    data = _data(response.content)
    assert data["text"] == HOSTILE
    assert data["renderer"] == REGISTRY.get(kind_name).renderer
    assert data["truncated"] is False


def test_embedded_json_cannot_break_out_of_its_script_block(env: ViewerEnv) -> None:
    item_id = _item_id(env, "markdown")
    body = env.preview_client().get(f"/r/{item_id}/1/{_name('markdown')}", headers=owner_headers())
    block = DATA_BLOCK.findall(body.content)[0]
    for raw in (b"<", b">", b"&", "\u2028".encode(), "\u2029".encode()):
        assert raw not in block
    assert block.isascii()
    # Exactly the page's own script end tags: nothing from the content closes one early.
    openers = re.findall(rb"<script[\s>]", body.content, re.IGNORECASE)
    closers = re.findall(rb"</script", body.content, re.IGNORECASE)
    assert len(openers) == len(closers) == 5  # data + DOMPurify + marked + hljs + renderer


def test_embed_json_escapes() -> None:
    out = embed_json({"t": HOSTILE})
    assert "<" not in out and ">" not in out and "&" not in out
    assert "\\u2028" in out and "\\u2029" in out
    assert json.loads(out) == {"t": HOSTILE}


@pytest.mark.parametrize("kind_name", [k.name for k in OTHER_KINDS])
def test_non_text_kinds_are_404(env: ViewerEnv, kind_name: str) -> None:
    item_id = _item_id(env, kind_name)
    response = env.preview_client().get(
        f"/r/{item_id}/1/{_name(kind_name)}", headers=owner_headers()
    )
    assert response.status_code == 404
    assert HOSTILE.encode() not in response.content


def test_trashed_item_needs_the_trash_flag() -> None:
    env = make_env()
    item = env.publish({"n.md": b"# hi"}, title="t")
    env.services.trash.trash(item.id)
    client = env.preview_client()
    assert client.get(f"/r/{item.id}/1/n.md", headers=owner_headers()).status_code == 404
    assert client.get(f"/r/{item.id}/1/n.md?t=1", headers=owner_headers()).status_code == 200
    assert client.get(f"/r/{item.id}/1/n.md?t=2", headers=owner_headers()).status_code == 400


def test_unknown_file_and_query_are_refused(env: ViewerEnv) -> None:
    item_id = _item_id(env, "text")
    client = env.preview_client()
    assert client.get(f"/r/{item_id}/1/missing.txt", headers=owner_headers()).status_code == 404
    assert (
        client.get(f"/r/{item_id}/1/{_name('text')}?x=1", headers=owner_headers()).status_code
        == 400
    )
    assert client.get(f"/r/{item_id}/1", headers=owner_headers()).status_code == 404


def test_truncation_is_flagged_and_cut_on_a_utf8_boundary() -> None:
    env = make_env(render_cap_bytes=10)
    item = env.publish({"big.txt": "abcdefghiétail".encode()}, title="big")
    response = env.preview_client().get(f"/r/{item.id}/1/big.txt", headers=owner_headers())
    assert response.status_code == 200
    assert response.headers["x-pdash-truncated"] == "1"
    data = _data(response.content)
    assert data["truncated"] is True
    assert data["text"] == "abcdefghi"
    assert data["size"] == len("abcdefghiétail".encode())


def test_etag_304_and_head(env: ViewerEnv) -> None:
    item_id = _item_id(env, "json")
    client = env.preview_client()
    url = f"/r/{item_id}/1/{_name('json')}"
    first = client.get(url, headers=owner_headers())
    etag = first.headers["etag"]
    text_etag = client.get(f"/t/{item_id}/1/{_name('json')}", headers=owner_headers()).headers[
        "etag"
    ]
    assert etag != text_etag
    again = client.get(url, headers=owner_headers({"If-None-Match": etag}))
    assert again.status_code == 304
    assert again.content == b""
    assert again.headers["content-type"] == "text/html; charset=utf-8"
    assert again.headers["content-security-policy"] == sandbox_csp([DASH_ORIGIN])
    head = client.head(url, headers=owner_headers())
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(first.content))


@pytest.mark.parametrize(
    ("site", "dest", "mode"),
    [
        ("same-site", "document", "navigate"),  # opened top-level: HTML never is
        ("none", "document", "navigate"),
        ("cross-site", "iframe", "navigate"),  # framed by someone else
        ("same-site", "script", "no-cors"),
        ("same-site", "image", "no-cors"),
        ("same-site", "empty", "cors"),
        ("same-site", "embed", "no-cors"),
    ],
)
def test_fetch_metadata_only_allows_a_dashboard_iframe(
    env: ViewerEnv, site: str, dest: str, mode: str
) -> None:
    item_id = _item_id(env, "code")
    response = env.preview_client().get(
        f"/r/{item_id}/1/{_name('code')}",
        headers=owner_headers(
            {"Sec-Fetch-Site": site, "Sec-Fetch-Dest": dest, "Sec-Fetch-Mode": mode}
        ),
    )
    assert response.status_code == 403
    assert HOSTILE.encode() not in response.content


def test_only_the_needed_libraries_are_inlined(env: ViewerEnv) -> None:
    client = env.preview_client()
    json_page = client.get(f"/r/{_item_id(env, 'json')}/1/{_name('json')}", headers=owner_headers())
    md_page = client.get(
        f"/r/{_item_id(env, 'markdown')}/1/{_name('markdown')}", headers=owner_headers()
    )
    assert b"@license DOMPurify" not in json_page.content
    assert b"marked v18" in md_page.content and b"@license DOMPurify" in md_page.content
    assert b"<script src" not in md_page.content.lower()


def test_every_text_kind_has_a_renderer() -> None:
    assert {k.renderer for k in TEXT_KINDS} <= TEXT_RENDERERS


def _assets() -> dict[str, bytes]:
    page = RendererPage.load(default_static_dir())
    return dict(page._assets)


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("renderer.js", b"x = '</script>';"),
        ("marked.js", b"var s = '<script>';"),
        ("hljs.js", b"/* <SCRIPT/ */"),
        ("renderer.css", b"a{} </style>"),
        ("theme.css", b"\xff\xfe"),
    ],
)
def test_renderer_refuses_assets_unsafe_to_inline(name: str, bad: bytes) -> None:
    assets = _assets()
    assets[name] = assets[name] + bad
    with pytest.raises(StaticAssetError):
        RendererPage(assets)


def test_renderer_refuses_missing_or_symlinked_assets(tmp_path: Path) -> None:
    with pytest.raises(StaticAssetError):
        RendererPage.load(tmp_path)
    assets = _assets()
    del assets["hljs.js"]
    with pytest.raises(StaticAssetError):
        RendererPage(assets)


def test_item_json_links_text_kinds_to_the_render_page(env: ViewerEnv) -> None:
    client = env.dash_client()
    text_id, image_id = _item_id(env, "markdown"), _item_id(env, "image")
    detail = client.get(f"/api/items/{text_id}", headers=owner_headers()).json()
    expected = f"{env.settings.preview_origin}/r/{text_id}/1/{_name('markdown')}"
    assert detail["render_page_url"] == expected
    assert detail["files"][0]["render_page_url"] == expected
    image = client.get(f"/api/items/{image_id}", headers=owner_headers()).json()
    assert image["render_page_url"] is None
    assert image["files"][0]["render_page_url"] is None
