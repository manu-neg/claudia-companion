"""Security tests: no cookies, no CORS on every real viewer route (docs/security.md I1, C19).

Every route of both apps is exercised (success and error paths, hostile
`Origin`/`Cookie`) and must never emit `Set-Cookie` or any
`Access-Control-*` header; preflights are refused. A route-coverage check
fails if a new route is added without a sample here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from preview_dashboard.domain.models import Item
from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from tests.viewer_support import ViewerEnv, csrf_headers, make_env, owner_headers, route_paths

if TYPE_CHECKING:
    from httpx2 import Response as ClientResponse

pytestmark = pytest.mark.security

MISSING = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
HOSTILE = {"Origin": "https://evil.example", "Cookie": "sid=attacker; pdash=1"}


@pytest.fixture(scope="module")
def env() -> ViewerEnv:
    env = make_env()
    env.publish({"index.html": b"<p>x</p>", "css/a.css": b"p{}"}, title="Bundle")
    env.publish({"notes.txt": b"hello"}, title="Notes")
    return env


def _samples(bundle: Item, text: Item) -> dict[str, list[tuple[str, str]]]:
    """Route path template -> (method, url) samples, success and error cases."""
    return {
        "/api/kinds": [("GET", "/api/kinds"), ("HEAD", "/api/kinds")],
        "/api/items": [
            ("GET", "/api/items"),
            ("GET", "/api/items?state=trashed"),
            ("GET", "/api/items?state=bogus"),
            ("GET", "/api/items?folder=unfiled"),
            ("GET", f"/api/items?folder={MISSING}"),
        ],
        "/api/folders": [
            ("GET", "/api/folders"),
            ("HEAD", "/api/folders"),
            ("GET", "/api/folders?x=1"),
        ],
        "/api/items/{item_id}": [
            ("GET", f"/api/items/{bundle.id}"),
            ("GET", f"/api/items/{MISSING}"),
            ("GET", "/api/items/not-an-id"),
        ],
        "/api/items/{item_id}/trash": [
            ("POST", f"/api/items/{text.id}/trash"),
            ("POST", f"/api/items/{MISSING}/trash"),
        ],
        "/api/items/{item_id}/restore": [
            ("POST", f"/api/items/{text.id}/restore"),
            ("POST", "/api/items/bad/restore"),
        ],
        "/api/items/{item_id}/pin": [
            ("POST", f"/api/items/{bundle.id}/pin"),
            ("POST", f"/api/items/{MISSING}/pin"),
        ],
        "/api/items/{item_id}/unpin": [
            ("POST", f"/api/items/{bundle.id}/unpin"),
            ("POST", "/api/items/bad/unpin"),
        ],
        "/api/items/{item_id}/revisions/prune": [
            ("POST", f"/api/items/{bundle.id}/revisions/prune"),
            ("POST", f"/api/items/{MISSING}/revisions/prune"),
        ],
        # Knowledge map (C57): off in this env, so 404s; the approvals list is always 200.
        "/api/kb/graph": [("GET", "/api/kb/graph"), ("HEAD", "/api/kb/graph")],
        "/api/kb/notes/{note_id}": [
            ("GET", f"/api/kb/notes/{'0' * 32}"),
            ("GET", "/api/kb/notes/not-an-id"),
        ],
        "/api/claudia/approvals": [("GET", "/api/claudia/approvals")],
        # Dashboard decisions (C46) are off in this env: 404, still no cookies/CORS.
        "/api/claudia/approvals/{approval_id}/decision": [
            ("POST", f"/api/claudia/approvals/{'0' * 32}/decision"),
        ],
        "/": [("GET", "/"), ("HEAD", "/")],
        "/static/{name:path}": [("GET", "/static/missing.js")],
        "/i/{item_id}/{rev}/{relpath:path}": [
            ("GET", f"/i/{bundle.id}/1/index.html"),
            ("GET", f"/i/{bundle.id}/latest/index.html"),
            ("GET", f"/i/{bundle.id}/2/index.html"),
            ("HEAD", f"/i/{bundle.id}/1/css/a.css"),
            ("GET", f"/i/{bundle.id}/1/missing.html"),
        ],
        "/t/{item_id}/{rev}/{relpath:path}": [
            ("GET", f"/t/{text.id}/1/notes.txt"),
            ("GET", f"/t/{bundle.id}/1/index.html"),
        ],
        "/r/{item_id}/{rev}/{relpath:path}": [
            ("GET", f"/r/{text.id}/1/notes.txt"),
            ("HEAD", f"/r/{text.id}/1/notes.txt"),
            ("GET", f"/r/{bundle.id}/1/index.html"),
        ],
        "/d/{item_id}/{rev}": [
            ("GET", f"/d/{bundle.id}/1"),
            ("GET", f"/d/{text.id}/1"),
            ("GET", f"/d/{MISSING}/1"),
        ],
        "/d/{item_id}/{rev}/{relpath:path}": [
            ("GET", f"/d/{bundle.id}/1/css/a.css"),
            ("GET", f"/d/{bundle.id}/latest/css/a.css"),
        ],
    }


def _route_paths(app: SecuredApp) -> set[str]:
    return route_paths(app)


def _assert_clean(response: ClientResponse) -> None:
    names = {k.lower() for k in response.headers}
    assert "set-cookie" not in names
    assert "set-cookie2" not in names
    assert not any(n.startswith("access-control-") for n in names), names


def test_every_route_has_a_sample(env: ViewerEnv) -> None:
    samples = _samples(env.items[0], env.items[1])
    assert _route_paths(env.dashboard) | _route_paths(env.preview) == set(samples)


def test_no_cookies_or_cors_on_any_route(env: ViewerEnv) -> None:
    dash_paths = _route_paths(env.dashboard)
    for template, requests in _samples(env.items[0], env.items[1]).items():
        client = env.dash_client() if template in dash_paths else env.preview_client()
        for method, url in requests:
            headers = csrf_headers() if method == "POST" else owner_headers()
            response = client.request(method, url, headers={**headers, **HOSTILE})
            assert response.status_code < 500, (method, url, response.status_code)
            _assert_clean(response)


@pytest.mark.parametrize("which", ["dashboard", "preview"])
def test_preflight_is_refused_everywhere(env: ViewerEnv, which: str) -> None:
    app = env.dashboard if which == "dashboard" else env.preview
    client = env.dash_client() if which == "dashboard" else env.preview_client()
    for path in _route_paths(app):
        url = path.replace("{item_id}", env.items[0].id).replace("{relpath:path}", "index.html")
        url = url.replace("{name:path}", "x.js")
        response = client.options(
            url,
            headers=owner_headers(
                {
                    "Origin": "https://evil.example",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "x-pdash-csrf, content-type",
                }
            ),
        )
        assert response.status_code == 405, url
        _assert_clean(response)


def test_cookie_header_changes_nothing(env: ViewerEnv) -> None:
    """No code reads cookies: responses are identical with or without one."""
    client = env.dash_client()
    plain = client.get("/api/items", headers=owner_headers())
    with_cookie = client.get("/api/items", headers=owner_headers({"Cookie": "state=trashed"}))
    assert plain.status_code == with_cookie.status_code == 200
    assert plain.json() == with_cookie.json()
