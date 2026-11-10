"""Security tests: the CSRF matrix and identity gate on every real dashboard POST (C2, C3, C4).

`test_viewer_csrf.py` proves the matrix on a dummy route; this file runs it
against the real state-changing routes (trash, restore, pin, unpin and
revisions/prune, the "delete old versions" of C43) and
checks that every rejected request leaves the item untouched. A coverage
check fails if a POST route is added without being listed here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from preview_dashboard.domain.models import Item, ItemId
from tests.viewer_support import (
    DASH_HOST,
    DASH_ORIGIN,
    OWNER,
    PREVIEW_ORIGIN,
    ViewerEnv,
    call_asgi,
    csrf_headers,
    make_env,
)

pytestmark = pytest.mark.security


def _active(env: ViewerEnv) -> Item:
    return env.publish({"a.txt": b"x"}, title="A")


def _trashed(env: ViewerEnv) -> Item:
    return env.services.trash.trash(_active(env).id)


def _pinned(env: ViewerEnv) -> Item:
    return env.services.pins.set_pinned(_active(env).id, pinned=True)


def _revised(env: ViewerEnv) -> Item:
    return env.revise(_active(env).id, {"a.txt": b"y"})


# action -> an item on which the action is a real change (so "unchanged" means refused).
_SETUP: dict[str, Callable[[ViewerEnv], Item]] = {
    "trash": _active,
    "restore": _trashed,
    "pin": _active,
    "unpin": _pinned,
    "revisions/prune": _revised,  # C43: delete old versions
}
ACTIONS = sorted(_SETUP)

_WRONG_VALUES = [
    ("Content-Type", "text/plain"),
    ("Content-Type", "application/x-www-form-urlencoded"),
    ("Content-Type", "multipart/form-data; boundary=x"),
    ("Content-Type", "application/json; charset=utf-8"),
    ("Origin", "null"),
    ("Origin", PREVIEW_ORIGIN),
    ("Origin", "https://evil.example"),
    ("Origin", f"http://{DASH_HOST}"),
    ("Origin", f"{DASH_ORIGIN}:443"),
    ("Sec-Fetch-Site", "same-site"),
    ("Sec-Fetch-Site", "cross-site"),
    ("Sec-Fetch-Site", "none"),
    ("X-PDash-CSRF", "0"),
    ("X-PDash-CSRF", ""),
    ("Tailscale-User-Login", "x" + OWNER),
    ("Tailscale-User-Login", ""),
]
_REQUIRED = ["Content-Type", "Origin", "Sec-Fetch-Site", "X-PDash-CSRF", "Tailscale-User-Login"]


def _prepare(action: str) -> tuple[ViewerEnv, Item, str]:
    env = make_env()
    item = _SETUP[action](env)
    # Prune requires the head the owner saw (C43); a valid one keeps the refusals CSRF-only.
    query = f"?expected={item.head.number}" if action == "revisions/prune" else ""
    return env, item, f"/api/items/{item.id}/{action}{query}"


def _stored(env: ViewerEnv, item: Item) -> Item:
    return env.services.repo.get(ItemId(item.id))


def _post_routes(env: ViewerEnv) -> set[str]:
    """Every POST route path of the dashboard app (descends into included routers)."""
    found: set[str] = set()
    pending: list[Any] = list(env.dashboard.inner.routes)
    while pending:
        route = pending.pop()
        if "POST" in (getattr(route, "methods", None) or ()):
            found.add(route.path)
        original = getattr(route, "original_router", None)
        if original is not None:
            pending.extend(original.routes)
    return found


# Covered by its own matrix in tests/security/test_dashboard_decisions.py (F-CL6).
_DECISION_ROUTE = "/api/claudia/approvals/{approval_id}/decision"


def test_every_post_route_is_covered() -> None:
    expected = {f"/api/items/{{item_id}}/{a}" for a in ACTIONS} | {_DECISION_ROUTE}
    assert _post_routes(make_env()) == expected


@pytest.mark.parametrize("action", ACTIONS)
def test_legitimate_post_changes_state(action: str) -> None:
    env, item, url = _prepare(action)
    response = env.dash_client().post(url, headers=csrf_headers(), content=b"{}")
    assert response.status_code == 200
    assert _stored(env, item) != item
    assert response.json()["item"]["id"] == item.id


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(("header", "value"), _WRONG_VALUES)
def test_wrong_header_value_is_refused_and_changes_nothing(
    action: str, header: str, value: str
) -> None:
    env, item, url = _prepare(action)
    response = env.dash_client().post(url, headers=csrf_headers({header: value}), content=b"{}")
    assert response.status_code == 403
    assert not any(k.lower().startswith("access-control-") for k in response.headers)
    assert _stored(env, item) == item


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("missing", _REQUIRED)
def test_missing_header_is_refused_and_changes_nothing(action: str, missing: str) -> None:
    env, item, url = _prepare(action)
    headers = csrf_headers()
    del headers[missing]
    response = env.dash_client().post(url, headers=headers, content=b"{}")
    assert response.status_code == 403
    assert _stored(env, item) == item


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize(
    "dup", [b"origin", b"content-type", b"x-pdash-csrf", b"sec-fetch-site", b"tailscale-user-login"]
)
async def test_duplicated_header_is_refused_and_changes_nothing(action: str, dup: bytes) -> None:
    env, item, url = _prepare(action)
    base = {k.lower().encode(): v.encode() for k, v in csrf_headers().items()}
    headers = [(b"host", DASH_HOST.encode()), *base.items(), (dup, base[dup])]
    result = await call_asgi(env.dashboard, method="POST", path=url, headers=headers)
    assert result.status == 403
    assert _stored(env, item) == item


@pytest.mark.parametrize("action", ACTIONS)
async def test_wrong_host_is_refused_and_changes_nothing(action: str) -> None:
    env, item, url = _prepare(action)
    base = [(k.lower().encode(), v.encode()) for k, v in csrf_headers().items()]
    headers = [(b"host", b"evil.example"), *base]
    result = await call_asgi(env.dashboard, method="POST", path=url, headers=headers)
    assert result.status == 421
    assert _stored(env, item) == item


@pytest.mark.parametrize("action", ACTIONS)
def test_sandboxed_preview_post_is_refused(action: str) -> None:
    """A sandboxed preview has an opaque origin: `Origin: null`, cross-site."""
    env, item, url = _prepare(action)
    headers = csrf_headers({"Origin": "null", "Sec-Fetch-Site": "cross-site"})
    assert env.dash_client().post(url, headers=headers).status_code == 403
    assert _stored(env, item) == item


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_other_methods_change_nothing(action: str, method: str) -> None:
    env, item, url = _prepare(action)
    response = env.dash_client().request(method, url, headers=csrf_headers())
    assert response.status_code == 405
    assert _stored(env, item) == item


@pytest.mark.parametrize("action", ACTIONS)
def test_oversized_body_is_413_and_changes_nothing(action: str) -> None:
    env, item, url = _prepare(action)
    response = env.dash_client().post(
        url, headers=csrf_headers(), content=b"{" + b" " * 1024 + b"}"
    )
    assert response.status_code == 413
    assert _stored(env, item) == item
