"""Security tests for the `claudia` token scope and the Claudia routes (unit M3): C44, C45.

C45: the admin, notifier and `claudia` tokens are each valid on exactly one
route family (4 tokens x every route, incl. the A1 cancel routes), the
route inventory has no answer, tap, code or grant route for the `claudia`
token (cancel exists, for `/stop`, and only closes requests), every route
re-checks its role, the `/v1/claudia/*` family has its own peer uids, and
the three tokens must differ. C44 (admin side): the admin re-checks the
sender against its own config, stores a re-delivered update once and never
logs message text.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

import pytest
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from preview_dashboard.interfaces.admin import (
    api,
    claudia_api,
    cleanup_api,
    folders_api,
    notifier_api,
    questions_api,
)
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.auth import PeerCredentials, route_family
from preview_dashboard.interfaces.admin.claudia_api import require_claudia
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from preview_dashboard.interfaces.admin.notifier_api import require_notifier
from preview_dashboard.interfaces.admin.questions_api import require_admin
from tests.claudia_admin_support import (
    approval_body,
    claudia_app,
    code_body,
    message_body,
    tap_body,
)
from tests.notify_admin_support import asgi_client, ask_body, bearer, notify_app

pytestmark = pytest.mark.security

ADMIN, NOTIFIER, CLAUDIA, NONE, WRONG = "admin", "notifier", "claudia", "none", "wrong"
ZERO_ULID = "0" * 26


def _headers(kind: str, rig: Any) -> dict[str, str]:
    tokens = {
        ADMIN: rig.admin_token,
        NOTIFIER: rig.notifier_token,
        CLAUDIA: rig.claudia_token,
        WRONG: secrets.token_urlsafe(32),
    }
    return {} if kind == NONE else bearer(tokens[kind])


# (family, method, path template, JSON body); {mid} inbox message, {aid} approval, {qid} question.
ROUTES: list[tuple[str, str, str, dict[str, Any] | None]] = [
    (ADMIN, "GET", "/v1/health", None),
    (ADMIN, "GET", "/v1/items", None),
    (ADMIN, "POST", "/v1/questions", ask_body()),
    (ADMIN, "GET", "/v1/questions/{qid}", None),
    (ADMIN, "POST", "/v1/notifications", {"event": "done", "title": "Build finished"}),
    (NOTIFIER, "GET", "/v1/notifier/tasks", None),
    (NOTIFIER, "POST", "/v1/notifier/answers", None),
    (NOTIFIER, "POST", "/v1/notifier/messages", message_body(update_id=7, message_id=70)),
    (NOTIFIER, "POST", "/v1/notifier/approvals", None),
    (NOTIFIER, "POST", "/v1/notifier/codes", code_body("000000", update_id=900)),
    # Voice notes for `sendVoice` (C56, M10b): 404 (nothing waiting) is fine for the notifier.
    (NOTIFIER, "GET", f"/v1/notifier/voice/{ZERO_ULID}", None),
    (NOTIFIER, "POST", f"/v1/notifier/voice/{ZERO_ULID}/release", {}),
    # Owner voice/photo intake (C61): a bad body is a 400/422 for the notifier token.
    (NOTIFIER, "POST", "/v1/notifier/media", {}),
    (CLAUDIA, "GET", "/v1/claudia/messages", None),
    (CLAUDIA, "POST", "/v1/claudia/messages/{mid}/handled", None),
    # A text message has no media: 404 is fine for the claudia token (C61).
    (CLAUDIA, "GET", "/v1/claudia/messages/{mid}/media", None),
    (CLAUDIA, "POST", "/v1/claudia/messages/{mid}/media/release", {}),
    (CLAUDIA, "POST", "/v1/claudia/replies", {"text": "Done!"}),
    # Bad audio is a 400 for the claudia token; every other token is refused first (C56, M10).
    (CLAUDIA, "POST", "/v1/claudia/voice", {"text": "Done!", "audio": ""}),
    (CLAUDIA, "POST", "/v1/claudia/approvals", approval_body(window_id=None)),
    (CLAUDIA, "GET", "/v1/claudia/approvals/{aid}", None),
    (CLAUDIA, "POST", "/v1/claudia/approvals/{aid}/consume", None),
    (CLAUDIA, "POST", "/v1/claudia/approvals/{aid}/cancel", None),
    (CLAUDIA, "POST", "/v1/claudia/approvals/cancel-open", {}),
    (CLAUDIA, "POST", "/v1/claudia/health", {"screen": "ok"}),
    (CLAUDIA, "GET", "/v1/claudia/no-such-route", None),
    (NOTIFIER, "GET", "/v1/notifier/no-such-route", None),
]


def _seed(client: TestClient, rig: Any) -> dict[str, str]:
    qid = client.post("/v1/questions", json=ask_body(), headers=bearer(rig.admin_token)).json()[
        "question"
    ]["id"]
    stored = client.post(
        "/v1/notifier/messages", json=message_body(), headers=bearer(rig.notifier_token)
    )
    assert stored.json() == {"result": "stored"}, stored.text
    mid = rig.claudia.inbox.unhandled(1)[0].id
    created = client.post(
        "/v1/claudia/approvals", json=approval_body(), headers=bearer(rig.claudia_token)
    )
    assert created.status_code == 201, created.text
    return {"qid": qid, "mid": mid, "aid": created.json()["approval"]["id"]}


@pytest.mark.parametrize("token_kind", [ADMIN, NOTIFIER, CLAUDIA, NONE, WRONG])
@pytest.mark.parametrize(("family", "method", "template", "body"), ROUTES)
def test_c45_token_route_family_matrix(tmp_path, token_kind, family, method, template, body):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        ids = _seed(client, rig)
        path = template.format(**ids)
        if body is not None and body.get("window_id", "") is None:
            body = {**body, "window_id": "323e4567-e89b-42d3-a456-426614174000"}
        if path == "/v1/notifier/approvals":
            body = tap_body(ids["aid"])
        if path == "/v1/notifier/answers":
            body = {"question_id": ids["qid"], "key": "a", "source": "telegram", "actor_ref": "1"}
        response = client.request(method, path, json=body, headers=_headers(token_kind, rig))
    if token_kind in (NONE, WRONG):
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    elif token_kind == family:
        assert response.status_code not in (401, 403), response.text
    else:
        # Never cross-accepted; unknown paths of another family don't leak (403, not 404).
        assert response.status_code == 403


def test_c45_route_family_classification():
    assert route_family("/v1/claudia") == CLAUDIA
    assert route_family("/v1/claudia/approvals") == CLAUDIA
    assert route_family("/v1/claudiax") == ADMIN  # prefix match is per segment
    assert route_family("/v1/notifier/codes") == NOTIFIER
    assert route_family("/v1/items") == ADMIN


def _routes() -> set[tuple[str, str]]:
    # Every router the admin app includes (app.py), walked directly.
    found: set[tuple[str, str]] = set()
    for module in (api, folders_api, cleanup_api, questions_api, notifier_api, claudia_api):
        for route in module.router.routes:
            if isinstance(route, APIRoute):
                found |= {(method, route.path) for method in route.methods or ()}
    return found


def test_c45_claudia_inventory_has_no_answer_tap_code_or_grant_route():
    routes = _routes()
    claudia = {r for r in routes if r[1].startswith("/v1/claudia")}
    assert claudia == {
        ("GET", "/v1/claudia/messages"),
        ("POST", "/v1/claudia/messages/{message_id}/handled"),
        # Owner voice/photo bytes (C61): fetch one, then release it.
        ("GET", "/v1/claudia/messages/{message_id}/media"),
        ("POST", "/v1/claudia/messages/{message_id}/media/release"),
        ("POST", "/v1/claudia/replies"),
        ("POST", "/v1/claudia/voice"),
        ("POST", "/v1/claudia/approvals"),
        ("GET", "/v1/claudia/approvals/{approval_id}"),
        ("POST", "/v1/claudia/approvals/{approval_id}/consume"),
        # `/stop` (C58): cancel only ever closes a request (A1, ADR 0033).
        ("POST", "/v1/claudia/approvals/{approval_id}/cancel"),
        ("POST", "/v1/claudia/approvals/cancel-open"),
        ("POST", "/v1/claudia/health"),
    }
    forbidden = ("answer", "tap", "code", "approve", "grant", "deny", "edit")
    for _method, path in claudia:
        assert not any(word in path for word in forbidden), path
    # Taps and codes exist only in the notifier family.
    for path in (
        "/v1/notifier/approvals",
        "/v1/notifier/codes",
        "/v1/notifier/messages",
        "/v1/notifier/media",
    ):
        assert ("POST", path) in routes
    # Voice audio leaves the store only through the notifier family (C56).
    assert ("GET", "/v1/notifier/voice/{voice_id}") in routes
    assert ("POST", "/v1/notifier/voice/{voice_id}/release") in routes
    no_patch_or_delete = {r for r in claudia if r[0] in {"PUT", "PATCH", "DELETE"}}
    assert no_patch_or_delete == set()


def test_c45_routes_recheck_the_token_role():
    class _Req:
        def __init__(self, role: str | None) -> None:
            self.scope: dict[str, Any] = {
                "state": {} if role is None else {"pdash.token_role": role}
            }

    for role in (ADMIN, NOTIFIER, None):
        with pytest.raises(ForbiddenError):
            require_claudia(_Req(role))  # type: ignore[arg-type]
    with pytest.raises(ForbiddenError):
        require_notifier(_Req(CLAUDIA))  # type: ignore[arg-type]
    with pytest.raises(ForbiddenError):
        require_admin(_Req(CLAUDIA))  # type: ignore[arg-type]
    require_claudia(_Req(CLAUDIA))  # type: ignore[arg-type]


def test_c45_claudia_token_must_differ_from_the_others(tmp_path):
    with notify_app(tmp_path) as rig:
        admin, notifier = rig.admin_token.encode(), rig.notifier_token.encode()
        for same in (admin, notifier):
            with pytest.raises(ValueError, match="claudia token must differ"):
                build_admin_app(rig.core, token=admin, notifier_token=notifier, claudia_token=same)


def test_c45_without_claudia_token_the_claudia_routes_are_closed(tmp_path):
    with (
        claudia_app(tmp_path, with_claudia_token=False) as rig,
        TestClient(rig.app) as client,
    ):
        for headers, status in (
            (bearer(rig.admin_token), 403),
            (bearer(rig.notifier_token), 403),
            (bearer(rig.claudia_token), 401),
            ({}, 401),
        ):
            assert client.get("/v1/claudia/messages", headers=headers).status_code == status


def test_c45_claudia_disabled_refuses_the_companion_routes(tmp_path):
    # Notifications on, Claudia off: even a configured claudia token gets nothing.
    with notify_app(tmp_path) as rig:
        claudia_token = secrets.token_urlsafe(32)
        app = build_admin_app(
            rig.core,
            token=rig.admin_token.encode(),
            notifier_token=rig.notifier_token.encode(),
            claudia_token=claudia_token.encode(),
        )
        with TestClient(app) as client:
            assert (
                client.get("/v1/claudia/messages", headers=bearer(claudia_token)).status_code == 400
            )
            posted = client.post(
                "/v1/notifier/messages", json=message_body(), headers=bearer(rig.notifier_token)
            )
            assert posted.status_code == 400
            code = client.post(
                "/v1/notifier/codes", json=code_body("123456"), headers=bearer(rig.notifier_token)
            )
            assert code.status_code == 400


@pytest.mark.parametrize(
    ("peer_uid", "token_kind", "path", "allowed"),
    [
        (3000, CLAUDIA, "/v1/claudia/messages", True),
        (1000, CLAUDIA, "/v1/claudia/messages", False),  # root/Claude's uid can't be the host
        (2000, CLAUDIA, "/v1/claudia/messages", False),  # nor the notifier's
        (3000, ADMIN, "/v1/health", False),  # the host's uid can't use admin routes
        (3000, NOTIFIER, "/v1/notifier/tasks", False),
        (None, CLAUDIA, "/v1/claudia/messages", False),  # unknown peer: fail closed
    ],
)
async def test_c45_peer_uid_family(tmp_path, peer_uid, token_kind, path, allowed):
    with claudia_app(
        tmp_path, allowed_peer_uids=[1000], notifier_peer_uids=[2000], claudia_peer_uids=[3000]
    ) as rig:
        peer = None if peer_uid is None else PeerCredentials(pid=1, uid=peer_uid, gid=1)
        async with asgi_client(rig.app, peer=peer) as client:
            response = await client.get(path, headers=_headers(token_kind, rig))
    assert (response.status_code == 403) is not allowed
    if allowed:
        assert response.status_code == 200


# --- C44 (admin side) -------------------------------------------------------------------


def test_c44_admin_rechecks_the_sender_against_its_own_owner(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        notifier = bearer(rig.notifier_token)
        foreign = client.post(
            "/v1/notifier/messages", json=message_body(sender_id=999), headers=notifier
        )
        assert foreign.status_code == 422  # refused for good: the notifier won't retry
        assert rig.claudia.inbox.unhandled(10) == []


def test_c44_redelivered_update_is_stored_once(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        notifier = bearer(rig.notifier_token)
        first = client.post("/v1/notifier/messages", json=message_body(), headers=notifier)
        again = client.post("/v1/notifier/messages", json=message_body(), headers=notifier)
        assert (first.json(), again.json()) == ({"result": "stored"}, {"result": "duplicate"})
        assert len(rig.claudia.inbox.unhandled(10)) == 1


@pytest.mark.parametrize("text", ["123456", "12 34 56", "my code is 123456 ok"])
def test_c44_codes_never_enter_the_inbox(tmp_path, text):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        response = client.post(
            "/v1/notifier/messages",
            json=message_body(text=text),
            headers=bearer(rig.notifier_token),
        )
        assert response.status_code == 400
        assert rig.claudia.inbox.unhandled(10) == []


def test_c44_message_text_is_never_logged(tmp_path, caplog):
    marker = "Zebra-secret-plan-words"
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        caplog.set_level(logging.DEBUG)
        client.post(
            "/v1/notifier/messages",
            json=message_body(text=marker, quote_text=marker),
            headers=bearer(rig.notifier_token),
        )
        listed = client.get("/v1/claudia/messages", headers=bearer(rig.claudia_token))
        assert listed.json()["messages"][0]["text"] == marker
    assert marker not in caplog.text


def test_c44_inbox_handled_mark_is_a_cas(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        claudia = bearer(rig.claudia_token)
        client.post(
            "/v1/notifier/messages", json=message_body(), headers=bearer(rig.notifier_token)
        )
        mid = client.get("/v1/claudia/messages", headers=claudia).json()["messages"][0]["id"]
        first = client.post(f"/v1/claudia/messages/{mid}/handled", headers=claudia)
        second = client.post(f"/v1/claudia/messages/{mid}/handled", headers=claudia)
        assert first.status_code == 200
        assert first.json()["message"]["state"] == "handled"
        assert second.status_code == 409
        assert (
            client.post(f"/v1/claudia/messages/{ZERO_ULID}/handled", headers=claudia).status_code
            == 404
        )
        assert client.post("/v1/claudia/messages/nope/handled", headers=claudia).status_code == 404
        assert client.get("/v1/claudia/messages", headers=claudia).json() == {"messages": []}
