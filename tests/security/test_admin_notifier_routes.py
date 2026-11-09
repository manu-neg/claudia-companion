"""Security tests for the admin question/notifier routes (unit N3): C33, C34, C36, C37.

C33: the admin and notifier tokens are never cross-accepted (route-family
matrix), peer uids are enforced per family. C34: only the notifier token
reaches `QuestionService.answer`. C36: token files are loaded with the C12
rules and errors name the token. C37: the shared alert rate limit, the
long-poll caps (16 question waiters, one notifier poller) and waits that
hold no threadpool worker.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time
from typing import Any

import anyio.to_thread
import pytest
from starlette.testclient import TestClient

from preview_dashboard.domain.questions import QuestionState
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.auth import PeerCredentials
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from preview_dashboard.interfaces.admin.longpoll import MAX_QUESTION_WAITERS
from preview_dashboard.interfaces.admin.notifier_api import require_notifier
from preview_dashboard.interfaces.admin.questions_api import require_admin
from preview_dashboard.interfaces.token_file import TokenFileError, load_admin_token
from tests.admin_support import write_token
from tests.notify_admin_support import (
    answer_body,
    asgi_client,
    ask_body,
    bearer,
    notify_app,
)

pytestmark = pytest.mark.security

ADMIN, NOTIFIER, NONE, WRONG = "admin", "notifier", "none", "wrong"
ZERO_ULID = "0" * 26


def _headers(kind: str, admin_token: str, notifier_token: str) -> dict[str, str]:
    if kind == ADMIN:
        return bearer(admin_token)
    if kind == NOTIFIER:
        return bearer(notifier_token)
    if kind == WRONG:
        return bearer(secrets.token_urlsafe(32))
    return {}


# (family, method, path template, JSON body)
ROUTES: list[tuple[str, str, str, dict[str, Any] | None]] = [
    (ADMIN, "GET", "/v1/health", None),
    (ADMIN, "GET", "/v1/items", None),
    (ADMIN, "POST", "/v1/questions", ask_body()),
    (ADMIN, "GET", "/v1/questions/{qid}", None),
    (ADMIN, "POST", "/v1/questions/{qid}/cancel", None),
    (ADMIN, "POST", "/v1/notifications", {"event": "done", "title": "Build finished"}),
    (NOTIFIER, "GET", "/v1/notifier/tasks", None),
    (NOTIFIER, "POST", "/v1/notifier/tasks/{tid}/done", {"message_ref": "1:2"}),
    (NOTIFIER, "POST", "/v1/notifier/tasks/{tid}/failed", {}),
    (NOTIFIER, "POST", "/v1/notifier/answers", answer_body(ZERO_ULID)),
    (NOTIFIER, "GET", "/v1/notifier/no-such-route", None),
]


@pytest.mark.parametrize("token_kind", [ADMIN, NOTIFIER, NONE, WRONG])
@pytest.mark.parametrize(("family", "method", "template", "body"), ROUTES)
def test_c33_token_route_family_matrix(tmp_path, token_kind, family, method, template, body):
    with notify_app(tmp_path, notify_rate_per_hour=100) as rig, TestClient(rig.app) as client:
        asked = client.post("/v1/questions", json=ask_body(), headers=bearer(rig.admin_token))
        qid = asked.json()["question"]["id"]
        tid = rig.core.outbox.pending(20)[0].id
        path = template.format(qid=qid, tid=tid)
        headers = _headers(token_kind, rig.admin_token, rig.notifier_token)
        response = client.request(method, path, json=body, headers=headers)
    if token_kind in (NONE, WRONG):
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    elif token_kind == family:
        assert response.status_code not in (401, 403), response.text
    else:
        # Never cross-accepted, and unknown paths of the other family don't leak (403, not 404).
        assert response.status_code == 403


def test_c33_same_token_for_both_families_is_refused(tmp_path):
    with notify_app(tmp_path) as rig:
        token = rig.admin_token.encode()
        with pytest.raises(ValueError, match="differ"):
            build_admin_app(rig.core, token=token, notifier_token=token)


def test_c33_without_notifier_token_the_notifier_routes_are_closed(tmp_path):
    with (
        notify_app(tmp_path, with_notifier_token=False) as rig,
        TestClient(rig.app) as client,
    ):
        for headers, status in (
            (bearer(rig.admin_token), 403),
            (bearer(rig.notifier_token), 401),
            ({}, 401),
        ):
            assert client.get("/v1/notifier/tasks", headers=headers).status_code == status


@pytest.mark.parametrize(
    ("peer_uid", "token_kind", "path", "allowed"),
    [
        (1000, ADMIN, "/v1/health", True),
        (2000, ADMIN, "/v1/health", False),  # the notifier's uid can't use admin routes
        (2000, NOTIFIER, "/v1/notifier/tasks", True),
        (1000, NOTIFIER, "/v1/notifier/tasks", False),  # root/Claude's uid can't answer
        (3000, NOTIFIER, "/v1/notifier/tasks", False),
        (None, ADMIN, "/v1/health", False),  # unknown peer: fail closed
    ],
)
async def test_c33_peer_uid_allowlist_per_route_family(
    tmp_path, peer_uid, token_kind, path, allowed
):
    with notify_app(tmp_path, allowed_peer_uids=[1000], notifier_peer_uids=[2000]) as rig:
        peer = None if peer_uid is None else PeerCredentials(pid=1, uid=peer_uid, gid=1)
        async with asgi_client(rig.app, peer=peer) as client:
            headers = _headers(token_kind, rig.admin_token, rig.notifier_token)
            response = await client.get(path, headers=headers)
    assert (response.status_code == 403) is not allowed
    if allowed:
        assert response.status_code == 200


def test_c33_routes_recheck_the_token_role():
    class _Req:
        def __init__(self, role: str | None) -> None:
            self.scope: dict[str, Any] = {
                "state": {} if role is None else {"pdash.token_role": role}
            }

    with pytest.raises(ForbiddenError):
        require_notifier(_Req("admin"))  # type: ignore[arg-type]
    with pytest.raises(ForbiddenError):
        require_notifier(_Req(None))  # type: ignore[arg-type]
    with pytest.raises(ForbiddenError):
        require_admin(_Req("notifier"))  # type: ignore[arg-type]
    require_notifier(_Req("notifier"))  # type: ignore[arg-type]
    require_admin(_Req("admin"))  # type: ignore[arg-type]


# --- C34 -------------------------------------------------------------------------------


def test_c34_admin_token_can_never_answer(tmp_path):
    with notify_app(tmp_path) as rig, TestClient(rig.app) as client:
        qid = client.post("/v1/questions", json=ask_body(), headers=bearer(rig.admin_token)).json()[
            "question"
        ]["id"]
        denied = client.post(
            "/v1/notifier/answers", json=answer_body(qid), headers=bearer(rig.admin_token)
        )
        assert denied.status_code == 403
        # No other admin route records an answer either.
        for path in (f"/v1/questions/{qid}/answer", f"/v1/questions/{qid}"):
            response = client.post(path, json={"key": "a"}, headers=bearer(rig.admin_token))
            assert response.status_code in (404, 405)
        assert rig.core.questions.get(qid).state is QuestionState.OPEN


def test_c34_only_the_notifier_token_answers_first_wins(tmp_path):
    with notify_app(tmp_path) as rig, TestClient(rig.app) as client:
        admin, notifier = bearer(rig.admin_token), bearer(rig.notifier_token)
        qid = client.post("/v1/questions", json=ask_body(), headers=admin).json()["question"]["id"]

        def answer(**kw: Any) -> str:
            response = client.post("/v1/notifier/answers", json=kw, headers=notifier)
            assert response.status_code == 200, response.text
            result: str = response.json()["result"]
            return result

        assert answer(**answer_body(qid, "z")) == "unknown"  # key not offered
        assert answer(**answer_body("not-a-ulid")) == "unknown"  # no existence oracle
        assert answer(**answer_body(ZERO_ULID)) == "unknown"
        assert answer(**answer_body(qid, "b")) == "recorded"
        assert answer(**answer_body(qid, "a")) == "already_answered"
        question = client.get(f"/v1/questions/{qid}", headers=admin).json()["question"]
        assert (question["state"], question["answer_key"]) == ("answered", "b")
        assert question["answer_source"] == "telegram"


def test_c34_answer_source_must_be_an_enabled_channel(tmp_path):
    with notify_app(tmp_path) as rig, TestClient(rig.app) as client:
        qid = client.post("/v1/questions", json=ask_body(), headers=bearer(rig.admin_token)).json()[
            "question"
        ]["id"]
        response = client.post(
            "/v1/notifier/answers",
            json=answer_body(qid, source="dashboard"),
            headers=bearer(rig.notifier_token),
        )
        assert response.status_code == 400
        assert rig.core.questions.get(qid).state is QuestionState.OPEN


def test_c34_no_answers_while_notifications_are_disabled(tmp_path):
    with (
        notify_app(tmp_path, notify_enabled=False) as rig,
        TestClient(rig.app) as client,
    ):
        asked = client.post("/v1/questions", json=ask_body(), headers=bearer(rig.admin_token))
        assert asked.status_code == 201  # questions are still stored
        assert rig.core.outbox.pending(20) == []  # ... but nothing is sent
        qid = asked.json()["question"]["id"]
        response = client.post(
            "/v1/notifier/answers", json=answer_body(qid), headers=bearer(rig.notifier_token)
        )
        assert response.status_code == 400
        assert rig.core.questions.get(qid).state is QuestionState.OPEN


# --- C36 -------------------------------------------------------------------------------


def test_c36_token_file_errors_name_the_token_not_admin(tmp_path):
    path = tmp_path / "secrets" / "notifier.token"
    write_token(path, mode=0o644)  # readable by others: refused (C12 rules)
    with pytest.raises(TokenFileError) as caught:
        load_admin_token(path, what="notifier token")
    assert "notifier token file" in str(caught.value)
    assert "admin" not in str(caught.value)
    os.chmod(path, 0o600)
    path.write_text("x" * 50 + "\n")  # low variety
    with pytest.raises(TokenFileError, match=r"^notifier token in "):
        load_admin_token(path, what="notifier token")


# --- C37 -------------------------------------------------------------------------------


def test_c37_questions_and_notifications_share_one_rate_limit(tmp_path):
    with (
        notify_app(tmp_path, notify_rate_per_hour=2) as rig,
        TestClient(rig.app) as client,
    ):
        admin = bearer(rig.admin_token)
        assert client.post("/v1/questions", json=ask_body(), headers=admin).status_code == 201
        done = {"event": "done", "title": "Build finished"}
        assert client.post("/v1/notifications", json=done, headers=admin).status_code == 201
        for path, body in (("/v1/questions", ask_body()), ("/v1/notifications", done)):
            refused = client.post(path, json=body, headers=admin)
            assert refused.status_code == 429
            assert refused.json()["error"] == "rate_limited"
            assert refused.headers["retry-after"].isdigit()


@pytest.mark.parametrize("query", ["wait=61", "wait=-1", "wait=%2B5", "wait=%D9%A3", "x=1"])
def test_c37_wait_is_bounded_and_strict(tmp_path, query):
    with notify_app(tmp_path) as rig, TestClient(rig.app) as client:
        admin = bearer(rig.admin_token)
        qid = client.post("/v1/questions", json=ask_body(), headers=admin).json()["question"]["id"]
        assert client.get(f"/v1/questions/{qid}?{query}", headers=admin).status_code == 400
        tasks = client.get(f"/v1/notifier/tasks?{query}", headers=bearer(rig.notifier_token))
        assert tasks.status_code == 400
        repeated = client.get(f"/v1/questions/{qid}?wait=1&wait=2", headers=admin)
        assert repeated.status_code == 400


async def test_c37_question_waiters_are_capped(tmp_path):
    with notify_app(tmp_path, notify_rate_per_hour=100) as rig:
        async with asgi_client(rig.app) as client:
            admin = bearer(rig.admin_token)
            reply = await client.post("/v1/questions", json=ask_body(), headers=admin)
            qid = reply.json()["question"]["id"]
            waiters = [
                asyncio.create_task(client.get(f"/v1/questions/{qid}?wait=3", headers=admin))
                for _ in range(MAX_QUESTION_WAITERS)
            ]
            await _until(lambda: rig.app_state().question_slots.busy == MAX_QUESTION_WAITERS)
            started = time.monotonic()
            extra = await client.get(f"/v1/questions/{qid}?wait=3", headers=admin)
            assert time.monotonic() - started < 1.0  # beyond the cap: answered at once
            assert extra.json()["question"]["state"] == "open"
            results = await asyncio.gather(*waiters)
            assert all(r.status_code == 200 for r in results)
            assert rig.app_state().question_slots.busy == 0


async def test_c37_long_polls_hold_no_threadpool_worker(tmp_path):
    with notify_app(tmp_path, notify_rate_per_hour=100) as rig:
        async with asgi_client(rig.app) as client:
            admin = bearer(rig.admin_token)
            reply = await client.post("/v1/questions", json=ask_body(), headers=admin)
            qid = reply.json()["question"]["id"]
            # Two worker threads for the whole app: 16 held long-polls must not use them.
            anyio.to_thread.current_default_thread_limiter().total_tokens = 2
            waiters = [
                asyncio.create_task(client.get(f"/v1/questions/{qid}?wait=5", headers=admin))
                for _ in range(MAX_QUESTION_WAITERS)
            ]
            poller = asyncio.create_task(
                client.get("/v1/notifier/tasks?wait=5", headers=bearer(rig.notifier_token))
            )
            await _until(lambda: rig.app_state().question_slots.busy == MAX_QUESTION_WAITERS)
            started = time.monotonic()
            listed = await client.get("/v1/items", headers=admin)
            asked = await client.post("/v1/questions", json=ask_body(), headers=admin)
            assert (listed.status_code, asked.status_code) == (200, 201)
            assert time.monotonic() - started < 2.0
            # The new question's alert wakes the notifier poll at once.
            tasks = (await asyncio.wait_for(poller, 3)).json()["tasks"]
            assert tasks and tasks[0]["channel"] == "telegram"
            await client.post(f"/v1/questions/{qid}/cancel", headers=admin)  # wakes all waiters
            results = await asyncio.wait_for(asyncio.gather(*waiters), 3)
            assert {r.json()["question"]["state"] for r in results} == {"cancelled"}


async def test_c37_one_notifier_poller_at_a_time(tmp_path):
    with notify_app(tmp_path) as rig:
        async with asgi_client(rig.app) as client:
            notifier = bearer(rig.notifier_token)
            first = asyncio.create_task(client.get("/v1/notifier/tasks?wait=5", headers=notifier))
            await _until(lambda: rig.app_state().notifier_gate.busy == 1)
            await client.post(
                "/v1/notifications",
                json={"event": "done", "title": "Build finished"},
                headers=bearer(rig.admin_token),
            )
            # A second concurrent poll never gets the same tasks: empty, immediately.
            second = await client.get("/v1/notifier/tasks?wait=5", headers=notifier)
            assert second.json() == {"tasks": []}
            got = (await asyncio.wait_for(first, 3)).json()["tasks"]
            assert len(got) == 1
            assert rig.app_state().notifier_gate.busy == 0


async def test_c37_question_long_poll_wakes_on_answer(tmp_path):
    with notify_app(tmp_path) as rig:
        async with asgi_client(rig.app) as client:
            admin = bearer(rig.admin_token)
            reply = await client.post("/v1/questions", json=ask_body(), headers=admin)
            qid = reply.json()["question"]["id"]
            started = time.monotonic()
            poll = client.get(f"/v1/questions/{qid}?wait=30", headers=admin)
            waiter = asyncio.create_task(poll)
            await _until(lambda: rig.app_state().question_slots.busy == 1)
            answered = await client.post(
                "/v1/notifier/answers",
                json=answer_body(qid, "b"),
                headers=bearer(rig.notifier_token),
            )
            assert answered.json() == {"result": "recorded"}
            question = (await asyncio.wait_for(waiter, 4)).json()["question"]
            # Woken by the in-process event, not by the 5 s re-read.
            assert time.monotonic() - started < 4.0
            assert (question["state"], question["answer_key"]) == ("answered", "b")


async def test_c37_question_long_poll_times_out_open(tmp_path):
    with notify_app(tmp_path) as rig:
        async with asgi_client(rig.app) as client:
            admin = bearer(rig.admin_token)
            reply = await client.post("/v1/questions", json=ask_body(), headers=admin)
            qid = reply.json()["question"]["id"]
            started = time.monotonic()
            held = await client.get(f"/v1/questions/{qid}?wait=1", headers=admin)
            elapsed = time.monotonic() - started
            assert 0.9 <= elapsed < 3.0
            assert held.json()["question"]["state"] == "open"
            assert rig.app_state().question_slots.busy == 0


async def _until(condition: Any, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)
