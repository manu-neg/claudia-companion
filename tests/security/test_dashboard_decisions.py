"""Security tests: Approve/Deny of Claudia's requests from the dashboard (F-CL6, C46/C47).

The viewer never holds the TOTP secret and never decides: it forwards
`{request_id, decision, code}` over the admin socket with its own scoped
token, and the admin re-validates everything. Proven here: wrong and
replayed codes refused and counted in the one shared step-up budget,
expired / decided / unknown requests refused, owner-only + CSRF on the
viewer route, the viewer token confined to `/v1/viewer/*`, no forged
decision through extra fields or a viewer-writable store, first decision
wins across Telegram and dashboard, the code never logged, and an approval
from the dashboard is consumable by the host exactly like a Telegram one.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field, fields
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError as PydanticValidationError
from pydantic_settings import SettingsError
from starlette.testclient import TestClient

from preview_dashboard.adapters.kb_reader import FileApprovalsSnapshot
from preview_dashboard.adapters.viewer_decision_client import AdminDecisionClient
from preview_dashboard.application.approvals import TapDecision
from preview_dashboard.application.dashboard_decisions import (
    DASHBOARD_DECISION_BUDGET,
    ForwardedDecisions,
)
from preview_dashboard.application.pending_approvals import PendingApprovalsService
from preview_dashboard.bootstrap import ViewerCore
from preview_dashboard.config import Settings
from preview_dashboard.domain.approval_decisions import (
    Decision,
    DecisionCommand,
    DecisionResult,
    parse_decision_command,
)
from preview_dashboard.domain.approvals import APPROVAL_TTL, ApprovalId, ApprovalState
from preview_dashboard.domain.errors import StorageUnavailableError, ValidationError
from preview_dashboard.interfaces.admin.auth import PeerCredentials
from preview_dashboard.interfaces.viewer.app_factory import build_dashboard_app
from preview_dashboard.interfaces.viewer.knowledge import Knowledge
from tests.claudia_admin_support import (
    ClaudiaApp,
    approval_body,
    claudia_app,
    code_body,
    tap_body,
)
from tests.fakes import FixedClock
from tests.notify_admin_support import asgi_client, bearer, notify_settings
from tests.viewer_support import (
    DASH_ORIGIN,
    PREVIEW_ORIGIN,
    StubServices,
    csrf_headers,
    dashboard_client,
    make_settings,
    owner_headers,
)

pytestmark = pytest.mark.security

ZERO_ULID = "00000000000000000000000000"
# "123456" in full-width digits (U+FF11..): not ASCII, so never a code.
FULLWIDTH_CODE = "".join(chr(0xFF10 + digit) for digit in (1, 2, 3, 4, 5, 6))
WINDOWS = [f"{i}23e4567-e89b-42d3-a456-426614174000" for i in range(1, 9)]


# --- helpers ----------------------------------------------------------------------------


def _create(client: TestClient, rig: ClaudiaApp, window: str = WINDOWS[0]) -> str:
    response = client.post(
        "/v1/claudia/approvals",
        json=approval_body(window_id=window),
        headers=bearer(rig.claudia_token),
    )
    assert response.status_code == 201, response.text
    aid: str = response.json()["approval"]["id"]
    return aid


def _decide(client: TestClient, rig: ClaudiaApp, aid: str, body: dict[str, Any]) -> Any:
    return client.post(
        f"/v1/viewer/approvals/{aid}/decision", json=body, headers=bearer(rig.viewer_token)
    )


def _approve(client: TestClient, rig: ClaudiaApp, aid: str, code: str) -> str:
    response = _decide(client, rig, aid, {"decision": "approve", "code": code})
    assert response.status_code == 200, response.text
    result: str = response.json()["result"]
    return result


def _deny(client: TestClient, rig: ClaudiaApp, aid: str) -> str:
    response = _decide(client, rig, aid, {"decision": "deny"})
    assert response.status_code == 200, response.text
    result: str = response.json()["result"]
    return result


def _state(rig: ClaudiaApp, aid: str) -> ApprovalState:
    return rig.claudia.approvals.get(aid).state


def _wrong(rig: ClaudiaApp) -> str:
    """A code that is not valid now (a far step; never equal to a code in -1..+1)."""
    valid = {rig.code(offset) for offset in (-1, 0, 1)}
    for offset in range(10, 100):
        candidate = rig.code(offset)
        if candidate not in valid:
            return candidate
    raise AssertionError("no wrong code found")


def _telegram_tap(client: TestClient, rig: ClaudiaApp, aid: str, decision: str) -> str:
    response = client.post(
        "/v1/notifier/approvals", json=tap_body(aid, decision), headers=bearer(rig.notifier_token)
    )
    result: str = response.json()["result"]
    return result


def _telegram_code(client: TestClient, rig: ClaudiaApp, code: str, update_id: int) -> str:
    response = client.post(
        "/v1/notifier/codes", json=code_body(code, update_id), headers=bearer(rig.notifier_token)
    )
    result: str = response.json()["result"]
    return result


# --- admin: the decision itself ------------------------------------------------------------


@pytest.mark.parametrize("tapped_first", [False, True])
def test_fcl6_right_code_approves_and_the_host_consumes_it(tmp_path, tapped_first):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        if tapped_first:
            assert _telegram_tap(client, rig, aid, "approve") == "tapped"
        assert _approve(client, rig, aid, rig.code()) == "approved"
        assert _state(rig, aid) is ApprovalState.APPROVED
        # Claudia resumes exactly as after a Telegram approval: the host consumes it.
        consumed = client.post(
            f"/v1/claudia/approvals/{aid}/consume", headers=bearer(rig.claudia_token)
        )
        assert consumed.json()["result"] == "consumed"


def test_fcl6_deny_needs_no_code(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        assert _deny(client, rig, aid) == "denied"
        assert _state(rig, aid) is ApprovalState.DENIED


def test_fcl6_wrong_code_is_refused_and_counted_towards_the_lockout(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        results = [_approve(client, rig, aid, _wrong(rig)) for _ in range(5)]
        assert results == ["wrong_code"] * 4 + ["locked"]
        # Locked out: even the right code is refused now, and nothing was approved.
        assert _approve(client, rig, aid, rig.code()) == "locked"
        assert _state(rig, aid) is ApprovalState.PENDING


def test_fcl6_one_attempt_budget_shared_with_telegram(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        for _ in range(3):
            assert _approve(client, rig, aid, _wrong(rig)) == "wrong_code"
        assert _telegram_tap(client, rig, aid, "approve") == "tapped"
        assert _telegram_code(client, rig, _wrong(rig), update_id=1) == "refused"
        assert _telegram_code(client, rig, _wrong(rig), update_id=2) == "locked"
        assert _approve(client, rig, aid, rig.code()) == "locked"
        assert _telegram_code(client, rig, rig.code(), update_id=3) == "locked"
        assert _state(rig, aid) is ApprovalState.TAPPED


def test_fcl6_replayed_code_is_refused_and_counted(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        first = _create(client, rig, WINDOWS[0])
        second = _create(client, rig, WINDOWS[1])
        code = rig.code()
        assert _approve(client, rig, first, code) == "approved"
        assert _approve(client, rig, second, code) == "wrong_code"  # same step: a replay
        assert _state(rig, second) is ApprovalState.PENDING
        # A Telegram-used step can't be replayed on the dashboard either.
        rig.clock.advance(timedelta(seconds=30))
        third_code = rig.code()
        assert _telegram_tap(client, rig, second, "approve") == "tapped"
        assert _telegram_code(client, rig, third_code, update_id=9) == "accepted"
        other = _create(client, rig, WINDOWS[2])
        assert _approve(client, rig, other, third_code) == "wrong_code"


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_fcl6_expired_request_is_refused_and_the_code_not_checked(tmp_path, decision):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        rig.clock.advance(APPROVAL_TTL)
        body = {"decision": decision, **({"code": _wrong(rig)} if decision == "approve" else {})}
        assert _decide(client, rig, aid, body).json()["result"] == "expired"
        assert _state(rig, aid) is ApprovalState.EXPIRED
        # Not counted: 5 more wrong codes elsewhere are needed for the lockout.
        other = _create(client, rig, WINDOWS[1])
        assert [_approve(client, rig, other, _wrong(rig)) for _ in range(4)] == ["wrong_code"] * 4


@pytest.mark.parametrize("decided", ["denied", "approved"])
@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_fcl6_decided_request_is_refused(tmp_path, decided, decision):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        if decided == "denied":
            assert _deny(client, rig, aid) == "denied"
        else:
            assert _approve(client, rig, aid, rig.code()) == "approved"
            rig.clock.advance(timedelta(seconds=60))
        body = {"decision": decision, **({"code": rig.code()} if decision == "approve" else {})}
        assert _decide(client, rig, aid, body).json()["result"] == "already_decided"
        assert _state(rig, aid) is ApprovalState(decided)


def test_fcl6_unknown_ids_have_no_oracle(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        assert _deny(client, rig, ZERO_ULID) == "unknown"
        assert _approve(client, rig, ZERO_ULID, _wrong(rig)) == "unknown"
        assert _decide(client, rig, "not-a-ulid", {"decision": "deny"}).status_code == 400


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "approve"},  # no code
        {"decision": "approve", "code": "12345"},
        {"decision": "approve", "code": FULLWIDTH_CODE},
        {"decision": "approve", "code": 123456},
        {"decision": "deny", "code": "123456"},  # a code on deny is a client bug
        {"decision": "approve", "code": "123456", "state": "approved"},  # forged field
        {"decision": "deny", "source": "telegram"},
        {"decision": "grant"},
        {},
    ],
)
def test_fcl6_admin_refuses_malformed_or_forged_bodies(tmp_path, body):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        response = _decide(client, rig, aid, body)
        assert response.status_code == 400
        assert "123456" not in response.text
        assert _state(rig, aid) is ApprovalState.PENDING


def test_fcl6_admin_attempt_budget(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        results = [_deny(client, rig, ZERO_ULID) for _ in range(DASHBOARD_DECISION_BUDGET + 1)]
        assert results[-1] == "rate_limited"
        assert set(results[:-1]) == {"unknown"}


# --- first decision wins across Telegram and dashboard ------------------------------------


def test_fcl6_telegram_deny_first_wins(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        assert _telegram_tap(client, rig, aid, "deny") == "denied"
        assert _approve(client, rig, aid, rig.code()) == "already_decided"
        assert _state(rig, aid) is ApprovalState.DENIED


def test_fcl6_dashboard_first_wins_over_a_later_telegram_tap(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        assert _approve(client, rig, aid, rig.code()) == "approved"
        assert _telegram_tap(client, rig, aid, "deny") == "already_decided"
        assert _state(rig, aid) is ApprovalState.APPROVED


def _race_once(rig: ClaudiaApp, aid: str, code: str) -> dict[str, object]:
    """Dashboard Approve and Telegram Deny of `aid` released at the same moment."""
    services = rig.claudia
    barrier = threading.Barrier(2)
    results: dict[str, object] = {}

    def approve() -> None:
        barrier.wait()
        command = DecisionCommand(ApprovalId(aid), Decision.APPROVE, code)
        results["dashboard"] = services.decisions.decide(command)

    def deny() -> None:
        barrier.wait()
        results["telegram"] = str(services.approvals.tap(aid, TapDecision.DENY))

    threads = [threading.Thread(target=approve), threading.Thread(target=deny)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def test_fcl6_dashboard_approve_races_telegram_deny(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig:
        for index, window in enumerate(WINDOWS[:4]):
            with TestClient(rig.app) as client:
                aid = _create(client, rig, window)
            rig.clock.advance(timedelta(seconds=30 * (index + 1)))
            results = _race_once(rig, aid, rig.code())
            won_dashboard = results["dashboard"] is DecisionResult.APPROVED
            won_telegram = results["telegram"] == "denied"
            assert won_dashboard != won_telegram  # exactly one decision counts
            expected = ApprovalState.APPROVED if won_dashboard else ApprovalState.DENIED
            assert _state(rig, aid) is expected


# --- admin: token scope and peer family (C33/C45 matrix extended) ---------------------------


@pytest.mark.parametrize("who", ["admin", "notifier", "claudia", "none", "wrong"])
def test_fcl6_only_the_viewer_token_reaches_the_decision_route(tmp_path, who):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        tokens = {
            "admin": rig.admin_token,
            "notifier": rig.notifier_token,
            "claudia": rig.claudia_token,
            "wrong": "x" * 43,
        }
        headers = bearer(tokens[who]) if who in tokens else {}
        response = client.post(
            f"/v1/viewer/approvals/{aid}/decision",
            json={"decision": "deny"},
            headers=headers,
        )
        assert response.status_code == (401 if who in ("none", "wrong") else 403)
        assert _state(rig, aid) is ApprovalState.PENDING


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/v1/health"),
        ("POST", "/v1/notifier/approvals"),
        ("POST", "/v1/notifier/codes"),
        ("POST", "/v1/claudia/approvals"),
        ("GET", "/v1/claudia/approvals/" + ZERO_ULID),
    ],
)
def test_fcl6_viewer_token_is_refused_everywhere_else(tmp_path, method, path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        response = client.request(method, path, json={}, headers=bearer(rig.viewer_token))
        assert response.status_code == 403


def test_fcl6_without_a_viewer_token_nothing_is_accepted(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        assert _decide(client, rig, aid, {"decision": "deny"}).status_code == 401


@pytest.mark.parametrize(("peer_uid", "allowed"), [(4000, True), (1000, False), (None, False)])
async def test_fcl6_viewer_peer_uid_family(tmp_path, peer_uid, allowed):
    with claudia_app(
        tmp_path,
        with_viewer_token=True,
        allowed_peer_uids=[1000],
        claudia_peer_uids=[3000],
        viewer_peer_uids=[4000],
    ) as rig:
        peer = None if peer_uid is None else PeerCredentials(pid=1, uid=peer_uid, gid=1)
        async with asgi_client(rig.app, peer=peer) as client:
            response = await client.post(
                f"/v1/viewer/approvals/{ZERO_ULID}/decision",
                json={"decision": "deny"},
                headers=bearer(rig.viewer_token),
            )
        assert (response.status_code == 200) is allowed
        if not allowed:
            assert response.status_code == 403


async def test_fcl6_viewer_uid_gets_403_when_no_viewer_uid_is_admitted(tmp_path):
    """What `serve-admin` builds with decisions off: an empty viewer family, so the
    viewer's uid is refused on /v1/viewer/* even though the other families are set."""
    with claudia_app(
        tmp_path,
        with_viewer_token=True,
        allowed_peer_uids=[1000],
        claudia_peer_uids=[3000],
        viewer_peer_uids=[],
    ) as rig:
        async with asgi_client(rig.app, peer=PeerCredentials(pid=1, uid=4000, gid=1)) as client:
            response = await client.post(
                f"/v1/viewer/approvals/{ZERO_ULID}/decision",
                json={"decision": "deny"},
                headers=bearer(rig.viewer_token),
            )
        assert response.status_code == 403


def test_fcl6_viewer_token_must_differ_from_the_others(tmp_path):
    with claudia_app(tmp_path) as rig:
        from preview_dashboard.interfaces.admin.app import build_admin_app

        with pytest.raises(ValueError, match="viewer token"):
            build_admin_app(
                rig.core,
                token=rig.admin_token.encode(),
                notifier_token=rig.notifier_token.encode(),
                claudia_token=rig.claudia_token.encode(),
                viewer_token=rig.claudia_token.encode(),
            )


# --- the code never reaches a log -----------------------------------------------------------


def test_fcl6_code_is_never_logged(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        wrong = _wrong(rig)
        right = rig.code()
        assert _approve(client, rig, aid, wrong) == "wrong_code"
        assert _approve(client, rig, aid, right) == "approved"
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert wrong not in text and right not in text
    assert "decided on the dashboard" in text  # the decision's source is recorded


def test_fcl6_command_repr_hides_the_code():
    command = parse_decision_command(ZERO_ULID, "approve", "246810")
    assert "246810" not in repr(command)


# --- viewer: route, CSRF, owner, rate limit, fail closed ------------------------------------


@dataclass
class RecordingDecider:
    """`ApprovalDecider` fake: records commands, answers a fixed verdict (or fails)."""

    verdict: DecisionResult = DecisionResult.APPROVED
    fail: bool = False
    calls: list[DecisionCommand] = field(default_factory=list)

    def decide(self, command: DecisionCommand) -> DecisionResult:
        if self.fail:
            raise StorageUnavailableError("admin down")
        self.calls.append(command)
        return self.verdict


def _snapshot(tmp_path: Path, clock: FixedClock) -> Path:
    folder = tmp_path / "view"
    folder.mkdir(mode=0o750, exist_ok=True)
    path = folder / "approvals.json"
    entry = {
        "id": ZERO_ULID[:-1] + "1",
        "action_text": "Merge PR 42 into main",
        "kind": "pr_merge",
        "target": "example-org/example-repo#42",
        "state": "pending",
        "expires_at": (clock.now() + timedelta(hours=1)).isoformat(),
    }
    path.write_text(json.dumps({"version": 1, "approvals": [entry]}), "utf-8")
    path.chmod(0o640)
    return path


def _viewer(tmp_path: Path, decider: Any | None, **budget: Any) -> TestClient:
    clock = FixedClock()
    source = FileApprovalsSnapshot(_snapshot(tmp_path, clock))
    decisions = None if decider is None else ForwardedDecisions(decider, **budget)
    knowledge = Knowledge(
        graph=None, approvals=PendingApprovalsService(source, clock), decisions=decisions
    )
    app = build_dashboard_app(make_settings(), StubServices(), knowledge=knowledge)
    return dashboard_client(app)


AID = ZERO_ULID[:-1] + "1"
URL = f"/api/claudia/approvals/{AID}/decision"


def _post(client: TestClient, body: object, headers: dict[str, str] | None = None) -> Any:
    return client.post(URL, content=json.dumps(body), headers=headers or csrf_headers())


def test_fcl6_viewer_forwards_only_the_validated_decision(tmp_path):
    decider = RecordingDecider()
    client = _viewer(tmp_path, decider)
    listed = client.get("/api/claudia/approvals", headers=owner_headers()).json()
    assert listed["decisions"] is True
    response = _post(client, {"decision": "approve", "code": "135790"})
    assert response.status_code == 200
    assert response.json() == {"result": "approved"}
    assert response.headers["cache-control"] == "no-store"
    assert decider.calls == [DecisionCommand(ApprovalId(AID), Decision.APPROVE, "135790")]


def test_fcl6_viewer_without_decisions_is_read_only(tmp_path):
    client = _viewer(tmp_path, None)
    assert (
        client.get("/api/claudia/approvals", headers=owner_headers()).json()["decisions"] is False
    )
    assert _post(client, {"decision": "deny"}).status_code == 404


@pytest.mark.parametrize("missing", ["Content-Type", "Origin", "Sec-Fetch-Site", "X-PDash-CSRF"])
def test_fcl6_viewer_post_without_a_csrf_header_is_refused(tmp_path, missing):
    decider = RecordingDecider()
    client = _viewer(tmp_path, decider)
    headers = {k: v for k, v in csrf_headers().items() if k != missing}
    assert _post(client, {"decision": "deny"}, headers).status_code == 403
    assert decider.calls == []


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("Origin", "https://evil.example"),
        ("Origin", PREVIEW_ORIGIN),
        ("Origin", "null"),
        ("Sec-Fetch-Site", "cross-site"),
        ("Tailscale-User-Login", "someone-else@example.com"),
        ("Content-Type", "text/plain"),
    ],
)
def test_fcl6_viewer_cross_site_or_non_owner_post_is_refused(tmp_path, name, value):
    decider = RecordingDecider()
    client = _viewer(tmp_path, decider)
    headers = csrf_headers({name: value})
    assert _post(client, {"decision": "approve", "code": "135790"}, headers).status_code == 403
    assert decider.calls == []


def test_fcl6_viewer_post_without_owner_identity_is_refused(tmp_path):
    decider = RecordingDecider()
    client = _viewer(tmp_path, decider)
    headers = {k: v for k, v in csrf_headers().items() if k != "Tailscale-User-Login"}
    assert _post(client, {"decision": "deny"}, headers).status_code == 403
    assert decider.calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"decision": "approve", "code": "12a456"},
        {"decision": "approve"},
        {"decision": "deny", "code": "135790"},
        {"decision": "approve", "code": "135790", "state": "approved"},
        ["approve"],
        "deny",
    ],
)
def test_fcl6_viewer_refuses_malformed_bodies_without_echo(tmp_path, body):
    decider = RecordingDecider()
    client = _viewer(tmp_path, decider)
    response = _post(client, body)
    assert response.status_code == 400
    assert "135790" not in response.text
    assert decider.calls == []


def test_fcl6_viewer_rate_limits_clicks(tmp_path):
    decider = RecordingDecider(verdict=DecisionResult.WRONG_CODE)
    client = _viewer(tmp_path, decider, limit=3)
    statuses = [_post(client, {"decision": "deny"}).status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 429]
    assert len(decider.calls) == 3


def test_fcl6_viewer_fails_closed_when_the_admin_is_unreachable(tmp_path):
    client = _viewer(tmp_path, RecordingDecider(fail=True))
    response = _post(client, {"decision": "approve", "code": "135790"})
    assert response.status_code == 503
    assert "135790" not in response.text


def test_fcl6_viewer_never_logs_the_code(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    client = _viewer(tmp_path, RecordingDecider())
    _post(client, {"decision": "approve", "code": "135790"})
    _post(client, {"decision": "approve", "code": "13579x"})
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "135790" not in text and "13579x" not in text


def test_fcl6_viewer_core_has_no_approval_capability():
    names = {f.name for f in fields(ViewerCore)}
    assert not names & {"approvals", "stepup", "decisions", "claudia", "inbox"}


# --- end to end: viewer app -> admin client -> admin app ------------------------------------


def _bridge(admin: TestClient, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        answer = admin.request(
            request.method, request.url.path, content=request.content, headers=request.headers
        )
        return httpx.Response(answer.status_code, content=answer.content)

    return httpx.MockTransport(handler)


def test_fcl6_end_to_end_dashboard_approval(tmp_path):
    with claudia_app(tmp_path, with_viewer_token=True) as rig, TestClient(rig.app) as admin:
        aid = _create(admin, rig)
        seen: list[httpx.Request] = []
        client = AdminDecisionClient(
            tmp_path / "admin.sock",
            rig.viewer_token.encode(),
            socket_check=None,
            transport=_bridge(admin, seen),
        )
        assert rig.viewer_token not in repr(client)
        decisions = ForwardedDecisions(client)
        command = parse_decision_command(aid, "approve", rig.code())
        assert decisions.decide(command) is DecisionResult.APPROVED
        assert _state(rig, aid) is ApprovalState.APPROVED
        # The code went in the body only; the URL carries the request id alone.
        assert seen[0].url.path == f"/v1/viewer/approvals/{aid}/decision"
        assert rig.code() not in str(seen[0].url)
        client.close()


def test_fcl6_client_checks_the_socket_before_every_call(tmp_path):
    seen: list[httpx.Request] = []

    def refuse(path: Path) -> None:
        raise RuntimeError("untrusted socket")

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    client = AdminDecisionClient(
        tmp_path / "admin.sock",
        b"t" * 43,
        socket_check=refuse,
        transport=httpx.MockTransport(record),
    )
    with pytest.raises(StorageUnavailableError):
        client.decide(parse_decision_command(ZERO_ULID, "deny", None))
    assert seen == []  # neither the token nor a code was sent


@pytest.mark.parametrize(
    ("status", "content"),
    [
        (200, b'{"result": "granted"}'),
        (200, b'{"result": "approved", "extra": 1}'),
        (200, b"not json"),
        (500, b'{"result": "approved"}'),
        (200, b'{"result": "' + b"a" * 5000 + b'"}'),
    ],
)
def test_fcl6_client_fails_closed_on_odd_answers(tmp_path, status, content):
    client = AdminDecisionClient(
        tmp_path / "admin.sock",
        b"t" * 43,
        socket_check=None,
        transport=httpx.MockTransport(lambda r: httpx.Response(status, content=content)),
    )
    with pytest.raises(StorageUnavailableError):
        client.decide(parse_decision_command(ZERO_ULID, "deny", None))


# --- config ---------------------------------------------------------------------------------


def test_fcl6_decisions_default_on_but_inert_without_claudia(tmp_path):
    # The owner asked for it: on by default, yet nothing acts while Claudia is off.
    settings = notify_settings(tmp_path)
    assert settings.claudia_dashboard_decisions is True
    assert settings.dashboard_decisions_active is False
    assert notify_settings(tmp_path, claudia_enabled=True).dashboard_decisions_active is True


def test_fcl6_explicit_false_turns_decisions_off(tmp_path):
    settings = notify_settings(tmp_path, claudia_enabled=True, claudia_dashboard_decisions=False)
    assert settings.dashboard_decisions_active is False


@pytest.mark.parametrize("value", ["maybe", 2, "", None])
def test_fcl6_invalid_switch_value_is_refused(tmp_path, value):
    # Fail closed: a typo never silently picks on or off.
    with pytest.raises(PydanticValidationError, match="claudia_dashboard_decisions"):
        notify_settings(tmp_path, claudia_enabled=True, claudia_dashboard_decisions=value)


def _decisions_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    conf_dir = tmp_path / "conf"
    conf_dir.mkdir(mode=0o700)
    config = conf_dir / "config.toml"
    config.write_text(body)
    config.chmod(0o600)
    monkeypatch.setenv("PDASH_CONFIG", str(config))


def test_fcl6_viewer_decider_off_without_claudia(tmp_path):
    from preview_dashboard.interfaces import cli
    from preview_dashboard.interfaces.token_file import TokenKind

    settings = notify_settings(
        tmp_path, claudia_approvals_snapshot=tmp_path / "pending-approvals.json"
    )
    # No viewer token file exists: a decider that tried to load it would raise.
    policy = cli.token_groups([], own=TokenKind.VIEWER)
    assert cli.viewer_decider(settings, policy) is None


def test_fcl6_viewer_token_file_must_be_its_own(tmp_path):
    with pytest.raises(PydanticValidationError, match="viewer_token_file"):
        notify_settings(
            tmp_path,
            claudia_enabled=True,
            claudia_dashboard_decisions=True,
            viewer_token_file=tmp_path / "secrets" / "notifier.token",
        )


@pytest.mark.parametrize("value", ["true", "1"])
def test_fcl6_env_cannot_turn_decisions_on(tmp_path, monkeypatch, value):
    # The root-owned TOML switched it off; env may not switch it back on.
    _decisions_toml(tmp_path, monkeypatch, "claudia_dashboard_decisions = false\n")
    monkeypatch.setenv("PDASH_CLAUDIA_DASHBOARD_DECISIONS", value)
    with pytest.raises(SettingsError, match="only turn dashboard decisions off"):
        Settings()


def test_fcl6_env_can_turn_decisions_off(monkeypatch):
    monkeypatch.setenv("PDASH_CLAUDIA_DASHBOARD_DECISIONS", "false")
    assert Settings().claudia_dashboard_decisions is False


def test_fcl6_parse_rejects_bad_ids_and_decisions():
    for args in [("x", "deny", None), (ZERO_ULID, "APPROVE", "123456"), (ZERO_ULID, None, None)]:
        with pytest.raises(ValidationError):
            parse_decision_command(*args)


def test_fcl6_dash_origin_is_the_only_allowed_origin():
    # Guard for the matrix above: the legitimate headers really are same-origin.
    assert csrf_headers()["Origin"] == DASH_ORIGIN
