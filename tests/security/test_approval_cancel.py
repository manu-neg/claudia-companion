"""Security tests for the host's cancel routes (unit A1): C46, C58 (`/stop`).

`POST /v1/claudia/approvals/{id}/cancel` and `POST
/v1/claudia/approvals/cancel-open` (token scope: `test_admin_claudia_routes`
matrix) only ever close a request: any open state -> CANCELLED by
compare-and-swap, a resolved one is reported `already_resolved` and never
changed, unknown or malformed ids answer `unknown` (no oracle), a cancelled
request can't be tapped, approved or consumed afterwards, cancel wins a
race against a concurrent tap, and cancel-open takes exactly `{}` or
`{"window_id"}`.
"""

from __future__ import annotations

import threading
from datetime import timedelta
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.application.approvals import (
    ApprovalCreateCommand,
    ApprovalService,
    CancelResult,
    TapDecision,
    TapResult,
)
from preview_dashboard.domain.approvals import (
    APPROVAL_TTL,
    ApprovalRequest,
    ApprovalState,
)
from preview_dashboard.domain.errors import ConflictError
from preview_dashboard.wire.claudia import parse_cancel_open_result, parse_cancel_result
from tests.claudia_admin_support import (
    OTHER_WINDOW,
    approval_body,
    claudia_app,
    code_body,
    tap_body,
)
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryApprovalStore,
    InMemoryOwnerMessageStore,
    SequentialIdGenerator,
)
from tests.notify_admin_support import bearer

pytestmark = pytest.mark.security

ZERO_ULID = "0" * 26


def _create(client: TestClient, rig: Any, **overrides: Any) -> str:
    response = client.post(
        "/v1/claudia/approvals", json=approval_body(**overrides), headers=bearer(rig.claudia_token)
    )
    assert response.status_code == 201, response.text
    aid: str = response.json()["approval"]["id"]
    return aid


def _cancel(client: TestClient, rig: Any, aid: str) -> tuple[str, Any]:
    response = client.post(f"/v1/claudia/approvals/{aid}/cancel", headers=bearer(rig.claudia_token))
    assert response.status_code == 200, response.text
    return parse_cancel_result(response.json())


def _tap(client: TestClient, rig: Any, aid: str, decision: str = "approve") -> str:
    response = client.post(
        "/v1/notifier/approvals", json=tap_body(aid, decision), headers=bearer(rig.notifier_token)
    )
    result: str = response.json()["result"]
    return result


def _code(client: TestClient, rig: Any, update_id: int = 1) -> str:
    response = client.post(
        "/v1/notifier/codes",
        json=code_body(rig.code(), update_id),
        headers=bearer(rig.notifier_token),
    )
    result: str = response.json()["result"]
    return result


def _state(rig: Any, aid: str) -> ApprovalState:
    state: ApprovalState = rig.claudia.approvals.get(aid).state
    return state


# --- cancel one ------------------------------------------------------------------------------


@pytest.mark.parametrize("stage", ["pending", "tapped", "approved"])
def test_c58_cancel_closes_any_open_request(tmp_path, stage):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        if stage in ("tapped", "approved"):
            assert _tap(client, rig, aid) == "tapped"
        if stage == "approved":
            assert _code(client, rig) == "accepted"
        result, approval = _cancel(client, rig, aid)
        assert result == "cancelled"
        assert approval is not None and approval.state is ApprovalState.CANCELLED
        # Closed for good: no tap, code or consume can reopen or use it.
        assert _tap(client, rig, aid) == "already_decided"
        consumed = client.post(
            f"/v1/claudia/approvals/{aid}/consume", headers=bearer(rig.claudia_token)
        )
        assert consumed.json()["result"] == "not_approved"
        assert _state(rig, aid) is ApprovalState.CANCELLED


def test_c58_cancel_is_a_cas_second_cancel_changes_nothing(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        first, stored = _cancel(client, rig, aid)
        again, unchanged = _cancel(client, rig, aid)
        assert (first, again) == ("cancelled", "already_resolved")
        assert unchanged == stored  # same version: nothing was written


@pytest.mark.parametrize("final", ["denied", "consumed", "expired"])
def test_c58_cancel_never_rewrites_a_resolved_request(tmp_path, final):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        if final == "denied":
            _tap(client, rig, aid, "deny")
        elif final == "consumed":
            _tap(client, rig, aid)
            _code(client, rig)
            client.post(f"/v1/claudia/approvals/{aid}/consume", headers=bearer(rig.claudia_token))
        else:
            rig.clock.advance(APPROVAL_TTL + timedelta(seconds=1))
        result, approval = _cancel(client, rig, aid)
        assert result == "already_resolved"
        assert approval is not None and str(approval.state) == final


@pytest.mark.parametrize("aid", [ZERO_ULID, "nope", "01J00000000000000000000ap1"])
def test_c58_cancel_unknown_ids_have_no_oracle(tmp_path, aid):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        assert _cancel(client, rig, aid) == ("unknown", None)


def test_c58_cancel_wins_or_reports_against_a_concurrent_tap(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        for _ in range(5):
            aid = _create(client, rig)
            cancelled, tapped = _race(rig, aid)
            # A tap never beats /stop: whatever the order, the request ends CANCELLED.
            assert cancelled is CancelResult.CANCELLED
            assert tapped in (TapResult.TAPPED, TapResult.ALREADY_DECIDED)
            assert _state(rig, aid) is ApprovalState.CANCELLED


def _race(rig: Any, aid: str) -> tuple[object, object]:
    results: dict[str, object] = {}
    barrier = threading.Barrier(2)

    def cancel() -> None:
        barrier.wait()
        results["cancel"] = rig.claudia.approvals.cancel(aid)[0]

    def tap() -> None:
        barrier.wait()
        results["tap"] = rig.claudia.approvals.tap(aid, TapDecision.APPROVE)

    threads = [threading.Thread(target=cancel), threading.Thread(target=tap)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results["cancel"], results["tap"]


class _RacingStore(InMemoryApprovalStore):
    """Loses the first `losses` saves to a concurrent tap (one CAS step each)."""

    def __init__(self, losses: int) -> None:
        super().__init__()
        self.losses = losses

    def save(self, request: ApprovalRequest, *, expected_updated_at: Any) -> None:
        if self.losses and request.state is ApprovalState.CANCELLED:
            self.losses -= 1
            stored = self.get(request.id)
            if stored.state is ApprovalState.PENDING:
                tapped = stored.tapped(stored.updated_at)
                super().save(tapped, expected_updated_at=stored.updated_at)
            raise ConflictError("lost the race")
        super().save(request, expected_updated_at=expected_updated_at)


def _service(store: InMemoryApprovalStore) -> ApprovalService:
    class _Prompts:
        def prompt(self, request: ApprovalRequest) -> None:
            del request

    return ApprovalService(
        store=store,
        messages=InMemoryOwnerMessageStore(),
        clock=FixedClock(),
        ids=SequentialIdGenerator(),
        scanner=FakeContentScanner(),
        prompts=_Prompts(),
    )


def _new(service: ApprovalService) -> str:
    body = approval_body()
    return service.create(
        ApprovalCreateCommand(
            window_id=body["window_id"],
            kind=body["kind"],
            action_text=body["action_text"],
            action_kind=body["action_kind"],
            action_target=body["action_target"],
        )
    ).id


def test_c58_cancel_retries_after_losing_a_cas():
    store = _RacingStore(losses=1)
    service = _service(store)
    aid = _new(service)
    result, stored = service.cancel(aid)
    assert result is CancelResult.CANCELLED
    assert stored is not None and stored.tapped_at is not None  # the tap happened, then /stop


def test_c58_cancel_reports_busy_when_it_keeps_losing():
    store = _RacingStore(losses=10)
    service = _service(store)
    aid = _new(service)
    result, stored = service.cancel(aid)
    assert result is CancelResult.BUSY  # still open: the host retries, nothing claimed
    assert stored is not None and stored.state.is_open


# --- cancel-open -----------------------------------------------------------------------------


def test_c58_cancel_open_closes_every_open_request(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        first = _create(client, rig)
        second = _create(client, rig, window_id=OTHER_WINDOW)
        _tap(client, rig, second)
        response = client.post(
            "/v1/claudia/approvals/cancel-open", json={}, headers=bearer(rig.claudia_token)
        )
        assert response.status_code == 200, response.text
        assert sorted(parse_cancel_open_result(response.json())) == sorted([first, second])
        assert {_state(rig, a) for a in (first, second)} == {ApprovalState.CANCELLED}
        again = client.post(
            "/v1/claudia/approvals/cancel-open", json={}, headers=bearer(rig.claudia_token)
        )
        assert again.json() == {"cancelled": []}


def test_c58_cancel_open_can_be_scoped_to_one_window(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        first = _create(client, rig)
        other = _create(client, rig, window_id=OTHER_WINDOW)
        response = client.post(
            "/v1/claudia/approvals/cancel-open",
            json={"window_id": OTHER_WINDOW},
            headers=bearer(rig.claudia_token),
        )
        assert response.json() == {"cancelled": [other]}
        assert _state(rig, first) is ApprovalState.PENDING


@pytest.mark.parametrize(
    "body",
    [
        {"window_id": "not-a-uuid"},
        {"window_id": "123E4567-E89B-42D3-A456-426614174000"},  # uppercase: not canonical
        {"window_id": None, "all": True},
        {"state": "approved"},
        [],
    ],
)
def test_c58_cancel_open_body_is_strict(tmp_path, body):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        response = client.post(
            "/v1/claudia/approvals/cancel-open", json=body, headers=bearer(rig.claudia_token)
        )
        assert response.status_code == 400
        assert _state(rig, aid) is ApprovalState.PENDING


def test_c58_cancel_routes_refuse_the_other_tokens(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _create(client, rig)
        for token in (rig.admin_token, rig.notifier_token):
            for path, body in (
                (f"/v1/claudia/approvals/{aid}/cancel", None),
                ("/v1/claudia/approvals/cancel-open", {}),
            ):
                assert client.post(path, json=body, headers=bearer(token)).status_code == 403
        assert _state(rig, aid) is ApprovalState.PENDING
