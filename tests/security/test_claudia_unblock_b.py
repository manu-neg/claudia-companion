"""F-CL3b security tests (S-CL3 review fixes; ADR 0041, docs/security.md C46, C58).

- `request_approval` is tied to the run in progress by a per-run nonce the
  host puts in the run's env (a wrong or missing nonce is refused);
- stranded requests (lost parked requests after a restart, an approved but
  unparked one at `/stop`, windows closed meanwhile) are cancelled in every
  window at host start and on `/stop`, so none holds the open cap for 24 h.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.claude_cli import run_env
from preview_dashboard.adapters.claudia_admin_client import ClaudiaAdminClient
from preview_dashboard.application.claudia import approval_flow as af
from preview_dashboard.application.claudia.windows import HostCommand
from preview_dashboard.domain.approvals import ApprovalState
from preview_dashboard.interfaces.claudia.approval_tool import (
    NO_RUN_TEXT,
    ApprovalToolError,
    HostApprovals,
)
from preview_dashboard.interfaces.claudia.main import HostLoop
from preview_dashboard.ports.claudia_host import RUN_NONCE_ENV, RunOutcome, RunRequest
from tests.claudia_admin_support import (
    OTHER_WINDOW,
    approval_body,
    claudia_app,
    code_body,
    tap_body,
)
from tests.claudia_host_support import WINDOW_A, FakeRunner, HostRig, host_rig, message
from tests.notify_admin_support import bearer

pytestmark = pytest.mark.security

PR = "example-org/example-repo#31"
WINDOW_N = "323e4567-e89b-42d3-a456-426614174000"


def _asking_rig(nonces: list[object], **overrides: object) -> tuple[HostRig, list[af.ToolAnswer]]:
    """A rig whose first run calls `request_approval` once per entry of `nonces`."""
    answers: list[af.ToolAnswer] = []
    ref: list[HostRig] = []

    def on_run(request: RunRequest) -> None:
        if request.recap:
            return
        for nonce in nonces:
            # `None` stands for "the run's own nonce", as the MCP server reads it from its env.
            presented = request.run_nonce if nonce is None else nonce
            answers.append(ref[0].flow.request_from_tool("pr_merge", PR, "go", presented))

    runner = FakeRunner(on_run=on_run, outcome=RunOutcome(exit_code=0, result_text="ok"))
    rig = host_rig(runner=runner, **overrides)  # type: ignore[arg-type]
    ref.append(rig)
    return rig, answers


# --- C46: request_approval is tied to the run (per-run nonce) ---------------------------------


def test_fcl3b_c46_wrong_or_missing_nonce_is_refused_during_an_active_run() -> None:
    rig, answers = _asking_rig(["", "not-the-nonce", 7, None, None])
    rig.host.handle_message(message("merge it"), generation=0)
    refused = [a.text for a in answers[:3]]
    assert refused == [af.TOOL_NO_RUN_TEXT] * 3
    assert answers[3].pending  # the run's own nonce works ...
    assert answers[4].text == af.TOOL_ONE_PER_TURN_TEXT  # ... under the usual rules
    assert len(rig.approvals.created) == 1


def test_fcl3b_c46_a_run_without_a_nonce_can_not_ask() -> None:
    rig = host_rig()
    rig.flow.begin_run(
        WINDOW_A, af.RunContext(window_id=WINDOW_A, message_id=None, actionable=True, generation=0)
    )
    assert rig.flow.request_from_tool("pr_merge", PR, "go", "").text == af.TOOL_NO_RUN_TEXT
    assert rig.flow.request_from_tool("pr_merge", PR, "go", None).text == af.TOOL_NO_RUN_TEXT


def test_fcl3b_c46_every_run_gets_its_own_secret_nonce_and_recap_none() -> None:
    rig, _ = _asking_rig([])
    rig.host.handle_message(message("one", 1), generation=0)
    rig.host.handle_message(message("two", 2), generation=0)
    rig.host.command(HostCommand.NEW, message("/new", 3).id)
    first, second, recap = rig.runner.requests
    assert first.run_nonce and second.run_nonce and first.run_nonce != second.run_nonce
    assert recap.recap and recap.run_nonce == ""
    # A secret: never in the reprs that end up in logs.
    assert first.run_nonce not in repr(first)
    context = af.RunContext(
        window_id=WINDOW_A, message_id=None, actionable=True, generation=0, nonce="s3cret"
    )
    assert "s3cret" not in repr(context)


def test_fcl3b_c46_nonce_ends_with_the_run() -> None:
    rig, answers = _asking_rig([None])
    rig.host.handle_message(message("merge it"), generation=0)
    assert answers[0].pending
    nonce = rig.runner.requests[0].run_nonce
    assert rig.flow.request_from_tool("pr_merge", PR, "go", nonce).text == af.TOOL_NO_RUN_TEXT


def test_fcl3b_c46_runner_puts_the_nonce_in_the_child_env_only_when_given() -> None:
    base = {"HOME": "/root", "PATH": "/usr/bin"}
    nonce = "0123456789abcdef0123456789abcdef"
    assert run_env(base, nonce) == {**base, RUN_NONCE_ENV: nonce}
    assert run_env(base, "") == base
    assert RUN_NONCE_ENV not in base  # the shared base env is never changed
    for bad in ("short", "ZZ" * 16, nonce + "\n", "a" * 65):
        with pytest.raises(ValueError, match="run nonce"):
            run_env(base, bad)


def test_fcl3b_c46_tool_without_a_run_nonce_in_its_env_never_calls_the_host(
    tmp_path: Path,
) -> None:
    client = HostApprovals(tmp_path / "missing.sock", environ={})
    with pytest.raises(ApprovalToolError) as refused:
        client.request("pr_merge", PR, "go")
    assert refused.value.text == NO_RUN_TEXT


# --- C46 / C58: stranded requests are cancelled in every window --------------------------------


def test_fcl3b_c58_host_start_cancels_every_open_request_and_logs_the_count() -> None:
    rig = host_rig()
    rig.admin.open_ids = ["a", "b", "c"]
    assert rig.host.cancel_stranded_approvals() == 3
    assert rig.admin.cancel_all_calls == 1
    assert rig.admin.cancelled_windows == []  # the all-windows form, not one window


def test_fcl3b_c58_start_cancel_failure_is_alerted_once_and_never_raises() -> None:
    rig = host_rig()
    rig.admin.cancel_fails = True
    assert rig.host.cancel_stranded_approvals() == 0
    assert len(rig.alerts.titles) == 1


def test_fcl3b_c58_the_host_loop_cancels_stranded_requests_before_it_starts() -> None:
    rig = host_rig()
    loop = HostLoop(rig.admin, rig.host, rig.screen, poll_wait=0, tick_seconds=0.01)
    loop.stop()  # threads end at once; run() still does its start and shutdown steps
    assert loop.run() is True
    assert rig.admin.cancel_all_calls == 2  # start + the shutdown /stop


def test_fcl3b_c58_stop_cancels_an_approved_but_unparked_request() -> None:
    asking, _ = _asking_rig([None])
    asking.approvals.decisions = [ApprovalState.APPROVED]
    asking.host.handle_message(message("merge it"), generation=0)
    decided = asking.flow.poll_parked()  # decided and unparked, settle still queued
    assert [d.request.state for d in decided] == [ApprovalState.APPROVED]
    asking.admin.open_ids = [decided[0].request.id]
    asking.host.stop()
    # The all-windows cancel runs too, so the request is not left APPROVED for 24 h.
    assert asking.admin.cancel_all_calls == 1
    assert asking.admin.cancelled_windows != []
    for entry in decided:
        asking.host.settle_approval(entry)
    assert asking.approvals.consumed == []  # and its late settle never runs


def test_fcl3b_c58_stop_without_an_open_window_still_cancels_all_windows() -> None:
    rig = host_rig()
    rig.host.stop()
    assert rig.admin.cancelled_windows == []
    assert rig.admin.cancel_all_calls == 1


def test_fcl3b_c58_stop_alerts_once_when_the_cancel_fails() -> None:
    rig = host_rig()
    rig.admin.cancel_fails = True
    rig.host.stop()
    assert len(rig.alerts.titles) == 1


def test_fcl3b_c58_admin_client_all_windows_form_posts_an_empty_body() -> None:
    approval = "01" + "0" * 24
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"cancelled": [approval]})

    admin = ClaudiaAdminClient(
        Path("/nonexistent.sock"), b"t" * 43, transport=httpx.MockTransport(handler)
    )
    assert admin.cancel_all_open_approvals() == [approval]
    assert json.loads(seen[0].content) == {}
    assert seen[0].url.path == "/v1/claudia/approvals/cancel-open"


def test_fcl3b_c58_cancelling_all_windows_frees_the_open_cap(tmp_path: Path) -> None:
    # Real admin service: the cap counts every window's open request (stranded ones included).
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:

        def create(window: str) -> int:
            body = approval_body(window_id=window)
            headers = bearer(rig.claudia_token)
            return client.post("/v1/claudia/approvals", json=body, headers=headers).status_code

        windows = [OTHER_WINDOW, WINDOW_N, "423e4567-e89b-42d3-a456-426614174000"]
        ids = []
        for window in windows:
            response = client.post(
                "/v1/claudia/approvals",
                json=approval_body(window_id=window),
                headers=bearer(rig.claudia_token),
            )
            assert response.status_code == 201
            ids.append(response.json()["approval"]["id"])
        # One of them is already APPROVED (tap + code) but never consumed.
        client.post(
            "/v1/notifier/approvals", json=tap_body(ids[0]), headers=bearer(rig.notifier_token)
        )
        client.post(
            "/v1/notifier/codes", json=code_body(rig.code(), 1), headers=bearer(rig.notifier_token)
        )
        assert rig.claudia.approvals.get(ids[0]).state is ApprovalState.APPROVED
        assert create("523e4567-e89b-42d3-a456-426614174000") == 409  # the cap
        cancelled = client.post(
            "/v1/claudia/approvals/cancel-open", json={}, headers=bearer(rig.claudia_token)
        )
        assert sorted(cancelled.json()["cancelled"]) == sorted(ids)
        assert create("523e4567-e89b-42d3-a456-426614174000") == 201
