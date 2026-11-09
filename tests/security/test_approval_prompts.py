"""Security tests for approval prompt delivery (unit A1): C46 (and the C47 code prompt).

The default admin wiring now queues prompts (create no longer 503s); a
prompt's shown text is the **stored** action text; its only buttons are
exactly Approve `p:<id>:ok` and Deny `p:<id>:no`, built by the channel from
`approval_id`; it is handed out only while its request is PENDING and
unexpired (else settled unsent); an approval payload can carry nothing
else (no answer buttons, link, question or long form); `dashboard_notify`
can never send one; no channel = create fails closed; after a recorded
Approve the notifier sends exactly the fixed code-prompt text.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.telegram.channel import TelegramChannel, reply_markup
from preview_dashboard.application.approval_prompts import OutboxApprovalPrompts
from preview_dashboard.domain.approvals import (
    APPROVAL_TTL,
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    WindowId,
)
from preview_dashboard.domain.errors import (
    InvalidStateError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.domain.notifications import (
    DeliveryPayload,
    MessageButton,
    MessageContent,
    Notification,
    NotificationId,
    PendingTask,
)
from preview_dashboard.wire import notifier as wire
from preview_dashboard.wire import notifier_messages as wm
from tests.claudia_admin_support import WINDOW, approval_body, claudia_app, tap_body
from tests.fakes import FixedClock, InMemoryNotificationOutbox, SequentialIdGenerator
from tests.notify_admin_support import bearer
from tests.notify_support import qid
from tests.owner_updates_support import APPROVAL_ID, Harness, result
from tests.telegram_support import OWNER, FakeBotApi, callback_update, message, ok

pytestmark = pytest.mark.security


def _create(client: TestClient, rig: Any, **overrides: Any) -> dict[str, Any]:
    response = client.post(
        "/v1/claudia/approvals", json=approval_body(**overrides), headers=bearer(rig.claudia_token)
    )
    assert response.status_code == 201, response.text
    approval: dict[str, Any] = response.json()["approval"]
    return approval


def _notifier_tasks(client: TestClient, rig: Any) -> list[PendingTask]:
    # Through the real route and wire, exactly as the notifier sees them.
    response = client.get("/v1/notifier/tasks", headers=bearer(rig.notifier_token))
    assert response.status_code == 200, response.text
    return [wire.parse_task(t) for t in wire.parse_tasks_envelope(response.json())]


def _request(**overrides: Any) -> ApprovalRequest:
    request = ApprovalRequest.new(
        id=ApprovalId(APPROVAL_ID),
        window_id=WindowId(WINDOW),
        kind=ApprovalKind.ACTION,
        action_text="Merge PR 31 into main",
        now=FixedClock().now(),
        action_kind=ActionKind.PR_MERGE,
        action_target="example-org/example-repo#31",
    )
    return replace(request, **overrides) if overrides else request


def _prompt_payload(text: str = "Merge PR 31 into main") -> DeliveryPayload:
    return DeliveryPayload(content=MessageContent(text=text), approval_id=ApprovalId(APPROVAL_ID))


# --- default wiring ------------------------------------------------------------------------


def test_c46_create_no_longer_503s_and_queues_one_prompt(tmp_path):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _create(client, rig)
        [task] = _notifier_tasks(client, rig)
    assert approval["state"] == "pending"
    assert task.channel == "telegram"
    assert task.payload.approval_id == approval["id"]
    assert task.payload.question_id is None
    assert task.payload.content.buttons == ()  # the channel adds Approve/Deny itself
    assert task.payload.content.link is None


def test_c46_shown_text_is_the_stored_action_text(tmp_path):
    # Raw text with extra spacing: the prompt shows the sanitized, stored form.
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _create(client, rig, action_text="  Merge PR 31   into main  ")
        [task] = _notifier_tasks(client, rig)
        stored = rig.claudia.approvals.get(approval["id"])
    assert task.payload.content.text == stored.action_text == approval["action_text"]
    api = FakeBotApi()
    api.script("sendMessage", ok(message(9)))
    TelegramChannel(api.client(), OWNER, dashboard_origin=None).send(task.payload)
    assert api.calls[0].body["text"] == stored.action_text


@pytest.mark.parametrize(
    "decide",
    [
        pytest.param(lambda c, rig, aid: _tap(c, rig, aid, "approve"), id="tapped"),
        pytest.param(lambda c, rig, aid: _tap(c, rig, aid, "deny"), id="denied"),
        pytest.param(
            lambda c, rig, aid: c.post(
                f"/v1/claudia/approvals/{aid}/cancel", headers=bearer(rig.claudia_token)
            ),
            id="cancelled",
        ),
        pytest.param(
            lambda c, rig, aid: rig.clock.advance(APPROVAL_TTL + timedelta(seconds=1)),
            id="expired-unmarked",
        ),
    ],
)
def test_c46_prompt_goes_out_for_a_pending_request_only(tmp_path, decide):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _create(client, rig)
        decide(client, rig, approval["id"])
        assert _notifier_tasks(client, rig) == []  # settled unsent, never shown
        # ...and it stays settled: a later poll does not hand it out either.
        assert _notifier_tasks(client, rig) == []


def _tap(client: TestClient, rig: Any, aid: str, decision: str) -> None:
    response = client.post(
        "/v1/notifier/approvals", json=tap_body(aid, decision), headers=bearer(rig.notifier_token)
    )
    assert response.status_code == 200, response.text


def test_c46_prompt_for_a_deleted_request_is_stale():
    # Fake outbox (same rules as SQLite): an unknown request id never gets buttons.
    outbox = InMemoryNotificationOutbox()
    prompts = OutboxApprovalPrompts(
        outbox=outbox, clock=FixedClock(), ids=SequentialIdGenerator(), channels=("telegram",)
    )
    prompts.prompt(_request())
    assert outbox.pending(FixedClock().now(), 10) == []  # approval_lookup finds nothing
    live = InMemoryNotificationOutbox()
    live.approval_lookup = lambda _aid: _request()
    OutboxApprovalPrompts(
        outbox=live, clock=FixedClock(), ids=SequentialIdGenerator(), channels=("telegram",)
    ).prompt(_request())
    [task] = live.pending(FixedClock().now(), 10)
    assert task.payload.approval_id == APPROVAL_ID


def test_c46_only_a_pending_request_is_prompted():
    prompts = OutboxApprovalPrompts(
        outbox=InMemoryNotificationOutbox(),
        clock=FixedClock(),
        ids=SequentialIdGenerator(),
        channels=("telegram",),
    )
    tapped = _request().tapped(FixedClock().now())
    with pytest.raises(InvalidStateError):
        prompts.prompt(tapped)


def test_c46_no_channel_means_create_fails_closed():
    prompts = OutboxApprovalPrompts(
        outbox=InMemoryNotificationOutbox(),
        clock=FixedClock(),
        ids=SequentialIdGenerator(),
        channels=(),
    )
    with pytest.raises(StorageUnavailableError):
        prompts.prompt(_request())


def test_c46_dashboard_notify_can_never_send_an_approval(tmp_path):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        response = client.post(
            "/v1/notifications",
            json={"event": "approval", "title": "Merge PR 31 into main"},
            headers=bearer(rig.admin_token),
        )
        assert response.status_code == 400
        assert _notifier_tasks(client, rig) == []


# --- buttons -----------------------------------------------------------------------------------


def test_c46_buttons_are_exactly_approve_and_deny_for_the_request():
    markup = reply_markup(_prompt_payload(), "https://dash.example")
    assert markup == {
        "inline_keyboard": [
            [
                {"text": "Approve", "callback_data": f"p:{APPROVAL_ID}:ok"},
                {"text": "Deny", "callback_data": f"p:{APPROVAL_ID}:no"},
            ]
        ]
    }
    # What the channel puts on the keyboard is exactly what the notifier accepts back.
    assert wm.parse_approval_callback(f"p:{APPROVAL_ID}:ok") == (
        APPROVAL_ID,
        wm.ApprovalDecision.APPROVE,
    )
    assert wm.parse_approval_callback(f"p:{APPROVAL_ID}:no") == (
        APPROVAL_ID,
        wm.ApprovalDecision.DENY,
    )


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: MessageContent(text="x", buttons=(MessageButton(key="ok", label="Yes"),)),
            id="extra-buttons",
        ),
        pytest.param(lambda: MessageContent(text="x", link="https://dash.example/"), id="link"),
        pytest.param(lambda: MessageContent(text="x", long_form=True), id="long-form"),
    ],
)
def test_c46_approval_payload_carries_nothing_but_id_and_text(build):
    with pytest.raises(ValidationError):
        DeliveryPayload(content=build(), approval_id=ApprovalId(APPROVAL_ID))


def test_c46_approval_payload_is_not_a_question():
    with pytest.raises(ValidationError):
        DeliveryPayload(
            content=MessageContent(text="x"),
            question_id=qid(1),
            approval_id=ApprovalId(APPROVAL_ID),
        )
    with pytest.raises(ValidationError):
        Notification(
            id=NotificationId(qid(2)),
            event_type="approval",
            title="Approval request",
            created_at=FixedClock().now(),
            question_id=qid(1),
            approval_id=ApprovalId(APPROVAL_ID),
        )


@pytest.mark.parametrize("bad", [None, "", "nope", APPROVAL_ID.lower(), 7, "../x"])
def test_c46_wire_approval_id_must_be_a_canonical_ulid(bad):
    body = {**wire.payload_to_json(_prompt_payload()), "approval_id": bad}
    with pytest.raises(ValidationError):
        wire.parse_payload(body)


def test_c46_wire_round_trip_keeps_the_approval_id():
    body = wire.payload_to_json(_prompt_payload())
    assert body["approval_id"] == APPROVAL_ID and body["buttons"] == []
    assert wire.parse_payload(body) == _prompt_payload()
    # Alerts never carry the key.
    alert = wire.payload_to_json(DeliveryPayload(content=MessageContent(text="✅ done")))
    assert "approval_id" not in alert


# --- C47: the code prompt after Approve -------------------------------------------------------


def test_c47_recorded_approve_sends_the_fixed_code_prompt():
    h = Harness()
    h.api.script("sendMessage", ok(message(8)))
    h.updates(callback_update(1, f"p:{APPROVAL_ID}:ok", query_id="t1"))
    h.router.poll(50)
    sent = [c.body for c in h.api.calls if c.method == "sendMessage"]
    assert sent == [
        {
            "chat_id": OWNER,
            "text": wm.CODE_PROMPT_TEXT,
            "link_preview_options": {"is_disabled": True},
        }
    ]


@pytest.mark.parametrize("verdict", ["denied", "already_decided", "expired", "unknown"])
def test_c47_no_code_prompt_unless_approve_was_recorded(verdict):
    h = Harness()
    h.admin.route("POST", wm.APPROVALS_PATH, result(verdict))
    h.updates(callback_update(1, f"p:{APPROVAL_ID}:ok", query_id="t1"))
    h.router.poll(50)
    assert "sendMessage" not in h.api.methods()


def test_c47_code_prompt_failure_is_isolated():
    h = Harness()
    h.api.script("sendMessage", ConnectionError("telegram down"))
    h.updates(callback_update(1, f"p:{APPROVAL_ID}:ok", query_id="t1"))
    assert h.router.poll(50) == []  # no exception: the tap was recorded and acked
    assert "answerCallbackQuery" in h.api.methods()
