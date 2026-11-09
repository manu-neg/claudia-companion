"""Security tests for the S-C2a storage/TOTP fixes (unit F-C2a-1): C44, C46, C47, S-C1 S1.

- storage-totp-1: an approval prompt's text is rebuilt from the admin-only
  request at handout; tampered task text, a forged second notification or
  a forged RESOLVE for a pending id never reach the owner.
- storage-totp-2: approval creation has a budget (created requests; refused
  attempts have their own, newcode-7) and a cap on open requests across all windows.
- storage-totp-3: the step-up state's load-modify-save holds a
  cross-process `flock` (admin and `claudia totp setup`); an unsafe lock
  file refuses every code.
- storage-totp-4: code redaction joins digit groups across short
  separators (tab, newline, dash, dot, ZWSP / Cf).
- M8 fix (a): a `-shm` sidecar mid-unlink (link count 0) is not an attack.
"""

from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.sqlite.claudia_db import (
    _check_private,
    connect_claudia,
    default_claudia_db_path,
)
from preview_dashboard.adapters.sqlite.connection import UnsafeDatabasePathError, default_db_path
from preview_dashboard.adapters.sqlite.questions import APPROVAL_PROMPT_TITLE
from preview_dashboard.adapters.stepup_state import (
    LOCK_FILE_NAME,
    FileStepUpState,
    StepUpStateError,
)
from preview_dashboard.application.approval_prompts import APPROVAL_TITLE
from preview_dashboard.application.approvals import (
    APPROVAL_CREATE_BUDGET,
    APPROVAL_WINDOW_REFUSED_BUDGET,
    MAX_OPEN_APPROVALS,
    ApprovalCreateCommand,
    TapDecision,
)
from preview_dashboard.application.stepup import CodeResult
from preview_dashboard.domain.approvals import APPROVAL_TTL
from preview_dashboard.domain.owner_messages import CODE_REDACTED, redact_code_runs
from preview_dashboard.wire import notifier as wire
from tests.claudia_admin_support import approval_body, claudia_app
from tests.notify_admin_support import OWNER_CHAT, bearer
from tests.notify_support import qid

pytestmark = pytest.mark.security

FORGED_TEXT = "Approve: read README"


def _window(n: int) -> str:
    return f"{n}23e4567-e89b-42d3-a456-426614174000"


def _post_approval(client: TestClient, rig: Any, **overrides: Any) -> Any:
    return client.post(
        "/v1/claudia/approvals", json=approval_body(**overrides), headers=bearer(rig.claudia_token)
    )


def _notifier_tasks(client: TestClient, rig: Any) -> list[Any]:
    response = client.get("/v1/notifier/tasks", headers=bearer(rig.notifier_token))
    assert response.status_code == 200, response.text
    return [wire.parse_task(t) for t in wire.parse_tasks_envelope(response.json())]


def _shared_db(rig: Any) -> sqlite3.Connection:
    # The viewer-writable item DB: what a compromised viewer could rewrite (S1).
    return sqlite3.connect(default_db_path(Path(rig.core.settings.data_dir)), isolation_level=None)


def _us(rig: Any) -> int:
    return int(rig.clock.now().timestamp() * 1_000_000)


def _task_states(rig: Any) -> list[str]:
    conn = _shared_db(rig)
    try:
        return [row[0] for row in conn.execute("SELECT state FROM delivery_tasks ORDER BY id")]
    finally:
        conn.close()


# --- storage-totp-1: prompt text from the admin-only request --------------------------------


def test_storage_totp_1_tampered_task_text_is_never_shown(tmp_path):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _post_approval(client, rig, action_text="Push to main").json()["approval"]
        conn = _shared_db(rig)
        try:
            conn.execute("UPDATE delivery_tasks SET text = ?", (FORGED_TEXT,))
        finally:
            conn.close()
        [task] = _notifier_tasks(client, rig)
    assert task.payload.approval_id == approval["id"]
    assert task.payload.content.text == "Push to main" != FORGED_TEXT
    assert task.payload.content.buttons == () and task.payload.content.link is None


def _forge_notification(rig: Any, approval_id: str, *, action: str = "send", n: int = 900) -> None:
    conn = _shared_db(rig)
    try:
        at = _us(rig)
        conn.execute(
            "INSERT INTO notifications (id, event_type, title, item_id, question_id, created_us, "
            "approval_id) VALUES (?, 'approval', 'Approval request', NULL, NULL, ?, ?)",
            (qid(n), at, approval_id),
        )
        conn.execute(
            "INSERT INTO delivery_tasks (id, notification_id, channel, action, state, attempts, "
            "next_attempt_us, created_us, message_ref, final_state, text, link, long_form) "
            "VALUES (?, ?, 'telegram', ?, 'pending', 0, ?, ?, NULL, ?, ?, NULL, 0)",
            (
                qid(n + 1),
                qid(n),
                action,
                at,
                at,
                "cancelled" if action == "resolve" else None,
                FORGED_TEXT,
            ),
        )
    finally:
        conn.close()


def test_storage_totp_1_second_prompt_notification_poisons_every_prompt(tmp_path):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _post_approval(client, rig).json()["approval"]
        _forge_notification(rig, approval["id"])
        assert _notifier_tasks(client, rig) == []  # neither the forged nor the real one
        assert _task_states(rig) == ["failed", "failed"]


def test_storage_totp_1_forged_prompt_after_the_real_one_was_sent_is_refused(tmp_path):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _post_approval(client, rig).json()["approval"]
        [real] = _notifier_tasks(client, rig)
        done = client.post(
            f"/v1/notifier/tasks/{real.id}/done",
            json={"message_ref": "telegram:1:9"},
            headers=bearer(rig.notifier_token),
        )
        assert done.status_code in (200, 204), done.text
        _forge_notification(rig, approval["id"])
        assert _notifier_tasks(client, rig) == []


def test_storage_totp_1_forged_resolve_for_a_prompt_is_refused(tmp_path):
    with claudia_app(tmp_path, real_prompts=True) as rig, TestClient(rig.app) as client:
        approval = _post_approval(client, rig).json()["approval"]
        conn = _shared_db(rig)
        try:
            (notification_id,) = conn.execute("SELECT id FROM notifications").fetchone()
            at = _us(rig)
            conn.execute(
                "INSERT INTO delivery_tasks (id, notification_id, channel, action, state, "
                "attempts, next_attempt_us, created_us, message_ref, final_state, text, link, "
                "long_form) VALUES (?, ?, 'telegram', 'resolve', 'pending', 0, ?, ?, NULL, "
                "'cancelled', ?, NULL, 0)",
                (qid(950), notification_id, at, at, FORGED_TEXT),
            )
        finally:
            conn.close()
        tasks = _notifier_tasks(client, rig)
    assert [t.payload.content.text for t in tasks] == ["Merge PR 31 into main"]
    assert all(t.payload.approval_id == approval["id"] for t in tasks)


def test_storage_totp_1_adapter_title_equals_the_prompt_title():
    assert APPROVAL_PROMPT_TITLE == APPROVAL_TITLE


# --- storage-totp-2: create budget and open cap ---------------------------------------------


def test_storage_totp_2_open_requests_are_capped_across_windows(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        ids = []
        for n in range(1, MAX_OPEN_APPROVALS + 1):
            response = _post_approval(client, rig, window_id=_window(n))
            assert response.status_code == 201, response.text
            ids.append(response.json()["approval"]["id"])
        refused = _post_approval(client, rig, window_id=_window(MAX_OPEN_APPROVALS + 1))
        assert refused.status_code == 409
        rig.claudia.approvals.cancel(ids[0])
        again = _post_approval(client, rig, window_id=_window(MAX_OPEN_APPROVALS + 1))
        assert again.status_code == 201, again.text


def test_storage_totp_2_expired_requests_do_not_count_as_open(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        for n in range(1, MAX_OPEN_APPROVALS + 1):
            assert _post_approval(client, rig, window_id=_window(n)).status_code == 201
        rig.clock.advance(APPROVAL_TTL + timedelta(seconds=1))
        assert _post_approval(client, rig, window_id=_window(8)).status_code == 201


def test_storage_totp_2_refused_attempts_have_their_own_budget(tmp_path):
    # newcode-7: refusals no longer use the created budget, but they are not free.
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        for _ in range(APPROVAL_WINDOW_REFUSED_BUDGET):
            assert _post_approval(client, rig, kind="bogus").status_code == 400
        # Spent: a further refusal answers 429 instead of its reason (no free probing) ...
        assert _post_approval(client, rig, kind="bogus").status_code == 429
        # ... while a real request still goes through.
        assert _post_approval(client, rig).status_code == 201


def test_storage_totp_2_created_requests_are_budgeted(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        for n in range(APPROVAL_CREATE_BUDGET):
            response = _post_approval(client, rig, window_id=_window(n % 9 + 1))
            assert response.status_code == 201, response.text
            rig.claudia.approvals.cancel(response.json()["approval"]["id"])
        over = _post_approval(client, rig, window_id=_window(9))
        assert over.status_code == 429
        assert rig.claudia.approvals.tapped_requests() == []


# --- storage-totp-3: cross-process lock on the step-up state ---------------------------------


def _tapped_request(rig: Any) -> str:
    request = rig.claudia.approvals.create(
        ApprovalCreateCommand(
            window_id=_window(1),
            kind="action",
            action_text="Merge PR 31 into main",
            action_kind="pr_merge",
            action_target="example-org/example-repo#31",
        )
    )
    rig.claudia.approvals.tap(request.id, TapDecision.APPROVE)
    return str(request.id)


def test_storage_totp_3_admin_code_waits_for_the_setup_lock(tmp_path):
    with claudia_app(tmp_path) as rig:
        _tapped_request(rig)
        state = FileStepUpState(Path(rig.core.settings.data_dir) / "claudia")
        results: list[CodeResult] = []

        def submit() -> None:
            results.append(
                rig.claudia.stepup.submit_code(
                    rig.code(), update_id=1, message_id=1, sender_id=OWNER_CHAT
                )
            )

        worker = threading.Thread(target=submit)
        with state.exclusive():
            # "Setup" holds the lock: the admin's load-modify-save must not run now.
            worker.start()
            worker.join(timeout=0.3)
            assert worker.is_alive() and results == []
            state.save(state.load().with_burned_step(0))
        worker.join(timeout=10)
        assert results == [CodeResult.ACCEPTED]


def test_storage_totp_3_exclusive_is_an_flock_others_see(tmp_path):
    state = FileStepUpState(tmp_path)
    with state.exclusive():
        fd = os.open(tmp_path / LOCK_FILE_NAME, os.O_RDONLY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)
    assert stat.S_IMODE(os.stat(tmp_path / LOCK_FILE_NAME).st_mode) == 0o600
    fd = os.open(tmp_path / LOCK_FILE_NAME, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released on exit
    finally:
        os.close(fd)


@pytest.mark.parametrize("tamper", ["symlink", "loose-mode", "hardlink", "directory"])
def test_storage_totp_3_unsafe_lock_file_is_refused(tmp_path, tamper):
    lock = tmp_path / LOCK_FILE_NAME
    if tamper == "symlink":
        (tmp_path / "elsewhere").write_text("")
        lock.symlink_to(tmp_path / "elsewhere")
    elif tamper == "loose-mode":
        lock.write_text("")
        os.chmod(lock, 0o644)
    elif tamper == "hardlink":
        lock.write_text("")
        os.chmod(lock, 0o600)
        os.link(lock, tmp_path / "second-name")
    else:
        lock.mkdir()
    state = FileStepUpState(tmp_path)
    with pytest.raises(StepUpStateError), state.exclusive():
        pytest.fail("the body must not run")


def test_storage_totp_3_unsafe_lock_refuses_every_code(tmp_path):
    with claudia_app(tmp_path) as rig:
        _tapped_request(rig)
        lock = Path(rig.core.settings.data_dir) / "claudia" / LOCK_FILE_NAME
        lock.write_text("")
        os.chmod(lock, 0o644)  # someone else could hold it and stall every code
        result = rig.claudia.stepup.submit_code(
            rig.code(), update_id=1, message_id=1, sender_id=OWNER_CHAT
        )
        assert result is CodeResult.REFUSED
        assert rig.claudia.approvals.tapped_requests() != []  # nothing approved


# (`claudia totp setup` taking the same lock: test_totp.py,
# test_storage_totp_3_setup_burns_the_step_under_the_lock.)


# --- storage-totp-4: separators between digit groups -----------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "123-456",
        "123.456",
        "123\t456",
        "123\n456",
        "123\r\n456",
        "123\N{ZERO WIDTH SPACE}456",  # Cf
        "123\N{SOFT HYPHEN}456",  # Cf
        "123\N{EN DASH}456",  # Pd
        "123 - 456",
        "12-34-56",
        "12.34.56",
        "code: 123-456, thanks",
        "1.500.000",  # grouped thousands: blanked too (fail closed)
    ],
)
def test_storage_totp_4_separated_codes_are_redacted(text):
    redacted = redact_code_runs(text)
    assert CODE_REDACTED in redacted
    assert not any(ch.isdigit() for ch in redacted.replace(CODE_REDACTED, ""))


@pytest.mark.parametrize(
    "text",
    [
        "2026-11-08",  # ISO date: 4+2+2, a 4-digit group never joins across a separator
        "123---456",  # three separators end the run
        "123-45",
        "PR 31-32",
    ],
)
def test_storage_totp_4_other_separated_numbers_are_kept(text):
    assert redact_code_runs(text) == text


def test_storage_totp_4_redaction_stays_idempotent():
    once = redact_code_runs("a 123-456 b 12.34.56 c")
    assert redact_code_runs(once) == once


# --- M8 fix (a): sidecar mid-unlink ----------------------------------------------------------


def _stat(nlink: int) -> os.stat_result:
    return os.stat_result((stat.S_IFREG | 0o600, 1, 1, nlink, os.geteuid(), 0, 0, 0, 0, 0))


def test_m8a_sidecar_mid_unlink_is_accepted_but_extra_links_are_not():
    _check_private(_stat(0), os.geteuid(), "-shm", regular=True, sidecar=True)
    _check_private(_stat(1), os.geteuid(), "-shm", regular=True, sidecar=True)
    with pytest.raises(UnsafeDatabasePathError):
        _check_private(_stat(2), os.geteuid(), "-shm", regular=True, sidecar=True)
    with pytest.raises(UnsafeDatabasePathError):
        _check_private(_stat(0), os.geteuid(), "db", regular=True)  # the DB file: exactly 1


def test_m8a_concurrent_opens_and_closes_never_trip_the_sidecar_check(tmp_path):
    # Stress (no shell loop): last-close unlinks -shm while other threads lstat it.
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    path = default_claudia_db_path(data)
    connect_claudia(path).close()
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def churn() -> None:
        barrier.wait()
        try:
            for _ in range(40):
                conn = connect_claudia(path, create=False)
                try:
                    conn.execute("SELECT 1").fetchone()
                finally:
                    conn.close()
        except BaseException as exc:  # collected: asserted below
            errors.append(exc)

    threads = [threading.Thread(target=churn) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
