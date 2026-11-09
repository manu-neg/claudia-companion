"""Pending-approvals snapshot writer (docs/security.md C46 "independent view", S1; unit M5b).

The admin rewrites one sanitized JSON file on every approval change; the
viewer's reader (`application/pending_approvals.py`, unit M8) must accept
exactly what is written. Checks: format round-trip through the real reader,
only open + unexpired requests, no inbox message id or text, 0640 + the
directory's group, atomic replace, fail closed (missing / unsafe dir,
too many entries, store failure -> no file), and the change hook on
`ApprovalService`.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.adapters.approvals_snapshot import (
    FileSnapshotSink,
    default_snapshot_path,
)
from preview_dashboard.adapters.kb_reader import FileApprovalsSnapshot
from preview_dashboard.application import approvals_snapshot, pending_approvals
from preview_dashboard.application.approvals import (
    ApprovalCreateCommand,
    ApprovalService,
    TapDecision,
)
from preview_dashboard.application.approvals_snapshot import (
    ApprovalsSnapshotWriter,
    SnapshotOnChange,
    build_snapshot,
)
from preview_dashboard.application.pending_approvals import PendingApprovalsService
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    flagged_message_text,
    parse_window_id,
)
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.owner_messages import OwnerMessageId
from tests.fakes import (
    FakeContentScanner,
    FakeOutboxEvents,
    FixedClock,
    InMemoryApprovalStore,
    InMemoryOwnerMessageStore,
    SequentialIdGenerator,
)

MESSAGE_ID = OwnerMessageId("0" * 25 + "9")


def window(n: int) -> str:
    return parse_window_id(f"{n:08d}-1111-4111-8111-111111111111")


def action(n: int, clock: FixedClock, **kw: object) -> ApprovalRequest:
    return ApprovalRequest.new(
        id=ApprovalId(f"{n:026d}"),
        window_id=window(n),  # type: ignore[arg-type]
        kind=ApprovalKind.ACTION,
        action_text=f"Merge PR: o/r#{n}",
        now=clock.now(),
        action_kind=ActionKind.PR_MERGE,
        action_target=f"o/r#{n}",
        **kw,  # type: ignore[arg-type]
    )


def flagged(clock: FixedClock) -> ApprovalRequest:
    return ApprovalRequest.new(
        id=ApprovalId("0" * 25 + "8"),
        window_id=window(8),  # type: ignore[arg-type]
        kind=ApprovalKind.FLAGGED_MESSAGE,
        action_text=flagged_message_text(MESSAGE_ID, "short"),
        now=clock.now(),
        message_id=MESSAGE_ID,
    )


@pytest.fixture
def view_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "claudia-view"
    directory.mkdir(mode=0o750)
    directory.chmod(0o750)
    return directory


def writer(store: InMemoryApprovalStore, path: Path, clock: FixedClock) -> ApprovalsSnapshotWriter:
    return ApprovalsSnapshotWriter(store=store, sink=FileSnapshotSink(path), clock=clock)


def read_back(path: Path, clock: FixedClock) -> pending_approvals.PendingApprovals:
    return PendingApprovalsService(FileApprovalsSnapshot(path), clock).current()


def test_c46_snapshot_format_matches_the_viewer_reader(view_dir: Path) -> None:
    assert approvals_snapshot.SNAPSHOT_VERSION == pending_approvals.SNAPSHOT_VERSION
    assert approvals_snapshot.MAX_ENTRIES == pending_approvals.MAX_ENTRIES
    clock = FixedClock()
    store = InMemoryApprovalStore()
    store.add(action(1, clock))
    store.add(flagged(clock))
    path = view_dir / "pending-approvals.json"
    assert writer(store, path, clock).refresh()
    seen = read_back(path, clock)
    assert seen.available
    assert {(a.id, a.kind, a.target, a.state) for a in seen.approvals} == {
        ("0" * 25 + "1", "pr_merge", "o/r#1", "pending"),
        ("0" * 25 + "8", None, None, "pending"),
    }


def test_c46_snapshot_holds_only_the_shown_text_never_the_message(view_dir: Path) -> None:
    clock = FixedClock()
    store = InMemoryApprovalStore()
    owner_text = "please tidy the server " + "tail-words-the-owner-wrote " * 10
    request = ApprovalRequest.new(
        id=ApprovalId("0" * 25 + "8"),
        window_id=window(8),  # type: ignore[arg-type]
        kind=ApprovalKind.FLAGGED_MESSAGE,
        action_text=flagged_message_text(MESSAGE_ID, owner_text),
        now=clock.now(),
        message_id=MESSAGE_ID,
    )
    store.add(request)
    path = view_dir / "pending-approvals.json"
    writer(store, path, clock).refresh()
    data = json.loads(path.read_bytes())
    [entry] = data["approvals"]
    # Exactly the reader's fields: no message id field, no timestamps besides expiry.
    assert set(entry) == {"id", "action_text", "kind", "target", "state", "expires_at"}
    # The text is the stored action text (what Telegram shows), never the inbox message.
    assert entry["action_text"] == request.action_text
    assert owner_text not in path.read_text()


def test_c46_snapshot_lists_only_open_unexpired_requests(view_dir: Path) -> None:
    clock = FixedClock()
    store = InMemoryApprovalStore()
    old = action(1, clock)
    store.add(old)
    clock.advance(timedelta(hours=23))
    store.add(action(2, clock))
    clock.advance(timedelta(hours=2))  # #1 is past its 24 h, #2 is not
    data = build_snapshot(store.list_open(), clock.now())
    assert data is not None
    assert [e["id"] for e in json.loads(data)["approvals"]] == ["0" * 25 + "2"]


def test_c46_snapshot_file_mode_group_and_atomic(view_dir: Path) -> None:
    clock = FixedClock()
    store = InMemoryApprovalStore()
    store.add(action(1, clock))
    path = view_dir / "pending-approvals.json"
    old = os.umask(0o077)
    try:
        writer(store, path, clock).refresh()
    finally:
        os.umask(old)
    st = os.lstat(path)
    assert stat.S_IMODE(st.st_mode) == 0o640
    assert st.st_gid == os.stat(view_dir).st_gid
    assert sorted(p.name for p in view_dir.iterdir()) == ["pending-approvals.json"]


def test_c46_snapshot_replaces_a_planted_symlink_instead_of_following_it(
    view_dir: Path, tmp_path: Path
) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    path = view_dir / "pending-approvals.json"
    path.symlink_to(victim)
    clock = FixedClock()
    writer(InMemoryApprovalStore(), path, clock).refresh()
    assert victim.read_text() == "keep"
    assert not path.is_symlink()


def test_c46_missing_or_unsafe_directory_writes_nothing(tmp_path: Path) -> None:
    clock = FixedClock()
    missing = tmp_path / "nope" / "pending-approvals.json"
    assert writer(InMemoryApprovalStore(), missing, clock).refresh() is False
    assert not missing.parent.exists()
    unsafe = tmp_path / "open"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    with pytest.raises(StorageUnavailableError):
        FileSnapshotSink(unsafe / "pending-approvals.json").write(b"{}")


def test_c46_too_many_open_requests_remove_the_snapshot(view_dir: Path) -> None:
    clock = FixedClock()
    store = InMemoryApprovalStore()
    path = view_dir / "pending-approvals.json"
    w = writer(store, path, clock)
    store.add(action(1, clock))
    assert w.refresh() and path.exists()
    for n in range(2, 53):
        store.add(action(n, clock))
    assert w.refresh() is False
    assert not path.exists()  # no partial list: the viewer says "nothing can be confirmed"


def test_c46_store_failure_removes_a_stale_snapshot(view_dir: Path) -> None:
    class Broken(InMemoryApprovalStore):
        def list_open(self, window_id: object = None) -> list[ApprovalRequest]:
            raise StorageUnavailableError("db down")

    clock = FixedClock()
    path = view_dir / "pending-approvals.json"
    path.write_text('{"version": 1, "approvals": []}')
    assert writer(Broken(), path, clock).refresh() is False
    assert not path.exists()


def test_c46_every_approval_change_rewrites_the_snapshot(view_dir: Path) -> None:
    clock = FixedClock()
    store = InMemoryApprovalStore()
    messages = InMemoryOwnerMessageStore()
    path = view_dir / "pending-approvals.json"
    events = FakeOutboxEvents()

    class _Prompts:
        def prompt(self, request: ApprovalRequest) -> None:
            del request

    service = ApprovalService(
        store=store,
        messages=messages,
        clock=clock,
        ids=SequentialIdGenerator(),
        scanner=FakeContentScanner(),
        prompts=_Prompts(),
        events=SnapshotOnChange(events, writer(store, path, clock)),
    )
    created = service.create(
        ApprovalCreateCommand(
            window_id=window(1),
            kind="action",
            action_text="Merge PR: o/r#1",
            action_kind="pr_merge",
            action_target="o/r#1",
        )
    )
    assert [a.state for a in read_back(path, clock).approvals] == ["pending"]
    service.tap(created.id, TapDecision.APPROVE)
    assert [a.state for a in read_back(path, clock).approvals] == ["tapped"]
    service.cancel(created.id)
    assert read_back(path, clock).approvals == ()
    assert events.notified >= 3  # long-polls still woken first


def _service(store: InMemoryApprovalStore, path: Path, clock: FixedClock) -> ApprovalService:
    class _Prompts:
        def prompt(self, request: ApprovalRequest) -> None:
            del request

    return ApprovalService(
        store=store,
        messages=InMemoryOwnerMessageStore(),
        clock=clock,
        ids=SequentialIdGenerator(),
        scanner=FakeContentScanner(),
        prompts=_Prompts(),
        events=SnapshotOnChange(FakeOutboxEvents(), writer(store, path, clock)),
    )


def _create(service: ApprovalService, n: int) -> ApprovalRequest:
    return service.create(
        ApprovalCreateCommand(
            window_id=window(n),
            kind="action",
            action_text=f"Merge PR: o/r#{n}",
            action_kind="pr_merge",
            action_target=f"o/r#{n}",
        )
    )


def test_fcl3_c46_panel_drops_a_24h_request_at_expiry_without_a_snapshot_rewrite(
    view_dir: Path,
) -> None:
    # Owner requirement (F-CL3): listed until 24 h after creation, gone from then on,
    # even though nothing rewrites the snapshot (the reader drops it by its own clock).
    clock = FixedClock()
    store = InMemoryApprovalStore()
    path = view_dir / "pending-approvals.json"
    created = _create(_service(store, path, clock), 1)
    written = path.read_bytes()
    clock.advance(timedelta(hours=23, minutes=59))
    assert [a.id for a in read_back(path, clock).approvals] == [created.id]
    clock.advance(timedelta(minutes=1))  # exactly 24 h after creation
    assert path.read_bytes() == written  # no rewrite happened
    assert read_back(path, clock).approvals == ()
    assert read_back(path, clock).available


def test_fcl3_c46_panel_drops_a_request_right_after_approve_deny_or_cancel(
    view_dir: Path,
) -> None:
    clock = FixedClock()
    store = InMemoryApprovalStore()
    path = view_dir / "pending-approvals.json"
    service = _service(store, path, clock)
    approved, denied, cancelled = (_create(service, n) for n in (1, 2, 3))
    assert len(read_back(path, clock).approvals) == 3
    # Approve tap: still listed (the owner checks it here before sending the code).
    service.tap(approved.id, TapDecision.APPROVE)
    assert approved.id in {a.id for a in read_back(path, clock).approvals}
    # Code verified (APPROVED): gone at once.
    [tapped] = service.tapped_requests()
    assert service.approve(tapped)
    assert approved.id not in {a.id for a in read_back(path, clock).approvals}
    service.tap(denied.id, TapDecision.DENY)
    assert denied.id not in {a.id for a in read_back(path, clock).approvals}
    service.cancel(cancelled.id)
    assert read_back(path, clock).approvals == ()


def test_default_snapshot_path_is_the_deploy_dir() -> None:
    assert default_snapshot_path(Path("/var/lib/preview-dashboard")) == Path(
        "/var/lib/preview-dashboard/claudia-view/pending-approvals.json"
    )
