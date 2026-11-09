"""C53 / F-C2c: a failed host post-run KB commit restores the KB work tree.

The host's commit after every run can fail (git broke, disk full); the
run's note changes then still sit in the work tree and the next commit
would take them in unverified. The host restores `*.md` to HEAD, deletes
untracked notes and sends exactly one fixed `failed` alert.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia.kb import KbService
from preview_dashboard.application.claudia.runs import (
    KB_COMMIT_FAILED_ALERT,
    KB_HALTED_TEXT,
    KB_RESTORE_FAILED_ALERT,
    KB_STILL_HALTED_TEXT,
    NEW_WINDOW_TEXT,
)
from preview_dashboard.application.claudia.windows import HostCommand
from preview_dashboard.domain.errors import StorageUnavailableError
from tests.claudia_host_support import FakeKb, host_rig, message

pytestmark = pytest.mark.security

NOTE = "---\ntags: [x]\nupdated: 2026-11-09\nsources: [dashboard:abc@rev1]\n---\n{body}\n"


def test_c53_commit_ok_needs_no_restore_and_no_alert() -> None:
    rig = host_rig()
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.kb.restores == 0
    assert rig.alerts.titles == []


def test_c53_failed_commit_restores_the_work_tree_and_alerts_once() -> None:
    rig = host_rig(kb=FakeKb(fail=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.kb.restores == 1
    assert rig.alerts.titles == [KB_COMMIT_FAILED_ALERT]
    assert len(rig.admin.replies) == 1  # her reply still went out


def test_c53_failed_restore_still_sends_exactly_one_alert() -> None:
    rig = host_rig(kb=FakeKb(fail=True, restore_fails=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.kb.restores == 1
    assert rig.alerts.titles == [KB_RESTORE_FAILED_ALERT]


def test_failed_restore_halts_until_new() -> None:
    rig = host_rig(kb=FakeKb(fail=True, restore_fails=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.windows.kb_halted
    replies = len(rig.admin.replies)
    rig.host.handle_message(message("again", 2), generation=0)
    assert len(rig.admin.replies) == replies + 1  # one fixed reply, no run
    assert rig.admin.replies[-1][0] == KB_HALTED_TEXT
    assert rig.windows.kb_halted  # a message does not clear it
    rig.host.command(HostCommand.NEW, message("/new", 3).id)
    assert rig.windows.kb_halted  # newcode-1: the restore still fails, so /new keeps it
    assert rig.admin.replies[-1][0] == KB_STILL_HALTED_TEXT
    rig.kb.restore_fails = False  # the owner fixed the work tree
    rig.host.command(HostCommand.NEW, message("/new", 4).id)
    assert not rig.windows.kb_halted
    assert rig.admin.replies[-1][0] == NEW_WINDOW_TEXT


def test_c53_kb_service_without_a_work_tree_refuses_to_restore(tmp_path: Path) -> None:
    svc = KbService(FsKbStore(tmp_path), RegexSecretScanner())
    with pytest.raises(StorageUnavailableError):
        svc.restore_worktree()


class _CommitFailsAfterFirst(FsKbStore):
    """The baseline commit works; every later one fails like a broken git."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.commits = 0

    def commit(self, message: str) -> str | None:
        self.commits += 1
        if self.commits > 1:
            raise StorageUnavailableError("git commit failed")
        return super().commit(message)


def test_c53_host_restores_the_real_kb_after_a_failed_commit(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    root = tmp_path / "kb"
    root.mkdir()
    store = _CommitFailsAfterFirst(root)
    svc = KbService(store, RegexSecretScanner(), worktree=GitKbHistory(root))
    svc.seed()
    svc.write("topics/people/ana.md", NOTE.format(body="Ana is a friend."), caller="claudia")
    assert svc.commit_run("baseline") is not None
    # What a run left behind: a changed note, a planted note, a deleted note, a non-note.
    (root / "topics/people/ana.md").write_text(NOTE.format(body="Changed."))
    (root / "topics/new").mkdir()
    (root / "topics/new/planted.md").write_text(NOTE.format(body="Planted."))
    (root / "now.md").unlink()
    (root / "keep.txt").write_text("not a note\n")

    rig = host_rig(kb=svc)
    rig.host.handle_message(message("hola", 1), generation=0)

    assert (root / "topics/people/ana.md").read_text() == NOTE.format(body="Ana is a friend.")
    assert not (root / "topics/new/planted.md").exists()
    assert (root / "now.md").exists()
    assert (root / "keep.txt").exists()  # `*.md` only
    assert GitKbHistory(root)._run("status", "--porcelain", "--", "*.md").stdout == ""
    assert rig.alerts.titles == [KB_COMMIT_FAILED_ALERT]
