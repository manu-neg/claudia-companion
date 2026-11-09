"""Review fixes for the knowledge base and gardener (C53/C54): kb-map-1, -2, -3 and -7.

Fail-closed post-run checks, the cross-process KB lock, invisible-character
refusal in notes, and `python -I` for the gardener's MCP child.
"""

from __future__ import annotations

import datetime
import json
import stat
import sys
import time
from pathlib import Path

import pytest

from preview_dashboard.adapters.gardener_runner import ClaudeGardenModel, kb_mcp_config
from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia.garden import Gardener, GardenStatus
from preview_dashboard.application.claudia.kb import KbRefusedError, KbService
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.ports.claudia_gardener import ChangedFile, GardenModelRun

TODAY = datetime.date(2026, 11, 9)
FM = "---\ntags: [a]\nupdated: 2026-11-01\nsources: [dashboard:X@rev3]\n---\n"


def note(body: str = "Short body.") -> str:
    return f"{FM}{body}\n"


class Reporter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, bool]] = []

    def report(self, title: str, markdown: str, *, ok: bool) -> None:
        self.calls.append((markdown, ok))


class Model:
    """Edits and commits like the claudia-kb child, then reports success."""

    def __init__(self, store: FsKbStore) -> None:
        self.store = store

    def run(self, prompt: str) -> GardenModelRun:
        self.store.write("topics/c/new.md", note("model wrote this").encode())
        self.store.commit("mcp: run")  # the MCP child's own commit, not the host's
        return GardenModelRun(ok=True, text="done")


class FailingCommitStore(FsKbStore):
    """Fails the host's post-run commit (e.g. a held `.git/index.lock`)."""

    def commit(self, message: str) -> str | None:
        if message == "gardener: run":
            raise StorageUnavailableError("git add failed")
        return super().commit(message)


class FailingDiffGit(GitKbHistory):
    def changed_since(self, base: str) -> list[ChangedFile]:
        raise StorageUnavailableError("git diff failed")


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "kb"
    r.mkdir(mode=0o750)
    return r


def seeded(store: FsKbStore) -> FsKbStore:
    store.write("persona.md", b"Persona.\n")
    store.write("index.md", b"- [[topics/c/a]]\n")
    store.write("now.md", b"Now.\n")
    store.write("topics/c/a.md", note("A.").encode())
    store.write("journal/2026-09-01-x.md", note("- a bullet").encode())  # old: one finding
    store.commit("seed")
    return store


def gardener(
    root: Path, store: FsKbStore, git: GitKbHistory, reporter: Reporter, **kw: object
) -> Gardener:
    return Gardener(
        store,
        git,
        Model(store),
        RegexSecretScanner(),
        reporter,
        lambda: TODAY,
        **kw,  # type: ignore[arg-type]
    )


# --- kb-map-1 -------------------------------------------------------------------------------


def test_kb_map_1_post_run_commit_failure_reverts_and_alerts(root: Path) -> None:
    store = seeded(FailingCommitStore(root))
    rep = Reporter()
    report = gardener(root, store, GitKbHistory(root), rep).run()
    assert report.status is GardenStatus.REVERTED
    assert "post-run check failed" in " ".join(report.violations)
    assert store.read("topics/c/new.md") is None  # the model's committed change is undone
    assert rep.calls and rep.calls[-1][1] is False  # failed alert


def test_kb_map_1_post_run_diff_failure_reverts_and_alerts(root: Path) -> None:
    store = seeded(FsKbStore(root))
    rep = Reporter()
    report = gardener(root, store, FailingDiffGit(root), rep).run()
    assert report.status is GardenStatus.REVERTED
    assert store.read("topics/c/new.md") is None
    assert rep.calls[-1][1] is False


def test_kb_map_1_failed_revert_still_sends_a_failed_alert(root: Path) -> None:
    class BadRevert(FailingDiffGit):
        def revert_since(self, base: str) -> str | None:
            raise StorageUnavailableError("revert failed")

    store = seeded(FsKbStore(root))
    rep = Reporter()
    with pytest.raises(StorageUnavailableError):
        gardener(root, store, BadRevert(root), rep).run()
    assert rep.calls and rep.calls[-1][1] is False


def test_kb_map_1_runner_reaps_the_process_group_after_a_normal_exit(tmp_path: Path) -> None:
    pidfile = tmp_path / "child.pid"
    fake = tmp_path / "claude"
    fake.write_text(
        "#!/bin/sh\n"
        f"sleep 60 &\necho $! > {pidfile}\n"
        'echo \'{"type":"result","is_error":false,"result":"ok"}\'\n'
    )
    fake.chmod(stat.S_IRWXU)
    kb = tmp_path / "kb"
    kb.mkdir()
    model = ClaudeGardenModel(fake, kb, "SYS", {"PATH": "/usr/bin:/bin"}, timeout_s=20)
    assert model.run("prompt").ok
    pid = int(pidfile.read_text())
    deadline = time.monotonic() + 3  # init reaps the killed orphan asynchronously
    while _alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(pid)  # the orphaned "sleep" was killed with the group


def _alive(pid: int) -> bool:
    try:
        return not Path(f"/proc/{pid}/stat").read_text().split(") ")[1].startswith("Z")
    except OSError:
        return False


# --- kb-map-2 -------------------------------------------------------------------------------


def test_kb_map_2_gardener_run_blocks_other_writers(root: Path) -> None:
    gardener_store = FsKbStore(root, exempt_run_lock=True)
    claudia = FsKbStore(root, lock_wait_s=0.2)
    with gardener_store.exclusive_run():
        with pytest.raises(StorageUnavailableError, match="busy"):
            claudia.write("now.md", b"x\n")
        with pytest.raises(StorageUnavailableError, match="busy"):
            claudia.commit("claudia: run")
        gardener_store.write("now.md", b"gardener may write\n")  # its own store is exempt
    claudia.write("now.md", b"after the run\n")
    assert claudia.read("now.md") == b"after the run\n"


def test_kb_map_2_writers_share_the_run_lock_and_serialise_on_the_mutex(root: Path) -> None:
    a, b = FsKbStore(root, lock_wait_s=0.2), FsKbStore(root, lock_wait_s=0.2)
    # Hold the short mutex like a write in flight.
    with a._locked(), pytest.raises(StorageUnavailableError, match="busy"):
        b.write("now.md", b"x\n")
    b.write("now.md", b"x\n")


def test_kb_map_2_gardener_holds_the_lock_for_the_whole_run(root: Path) -> None:
    store = seeded(FsKbStore(root, exempt_run_lock=True))
    other = FsKbStore(root, lock_wait_s=0.1)
    seen: list[str] = []

    class Probe(Model):
        def run(self, prompt: str) -> GardenModelRun:
            try:
                other.write("now.md", b"claudia\n")
            except StorageUnavailableError as exc:
                seen.append(str(exc))
            return super().run(prompt)

    g = Gardener(
        store,
        GitKbHistory(root),
        Probe(store),
        RegexSecretScanner(),
        Reporter(),
        lambda: TODAY,
        run_guard=store.exclusive_run,
    )
    g.run()
    assert seen == ["knowledge base is busy"]
    other.write("now.md", b"claudia\n")  # released afterwards


def test_kb_map_2_lock_files_are_not_notes(root: Path) -> None:
    s = FsKbStore(root)
    s.write("now.md", b"x\n")
    s.commit("c")
    assert (root / ".lock").exists()
    assert s.stats().files == 1  # lock files are never counted as notes


# --- kb-map-3 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ch",
    [chr(c) for c in (0x202E, 0x200B, 0xE0041, 0x2066, 0xFEFF, 0x2060, 0xAD, 0x61C)],
)
def test_kb_map_3_invisible_and_bidi_characters_refused(root: Path, ch: str) -> None:
    svc = KbService(FsKbStore(root), RegexSecretScanner())
    with pytest.raises(KbRefusedError):
        svc.write("topics/c/n.md", note(f"hidden{ch}text"), caller="claudia")


def test_kb_map_3_legitimate_emoji_joiners_still_allowed(root: Path) -> None:
    svc = KbService(FsKbStore(root), RegexSecretScanner())
    text = note("family \U0001f468\u200d\U0001f469 heart \u2764\ufe0f plain")
    svc.write("topics/c/n.md", text, caller="claudia")
    assert svc.read("topics/c/n.md") == text


def test_kb_map_3_a_bare_joiner_is_refused(root: Path) -> None:
    svc = KbService(FsKbStore(root), RegexSecretScanner())
    with pytest.raises(KbRefusedError):
        svc.write("topics/c/n.md", note("a\u200db"), caller="claudia")


# --- kb-map-7 -------------------------------------------------------------------------------


def test_kb_map_7_mcp_child_runs_isolated(root: Path) -> None:
    cfg = kb_mcp_config(root, sys.executable)
    servers = cfg["mcpServers"]
    assert isinstance(servers, dict)
    server = servers["claudia-kb"]
    assert server["command"] == sys.executable
    assert server["args"][:3] == ["-I", "-m", "preview_dashboard.interfaces.claudia.kb_mcp"]
    json.dumps(cfg)  # stays serialisable for the temp config file
