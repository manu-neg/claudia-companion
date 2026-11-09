"""Security tests for C54: the weekly gardener is confined, capped and reverted on violation.

A fake model stands in for `claude` (it edits the KB the way a misbehaving
model could); the KB is a real tmp git repo behind `FsKbStore`.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable
from pathlib import Path

import pytest

from preview_dashboard.adapters.gardener_runner import (
    KB_TOOLS,
    MAX_TURNS,
    gardener_argv,
    kb_mcp_config,
)
from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia.garden import Gardener, GardenReport, GardenStatus
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.interfaces.claudia import gardener as entry
from preview_dashboard.ports.claudia_gardener import GardenModelRun

TODAY = datetime.date(2026, 11, 9)
FM = "---\ntags: [a]\nupdated: 2026-11-01\nsources: [dashboard:X@rev3]\n---\n"
# Fake token shaped like a GitHub PAT; built from parts so the repo scan stays clean.
FAKE_SECRET = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def note(body: str = "Short body.") -> str:
    return f"{FM}{body}\n"


class FakeModel:
    def __init__(self, act: Callable[[FsKbStore], None], ok: bool = True) -> None:
        self.act, self.ok = act, ok
        self.prompts: list[str] = []
        self.store: FsKbStore | None = None

    def run(self, prompt: str) -> GardenModelRun:
        self.prompts.append(prompt)
        assert self.store is not None
        self.act(self.store)
        return GardenModelRun(ok=self.ok, text="done")


class FakeReporter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []

    def report(self, title: str, markdown: str, *, ok: bool) -> None:
        self.calls.append((title, markdown, ok))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "kb"
    r.mkdir(mode=0o750)
    return r


@pytest.fixture
def store(root: Path) -> FsKbStore:
    s = FsKbStore(root)
    s.write("persona.md", b"Persona.\n")
    s.write("index.md", b"- [[topics/people/ana]]\n")
    s.write("now.md", b"Now.\n")
    s.write("topics/people/ana.md", note("Ana is a friend.").encode())
    # Old journal -> one finding, so the model is always invoked.
    s.write("journal/2026-09-01-x.md", note("- a bullet").encode())
    s.commit("seed")
    return s


def garden(
    root: Path, store: FsKbStore, act: Callable[[FsKbStore], None], ok: bool = True
) -> tuple[GardenReport, FakeModel, FakeReporter]:
    model = FakeModel(act, ok)
    model.store = store
    rep = FakeReporter()
    g = Gardener(store, GitKbHistory(root), model, RegexSecretScanner(), rep, lambda: TODAY)
    return g.run(), model, rep


def head_text(store: FsKbStore, path: str) -> str | None:
    data = store.read(path)
    return None if data is None else data.decode()


def test_c54_argv_golden() -> None:
    argv = gardener_argv("/bin/claude", Path("/run/m.json"), "SYS")
    assert argv == [
        "/bin/claude",
        "-p",
        "--model",
        "haiku",
        "--output-format",
        "json",
        "--tools",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        "/run/m.json",
        "--allowedTools=mcp__claudia-kb__kb_read,mcp__claudia-kb__kb_write,mcp__claudia-kb__kb_delete",
        "--max-turns",
        "20",
        "--setting-sources",
        "",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--system-prompt",
        "SYS",
    ]
    assert MAX_TURNS == 20
    assert len(KB_TOOLS) == 3
    assert not any("dangerously" in a or "bypass" in a for a in argv)


def test_c54_mcp_config_is_kb_only_with_gardener_caller(root: Path) -> None:
    cfg = kb_mcp_config(root, "/usr/bin/python3")
    servers = cfg["mcpServers"]
    assert isinstance(servers, dict)
    assert list(servers) == ["claudia-kb"]
    args = servers["claudia-kb"]["args"]
    assert args[-2:] == ["--caller", "gardener"]
    assert str(root) in args


def test_c54_refuses_api_key_env(tmp_path: Path) -> None:
    code = entry.main(["--kb-root", str(tmp_path)], {"ANTHROPIC_API_KEY": "x"})
    assert code == entry.EXIT_REFUSED


def test_c54_clean_run_keeps_changes_and_reports_done(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.delete("journal/2026-09-01-x.md")
        s.write("topics/people/ana.md", note("Ana is a friend, folded.").encode())

    report, model, rep = garden(root, store, act)
    assert report.status is GardenStatus.DONE
    assert set(report.changed) == {"journal/2026-09-01-x.md", "topics/people/ana.md"}
    assert head_text(store, "journal/2026-09-01-x.md") is None
    assert "old-journal: journal/2026-09-01-x.md" in model.prompts[0]
    assert len(rep.calls) == 1 and rep.calls[0][2] is True
    assert FAKE_SECRET not in rep.calls[0][1]


def test_c54_nothing_to_do_skips_the_model(root: Path, store: FsKbStore) -> None:
    store.delete("journal/2026-09-01-x.md")
    store.commit("tidy")
    report, model, rep = garden(root, store, lambda s: None)
    assert report.status is GardenStatus.NOTHING_TO_DO
    assert model.prompts == []
    assert len(rep.calls) == 1


def assert_reverted(report: GardenReport, store: FsKbStore, rep: FakeReporter) -> None:
    assert report.status is GardenStatus.REVERTED
    assert report.revert_commit
    assert head_text(store, "journal/2026-09-01-x.md") == note("- a bullet")
    assert head_text(store, "topics/people/ana.md") == note("Ana is a friend.")
    assert len(rep.calls) == 1 and rep.calls[0][2] is False


def test_c54_file_cap_reverts(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        for i in range(31):
            s.write(f"topics/bulk/n{i}.md", note(f"Note {i}.").encode())

    report, _model, rep = garden(root, store, act)
    assert any("max 30" in v for v in report.violations)
    assert_reverted(report, store, rep)
    assert head_text(store, "topics/bulk/n0.md") is None


def test_c54_exactly_thirty_files_is_allowed(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        for i in range(30):
            s.write(f"topics/bulk/n{i}.md", note(f"Note {i}.").encode())

    report, _m, _r = garden(root, store, act)
    assert report.status is GardenStatus.DONE


def test_c54_cap_violation_reverts(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.write("topics/people/ana.md", note("word " * 400).encode())

    report, _m, rep = garden(root, store, act)
    assert any("max" in v for v in report.violations)
    assert_reverted(report, store, rep)


def test_c54_secret_in_changed_file_reverts(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.write("topics/people/ana.md", note(f"token {FAKE_SECRET}").encode())

    report, _m, rep = garden(root, store, act)
    assert any("secret scan" in v for v in report.violations)
    assert FAKE_SECRET not in rep.calls[0][1]  # the summary never echoes the match
    assert_reverted(report, store, rep)


def test_c54_persona_change_reverts(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.write("persona.md", b"Hijacked.\n")

    report, _m, rep = garden(root, store, act)
    assert "persona.md was changed" in report.violations
    assert head_text(store, "persona.md") == "Persona.\n"
    assert report.status is GardenStatus.REVERTED
    assert rep.calls[0][2] is False


def test_c54_persona_untouched_on_clean_run(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.delete("journal/2026-09-01-x.md")

    report, _m, _r = garden(root, store, act)
    assert report.status is GardenStatus.DONE
    assert head_text(store, "persona.md") == "Persona.\n"


def test_c54_deleting_now_md_reverts(root: Path, store: FsKbStore) -> None:

    def act(s: FsKbStore) -> None:
        s.delete("now.md")

    report, _m, _r = garden(root, store, act)
    assert report.status is GardenStatus.REVERTED
    assert head_text(store, "now.md") == "Now.\n"


def test_c54_failed_run_with_changes_reverts(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.delete("journal/2026-09-01-x.md")

    report, _m, rep = garden(root, store, act, ok=False)
    assert report.status is GardenStatus.REVERTED
    assert head_text(store, "journal/2026-09-01-x.md") == note("- a bullet")
    assert rep.calls[0][2] is False


def test_c54_model_crash_is_a_failed_run(root: Path, store: FsKbStore) -> None:
    def act(s: FsKbStore) -> None:
        s.delete("journal/2026-09-01-x.md")
        raise RuntimeError("boom")

    report, _m, _r = garden(root, store, act)
    assert report.status is GardenStatus.REVERTED
    assert head_text(store, "journal/2026-09-01-x.md") == note("- a bullet")


class CommitFailsAfterSeed(FsKbStore):
    """The post-run commit fails, so the model's files stay uncommitted in the work tree."""

    calls = 0

    def commit(self, message: str) -> str | None:
        self.calls += 1
        if self.calls > 1:
            raise StorageUnavailableError("git commit failed")
        return super().commit(message)


@pytest.mark.parametrize("staged", [False, True])
def test_c54_failed_post_run_commit_restores_and_cleans_the_work_tree(
    root: Path, store: FsKbStore, staged: bool
) -> None:
    """F-C2a-2 leftover: unverified model files must not wait for the next commit."""
    (root / "keep.txt").write_text("not a note\n")
    failing = CommitFailsAfterSeed(root)

    def act(s: FsKbStore) -> None:
        s.write("topics/people/ana.md", note(f"token {FAKE_SECRET}").encode())
        s.write("topics/new/planted.md", note("Planted.").encode())
        s.delete("now.md")
        if staged:
            GitKbHistory(root)._run("add", "-A", "--", "*.md")

    model = FakeModel(act)
    model.store = failing
    rep = FakeReporter()
    report = Gardener(
        failing, GitKbHistory(root), model, RegexSecretScanner(), rep, lambda: TODAY
    ).run()
    assert report.status is GardenStatus.REVERTED
    assert any("could not be verified" in v for v in report.violations)
    assert (root / "topics/people/ana.md").read_text() == note("Ana is a friend.")
    assert not (root / "topics/new/planted.md").exists()
    assert (root / "now.md").read_text() == "Now.\n"
    assert (root / "keep.txt").exists()  # only notes are cleaned
    assert (root / ".git").is_dir()
    status = GitKbHistory(root)._run("status", "--porcelain", "--", "*.md").stdout
    assert status == ""
    assert rep.calls[0][2] is False


def test_c54_restore_worktree_without_commits_is_a_no_op(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    GitKbHistory(empty)._run("init", "-q")
    (empty / "a.md").write_text("x\n")
    GitKbHistory(empty).restore_worktree()
    assert (empty / "a.md").exists()


def test_c54_uncommitted_changes_are_committed_then_checked(root: Path, store: FsKbStore) -> None:
    """The MCP server may die before its commit; the host commits and still verifies."""

    def act(s: FsKbStore) -> None:
        s.write("persona.md", b"Hijacked.\n")  # nothing commits this

    report, _m, _r = garden(root, store, act)
    assert report.status is GardenStatus.REVERTED
    assert head_text(store, "persona.md") == "Persona.\n"
