"""Security tests for C53: KB writes only through the host (layout, caps, scan, confinement)."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia import kb
from preview_dashboard.application.claudia.kb import KbRefusedError, KbService
from preview_dashboard.domain.errors import (
    NotFoundError,
    SecretDetectedError,
    StorageUnavailableError,
)

FM = "---\ntags: [a]\nupdated: 2026-11-09\nsources: [dashboard:X@rev3]\n---\n"


def note(body: str = "Short body.") -> str:
    return f"{FM}{body}\n"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "kb"
    r.mkdir(mode=0o750)
    return r


@pytest.fixture
def svc(root: Path) -> KbService:
    return KbService(FsKbStore(root), RegexSecretScanner())


class TestLayout:
    @pytest.mark.parametrize(
        "path",
        [
            "index.md",
            "now.md",
            "topics/people/_topic.md",
            "topics/people/ana-1.md",
            "topics/work-log/2026-11.md",
            "journal/2026-11-09-evening.md",
        ],
    )
    def test_c53_layout_paths_accepted(self, svc: KbService, path: str) -> None:
        text = "x\n" if path in ("index.md", "now.md", "topics/people/_topic.md") else note()
        svc.write(path, text, caller="claudia")
        assert svc.read(path) == text

    @pytest.mark.parametrize(
        "path",
        [
            "../x.md",
            "topics/../../x.md",
            "/etc/passwd",
            "topics/a/b/c.md",
            "topics/Upper/n.md",
            "topics/a/n.txt",
            "topics/a/n",
            "topics/a/.md",
            "topics//n.md",
            "topics/a/" + "x" * 49 + ".md",
            "topics/a\\b.md",
            "topics/a/n.md\0",
            "topics/" + chr(0x430) + "/n.md",  # Cyrillic a
            "topics/work-log/notes.md",
            "topics/work-log/2026-13.md",
            "journal/2026-02-30-x.md",
            "journal/x.md",
            "other.md",
            ".git/config",
            ".tmp-abc",
        ],
    )
    def test_c53_odd_paths_refused(self, svc: KbService, path: str) -> None:
        with pytest.raises(KbRefusedError):
            svc.write(path, note(), caller="claudia")
        with pytest.raises(KbRefusedError):
            svc.read(path)


class TestPersona:
    @pytest.mark.parametrize("caller", ["claudia", "recap", "gardener", "root", "x"])
    def test_c53_persona_write_and_delete_refused_for_every_caller(
        self, svc: KbService, root: Path, caller: str
    ) -> None:
        svc.seed()
        before = (root / "persona.md").read_bytes()
        with pytest.raises(KbRefusedError):
            svc.write("persona.md", "I am evil\n", caller=caller)
        with pytest.raises(KbRefusedError):
            svc.delete("persona.md", caller=caller)
        assert (root / "persona.md").read_bytes() == before

    def test_persona_is_readable_and_seeded_once(self, svc: KbService, root: Path) -> None:
        assert set(svc.seed()) == {"persona.md", "index.md", "now.md"}
        assert "joyful" in svc.read("persona.md")
        (root / "now.md").write_text("mine\n")
        assert svc.seed() == []
        assert (root / "now.md").read_text() == "mine\n"

    def test_seeds_satisfy_their_own_caps(self, svc: KbService) -> None:
        svc.seed()
        for p in ("index.md", "now.md"):
            svc.write(p, svc.read(p), caller="claudia")


class TestCaps:
    def test_c53_now_md_40_lines(self, svc: KbService) -> None:
        svc.write("now.md", "l\n" * 40, caller="claudia")
        with pytest.raises(KbRefusedError, match="lines"):
            svc.write("now.md", "l\n" * 41, caller="claudia")

    def test_c53_topic_150_words(self, svc: KbService) -> None:
        p = "topics/c/_topic.md"
        svc.write(p, "w " * 150, caller="claudia")
        with pytest.raises(KbRefusedError, match="words"):
            svc.write(p, "w " * 151, caller="claudia")

    def test_c53_note_300_words(self, svc: KbService) -> None:
        p = "topics/c/n.md"
        svc.write(p, note("w " * 300), caller="claudia")
        with pytest.raises(KbRefusedError, match="words"):
            svc.write(p, note("w " * 301), caller="claudia")

    def test_c53_note_4kib(self, svc: KbService) -> None:
        p = "topics/c/n.md"
        svc.write(p, note("w" * (4096 - len(note("")) - 1)), caller="claudia")
        with pytest.raises(KbRefusedError, match="bytes"):
            svc.write(p, note("w" * 4096), caller="claudia")

    def test_c53_journal_10_bullets(self, svc: KbService) -> None:
        p = "journal/2026-11-09-a.md"
        svc.write(p, note("- b\n" * 10), caller="claudia")
        with pytest.raises(KbRefusedError, match="bullets"):
            svc.write(p, note("- b\n" * 11), caller="claudia")

    def test_c53_2000_notes(
        self, svc: KbService, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(kb, "MAX_NOTES", 3)
        for i in range(3):
            svc.write(f"topics/c/n{i}.md", note(), caller="claudia")
        with pytest.raises(KbRefusedError, match="full"):
            svc.write("topics/c/n3.md", note(), caller="claudia")
        svc.write("topics/c/n0.md", note("replace"), caller="claudia")  # replacing is fine
        svc.delete("topics/c/n1.md", caller="claudia")
        svc.write("topics/c/n3.md", note(), caller="claudia")

    def test_c53_8mib_total(self, svc: KbService, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(kb, "MAX_TOTAL_BYTES", 600)
        svc.write("topics/c/a.md", note("x" * 300), caller="claudia")
        with pytest.raises(KbRefusedError, match="8 MiB"):
            svc.write("topics/c/b.md", note("x" * 300), caller="claudia")
        # Replacing a note counts only the growth.
        svc.write("topics/c/a.md", note("x" * 310), caller="claudia")

    def test_refused_write_leaves_old_note(self, svc: KbService) -> None:
        svc.write("topics/c/n.md", note("old"), caller="claudia")
        with pytest.raises(KbRefusedError):
            svc.write("topics/c/n.md", note("w " * 400), caller="claudia")
        assert "old" in svc.read("topics/c/n.md")

    @pytest.mark.parametrize(
        "text",
        ["# no frontmatter\n", "---\ntags: [a]\n---\nbody\n", "---\nsources: []\n---\nb\n"],
    )
    def test_c53_notes_must_name_sources(self, svc: KbService, text: str) -> None:
        with pytest.raises(KbRefusedError):
            svc.write("topics/c/n.md", text, caller="claudia")

    def test_block_style_sources_accepted(self, svc: KbService) -> None:
        svc.write("topics/c/n.md", "---\nsources:\n  - pr:4@t\n---\nb\n", caller="claudia")

    def test_control_chars_and_empty_refused(self, svc: KbService) -> None:
        for bad in ("a\x00b", "a\x1b[2Jb", "a\rb", "", "   \n", "a\ud800b"):
            with pytest.raises(KbRefusedError):
                svc.write("now.md", bad, caller="claudia")

    def test_index_and_now_cannot_be_deleted(self, svc: KbService) -> None:
        svc.seed()
        for p in ("index.md", "now.md"):
            with pytest.raises(KbRefusedError):
                svc.delete(p, caller="claudia")

    def test_delete_missing_is_not_found(self, svc: KbService) -> None:
        with pytest.raises(NotFoundError):
            svc.delete("topics/c/none.md", caller="claudia")
        with pytest.raises(NotFoundError):
            svc.read("topics/c/none.md")

    def test_bad_caller_label_refused(self, svc: KbService) -> None:
        with pytest.raises(KbRefusedError):
            svc.write("now.md", "x\n", caller="Bad Caller")


class TestSecretScan:
    AWS = "AKIA" + "IOSFODNN7EXAMPLE"  # split: the file itself stays scan-clean

    def test_c53_secret_refused_nothing_stored(self, svc: KbService, root: Path) -> None:
        with pytest.raises(SecretDetectedError) as ei:
            svc.write("topics/c/n.md", note(f"key {self.AWS}"), caller="claudia")
        assert self.AWS not in str(ei.value)
        assert not (root / "topics").exists()

    def test_c53_nfkc_folded_secret_refused(self, svc: KbService) -> None:
        fullwidth = "".join(chr(ord(c) + 0xFEE0) for c in self.AWS)
        with pytest.raises(SecretDetectedError):
            svc.write("now.md", f"k {fullwidth}\n", caller="claudia")

    def test_c53_joiner_split_secret_refused(self, svc: KbService) -> None:
        split = "AKIA‍IOSFODNN7EXAMPLE"
        # A bare joiner is now refused by the character filter (kb-map-3) before the
        # scan; either way the split secret never reaches disk.
        with pytest.raises((SecretDetectedError, KbRefusedError)):
            svc.write("now.md", f"k {split}\n", caller="claudia")

    def test_secret_in_frontmatter_refused(self, svc: KbService) -> None:
        text = f"---\nsources: [{self.AWS}]\n---\nb\n"
        with pytest.raises(SecretDetectedError):
            svc.write("topics/c/n.md", text, caller="claudia")


class TestConfinement:
    def test_c53_planted_symlink_file_not_followed(
        self, svc: KbService, root: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside.md"
        outside.write_text("orig")
        (root / "topics").mkdir()
        (root / "topics" / "c").mkdir()
        (root / "topics" / "c" / "n.md").symlink_to(outside)
        with pytest.raises(StorageUnavailableError):
            svc.write("topics/c/n.md", note(), caller="claudia")
        with pytest.raises(StorageUnavailableError):
            svc.read("topics/c/n.md")
        with pytest.raises(StorageUnavailableError):
            svc.delete("topics/c/n.md", caller="claudia")
        assert outside.read_text() == "orig"

    def test_c53_planted_symlink_dir_not_followed(
        self, svc: KbService, root: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outdir"
        outside.mkdir()
        (root / "topics").symlink_to(outside)
        with pytest.raises(StorageUnavailableError):
            svc.write("topics/c/n.md", note(), caller="claudia")
        assert list(outside.iterdir()) == []

    def test_c53_planted_fifo_refused_without_hanging(self, svc: KbService, root: Path) -> None:
        os.mkfifo(root / "now.md")
        with pytest.raises(StorageUnavailableError):
            svc.read("now.md")
        with pytest.raises(StorageUnavailableError):
            svc.write("now.md", "x\n", caller="claudia")

    def test_c53_planted_hardlink_refused(self, svc: KbService, root: Path, tmp_path: Path) -> None:
        other = tmp_path / "elsewhere"
        other.write_text("secret-ish")
        os.link(other, root / "now.md")
        with pytest.raises(StorageUnavailableError):
            svc.read("now.md")
        with pytest.raises(StorageUnavailableError):
            svc.write("now.md", "x\n", caller="claudia")
        assert other.read_text() == "secret-ish"

    def test_odd_entries_not_counted(self, svc: KbService, root: Path, tmp_path: Path) -> None:
        (root / "link.md").symlink_to(tmp_path)
        os.mkfifo(root / "fifo.md")
        (root / "notes.txt").write_text("x")
        assert svc.write("now.md", "x\n", caller="claudia").size_bytes == 2
        assert FsKbStore(root).stats().files == 1

    def test_symlinked_root_refused(self, root: Path, tmp_path: Path) -> None:
        link = tmp_path / "kblink"
        link.symlink_to(root)
        with pytest.raises(StorageUnavailableError):
            FsKbStore(link)

    def test_no_temp_files_left(self, svc: KbService, root: Path) -> None:
        svc.write("topics/c/n.md", note(), caller="claudia")
        assert [p.name for p in (root / "topics" / "c").iterdir()] == ["n.md"]


class TestModes:
    def test_c53_dir_and_file_modes(self, svc: KbService, root: Path) -> None:
        old = os.umask(0o077)  # a strict umask must not break group read (C57)
        try:
            svc.write("topics/c/n.md", note(), caller="claudia")
        finally:
            os.umask(old)
        assert stat.S_IMODE((root / "topics").stat().st_mode) == 0o750
        assert stat.S_IMODE((root / "topics" / "c").stat().st_mode) == 0o750
        assert stat.S_IMODE((root / "topics" / "c" / "n.md").stat().st_mode) == 0o640

    def test_group_is_applied_when_given(self, root: Path) -> None:
        gid = os.getgid()
        s = KbService(FsKbStore(root, group_id=gid), RegexSecretScanner())
        s.write("now.md", "x\n", caller="claudia")
        assert (root / "now.md").stat().st_gid == gid


def git(root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(root), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout


class TestCommitPerRun:
    def test_c53_one_commit_per_run_with_host_identity(self, svc: KbService, root: Path) -> None:
        svc.write("now.md", "a\n", caller="claudia")
        svc.write("topics/c/n.md", note(), caller="claudia")
        svc.delete("topics/c/n.md", caller="claudia")
        svc.write("topics/c/m.md", note(), caller="claudia")
        assert svc.commit_run("claudia: run 1") is not None
        assert git(root, "rev-list", "--count", "HEAD").strip() == "1"
        assert (
            git(root, "log", "-1", "--format=%an <%ae>").strip()
            == "Claudia host <claudia@localhost>"
        )
        assert sorted(git(root, "ls-files").split()) == ["now.md", "topics/c/m.md"]

    def test_c53_clean_run_makes_no_commit_and_second_run_second_commit(
        self, svc: KbService, root: Path
    ) -> None:
        svc.write("now.md", "a\n", caller="claudia")
        svc.commit_run("r1")
        assert svc.commit_run("r2") is None
        svc.write("now.md", "b\n", caller="claudia")
        svc.commit_run("r3")
        assert git(root, "rev-list", "--count", "HEAD").strip() == "2"

    def test_no_remote_and_only_md_committed(self, svc: KbService, root: Path) -> None:
        svc.write("now.md", "a\n", caller="claudia")
        (root / "stray.txt").write_text("x")
        svc.commit_run("r")
        assert git(root, "remote").strip() == ""
        assert git(root, "ls-files").split() == ["now.md"]

    def test_hooks_do_not_run(self, svc: KbService, root: Path) -> None:
        svc.write("now.md", "a\n", caller="claudia")
        svc.commit_run("r0")
        hook = root / ".git" / "hooks" / "pre-commit"
        hook.parent.mkdir(exist_ok=True)
        hook.write_text("#!/bin/sh\ntouch /tmp/kb-hook-ran-not-expected\nexit 1\n")
        hook.chmod(0o755)
        svc.write("now.md", "b\n", caller="claudia")
        assert svc.commit_run("r1") is not None
