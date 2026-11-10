"""F-CL7 tests: host-owned guide.md is read-only for Claudia, and the topic-recording prompts."""

from __future__ import annotations

import datetime
import os
import stat
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia import garden_rules
from preview_dashboard.application.claudia.garden import Gardener, GardenStatus
from preview_dashboard.application.claudia.kb import (
    KbRefusedError,
    KbService,
    NoteKind,
    classify,
    load_prompt,
)
from preview_dashboard.application.claudia.runs import _RECAP_PROMPT, HOST_RULES_PROMPT
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.risky_actions import PEER_MESSAGE_PREFIX
from preview_dashboard.interfaces.claudia import kb_mcp
from preview_dashboard.ports.claudia_gardener import GardenModelRun
from preview_dashboard.ports.claudia_kb import KbBusyError


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "kb"
    r.mkdir(mode=0o750)
    return r


@pytest.fixture
def svc(root: Path) -> KbService:
    s = KbService(FsKbStore(root), RegexSecretScanner())
    s.seed()
    return s


@pytest.mark.parametrize("caller", ["claudia", "recap", "gardener"])
def test_c53_guide_write_and_delete_refused(svc: KbService, root: Path, caller: str) -> None:
    svc.sync_guide()
    before = (root / "guide.md").read_bytes()
    with pytest.raises(KbRefusedError, match=r"guide\.md"):
        svc.write("guide.md", "mine\n", caller=caller)
    with pytest.raises(KbRefusedError, match=r"guide\.md"):
        svc.delete("guide.md", caller=caller)
    assert (root / "guide.md").read_bytes() == before


@pytest.mark.parametrize(
    "path",
    [
        "Guide.md",
        "./guide.md",
        "//guide.md",
        "guide.md/",
        "gu" + chr(0x456) + "de.md",  # Cyrillic i
        chr(0xFF47) + "uide.md",  # fullwidth g
    ],
)
def test_c53_guide_path_variants_refused(svc: KbService, root: Path, path: str) -> None:
    svc.sync_guide()
    before = (root / "guide.md").read_bytes()
    with pytest.raises(KbRefusedError):
        svc.write(path, "mine\n", caller="claudia")
    with pytest.raises(KbRefusedError):
        svc.delete(path, caller="claudia")
    assert (root / "guide.md").read_bytes() == before


def test_guide_is_synced_overwritten_and_linked(svc: KbService, root: Path) -> None:
    assert svc.sync_guide() is True
    assert svc.read("guide.md") == load_prompt("seed/guide.md")
    assert "[[guide]]" in svc.read("index.md")
    assert svc.sync_guide() is False
    (root / "guide.md").write_text("tampered\n")
    (root / "index.md").write_text("# Index\n")
    assert svc.sync_guide() is True
    assert svc.read("guide.md") == load_prompt("seed/guide.md")
    assert svc.read("index.md").count("[[guide]]") == 1


def test_c53_sync_refuses_planted_symlink(svc: KbService, root: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.md"
    target.write_text("outside\n")
    (root / "guide.md").symlink_to(target)
    with pytest.raises(StorageUnavailableError):
        svc.sync_guide()
    assert target.read_text() == "outside\n"


def test_c53_sync_refuses_planted_fifo(svc: KbService, root: Path) -> None:
    os.mkfifo(root / "guide.md")
    with pytest.raises(StorageUnavailableError):
        svc.sync_guide()
    assert stat.S_ISFIFO((root / "guide.md").lstat().st_mode)


def test_synced_guide_has_mode_and_group(root: Path) -> None:
    gid = os.getgid()
    s = KbService(FsKbStore(root, group_id=gid), RegexSecretScanner())
    s.seed()
    old = os.umask(0o077)
    try:
        s.sync_guide()
    finally:
        os.umask(old)
    st = (root / "guide.md").stat()
    assert stat.S_IMODE(st.st_mode) == 0o640
    assert st.st_gid == gid


def test_guide_index_append_holds_the_lock_across_read_and_write(root: Path) -> None:
    """A write landing while sync waits for the lock must survive (no lost update)."""
    store = FsKbStore(root)
    s = KbService(store, RegexSecretScanner())
    s.seed()
    s.sync_guide()  # guide.md current: the next sync only touches the index
    store.write("index.md", b"# Old\n")
    entered, release = threading.Event(), threading.Event()

    def other_process() -> None:
        def hold() -> None:
            entered.set()
            release.wait(5)
            store._write("index.md", b"# Mine\n")  # the lock is already held

        store.run_locked(hold)

    holder = threading.Thread(target=other_process)
    holder.start()
    assert entered.wait(5)
    syncer = threading.Thread(target=s.sync_guide)
    syncer.start()
    syncer.join(0.3)  # blocked on the lock; with an unlocked read it would have read "# Old"
    release.set()
    holder.join(5)
    syncer.join(5)
    text = (root / "index.md").read_text()
    assert "# Mine" in text and "[[guide]]" in text


def test_guide_link_skipped_when_index_would_exceed_caps(svc: KbService, root: Path) -> None:
    (root / "index.md").write_text("- x\n" * 100)  # already at the line cap
    svc.sync_guide()
    assert "[[guide" not in (root / "index.md").read_text()
    assert (root / "guide.md").exists()


def test_guide_text_matches_host_rules() -> None:
    guide = load_prompt("seed/guide.md")
    assert PEER_MESSAGE_PREFIX in guide
    assert "request_approval" in guide
    assert "Claudia" in guide


def test_host_rule_8_records_topics_in_the_allowed_layout() -> None:
    assert "8. " in HOST_RULES_PROMPT
    assert HOST_RULES_PROMPT.index("7. ") < HOST_RULES_PROMPT.index("8. ")
    assert "topics/<category>/<note>.md" in HOST_RULES_PROMPT
    assert "guide.md" in HOST_RULES_PROMPT


def test_recap_prompts_fold_topics() -> None:
    assert "topics discussed" in _RECAP_PROMPT
    recap = load_prompt("recap.md")
    assert "topics, ideas, decisions" in recap
    assert "topics/<category>/<note>" in recap


def test_oversized_skips_guide() -> None:
    huge = "word " * 5000
    assert classify("guide.md") is NoteKind.GUIDE
    assert garden_rules._oversized({"guide.md": huge}, {"guide.md": NoteKind.GUIDE}) == []
    assert garden_rules._oversized({"now.md": huge}, {"now.md": NoteKind.NOW})


# -- gardener: a change to guide.md is reverted ------------------------------


class _Model:
    def __init__(self, act: Callable[[FsKbStore], None], store: FsKbStore) -> None:
        self._act, self._store = act, store

    def run(self, _prompt: str) -> GardenModelRun:
        self._act(self._store)
        return GardenModelRun(ok=True, text="done")


class _Reporter:
    def report(self, title: str, markdown: str, *, ok: bool) -> None:
        pass


def test_c54_guide_change_reverts(root: Path) -> None:
    store = FsKbStore(root)
    store.write("persona.md", b"Persona.\n")
    store.write("index.md", b"- [[guide]]\n")
    store.write("now.md", b"Now.\n")
    store.write("guide.md", b"Guide.\n")
    store.write("journal/2026-09-01-x.md", b"- a bullet\n")  # old: a finding, so the model runs
    store.commit("seed")

    def act(s: FsKbStore) -> None:
        s.write("guide.md", b"Hijacked.\n")

    gardener = Gardener(
        store,
        GitKbHistory(root),
        _Model(act, store),
        RegexSecretScanner(),
        _Reporter(),
        lambda: datetime.date(2026, 11, 9),
    )
    report = gardener.run()
    assert "guide.md was changed" in report.violations
    assert report.status is GardenStatus.REVERTED
    assert store.read("guide.md") == b"Guide.\n"


# -- claudia-kb startup ------------------------------------------------------


class _StubServer:
    def __init__(self) -> None:
        self.ran = False

    def run(self, _transport: str) -> None:
        self.ran = True


def _patch_main(monkeypatch: pytest.MonkeyPatch, sync: Callable[[KbService], bool]) -> _StubServer:
    server = _StubServer()
    monkeypatch.setattr(kb_mcp, "build_server", lambda _tools: server)
    monkeypatch.setattr(KbService, "sync_guide", sync)
    return server


def test_busy_guide_sync_does_not_stop_the_server(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def busy(_self: KbService) -> bool:
        raise KbBusyError("knowledge base is busy")

    server = _patch_main(monkeypatch, busy)
    assert kb_mcp.main(["--root", str(root), "--caller", "claudia"]) == kb_mcp.EXIT_OK
    assert server.ran


def test_other_guide_sync_failure_is_also_best_effort(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_self: KbService) -> bool:
        raise StorageUnavailableError("not a plain file")

    server = _patch_main(monkeypatch, broken)
    assert kb_mcp.main(["--root", str(root)]) == kb_mcp.EXIT_OK
    assert server.ran


def test_unexpected_startup_error_still_fails_closed(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_self: KbService) -> list[str]:
        raise RuntimeError("bug")

    monkeypatch.setattr(KbService, "seed", boom)
    assert kb_mcp.main(["--root", str(root)]) == kb_mcp.EXIT_FAILED


@pytest.mark.parametrize(("caller", "syncs"), [("claudia", 1), ("recap", 1), ("gardener", 0)])
def test_gardener_caller_skips_the_guide_sync(
    root: Path, monkeypatch: pytest.MonkeyPatch, caller: str, syncs: int
) -> None:
    calls: list[str] = []

    def count(_self: KbService) -> bool:
        calls.append(caller)
        return False

    _patch_main(monkeypatch, count)
    assert kb_mcp.main(["--root", str(root), "--caller", caller]) == kb_mcp.EXIT_OK
    assert len(calls) == syncs
