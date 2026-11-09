"""Security tests for the knowledge map's KB source (docs/security.md C57, unit M8).

Each test plants one hostile shape in a tmp KB (symlink, FIFO, hardlink, dotfile,
oversized or deep file, unsafe root, forged id) and checks the viewer neither
reads it nor leaks it; plus: GET/HEAD only, no KB routes on the preview origin,
bounded parser, no innerHTML in the map's JS, env cannot point the map elsewhere.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import pytest
from pydantic_settings import SettingsError

from preview_dashboard.adapters import kb_reader
from preview_dashboard.application import kb_graph
from preview_dashboard.config import Settings
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.interfaces.viewer.static_assets import default_static_dir
from tests.kb_viewer_support import KEY, graph_service, kb_client, reader, write_kb
from tests.viewer_support import csrf_headers, owner_headers, preview_app, route_paths

pytestmark = pytest.mark.security

STATIC = default_static_dir()
KMAP_JS = ["knowledge-map.js", "kmap-layout.js", "kmap-note.js", "kmap-approvals.js"]


def _relpaths(root: Path) -> set[str]:
    return {note.relpath for note in reader(root).walk().notes}


@pytest.fixture
def kb(tmp_path: Path) -> Path:
    return write_kb(
        tmp_path / "kb",
        {
            "index.md": "Start at [[alpha]].\n",
            "topics/work/alpha.md": "---\ntags: [x]\n---\nSee [[beta]].\n",
            "topics/work/beta.md": "---\ntags: [x]\n---\nBack to [[index]].\n",
        },
    )


def test_c57_reads_a_plain_tree(kb: Path) -> None:
    walk = reader(kb).walk()
    assert {n.relpath for n in walk.notes} == {
        "index.md",
        "topics/work/alpha.md",
        "topics/work/beta.md",
    }
    assert walk.skipped == 0 and not walk.truncated


def test_c57_symlinks_are_not_followed(kb: Path, tmp_path: Path) -> None:
    secret = tmp_path / "secret.md"
    secret.write_text("TOKEN", "utf-8")
    (kb / "leak.md").symlink_to(secret)
    (kb / "topics" / "outside").symlink_to(tmp_path)
    walk = reader(kb).walk()
    assert "leak.md" not in {n.relpath for n in walk.notes}
    assert not any("TOKEN" in n.text for n in walk.notes)
    assert walk.skipped == 2


def test_c57_fifo_is_skipped_without_blocking(kb: Path) -> None:
    os.mkfifo(kb / "pipe.md")
    walk = reader(kb).walk()
    assert "pipe.md" not in {n.relpath for n in walk.notes}
    assert walk.skipped == 1


def test_c57_hardlinked_file_is_skipped(kb: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("TOKEN", "utf-8")
    os.link(outside, kb / "linked.md")
    assert "linked.md" not in _relpaths(kb)


def test_c57_dotfiles_and_git_are_skipped(kb: Path) -> None:
    write_kb(kb, {".hidden.md": "x", ".git/config.md": "x", "bad name.md": "x"})
    paths = _relpaths(kb)
    assert not any(p.startswith(".") or "/." in p or " " in p for p in paths)


def test_c57_oversized_file_is_skipped(kb: Path) -> None:
    write_kb(kb, {"big.md": "a" * (kb_reader.MAX_FILE_BYTES + 1)})
    walk = reader(kb).walk()
    assert "big.md" not in {n.relpath for n in walk.notes}
    assert walk.skipped == 1


def test_c57_non_utf8_and_non_markdown_are_skipped(kb: Path) -> None:
    write_kb(kb, {"bin.md": b"\xff\xfe\x00", "notes.txt": "x"})
    assert {"bin.md", "notes.txt"}.isdisjoint(_relpaths(kb))


def test_c57_depth_is_capped(kb: Path) -> None:
    write_kb(kb, {"a/b/c/d/ok.md": "x", "a/b/c/d/e/deep.md": "x"})
    paths = _relpaths(kb)
    assert "a/b/c/d/ok.md" in paths
    assert "a/b/c/d/e/deep.md" not in paths


def test_c57_file_and_total_budgets_truncate(kb: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_kb(kb, {f"n{i}.md": "x" for i in range(5)})
    monkeypatch.setattr(kb_reader, "MAX_FILES", 3)
    walk = reader(kb).walk()
    assert len(walk.notes) == 3 and walk.truncated
    monkeypatch.setattr(kb_reader, "MAX_FILES", 2000)
    monkeypatch.setattr(kb_reader, "MAX_TOTAL_BYTES", 40)
    walk = reader(kb).walk()
    assert sum(len(n.text) for n in walk.notes) <= 40 and walk.truncated


def test_c57_group_writable_subdir_is_skipped(kb: Path) -> None:
    os.chmod(kb / "topics", 0o770)  # noqa: S103 - the unsafe mode under test
    assert _relpaths(kb) == {"index.md"}


@pytest.mark.parametrize("mode", [0o770, 0o757])
def test_c57_unsafe_root_turns_the_map_off(kb: Path, mode: int) -> None:
    os.chmod(kb, mode)
    with pytest.raises(StorageUnavailableError):
        reader(kb).walk()
    response = kb_client(kb).get("/api/kb/graph", headers=owner_headers())
    assert response.status_code == 404


def test_c57_root_owned_by_someone_else_is_refused(kb: Path) -> None:
    with pytest.raises(StorageUnavailableError):
        kb_reader.FsKbReader(kb, expected_uid=os.getuid() + 1).walk()


def test_c57_symlinked_root_or_parent_is_refused(kb: Path, tmp_path: Path) -> None:
    (tmp_path / "alias").symlink_to(kb)
    with pytest.raises(StorageUnavailableError):
        reader(tmp_path / "alias").walk()
    with pytest.raises(StorageUnavailableError):
        reader(tmp_path / "alias" / "topics").walk()
    with pytest.raises(StorageUnavailableError):
        reader(tmp_path / "missing").walk()


def test_c57_skipped_entries_are_logged_as_counts_only(
    kb: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (kb / "secret-name.md").symlink_to(tmp_path)
    with caplog.at_level(logging.INFO):
        reader(kb).walk()
    assert caplog.records
    assert not any("secret-name" in r.getMessage() for r in caplog.records)


def test_c57_ids_are_opaque(kb: Path) -> None:
    body = kb_client(kb).get("/api/kb/graph", headers=owner_headers()).json()
    ids = [n["id"] for n in body["nodes"]]
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    text = str(body)
    assert "topics/" not in text and ".md" not in text


@pytest.mark.parametrize(
    "note_id",
    ["../index", "index.md", "%2e%2e%2fsecret", "A" * 32, "0" * 31, "0" * 33, "g" * 32],
)
def test_c57_malformed_ids_are_refused(kb: Path, note_id: str) -> None:
    response = kb_client(kb).get(f"/api/kb/notes/{note_id}", headers=owner_headers())
    assert response.status_code in (400, 404)
    assert "TOKEN" not in response.text


def test_c57_forged_id_is_not_found(kb: Path) -> None:
    other = kb_graph.KbGraphService(reader(kb), graph_service(kb)._clock, key=b"x" * 32)
    forged = other.note_id("index.md")
    response = kb_client(kb).get(f"/api/kb/notes/{forged}", headers=owner_headers())
    assert response.status_code == 404


def test_c57_link_traversal_stays_unresolved(kb: Path, tmp_path: Path) -> None:
    (tmp_path / "secret.md").write_text("TOKEN", "utf-8")
    write_kb(kb, {"evil.md": "[[../secret]] [[/etc/passwd]] [[../../secret.md]]"})
    service = graph_service(kb)
    detail = service.note(service.note_id("evil.md"))
    assert all(link.id is None for link in detail.links)


def test_c57_note_round_trip(kb: Path) -> None:
    client = kb_client(kb)
    alpha = kb_graph.KbGraphService(reader(kb), graph_service(kb)._clock, key=KEY)
    note_id = alpha.note_id("topics/work/alpha.md")
    body = client.get(f"/api/kb/notes/{note_id}", headers=owner_headers()).json()
    assert body["title"] == "Alpha" and body["category"] == "work"
    assert body["links"] == [{"target": "beta", "id": alpha.note_id("topics/work/beta.md")}]
    assert body["backlinks"] == [{"id": alpha.note_id("index.md"), "title": "Index"}]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "path", ["/api/kb/graph", f"/api/kb/notes/{'0' * 32}", "/api/claudia/approvals"]
)
def test_c57_routes_are_read_only(kb: Path, method: str, path: str) -> None:
    response = kb_client(kb).request(method, path, headers=csrf_headers())
    assert response.status_code in (403, 405)


def test_c57_routes_need_owner_headers(kb: Path) -> None:
    response = kb_client(kb).get("/api/kb/graph")
    assert response.status_code in (400, 403, 421)


def test_c57_query_strings_are_refused(kb: Path) -> None:
    response = kb_client(kb).get("/api/kb/graph?path=/etc", headers=owner_headers())
    assert response.status_code == 400


def test_c57_preview_app_has_no_kb_routes() -> None:
    paths = route_paths(preview_app())
    assert not any(p.startswith(("/api/kb", "/api/claudia")) for p in paths)


def test_c57_map_is_off_without_kb_root() -> None:
    client = kb_client(None)
    assert client.get("/api/kb/graph", headers=owner_headers()).status_code == 404
    assert client.get(f"/api/kb/notes/{'0' * 32}", headers=owner_headers()).status_code == 404


def test_c57_parser_is_bounded() -> None:
    links = " ".join(f"[[n{i}]]" for i in range(kb_graph.MAX_LINKS_PER_NOTE + 50))
    tags = ", ".join(f"t{i}" for i in range(kb_graph.MAX_TAGS + 10))
    parsed = kb_graph.parse_note(f"---\ntags: [{tags}]\n---\n{links}")
    assert len(parsed.links) == kb_graph.MAX_LINKS_PER_NOTE
    assert len(parsed.tags) == kb_graph.MAX_TAGS
    # An unclosed or huge frontmatter block is plain body, never parsed as fields.
    huge = "---\n" + "tags: [a]\n" * (kb_graph.MAX_FRONTMATTER_LINES + 5) + "---\nbody"
    assert kb_graph.parse_note(huge).tags == ()
    assert kb_graph.parse_note("---\ntags: [a]\nno end").tags == ()


def test_c57_parser_reads_only_links_tags_and_updated() -> None:
    parsed = kb_graph.parse_note(
        "---\ntitle: Evil\nowner: x\nupdated: 2026-01-02\ntags: a\n---\n# H"
    )
    assert parsed.tags == ("a",)
    assert parsed.updated is not None and parsed.updated.isoformat() == "2026-01-02"
    assert {f for f in parsed.__dataclass_fields__} == {"tags", "updated", "links", "body"}


@pytest.mark.parametrize("name", KMAP_JS)
def test_c57_map_js_never_uses_html_sinks(name: str) -> None:
    text = (STATIC / name).read_text("utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in text, (name, sink)


def test_c57_kb_root_cannot_come_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_KB_ROOT", str(tmp_path))
    with pytest.raises(SettingsError):
        Settings()
    monkeypatch.delenv("PDASH_KB_ROOT")
    monkeypatch.setenv("PDASH_CLAUDIA_APPROVALS_SNAPSHOT", str(tmp_path / "s.json"))
    with pytest.raises(SettingsError):
        Settings()
