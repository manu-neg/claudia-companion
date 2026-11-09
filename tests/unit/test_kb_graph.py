"""Unit tests for the knowledge-map graph (application/kb_graph.py, unit M8).

Uses an in-memory KbSource: parser fields, categories and titles, link
resolution (path suffix, ambiguity), tag edges, degree and the recent flag.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from preview_dashboard.application.kb_graph import (
    KbGraphService,
    category_of,
    parse_note,
    title_of,
)
from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.ports.kb_source import KbWalk, RawNote
from tests.fakes import FixedClock

NOW = datetime(2026, 11, 9, 12, tzinfo=UTC)
OLD = datetime(2026, 1, 1, tzinfo=UTC)


class _Source:
    def __init__(self, files: dict[str, str], modified: datetime = OLD) -> None:
        self._walk = KbWalk(
            notes=tuple(RawNote(p, t, modified) for p, t in files.items()),
            skipped=0,
            truncated=False,
        )

    def walk(self) -> KbWalk:
        return self._walk


def _service(files: dict[str, str], modified: datetime = OLD) -> KbGraphService:
    return KbGraphService(_Source(files, modified), FixedClock(NOW), key=b"k" * 32)


def test_parse_note_frontmatter_forms() -> None:
    assert parse_note("---\ntags: [a, b]\n---\nx").tags == ("a", "b")
    assert parse_note("---\ntags: a, b\n---\nx").tags == ("a", "b")
    assert parse_note("---\ntags:\n  - a\n  - b\n---\nx").tags == ("a", "b")
    assert parse_note("no frontmatter [[x]]").links == ("x",)


def test_parse_note_links_alias_heading_and_dedupe() -> None:
    parsed = parse_note("[[Alpha|the a]] [[alpha#part]] [[beta]] [[]]")
    assert parsed.links == ("Alpha", "beta")


@pytest.mark.parametrize(
    ("relpath", "category"),
    [
        ("index.md", "core"),
        ("topics/work/a.md", "work"),
        ("journal/2026-11-09.md", "journal"),
        ("topics/a.md", "topics"),
        ("Weird_Dir/a.md", "other"),
    ],
)
def test_category_of(relpath: str, category: str) -> None:
    assert category_of(relpath) == category


def test_title_of() -> None:
    assert title_of("topics/home-lab/_topic.md", "home-lab") == "Home lab overview"
    assert title_of("people/ana-lopez.md", "people") == "Ana lopez"


def test_resolves_by_name_and_path_suffix() -> None:
    service = _service(
        {
            "index.md": "[[alpha]] [[work/beta]] [[missing]]",
            "topics/work/alpha.md": "",
            "topics/work/beta.md": "",
        }
    )
    detail = service.note(service.note_id("index.md"))
    ids = [link.id for link in detail.links]
    assert ids == [
        service.note_id("topics/work/alpha.md"),
        service.note_id("topics/work/beta.md"),
        None,
    ]


def test_ambiguous_name_prefers_same_folder_else_unresolved() -> None:
    service = _service(
        {
            "a/note.md": "",
            "b/note.md": "",
            "a/x.md": "[[note]]",
            "c/y.md": "[[note]]",
        }
    )
    assert service.note(service.note_id("a/x.md")).links[0].id == service.note_id("a/note.md")
    assert service.note(service.note_id("c/y.md")).links[0].id is None


def test_tag_edges_chain_and_degree() -> None:
    service = _service({f"n{i}.md": "---\ntags: [t]\n---\n" for i in range(4)})
    graph = service.graph()
    assert len(graph.edges) == 3 and {e.kind for e in graph.edges} == {"tag"}
    assert sorted(n.degree for n in graph.nodes) == [1, 1, 2, 2]


def test_link_beats_tag_and_no_self_edges() -> None:
    service = _service(
        {"a.md": "---\ntags: [t]\n---\n[[b]] [[a]]", "b.md": "---\ntags: [t]\n---\n"}
    )
    graph = service.graph()
    assert [e.kind for e in graph.edges] == ["link"]


def test_recent_from_updated_or_mtime() -> None:
    service = _service({"a.md": "---\nupdated: 2026-11-05\n---\n", "b.md": ""})
    recent = {n.title: n.recent for n in service.graph().nodes}
    assert recent == {"A": True, "B": False}
    assert all(n.recent for n in _service({"c.md": ""}, modified=NOW).graph().nodes)


def test_categories_counted() -> None:
    graph = _service({"index.md": "", "topics/w/a.md": "", "topics/w/b.md": ""}).graph()
    assert graph.categories == (("core", 1), ("w", 2))


def test_note_errors() -> None:
    service = _service({"a.md": ""})
    with pytest.raises(ValidationError):
        service.note("../a")
    with pytest.raises(NotFoundError):
        service.note("0" * 32)


def test_ids_differ_per_key() -> None:
    a = KbGraphService(_Source({}), FixedClock(NOW))
    b = KbGraphService(_Source({}), FixedClock(NOW))
    assert a.note_id("x.md") != b.note_id("x.md")
