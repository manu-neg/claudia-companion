"""Knowledge map frontend (unit M8): pure layout helpers under node, plus wiring checks.

`kmap-layout.js` is driven under node (deterministic layout, fit, zoom, search);
`kmap-note.js` link splitting is driven too (DOM-free part). Grep checks pin the
router route, the shell shortcut and that note text never meets an HTML sink.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs only a fixed node script on our own files

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()

_SCRIPT = """
const L = await import(process.argv[1]);
const N = await import(process.argv[2]);
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };
const nodes = [
  { id: "a", title: "Alpha", category: "work", tags: ["x"], degree: 2 },
  { id: "b", title: "Beta", category: "work", tags: [], degree: 1 },
  { id: "c", title: "Home lab", category: "home", tags: ["net"], degree: 1 },
];
const edges = [
  { source: "a", target: "b", kind: "link" },
  { source: "a", target: "c", kind: "tag" },
];
const p1 = L.layoutGraph(nodes, edges, { size: 1000 });
const p2 = L.layoutGraph(nodes, edges, { size: 1000 });
check(p1.size === 3, "every node placed");
for (const [id, p] of p1) {
  check(Number.isFinite(p.x) && Number.isFinite(p.y), "finite " + id);
  check(p.x === p2.get(id).x && p.y === p2.get(id).y, "deterministic " + id);
}
check(L.layoutGraph([], []).size === 0, "empty graph");
const view = L.fitTransform(p1, 800, 600);
check(view.k > 0 && Number.isFinite(view.x), "fit");
const z = L.zoomAt({ x: 0, y: 0, k: 1 }, 2, 100, 100);
check(z.k === 2 && z.x === -100 && z.y === -100, "zoom keeps the point under the cursor");
check(L.zoomAt({ x: 0, y: 0, k: 1 }, 1e9, 0, 0).k <= 8, "zoom clamped");
check(L.nodeRadius(0) >= 4 && L.nodeRadius(1000) <= 14, "radius bounds");
check(L.neighbours(edges).get("a").has("c"), "neighbours");
check(L.matchesQuery(nodes[2], "home NET"), "title + tag match");
check(!L.matchesQuery(nodes[1], "alpha"), "no match");
check(L.matchesQuery(nodes[1], ""), "empty query matches");
const stack = () => [
  { id: "p", x: 100, y: 100 },
  { id: "q", x: 110, y: 102 },
  { id: "r", x: 400, y: 100 },
];
const titled = [
  { id: "p", title: "A rather long note title", degree: 1 },
  { id: "q", title: "Another long note title", degree: 1 },
  { id: "r", title: "Far away", degree: 1 },
];
const n1 = stack();
L.nudgeLabels(n1, titled);
const n2 = stack();
L.nudgeLabels(n2, titled);
check(JSON.stringify(n1) === JSON.stringify(n2), "label nudge is deterministic");
check(Math.abs(n1[0].y - n1[1].y) >= 13, "overlapping labels are pushed apart");
check(n1[2].y === 100 && n1[2].x === 400, "a distant label is untouched");
check(n1.every((p) => Math.abs(p.y - 100) <= 36 + 2), "nudge stays bounded");
const crowd = Array.from({ length: 40 }, (_, i) => (
  { id: "n" + i, title: "Note " + i, category: "c", tags: [], degree: 0 }));
const placed = L.layoutGraph(crowd, [], { size: 1000 });
check(placed.size === 40, "crowd laid out");
check([...placed.values()].every((p) => Number.isFinite(p.x) && Number.isFinite(p.y)), "finite");
const slots = L.categorySlots(["work", "home", "work"]);
check(slots.size === 2 && [...slots.values()].every((v) => v >= 0 && v < 8), "slots");
const parts = N.splitLinks("see [[Alpha|the a]] and [[b]].");
check(parts.length === 5 && parts[1].link === "Alpha" && parts[1].label === "the a", "split links");
check(N.splitLinks("<img src=x onerror=1>")[0].text === "<img src=x onerror=1>", "plain text kept");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_layout_and_link_helpers() -> None:
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own files
        [
            node,
            "--input-type=module",
            "-e",
            _SCRIPT,
            (STATIC / "kmap-layout.js").as_uri(),
            (STATIC / "kmap-note.js").as_uri(),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_route_and_shortcut_are_wired() -> None:
    app = (STATIC / "app.js").read_text("utf-8")
    assert '"/knowledge"' in app and "renderKnowledgeMap(main)" in app
    index = (STATIC / "index.html").read_text("utf-8")
    assert 'href="#/knowledge"' in index and 'data-nav="knowledge"' in index


def test_note_text_only_becomes_text_nodes() -> None:
    note = (STATIC / "kmap-note.js").read_text("utf-8")
    assert "textContent" in note or "untrusted(" in note
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML"):
        assert sink not in note
