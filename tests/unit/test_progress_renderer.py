"""Checks for the `progress` renderer on the preview origin (static/preview-render/progress.*).

The dashboard never fetches item bytes, so `progress` is drawn inside the sandboxed /r/ page
like the other text kinds (ADR 0018, 0029). Here: registration, the OS-neutral page, static
hygiene, and the script itself run under Node against a tiny fake DOM.
"""

import json
import re
import shutil
import subprocess

import pytest

from preview_dashboard.interfaces.viewer.renderer_page import TEXT_RENDERERS, RendererPage
from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
SCRIPT = STATIC / "preview-render" / "progress.js"
CSS = STATIC / "preview-render" / "progress.css"

FIXTURE = {
    "version": 1,
    "title": "Folders progress",
    "note": "Note text",
    "updated_at": "2026-09-30T10:00:00Z",
    "phases": ["Plan", "Build", "Review"],
    "units": [
        {"id": "P0", "name": "Plan", "who": "Claude", "state": "done", "detail": "Done."},
        {"id": "P1", "name": "Kind", "who": "dev", "state": "running", "detail": "Building."},
        {"id": "P2", "name": "View", "who": "dev", "state": "waiting", "detail": ""},
    ],
    "timeline": [
        {
            "lane": "Claude",
            "model": "Opus",
            "bars": [
                {"unit": "P0", "from": 0, "to": 1, "label": "Plan"},
                {"unit": "P1", "from": 0, "to": 2, "label": "Overlaps the plan bar"},
            ],
        },
        {"lane": "You", "model": "", "bars": [{"unit": "P2", "from": 2, "to": 3, "label": "OK"}]},
    ],
}

# Runs progress.js against a minimal DOM and prints {"texts": [...], "states": [...], "html": bool}.
_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const [scriptPath, payload] = process.argv.slice(1);
class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.className = ""; this.attrs = {};
    this.style = {}; this._text = ""; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text; }
  appendChild(c) { this.children.push(c); return c; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
}
const root = new Node("main");
const data = new Node("script"); data._text = payload;
const document = {
  createElement: (t) => new Node(t),
  createTextNode: (t) => { const n = new Node("#text"); n._text = String(t); return n; },
  getElementById: (id) => (id === "pdash-root" ? root : data),
};
const sandbox = { document, Date, JSON, Math, isNaN, Object, Array, Boolean, String };
const boom = () => { throw new Error("innerHTML used"); };
Object.defineProperty(Node.prototype, "innerHTML", { set: boom });
vm.runInNewContext(fs.readFileSync(scriptPath, "utf8"), sandbox);
const texts = [], states = [];
(function walk(n) {
  if (n._text) texts.push(n._text);
  if (n.attrs["data-state"]) states.push(n.attrs["data-state"]);
  n.children.forEach(walk);
})(root);
console.log(JSON.stringify({ texts, states, rows: Object.keys(root.attrs).length }));
"""


def _run(text: str, *, truncated: bool = False) -> dict[str, list[str]]:
    node = shutil.which("node")
    assert node is not None
    payload = json.dumps({"renderer": "progress", "text": text, "truncated": truncated})
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own script
        [node, "-e", _HARNESS, str(SCRIPT), payload],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    out: dict[str, list[str]] = json.loads(result.stdout)
    return out


def test_progress_is_a_text_renderer_on_both_sides() -> None:
    assert "progress" in TEXT_RENDERERS
    index = (STATIC / "renderers" / "index.js").read_text("utf-8")
    assert re.search(r'for \(const id of \[[^\]]*"progress"', index)


def test_progress_page_is_os_neutral_and_self_contained() -> None:
    page = (
        RendererPage.load(STATIC)
        .render(renderer="progress", text=json.dumps(FIXTURE), meta={"filename": "progress.json"})
        .decode()
    )
    assert "--p-bg" in page and "Who runs when" in page
    # No OS theme tokens, no shared renderer code, no vendor libraries, no external loads.
    assert "--color-window" not in page and "--font-chrome" not in page
    assert "r-pre" not in page and "DOMPurify" not in page and "<script src" not in page


def test_progress_sources_are_neutral_and_free_of_sinks() -> None:
    script, css = SCRIPT.read_text("utf-8"), CSS.read_text("utf-8")
    for pattern in (r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"eval\s*\(", r"fetch\("):
        assert not re.search(pattern, script), pattern
    for word in ("platinum", "aero", "data-os"):
        assert word not in (script + css).lower(), word
    assert "var(--color-" not in css and "var(--font-" not in css and "var(--space-" not in css
    for decoration in ("box-shadow", "text-shadow", "gradient", "url(", "@import", "@font-face"):
        assert decoration not in css, decoration
    assert "prefers-color-scheme: dark" in css


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_fixture_renders_meter_units_and_timeline() -> None:
    out = _run(json.dumps(FIXTURE))
    texts = out["texts"]
    assert "1 / 3" in texts and "Folders progress" in texts and "Who runs when" in texts
    assert "Overlaps the plan bar" in texts and "Claude" in texts
    assert {"done", "running", "waiting"} <= set(out["states"])
    assert not any("can't be shown" in t for t in texts)


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(version=2),
        lambda d: d.update(title=""),
        lambda d: d.update(title=5),
        lambda d: d["units"][0].update(state="paused"),
        lambda d: d["units"][1].update(id="P0"),
        lambda d: d["units"][0].update(id="bad id!"),
        lambda d: d["timeline"][0]["bars"][0].update(to=9),
        lambda d: d["timeline"][0]["bars"][0].update(**{"from": 1, "to": 1}),
        lambda d: d["timeline"][0]["bars"][0].update(unit="nope"),
        lambda d: d["timeline"][0]["bars"][0].update(**{"from": 0.5}),
        lambda d: d.update(units=[d["units"][0]] * 41),
        lambda d: d.update(phases=["x"] * 13),
    ],
)
def test_bad_documents_show_the_safe_fallback(mutate) -> None:  # type: ignore[no-untyped-def]
    doc = json.loads(json.dumps(FIXTURE))
    mutate(doc)
    out = _run(json.dumps(doc))
    assert any("can't be shown" in t for t in out["texts"])
    assert out["states"] == []


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("text", ["{", "[]", "null", '"x"', ""])
def test_junk_and_truncated_files_show_the_safe_fallback(text: str) -> None:
    assert any("can't be shown" in t for t in _run(text)["texts"])
    assert any("can't be shown" in t for t in _run(json.dumps(FIXTURE), truncated=True)["texts"])


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize(
    ("field", "limit"), [("title", 120), ("note", 500), ("phase", 40), ("detail", 600)]
)
def test_length_limits_count_code_points_not_utf16_units(field: str, limit: int) -> None:
    def doc_with(n: int) -> str:
        d = json.loads(json.dumps(FIXTURE))
        value = "\U0001f600" * n  # astral: 2 UTF-16 units, 1 code point
        if field == "phase":
            d["phases"][0] = value
        elif field == "detail":
            d["units"][0]["detail"] = value
        else:
            d[field] = value
        return json.dumps(d)

    assert not any("can't be shown" in t for t in _run(doc_with(limit))["texts"])
    assert any("can't be shown" in t for t in _run(doc_with(limit + 1))["texts"])
