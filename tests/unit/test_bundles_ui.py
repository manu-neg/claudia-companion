"""Bundles and document icons (backlog §10.1, unit U1).

Runtime checks (Node) of the bundle rule in `static/bundle.js` and of the icon ids
`static/chrome.js` picks for items and their files; static checks that feed/item use them,
that both new sprite symbols exist, and that Aero redraws every file-type symbol as a
Vista/7 document so no symbol falls back to Platinum's pixel art.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - runs only fixed node scripts on our own files
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
AERO_SHELL = STATIC / "os" / "aero" / "shell.js"
FILE_TYPE_ICONS = {
    "i-html", "i-svg", "i-image", "i-csv", "i-diff", "i-markdown", "i-code", "i-video",
    "i-audio", "i-pdf", "i-json", "i-text", "i-file", "i-bundle", "i-progress",
}  # fmt: skip


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _node(script: str, *args: str) -> None:
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own files, no user input
        [node, "--input-type=module", "-e", script, *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


_RULE_SCRIPT = """
const b = await import(process.argv[1]);
const cases = [
  [{ file_count: 2, kind: "image" }, true],
  [{ file_count: 10, kind: "markdown" }, true],
  [{ file_count: 2, kind: "file" }, true],
  [{ file_count: 1, kind: "image" }, false],
  [{ file_count: 0, kind: "image" }, false],
  [{ file_count: 5, kind: "html" }, false],
  [{ file_count: 1, kind: "html" }, false],
  [{ file_count: "3", kind: "image" }, false],
  [{ file_count: 2.5, kind: "image" }, false],
  [{ kind: "image" }, false],
  [null, false],
  [undefined, false],
  ["bundle", false],
];
for (const [item, want] of cases) {
  if (b.isBundle(item) !== want) throw new Error(`isBundle(${JSON.stringify(item)}) != ${want}`);
}
if (b.bundleDetail({ file_count: 10 }, "Image") !== "10 files · Image") throw new Error("detail");
if (b.bundleDetail({ file_count: 2 }, "") !== "2 files") throw new Error("detail without kind");
if (b.filesText(1) !== "1 file") throw new Error("filesText");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_bundle_rule_is_two_or_more_files_except_html_sites() -> None:
    _node(_RULE_SCRIPT, (STATIC / "bundle.js").as_uri())


_ICON_SCRIPT = """
const c = await import(process.argv[1]);
const kinds = [
  { name: "image", renderer: "image", extensions: [".png", ".jpg"] },
  { name: "markdown", renderer: "markdown", extensions: [".md"] },
  { name: "code", renderer: "code", extensions: [".py"] },
  { name: "json", renderer: "json", extensions: [".json"] },
  { name: "html", renderer: "html", extensions: [".html"] },
  { name: "progress", renderer: "progress", extensions: [] },
  { name: "file", renderer: "file", extensions: [] },
];
const eq = (got, want, what) => {
  if (got !== want) throw new Error(`${what}: ${got} != ${want}`);
};
eq(c.itemIconId({ file_count: 4, kind: "image" }, kinds[0]), "i-bundle", "bundle item");
eq(c.itemIconId({ file_count: 4, kind: "html" }, kinds[4]), "i-html", "html site");
eq(c.itemIconId({ file_count: 1, kind: "image" }, kinds[0]), "i-image", "single file");
eq(c.itemIconId({ file_count: 1, kind: "progress" }, kinds[5]), "i-progress", "progress");
eq(c.kindIconId(null), "i-file", "no kind");
eq(c.kindIconId({ renderer: "nope" }), "i-file", "unknown renderer");
eq(c.fileIconId("a/b/Photo.PNG", kinds), "i-image", "extension, any case");
eq(c.fileIconId("notes.md", kinds), "i-markdown", "markdown file");
eq(c.fileIconId("main.py", kinds), "i-code", "code file");
eq(c.fileIconId("blob.bin", kinds), "i-file", "unknown extension");
eq(c.fileIconId("Makefile", kinds), "i-file", "no extension");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_items_and_files_get_their_icons() -> None:
    _node(_ICON_SCRIPT, (STATIC / "chrome.js").as_uri())


def test_feed_and_item_present_bundles() -> None:
    feed = _text(STATIC / "feed.js")
    item = _text(STATIC / "item.js")
    assert "icon(itemIconId(item, kind), " in feed and "kindIconId" not in feed
    assert '"Bundle"' in feed and "bundleDetail(item, entryKindLabel)" in feed
    assert "Download bundle (${item.file_count} files)" in feed
    assert "Bundle (${filesText(item.file_count)})" in item
    # Files list: every file its own icon by extension; the entry file is marked.
    assert "icon(fileIcon(item, file, kindOf(item), ctx.kindList), " in item
    assert "return fileIconId(file.relpath, kindList);" in item
    assert 'class: "file-entry", text: "Opens first"' in item


def test_new_symbols_exist_in_the_shared_sprite() -> None:
    sprite = _text(STATIC / "index.html")
    for symbol in ("i-bundle", "i-progress"):
        assert f'<symbol id="{symbol}" viewBox="0 0 32 32">' in sprite


def test_aero_draws_every_file_type_as_a_document() -> None:
    shell = _text(AERO_SHELL)
    doc_art = set(re.findall(r'^\s*"(i-[a-z-]+)": doc\(', shell, re.M))
    doc_art |= set(re.findall(r'DOC_ART\["(i-[a-z-]+)"\] =', shell))
    assert doc_art == FILE_TYPE_ICONS
    assert "...DOC_ART," in shell
    assert 'ART["i-trash-full"] =' in shell
    # Same safe sprite swap as A1: constant table, createElementNS, no HTML parsing.
    assert "innerHTML" not in shell and "createElementNS(ns, tag)" in shell
