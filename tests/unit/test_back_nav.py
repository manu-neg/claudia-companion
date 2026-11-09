"""Back navigation (backlog §13.2, unit N1): `static/nav.js` origin tracking and fallbacks.

Runtime checks drive the pure functions under node; grep checks pin the wiring (router
records routes, item and folder views render `backButton`, no history.back()).
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs only a fixed node script on our own file
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
DOCS = Path(__file__).resolve().parents[2] / "docs"
FOLDER = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
OTHER = "01ARZ3NDEKTSV4RRFFQ69G5FAW"

_SCRIPT = """
const nav = await import(process.argv[1]);
const [F, O] = [process.argv[2], process.argv[3]];
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };
const filed = { id: F, name: "Reports" };

// origin recorded: previous hash only, a repeated hash keeps it, a reload forgets it
nav.resetNav();
check(nav.previousHash() === null, "no origin at first load");
nav.recordRoute("#/folder/" + F);
nav.recordRoute("#/item/X");
check(nav.previousHash() === "#/folder/" + F, "origin recorded");
nav.recordRoute("#/item/X");
check(nav.previousHash() === "#/folder/" + F, "same hash keeps origin");
nav.resetNav();
check(nav.previousHash() === null, "reset forgets origin");

// item: origin wins
let b = nav.itemBack({ trashed: false, folder: filed, origin: "#/" });
check(b.href === "#/" && b.text === "Back to Feed" && b.name === null, "origin feed");
b = nav.itemBack({ trashed: false, folder: filed, origin: "#/folder/" + F });
check(b.href === "#/folder/" + F && b.name === "Reports", "origin own folder");
check(b.folderId === null, "own folder needs no lookup");
b = nav.itemBack({ trashed: false, folder: filed, origin: "#/folder/" + O });
check(b.href === "#/folder/" + O && b.folderId === O && b.name === null, "origin other folder");

// item: fallbacks (no origin, or an unusable one)
b = nav.itemBack({ trashed: false, folder: filed, origin: null });
check(b.href === "#/folder/" + F && b.name === "Reports", "fallback to its folder");
b = nav.itemBack({ trashed: false, folder: null, origin: null });
check(b.href === "#/" && b.text === "Back to Feed", "fallback to Feed when unfiled");
for (const bad of ["#/item/X", "#/folder/not-a-ulid", "#/trash", "garbage"]) {
  b = nav.itemBack({ trashed: false, folder: null, origin: bad });
  check(b.href === "#/", "unusable origin " + bad + " -> Feed");
}

// trashed item always goes back to the trash
b = nav.itemBack({ trashed: true, folder: filed, origin: null });
check(b.href === "#/trash" && b.text === "Back to Trash", "trashed fallback");
b = nav.itemBack({ trashed: true, folder: null, origin: "#/trash" });
check(b.href === "#/trash", "trashed with origin");

// item whose folder id is not a ULID never builds a folder route
b = nav.itemBack({ trashed: false, folder: { id: "x/../y", name: "Evil" }, origin: null });
check(b.href === "#/" && b.name === null, "non-ULID own folder id -> Feed");

// folder window: always the Feed, whatever the origin (two folders can't bounce)
check(nav.folderBack().href === "#/", "folder back is Feed");
check(nav.folderBack({ origin: "#/folder/" + O }).href === "#/", "folder origin ignored");
check(nav.folderBack({ origin: "#/item/X" }).href === "#/", "item origin ignored");
"""


def _text(name: str) -> str:
    return (STATIC / name).read_text("utf-8")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_back_target_origin_and_fallbacks() -> None:
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own file
        [node, "--input-type=module", "-e", _SCRIPT, (STATIC / "nav.js").as_uri(), FOLDER, OTHER],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_back_is_wired_into_router_item_and_folder_views() -> None:
    assert "recordRoute(location.hash)" in _text("app.js")
    assert "itemBack(" in _text("item.js") and "backButton(" in _text("item.js")
    assert "folderBack(" in _text("feed.js") and "backButton(" in _text("feed.js")
    chrome = _text("chrome.js")
    assert 'h(\n    "button"' in chrome.split("export function backButton", 1)[1]
    for name in ("app.js", "item.js", "feed.js", "nav.js", "chrome.js"):
        assert "history.back" not in _text(name) and "history.go" not in _text(name), name


def test_docs_describe_back_navigation() -> None:
    doc = (DOCS / "frontend.md").read_text("utf-8")
    assert "### Navigation (Back)" in doc and "nav.js" in doc
