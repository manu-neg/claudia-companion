"""Static + runtime checks for folders inside the Feed window (backlog §7.1, unit F4).

`static/folders.js` is built against the exact viewer read contract in the
backlog (`GET /api/folders`), which doesn't exist yet in this worktree (F1/F2
land separately): these tests confirm the module degrades to "no folders"
quietly on any failure, never throws, keeps id validation and untrusted-text
rendering consistent with the rest of the dashboard, and is wired into the
router/feed/item views. Grep-level guards mirror `test_static_ui.py`; the
generic sink/eval/origin/header-comment checks there already cover this file
since it's picked up by the same `static/**/*.js` glob.
"""

from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 - runs only `node --check`/fixed scripts on our own files
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
DOCS = Path(__file__).resolve().parents[2] / "docs"
DASHBOARD_JS = sorted(
    p
    for p in STATIC.rglob("*.js")
    if p.parts[len(STATIC.parts)] not in {"vendor", "preview-render", "os", "os-boot.js"}
)
FOLDERS_JS = STATIC / "folders.js"


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def test_folders_module_is_data_only_and_router_serves_folders_in_the_feed() -> None:
    app = _text(STATIC / "app.js")
    assert 'from "./folders.js"' not in app  # feed.js is the only consumer
    assert 'from "./folders.js"' in _text(STATIC / "feed.js")
    # #/folder/<id> is ULID-checked and rendered by the Feed window; #/folders redirects to #/.
    assert re.search(r"/\^\\/folder\\/\(\[\^/\]\+\)\$/", app)
    assert "folderId: current.id" in app
    assert 'path === "/folders"' in app and 'replaceState(null, "", "#/")' in app
    # F3's separate windows and desktop icons are gone.
    removed = (
        "renderFolderWindow",
        "renderFoldersIndexWindow",
        "refreshDesktopFolders",
        "startFolderPolling",
    )
    for gone in removed:
        assert not any(gone in _text(p) for p in DASHBOARD_JS), gone
    assert "folder-icon" not in _text(STATIC / "app.css")


def test_folder_ids_reuse_the_single_ulid_pattern() -> None:
    """One definition of the ULID pattern (dom.js), imported everywhere else."""
    dom = _text(STATIC / "dom.js")
    assert "export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;" in dom
    definitions = [
        p for p in DASHBOARD_JS if re.search(r"=\s*/\^\[0-9A-HJKMNP-TV-Z\]\{26\}\$/", _text(p))
    ]
    assert [p.name for p in definitions] == ["dom.js"]
    assert "ULID_RE" in _text(STATIC / "app.js")
    assert "ULID_RE" in _text(FOLDERS_JS)


def test_folders_js_only_talks_to_the_network_via_api_js() -> None:
    source = _text(FOLDERS_JS)
    assert "fetch(" not in source
    assert 'from "./api.js"' in source
    assert "apiGet" in source


def test_folder_name_only_rendered_via_untrusted_helper() -> None:
    """Same rule as item titles/descriptions (test_static_ui.py): never a raw text sink."""
    allowed = re.compile(r"untrusted\((?:item\.)?folder\.name\)")
    for path in DASHBOARD_JS:
        for line in _text(path).splitlines():
            for match in re.finditer(r"(?:item\.)?folder\.name\b", line):
                window = line[max(0, match.start() - 10) : match.end() + 2]
                assert allowed.search(window), f"{path.name}: {line.strip()}"


def test_folder_hints_are_fixed_strings_not_item_data() -> None:
    """data-hint text must never be built from folder.name (balloon.js shows it to everyone)."""
    source = _text(STATIC / "feed.js")
    for match in re.finditer(r'hint:\s*(".*?"|`[^$]*?`)', source):
        value = match.group(1)
        assert "folder.name" not in value and "${" not in value, value


def test_root_feed_lists_folder_rows_then_unfiled_items_and_drops_the_folder_column() -> None:
    feed = _text(STATIC / "feed.js")
    assert "cell-folder" not in feed and "cell-folder" not in _text(STATIC / "app.css")
    assert '"unfiled"' in feed and "folderRow" in feed and "loadFolders" in feed
    assert "backButton(back)" in feed and 'close: folder ? { href: "#/"' in feed  # Back + close box
    assert "Backspace" in feed and "ArrowUp" in feed
    assert "renderFeed(main, ctx, { trashed: true })" in _text(STATIC / "app.js")


def test_folder_row_highlight_spans_the_whole_row() -> None:
    """Backlog 14.1: a blank spacer sibling left the end of a folder row unhighlighted on hover."""
    feed = _text(STATIC / "feed.js")
    body = feed[feed.index("function folderRow(") : feed.index("function row(")]
    assert "list-head-spacer" not in body  # the end column is link padding, inside the highlight
    css = _text(STATIC / "app.css")
    assert re.search(r"\.row-folder \.row-link\s*\{\s*padding-right: var\(--tap-target\);", css)
    assert re.search(r"\.row-folder \.row-link\s*\{\s*padding-right: 2rem;", css)  # fine pointer


def test_item_info_gets_a_read_only_folder_field() -> None:
    item = _text(STATIC / "item.js")
    assert 'field("Folder:", item.folder ? untrusted(item.folder.name) : "Unfiled")' in item


def test_folder_route_shows_page_not_found_for_a_bad_or_unknown_id() -> None:
    source = _text(STATIC / "feed.js")
    assert '"Page not found"' in source
    assert "renderPageNotFound" in source


def test_docs_mention_the_new_routes_and_hooks() -> None:
    doc = _text(DOCS / "frontend.md")
    assert "#/folder/<id>" in doc
    assert "#/folders" in doc and "redirects to `#/`" in doc
    assert "folders.js" in doc
    assert "data-folders" not in doc


_FOLDERS_SCRIPT = """
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };

// 1) The endpoint doesn't exist yet (F1/F2 land separately): a 404 degrades quietly.
global.fetch = async () => ({
  ok: false,
  status: 404,
  headers: { get: () => null },
  json: async () => ({ error: "not_found" }),
});
let folders = await import(process.argv[1]);
let result = await folders.loadFolders();
check(Array.isArray(result.folders) && result.folders.length === 0, "404 -> no folders");

// 2) A network failure degrades the same way.
global.fetch = async () => { throw new TypeError("network down"); };
result = await folders.loadFolders();
check(result.folders.length === 0, "network error -> no folders");

// 3) A well-formed body is parsed; a malformed entry (bad id) is dropped defensively.
global.fetch = async () => ({
  ok: true,
  status: 200,
  headers: { get: () => '"etag"' },
  json: async () => ({
    folders: [
      { id: "not-a-ulid", name: "Bad", count: 1 },
      { id: "01ARZ3NDEKTSV4RRFFQ69G5FAV", name: "Ok", count: 2 },
    ],
    unfiled_count: 3,
  }),
});
result = await folders.loadFolders();
check(result.folders.length === 1, "invalid entries are dropped");
check(result.folders[0].id === "01ARZ3NDEKTSV4RRFFQ69G5FAV", "valid entry kept");

// 4) A malformed top-level body (not an object with a folders array) also degrades quietly.
global.fetch = async () => ({
  ok: true,
  status: 200,
  headers: { get: () => null },
  json: async () => ({ nonsense: true }),
});
result = await folders.loadFolders();
check(result.folders.length === 0, "malformed body -> no folders");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_load_folders_degrades_quietly_on_every_failure() -> None:
    """Runtime proof (not just grep) of the "no folder icons, no errors" contract."""
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own file, no user input
        [node, "--input-type=module", "-e", _FOLDERS_SCRIPT, FOLDERS_JS.as_uri()],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


# JS syntax for every file this unit touches (incl. folders.js) is already covered by
# test_static_ui.py::test_js_parses, which parametrizes over every file in DASHBOARD_JS.


def test_folder_keydown_listener_is_scoped_guarded_and_cleaned_up() -> None:
    feed = _text(STATIC / "feed.js")
    body = feed.split("function onKeydown(", 1)[1].split("\n  }\n", 1)[0]
    assert "isTextEntry(document.activeElement)" in body
    assert "event.defaultPrevented" in body and "event.ctrlKey" in body and "event.metaKey" in body
    assert '".ctx-menu"' in body  # never steal keys from an open context menu
    assert 'if (folder) document.addEventListener("keydown", onKeydown);' in feed
    assert 'if (folder) document.removeEventListener("keydown", onKeydown);' in feed
    assert feed.count('addEventListener("keydown", onKeydown)') == 1


def test_splash_text_contrast_uses_accent_surface() -> None:
    fx_css = _text(STATIC / "os" / "platinum" / "fx" / "fx.css")
    css = fx_css.split(".fx-splash {", 1)[1].split("}", 1)[0]
    assert "background: var(--color-accent);" in css  # white on it is >= 4.5:1 (5.2:1)
