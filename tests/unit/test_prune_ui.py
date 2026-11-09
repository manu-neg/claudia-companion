"""The viewer's "Delete old versions" button (backlog §13.3, unit R2): `static/versions.js`.

Runtime checks drive the pure helpers under node (when the button shows, what the
confirm dialog says); grep checks pin the wiring (a real button beside the version
popup, active items only, the guarded POST, docs).
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs only a fixed node script on our own file
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

pytestmark = pytest.mark.unit

STATIC = default_static_dir()
DOCS = Path(__file__).resolve().parents[2] / "docs"

_SCRIPT = """
const v = await import(process.argv[1]);
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };
const rev = (number, total_size) => ({ number, total_size, created_at: "2026-10-26T00:00:00Z" });

// visibility: only with more than one kept revision
check(v.olderVersions({}) === null, "no revisions field -> hidden");
check(v.olderVersions({ revisions: "x" }) === null, "malformed -> hidden");
const single = { latest_revision: 1, revisions: [rev(1, 10)] };
check(v.olderVersions(single) === null, "one revision -> hidden");

// count and size exclude the latest; bad sizes count as 0
const revisions = [rev(5, 999), rev(4, 1024), rev(2, 2048), rev(1, -3), { number: 0 }];
const item = { latest_revision: 5, revisions };
const older = v.olderVersions(item);
check(older && older.count === 3 && older.bytes === 3072 && older.latest === 5, "counts");

// viewing an older revision: still the head that stays
check(v.olderVersions({ ...item, revision: 2 }).latest === 5, "head, not the shown revision");

// dialog copy: count, size, irreversible, freed within the hour
const text = v.pruneDialogText(older);
check(text.title === "Delete 3 older versions (3.0 KB)?", "title " + text.title);
check(text.body.includes("can't be undone"), "body: irreversible");
check(text.body.includes("Space is freed within about two hours"), "body: freed later");
const one = v.pruneDialogText({ count: 1, bytes: 10, latest: 2 });
check(one.title === "Delete 1 older version (10 B)?", "singular");
"""


def _text(name: str) -> str:
    return (STATIC / name).read_text("utf-8")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_visibility_and_dialog_copy() -> None:
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own file
        [node, "--input-type=module", "-e", _SCRIPT, (STATIC / "versions.js").as_uri()],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_button_is_wired_for_active_items_only() -> None:
    versions = _text("versions.js")
    switcher = versions.split("export function versionSwitcher", 1)[1]
    # A real <button>, only with a handler and something older to delete.
    assert 'h("button"' in switcher and 'text: "Delete old versions"' in switcher
    assert 'typeof onPrune === "function" && olderVersions(item)' in switcher
    # The POST names the head the owner saw, so a newer version is never deleted unseen.
    assert "/revisions/prune?expected=${older.latest}" in versions
    assert "innerHTML" not in versions
    item = _text("item.js")
    assert "trashed ? null : pruneOldVersions" in item
    assert "deleteOldVersions(state.item)" in item


def test_docs_describe_delete_old_versions() -> None:
    frontend = (DOCS / "frontend.md").read_text("utf-8")
    assert "Delete old versions" in frontend
    adr_path = DOCS / "adr" / "0030-deleting-old-revisions-and-emptying-the-trash.md"
    adr = adr_path.read_text("utf-8")
    assert "/api/items/{id}/revisions/prune" in adr and "two hours" in adr
    security = (DOCS / "security.md").read_text("utf-8")
    assert "/api/items/{id}/revisions/prune" in security
