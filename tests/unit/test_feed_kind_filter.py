"""Static + runtime checks for the feed's Show filter (backlog §12.3, unit K1).

Owner decision 2026-09-30: `progress` is never offered in the Show popup,
and choosing HTML lists `html` and `progress` items (one request,
`kind=html,progress`). A stale saved "progress" choice falls back to All kinds.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - runs only fixed node scripts on our own files

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

pytestmark = pytest.mark.unit

STATIC = default_static_dir()


def _feed() -> str:
    return (STATIC / "feed.js").read_text("utf-8")


def test_progress_is_hidden_and_folded_into_html() -> None:
    feed = _feed()
    assert 'const HIDDEN_KINDS = new Set(["progress"]);' in feed
    assert 'const KIND_ALSO = new Map([["html", ["progress"]]]);' in feed
    groups = feed.split("const KIND_GROUPS = [", 1)[1].split("];", 1)[0]
    assert '"progress"' not in groups


def test_popup_and_other_group_use_only_offered_kinds() -> None:
    body = _feed().split("function kindSelect(", 1)[1].split("\n}\n", 1)[0]
    assert "const offered = offeredKinds(ctx);" in body
    # Neither the grouped kinds nor the "Other" leftovers read the raw registry list.
    assert "ctx.kindList" not in body


def test_request_sends_the_folded_kinds_and_stale_choice_resets() -> None:
    feed = _feed()
    assert "kind: filterKinds(currentFilter(viewKey))," in feed
    list_body = feed.split("function renderList(", 1)[1]
    assert "filterByView.delete(viewKey);" in list_body.split("const atRoot", 1)[0]
    # The status line still names the chosen kind ("Showing HTML only").
    assert "`Showing ${kindName()} only`" in feed


_ITEMS_PATH_SCRIPT = """
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };
const { itemsPath } = await import(process.argv[1]);
check(itemsPath({}) === "/api/items", "no params");
check(itemsPath({ kind: "html" }) === "/api/items?kind=html", "one kind");
check(itemsPath({ kind: ["html", "progress"] }) === "/api/items?kind=html%2Cprogress",
      "several kinds: one comma list, never a repeated key");
check(itemsPath({ kind: [] }) === "/api/items", "empty list = all kinds");
check(itemsPath({ kind: "" }) === "/api/items", "empty string = all kinds");
check(itemsPath({ state: "trashed", kind: ["image"], limit: 30 })
      === "/api/items?state=trashed&kind=image&limit=30", "combined");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_items_path_joins_kinds_into_one_param() -> None:
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own file, no user input
        [node, "--input-type=module", "-e", _ITEMS_PATH_SCRIPT, (STATIC / "api.js").as_uri()],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
