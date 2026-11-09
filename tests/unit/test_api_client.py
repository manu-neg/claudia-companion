"""Node-run checks for `static/api.js`'s fetch(init) shape (docs/security.md C4).

Stubs `globalThis.fetch` to capture the `init` object api.js builds, so we can
assert the exact CSRF headers/body on POST and the referrer-policy fix for
Safari/WebKit (R1: POST needs "same-origin", GET keeps "no-referrer").
Skipped when Node isn't available (same convention as test_static_ui.py).
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404 - runs only `node --check`/`node -e` on our own files in tests

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
API_JS = STATIC / "api.js"

# Captures the `init` object passed to fetch() for a GET and a POST call, then
# prints them as JSON so the Python side can assert on them precisely.
_SCRIPT = """
const api = await import(process.argv[1]);
const calls = [];
globalThis.fetch = async (path, init) => {
  calls.push({ path, init });
  return {
    status: 200,
    ok: true,
    headers: { get: () => null },
    json: async () => ({}),
  };
};
await api.apiGet("/api/items/01ARZ3NDEKTSV4RRFFQ69G5FAV");
await api.apiPost("/api/items/01ARZ3NDEKTSV4RRFFQ69G5FAV/trash");
console.log(JSON.stringify(calls));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_get_keeps_no_referrer_and_post_uses_same_origin_referrer_policy() -> None:
    """R1 fix: POST referrerPolicy "same-origin" avoids WebKit sending Origin: null."""
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own file
        [node, "--input-type=module", "-e", _SCRIPT, API_JS.as_uri()],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    calls = json.loads(result.stdout)
    assert len(calls) == 2
    get_call, post_call = calls

    # GET: unchanged, no CSRF headers/body, no-referrer.
    assert get_call["path"] == "/api/items/01ARZ3NDEKTSV4RRFFQ69G5FAV"
    get_init = get_call["init"]
    assert get_init["method"] == "GET"
    assert get_init["referrerPolicy"] == "no-referrer"
    assert get_init["mode"] == "same-origin"
    assert get_init["credentials"] == "same-origin"
    assert get_init["cache"] == "no-store"
    assert get_init["redirect"] == "error"
    assert "Content-Type" not in get_init["headers"]
    assert "X-PDash-CSRF" not in get_init["headers"]
    assert "body" not in get_init

    # POST: same-origin referrer policy (the fix) plus the exact CSRF matrix (C4).
    assert post_call["path"] == "/api/items/01ARZ3NDEKTSV4RRFFQ69G5FAV/trash"
    post_init = post_call["init"]
    assert post_init["method"] == "POST"
    assert post_init["referrerPolicy"] == "same-origin"
    assert post_init["mode"] == "same-origin"
    assert post_init["credentials"] == "same-origin"
    assert post_init["cache"] == "no-store"
    assert post_init["redirect"] == "error"
    assert post_init["headers"]["Content-Type"] == "application/json"
    assert post_init["headers"]["X-PDash-CSRF"] == "1"
    assert post_init["headers"]["Accept"] == "application/json"
    assert post_init["body"] == "{}"
