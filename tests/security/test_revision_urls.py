"""Security controls for revision URLs (ADR 0019; docs/security.md C7, C9, C20, C31).

- Bundle sub-resources are bound to their own item **and** revision: a page
  of revision 1 (or of the `latest` alias) can't pull revision 2's files
  cross-site, and vice versa.
- The revision segment is strictly parsed and must arrive literally; it is
  never a path and hostile values never reach the blob store.
- Integrity: `/t` verifies SHA-256 of files under the cap; a blob whose
  real size differs from the manifest is refused before any header (ranges
  included, since ranges aren't hashed).
"""

from __future__ import annotations

import pytest

from preview_dashboard.domain.models import Item
from tests.security.test_download_headers import _corrupting_env
from tests.viewer_support import PREVIEW_ORIGIN, ViewerEnv, make_env, owner_headers

pytestmark = pytest.mark.security

CROSS_SITE_SCRIPT = {"Sec-Fetch-Dest": "script", "Sec-Fetch-Site": "cross-site"}


@pytest.fixture
def bundle() -> tuple[ViewerEnv, Item]:
    env = make_env()
    item = env.publish({"index.html": b"<script src=app.js></script>", "app.js": b"1;"})
    env.revise(item.id, {"index.html": b"<script src=app.js></script>", "app.js": b"2;"})
    return env, item


@pytest.mark.parametrize(
    ("resource_rev", "page_rev", "allowed"),
    [
        ("1", "1", True),
        ("2", "2", True),
        ("latest", "latest", True),
        ("2", "1", False),  # an old page must not pull the new revision's files
        ("1", "2", False),
        ("latest", "2", False),  # the alias and the number are different bundles
        ("2", "latest", False),
    ],
)
def test_subresources_are_bound_to_item_and_revision(
    bundle: tuple[ViewerEnv, Item], resource_rev: str, page_rev: str, allowed: bool
) -> None:
    env, item = bundle
    referer = f"{PREVIEW_ORIGIN}/i/{item.id}/{page_rev}/index.html"
    response = env.preview_client().get(
        f"/i/{item.id}/{resource_rev}/app.js",
        headers=owner_headers({**CROSS_SITE_SCRIPT, "Referer": referer}),
    )
    if allowed:
        assert response.status_code == 200
        assert response.headers["cross-origin-resource-policy"] == "cross-origin"
    else:
        assert response.status_code == 403
        assert response.headers["cross-origin-resource-policy"] == "same-site"


def test_unbound_legacy_request_gets_same_site_corp(bundle: tuple[ViewerEnv, Item]) -> None:
    env, item = bundle
    response = env.preview_client().get(
        f"/i/{item.id}/2/app.js",
        headers=owner_headers({"Referer": f"{PREVIEW_ORIGIN}/i/{item.id}/1/index.html"}),
    )
    assert response.status_code == 200
    assert response.headers["cross-origin-resource-policy"] == "same-site"


@pytest.mark.parametrize(
    "rev",
    [
        "..",
        ".",
        "%2e%2e",
        "%31",  # "1", percent-encoded: must arrive literally
        "1%2F..",
        "1%00",
        "latest%00",
        "%6Catest",
        "1;x",
        "~1",
    ],
)
def test_hostile_revision_segments_are_refused(bundle: tuple[ViewerEnv, Item], rev: str) -> None:
    env, item = bundle
    client = env.preview_client()
    for path in (
        f"/i/{item.id}/{rev}/index.html",
        f"/t/{item.id}/{rev}/index.html",
        f"/r/{item.id}/{rev}/index.html",
        f"/d/{item.id}/{rev}",
        f"/d/{item.id}/{rev}/index.html",
    ):
        status = client.get(path, headers=owner_headers()).status_code
        assert status in {400, 404}, (path, status)


def test_text_under_the_cap_is_hash_verified() -> None:
    env, blobs = _corrupting_env()
    item = env.publish({"notes.txt": b"hello world"})
    blobs.corrupt.add(item.files[0].blob_id)  # same size, other bytes
    for prefix in ("t", "r"):
        response = env.preview_client().get(
            f"/{prefix}/{item.id}/1/notes.txt", headers=owner_headers()
        )
        assert response.status_code == 500, prefix
        assert b"hello" not in response.content


@pytest.mark.parametrize("range_header", ["bytes=0-3", "bytes=5-", "bytes=-2"])
def test_range_of_a_resized_blob_is_refused_before_headers(range_header: str) -> None:
    env, blobs = _corrupting_env()
    item = env.publish({"a.bin": b"0123456789"})
    blobs.extended.add(item.files[0].blob_id)
    for path in (f"/i/{item.id}/1/a.bin", f"/d/{item.id}/1/a.bin"):
        response = env.preview_client().get(path, headers=owner_headers({"Range": range_header}))
        assert response.status_code == 500, path
        assert "content-range" not in response.headers
