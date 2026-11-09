"""Integration tests for `POST /v1/items/{id}/revisions` over real adapters (ADR 0019).

Same manifest-first streamed multipart as publish, with fields `kind_hint`,
`expected_revision` and `manifest`. Checks the response shape, pruning to
the last 20 revisions (with blob deletion on disk), error mapping (400,
404, 409, 422) and that failed revisions leave nothing behind.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from preview_dashboard.bootstrap import AdminCore
from preview_dashboard.domain.models import MAX_REVISIONS
from tests.admin_support import (
    admin_client,
    auth,
    multipart_body,
    multipart_headers,
    publish,
    revise,
)

pytestmark = pytest.mark.integration

AdminFixture = tuple[TestClient, str, AdminCore]

# Split so no scanner in the repo's own tooling flags this test file.
FAKE_AWS_KEY = "AK" + "IA" + "QZ7XW4B2" + "MLKH3VDN"


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[AdminFixture]:
    with admin_client(tmp_path) as ctx:
        yield ctx


def _blob_files(tmp_path: Path) -> set[str]:
    root = tmp_path / "data"
    return {p.name for sub in ("blobs", "staging") for p in (root / sub).rglob("*") if p.is_file()}


def _published(client: TestClient, token: str) -> dict[str, object]:
    response = publish(client, token, [("index.html", b"<p>v1</p>")], title="Site", pinned=True)
    assert response.status_code == 201
    body: dict[str, object] = response.json()
    return body


def test_revision_keeps_id_and_metadata_and_lists_revisions(admin: AdminFixture) -> None:
    client, token, _ = admin
    item = _published(client, token)
    response = revise(
        client, token, str(item["id"]), [("index.html", b"<p>v2</p>"), ("a.css", b"p{}")]
    )
    assert response.status_code == 201
    body = response.json()
    assert response.headers["cache-control"] == "no-store"
    assert (body["id"], body["title"], body["pinned"]) == (item["id"], "Site", True)
    assert body["revision"] == 2
    assert [f["relpath"] for f in body["files"]] == ["index.html", "a.css"]
    assert [r["number"] for r in body["revisions"]] == [2, 1]
    assert body["revisions"][1]["file_count"] == 1
    assert body["stored_size"] == 9 + 9 + 3
    assert body["total_size"] == 12
    assert body["viewer_url"] == item["viewer_url"]
    got = client.get(f"/v1/items/{item['id']}", headers=auth(token)).json()
    assert got == body


def test_revision_can_change_kind(admin: AdminFixture) -> None:
    client, token, _ = admin
    item = _published(client, token)
    body = revise(client, token, str(item["id"]), [("notes.md", b"# hi")]).json()
    assert body["kind"] == "markdown"
    assert body["revisions"][1]["kind"] == "html"
    hinted = revise(client, token, str(item["id"]), [("x.txt", b"y")], kind_hint="text").json()
    assert hinted["kind"] == "text"


def test_old_revisions_are_pruned_with_their_blobs(admin: AdminFixture, tmp_path: Path) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    first_blobs = _blob_files(tmp_path)
    body: dict[str, object] = {}
    for n in range(2, MAX_REVISIONS + 2):
        response = revise(client, token, item_id, [("index.html", f"v{n}".encode())])
        assert response.status_code == 201, response.text
        body = response.json()
    assert body["revision"] == MAX_REVISIONS + 1
    revisions = body["revisions"]
    assert isinstance(revisions, list) and len(revisions) == MAX_REVISIONS
    assert revisions[-1]["number"] == 2
    on_disk = _blob_files(tmp_path)
    assert len(on_disk) == MAX_REVISIONS
    assert not first_blobs & on_disk


def test_expected_revision(admin: AdminFixture) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    stale = revise(client, token, item_id, [("index.html", b"v2")], expected_revision="2")
    assert stale.status_code == 409
    assert stale.json()["error"] == "conflict"
    ok = revise(client, token, item_id, [("index.html", b"v2")], expected_revision="1")
    assert ok.status_code == 201
    for bad in ("0", "01", "-1", "1.0", "²", "x", "99999999999"):
        response = revise(client, token, item_id, [("index.html", b"v3")], expected_revision=bad)
        assert response.status_code == 400, bad


def test_trashed_item_is_409_and_nothing_is_stored(admin: AdminFixture, tmp_path: Path) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    assert client.post(f"/v1/items/{item_id}/trash", headers=auth(token)).status_code == 200
    before = _blob_files(tmp_path)
    response = revise(client, token, item_id, [("index.html", b"v2")])
    assert response.status_code == 409
    assert response.json()["error"] == "invalid_state"
    assert _blob_files(tmp_path) == before


def test_unknown_and_malformed_ids(admin: AdminFixture) -> None:
    client, token, _ = admin
    missing = revise(client, token, "0" * 26, [("a.txt", b"x")])
    assert missing.status_code == 404
    bad = revise(client, token, "not-an-id", [("a.txt", b"x")])
    assert bad.status_code == 400


def test_secret_in_revision_content_is_422_and_rolled_back(
    admin: AdminFixture, tmp_path: Path
) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    before = _blob_files(tmp_path)
    data = f"key={FAKE_AWS_KEY}\n".encode()
    response = revise(client, token, item_id, [("ok.txt", b"fine"), ("conf.txt", data)])
    assert response.status_code == 422
    body = response.json()
    assert (body["error"], body["rule"], body["relpath"]) == (
        "secret_detected",
        "AWS access key id",
        "conf.txt",
    )
    assert FAKE_AWS_KEY not in response.text
    assert _blob_files(tmp_path) == before
    assert client.get(f"/v1/items/{item_id}", headers=auth(token)).json()["revision"] == 1


def test_secret_in_revision_relpath_is_422(admin: AdminFixture) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    response = revise(client, token, item_id, [(f"{FAKE_AWS_KEY}.txt", b"x")])
    assert response.status_code == 422
    assert "relpath" not in response.json()


@pytest.mark.parametrize(
    ("fields", "files"),
    [
        ([("title", "x"), ("manifest", '["a.txt"]')], [("a.txt", b"x")]),  # publish-only field
        ([("pinned", "true"), ("manifest", '["a.txt"]')], [("a.txt", b"x")]),
        ([("manifest", '["a.txt"]'), ("kind_hint", "text")], []),  # no files
        ([("manifest", '["a.txt"]')], [("b.txt", b"x")]),  # not the manifest entry
        ([("kind_hint", "text")], [("a.txt", b"x")]),  # no manifest
        ([("manifest", '["a.txt"]'), ("manifest", '["a.txt"]')], [("a.txt", b"x")]),
        ([("manifest", '["../a.txt"]')], [("../a.txt", b"x")]),
    ],
)
def test_malformed_revision_forms_are_400(
    admin: AdminFixture,
    tmp_path: Path,
    fields: list[tuple[str, str]],
    files: list[tuple[str, bytes]],
) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    before = _blob_files(tmp_path)
    response = client.post(
        f"/v1/items/{item_id}/revisions",
        content=multipart_body(fields, files),
        headers=multipart_headers(token),
    )
    assert response.status_code == 400, response.text
    assert _blob_files(tmp_path) == before


def test_revision_needs_the_token(admin: AdminFixture) -> None:
    client, token, _ = admin
    item_id = str(_published(client, token)["id"])
    response = client.post(
        f"/v1/items/{item_id}/revisions",
        content=b"",
        headers={"Content-Type": "multipart/form-data; boundary=x"},
    )
    assert response.status_code == 401


def test_revision_bytes_count_against_the_quota(tmp_path: Path) -> None:
    with admin_client(
        tmp_path, max_file_bytes=1_000, max_item_bytes=1_000, max_total_bytes=1_500
    ) as (client, token, _):
        item_id = str(publish(client, token, [("a.txt", b"x" * 900)]).json()["id"])
        response = revise(client, token, item_id, [("a.txt", b"y" * 900)])
        assert response.status_code == 413
        assert response.json()["error"] == "limit_exceeded"
