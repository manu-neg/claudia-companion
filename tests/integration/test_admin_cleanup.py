"""Integration tests for the permanent-delete routes over real SQLite + filesystem (ADR 0030).

Blobs really leave the disk, kept and other items' blobs stay, error mapping
(400/404/409/415) and idempotency of prune and empty-trash.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.bootstrap import AdminCore
from tests.admin_support import admin_client, auth, publish, revise

pytestmark = pytest.mark.integration

AdminFixture = tuple[TestClient, str, AdminCore]


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[AdminFixture]:
    with admin_client(tmp_path) as ctx:
        yield ctx


def _blob_files(tmp_path: Path) -> set[str]:
    return {p.name for p in (tmp_path / "data" / "blobs").rglob("*") if p.is_file()}


def _item_with_revisions(client: TestClient, token: str, count: int, name: str = "a") -> str:
    response = publish(client, token, [("index.html", f"<p>{name}1</p>".encode())], title=name)
    assert response.status_code == 201
    item_id = str(response.json()["id"])
    for n in range(2, count + 1):
        assert revise(client, token, item_id, [("index.html", f"{name}{n}".encode())]).is_success
    return item_id


def _prune(client: TestClient, token: str, item_id: str, body: object = None) -> Any:
    return client.post(
        f"/v1/items/{item_id}/revisions/prune",
        json={} if body is None else body,
        headers=auth(token),
    )


def test_prune_deletes_old_blobs_only(admin: AdminFixture, tmp_path: Path) -> None:
    client, token, core = admin
    other = _item_with_revisions(client, token, 2, "other")
    other_before = client.get(f"/v1/items/{other}", headers=auth(token)).json()
    other_blobs = {f.blob_id for f in core.queries.get(other).all_files}
    item_id = _item_with_revisions(client, token, 4)
    stored = core.queries.get(item_id)
    head_blobs = {f.blob_id for f in stored.files}
    old_blobs = {f.blob_id for r in stored.history for f in r.files}
    assert old_blobs <= _blob_files(tmp_path)

    response = _prune(client, token, item_id)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["revisions_removed"] == 3
    assert body["bytes_freed"] == sum(r.total_size for r in stored.history)
    item = body["item"]
    assert (item["id"], item["revision"], item["title"]) == (item_id, 4, "a")
    assert [r["number"] for r in item["revisions"]] == [4]
    assert item["stored_size"] == item["total_size"]

    on_disk = _blob_files(tmp_path)
    assert not old_blobs & on_disk
    assert head_blobs | other_blobs <= on_disk
    assert client.get(f"/v1/items/{other}", headers=auth(token)).json() == other_before


def test_prune_with_keep_and_expected_revision(admin: AdminFixture) -> None:
    client, token, _ = admin
    item_id = _item_with_revisions(client, token, 5)
    stale = _prune(client, token, item_id, {"keep": 2, "expected_revision": 4})
    assert stale.status_code == 409
    assert stale.json()["error"] == "conflict"
    ok = _prune(client, token, item_id, {"keep": 2, "expected_revision": 5}).json()
    assert ok["revisions_removed"] == 3
    assert [r["number"] for r in ok["item"]["revisions"]] == [5, 4]
    again = _prune(client, token, item_id, {"keep": 2}).json()
    assert (again["revisions_removed"], again["bytes_freed"]) == (0, 0)
    assert again["item"] == client.get(f"/v1/items/{item_id}", headers=auth(token)).json()


def test_prune_then_new_revision_keeps_numbering(admin: AdminFixture) -> None:
    client, token, _ = admin
    item_id = _item_with_revisions(client, token, 3)
    _prune(client, token, item_id)
    body = revise(client, token, item_id, [("index.html", b"next")]).json()
    assert [r["number"] for r in body["revisions"]] == [4, 3]


@pytest.mark.parametrize(
    "body",
    [
        {"keep": 0},
        {"keep": 21},
        {"keep": True},
        {"keep": "1"},
        {"keep": 1.0},
        {"expected_revision": 0},
        {"expected_revision": "3"},
        {"other": 1},
        [],
    ],
)
def test_prune_rejects_bad_bodies(admin: AdminFixture, tmp_path: Path, body: object) -> None:
    client, token, _ = admin
    item_id = _item_with_revisions(client, token, 3)
    before = _blob_files(tmp_path)
    response = _prune(client, token, item_id, body)
    assert response.status_code == 400, response.text
    assert _blob_files(tmp_path) == before


def test_prune_needs_a_json_body(admin: AdminFixture) -> None:
    client, token, _ = admin
    item_id = _item_with_revisions(client, token, 2)
    response = client.post(
        f"/v1/items/{item_id}/revisions/prune",
        content=b"keep=1",
        headers={**auth(token), "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 415


def test_prune_unknown_malformed_and_trashed(admin: AdminFixture, tmp_path: Path) -> None:
    client, token, _ = admin
    assert _prune(client, token, "0" * 26).status_code == 404
    assert _prune(client, token, "not-an-id").status_code == 400
    item_id = _item_with_revisions(client, token, 3)
    assert client.post(f"/v1/items/{item_id}/trash", headers=auth(token)).status_code == 200
    before = _blob_files(tmp_path)
    trashed = _prune(client, token, item_id)
    assert trashed.status_code == 409
    assert trashed.json()["error"] == "invalid_state"
    assert _blob_files(tmp_path) == before


def test_empty_trash_deletes_trashed_items_and_their_blobs(
    admin: AdminFixture, tmp_path: Path
) -> None:
    client, token, core = admin
    keep = _item_with_revisions(client, token, 2, "keep")
    keep_blobs = {f.blob_id for f in core.queries.get(keep).all_files}
    doomed = [_item_with_revisions(client, token, n, f"d{n}") for n in (1, 3)]
    doomed_blobs = {f.blob_id for i in doomed for f in core.queries.get(i).all_files}
    for item_id in doomed:
        assert client.post(f"/v1/items/{item_id}/trash", headers=auth(token)).status_code == 200

    response = client.post("/v1/trash/empty", headers=auth(token))
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"items_purged": 2, "blobs_deleted": len(doomed_blobs)}
    for item_id in doomed:
        assert client.get(f"/v1/items/{item_id}", headers=auth(token)).status_code == 404
    on_disk = _blob_files(tmp_path)
    assert not doomed_blobs & on_disk
    assert keep_blobs <= on_disk
    trash = client.get("/v1/items?state=trashed", headers=auth(token)).json()
    assert trash["items"] == []
    again = client.post("/v1/trash/empty", headers=auth(token)).json()
    assert again == {"items_purged": 0, "blobs_deleted": 0}
