"""Integration tests for the admin folder API (ADR 0027) over real SQLite + filesystem.

Covers `/v1/folders` (list, create, rename, delete), `POST /v1/items/{id}/move`,
publishing into a folder, the `?folder=` listing filter, the `folder` field
of item JSON, and the error mapping (400/404/409/413/415/422).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.bootstrap import AdminCore
from preview_dashboard.domain.folders import MAX_FOLDERS
from tests.admin_support import admin_client, auth, multipart_body, multipart_headers, publish

pytestmark = pytest.mark.integration

MISSING = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[tuple[TestClient, str, AdminCore]]:
    with admin_client(tmp_path) as ctx:
        yield ctx


def _create(client: TestClient, token: str, name: str) -> Any:
    return client.post("/v1/folders", json={"name": name}, headers=auth(token))


def _folder(client: TestClient, token: str, name: str) -> dict[str, Any]:
    response = _create(client, token, name)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _item(client: TestClient, token: str, **kwargs: Any) -> dict[str, Any]:
    response = publish(client, token, [("a.txt", b"x")], **kwargs)
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _move(client: TestClient, token: str, item_id: str, folder_id: str | None) -> Any:
    return client.post(
        f"/v1/items/{item_id}/move", json={"folder_id": folder_id}, headers=auth(token)
    )


def _publish_into(client: TestClient, token: str, folder_id: str) -> Any:
    """Publish with a `folder_id` form field (before the manifest, as required)."""
    body = multipart_body(
        [("title", "Filed"), ("folder_id", folder_id), ("manifest", json.dumps(["a.txt"]))],
        [("a.txt", b"x")],
    )
    return client.post("/v1/items", content=body, headers=multipart_headers(token))


def _list(client: TestClient, token: str, **params: str) -> Any:
    return client.get("/v1/items", params=params, headers=auth(token))


class TestFolderCrud:
    def test_create_list_rename_delete(self, admin):
        client, token, _ = admin
        created = _folder(client, token, "Plans")
        assert set(created) == {"id", "name", "created_at", "updated_at"}
        assert created["name"] == "Plans"
        listed = client.get("/v1/folders", headers=auth(token))
        assert listed.status_code == 200
        assert listed.headers["cache-control"] == "no-store"
        assert listed.json() == {
            "folders": [{**created, "count": 0, "trashed_count": 0}],
            "unfiled_count": 0,
            "unfiled_trashed_count": 0,
        }
        renamed = client.patch(
            f"/v1/folders/{created['id']}", json={"name": "Roadmap"}, headers=auth(token)
        )
        assert renamed.status_code == 200
        assert renamed.json()["name"] == "Roadmap"
        assert renamed.json()["updated_at"] > created["updated_at"]
        deleted = client.delete(f"/v1/folders/{created['id']}", headers=auth(token))
        assert deleted.status_code == 200
        assert deleted.json() == {"id": created["id"], "deleted": True}
        assert client.get("/v1/folders", headers=auth(token)).json()["folders"] == []
        again = client.delete(f"/v1/folders/{created['id']}", headers=auth(token))
        assert again.status_code == 404

    def test_list_is_in_caseless_name_order_with_counts(self, admin):
        client, token, _ = admin
        b = _folder(client, token, "beta")
        a = _folder(client, token, "Alpha")
        _item(client, token)  # unfiled
        filed = _item(client, token)
        assert _move(client, token, filed["id"], b["id"]).status_code == 200
        trashed = _item(client, token)
        _move(client, token, trashed["id"], b["id"])
        client.post(f"/v1/items/{trashed['id']}/trash", headers=auth(token))
        body = client.get("/v1/folders", headers=auth(token)).json()
        assert [(f["id"], f["count"], f["trashed_count"]) for f in body["folders"]] == [
            (a["id"], 0, 0),
            (b["id"], 1, 1),
        ]
        assert (body["unfiled_count"], body["unfiled_trashed_count"]) == (1, 0)

    def test_rename_to_same_name_is_a_no_op(self, admin):
        client, token, _ = admin
        created = _folder(client, token, "Plans")
        same = client.patch(
            f"/v1/folders/{created['id']}", json={"name": "Plans"}, headers=auth(token)
        )
        assert same.status_code == 200
        assert same.json() == created

    def test_caseless_duplicate_is_409_without_echoing_the_name(self, admin):
        client, token, _ = admin
        _folder(client, token, "Plans")
        response = _create(client, token, "\uff30\uff2c\uff21\uff2e\uff33")
        assert response.status_code == 409
        assert response.json()["error"] == "conflict"
        assert "PLANS" not in response.text and "Plans" not in response.text

    def test_rename_onto_a_taken_name_is_409(self, admin):
        client, token, _ = admin
        _folder(client, token, "Plans")
        other = _folder(client, token, "Other")
        response = client.patch(
            f"/v1/folders/{other['id']}", json={"name": "plans"}, headers=auth(token)
        )
        assert response.status_code == 409

    def test_quota_is_413(self, admin):
        client, token, _ = admin
        for n in range(MAX_FOLDERS):
            assert _create(client, token, f"Folder {n}").status_code == 201
        response = _create(client, token, "One too many")
        assert response.status_code == 413
        assert response.json()["error"] == "limit_exceeded"

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"name": "x", "extra": 1},
            {"name": 5},
            {"name": None},
            {"name": ""},
            {"name": "\u200b\u200b"},
            {"name": "x" * 81},
            {"name": "x" * 400},
        ],
        ids=["empty", "extra-key", "int", "null", "blank", "invisible", "81", "raw-too-long"],
    )
    def test_invalid_bodies_are_400(self, admin, body):
        client, token, _ = admin
        response = client.post("/v1/folders", json=body, headers=auth(token))
        assert response.status_code == 400
        assert client.get("/v1/folders", headers=auth(token)).json()["folders"] == []

    def test_non_json_body_is_415(self, admin):
        client, token, _ = admin
        response = client.post("/v1/folders", content=b"name=x", headers=auth(token))
        assert response.status_code == 415

    @pytest.mark.parametrize("method", ["PATCH", "DELETE"])
    def test_unknown_and_malformed_ids(self, admin, method):
        client, token, _ = admin
        kwargs: dict[str, Any] = {"json": {"name": "x"}} if method == "PATCH" else {}
        missing = client.request(method, f"/v1/folders/{MISSING}", headers=auth(token), **kwargs)
        assert missing.status_code == 404
        bad = client.request(method, "/v1/folders/not-an-id", headers=auth(token), **kwargs)
        assert bad.status_code == 400

    def test_query_parameters_are_refused(self, admin):
        client, token, _ = admin
        assert client.get("/v1/folders?state=trashed", headers=auth(token)).status_code == 400


class TestDeleteOnlyWhenEmpty:
    def test_folder_with_an_active_item_is_409(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        item = _item(client, token)
        _move(client, token, item["id"], folder["id"])
        response = client.delete(f"/v1/folders/{folder['id']}", headers=auth(token))
        assert response.status_code == 409
        assert response.json()["error"] == "conflict"

    def test_folder_with_only_a_trashed_item_is_409_until_moved_out(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        item = _item(client, token)
        _move(client, token, item["id"], folder["id"])
        client.post(f"/v1/items/{item['id']}/trash", headers=auth(token))
        assert client.delete(f"/v1/folders/{folder['id']}", headers=auth(token)).status_code == 409
        moved = _move(client, token, item["id"], None)
        assert moved.status_code == 200
        assert moved.json()["state"] == "trashed"
        assert client.delete(f"/v1/folders/{folder['id']}", headers=auth(token)).status_code == 200


class TestMove:
    def test_move_in_and_out_updates_the_item_folder(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        item = _item(client, token)
        assert item["folder"] is None
        moved = _move(client, token, item["id"], folder["id"])
        assert moved.status_code == 200
        assert moved.json()["folder"] == {"id": folder["id"], "name": "Plans"}
        assert moved.json()["updated_at"] > item["updated_at"]
        got = client.get(f"/v1/items/{item['id']}", headers=auth(token)).json()
        assert got["folder"] == {"id": folder["id"], "name": "Plans"}
        out = _move(client, token, item["id"], None)
        assert out.status_code == 200
        assert out.json()["folder"] is None

    def test_move_is_idempotent(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        item = _item(client, token)
        first = _move(client, token, item["id"], folder["id"]).json()
        second = _move(client, token, item["id"], folder["id"]).json()
        assert second == first

    def test_trashed_item_can_be_moved_and_keeps_its_folder_on_restore(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        item = _item(client, token)
        client.post(f"/v1/items/{item['id']}/trash", headers=auth(token))
        moved = _move(client, token, item["id"], folder["id"])
        assert moved.status_code == 200
        assert moved.json()["state"] == "trashed"
        restored = client.post(f"/v1/items/{item['id']}/restore", headers=auth(token)).json()
        assert restored["folder"] == {"id": folder["id"], "name": "Plans"}

    def test_unknown_folder_or_item_is_404_and_changes_nothing(self, admin):
        client, token, _ = admin
        item = _item(client, token)
        assert _move(client, token, item["id"], MISSING).status_code == 404
        after = client.get(f"/v1/items/{item['id']}", headers=auth(token)).json()
        assert after == item
        folder = _folder(client, token, "Plans")
        assert _move(client, token, MISSING, folder["id"]).status_code == 404

    @pytest.mark.parametrize(
        "body",
        [{}, {"folder_id": 1}, {"folder_id": "bad"}, {"folder_id": None, "x": 1}, {"folder": None}],
        ids=["empty", "int", "bad-id", "extra-key", "wrong-key"],
    )
    def test_invalid_bodies_are_400(self, admin, body):
        client, token, _ = admin
        item = _item(client, token)
        response = client.post(f"/v1/items/{item['id']}/move", json=body, headers=auth(token))
        assert response.status_code == 400

    def test_bad_item_id_is_400(self, admin):
        client, token, _ = admin
        response = _move(client, token, "not-an-id", None)
        assert response.status_code == 400

    def test_item_json_follows_a_folder_rename(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        item = _item(client, token)
        _move(client, token, item["id"], folder["id"])
        client.patch(f"/v1/folders/{folder['id']}", json={"name": "Later"}, headers=auth(token))
        got = client.get(f"/v1/items/{item['id']}", headers=auth(token)).json()
        assert got["folder"] == {"id": folder["id"], "name": "Later"}


class TestPublishIntoFolder:
    def test_publish_files_the_item(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        response = _publish_into(client, token, folder["id"])
        assert response.status_code == 201, response.text
        assert response.json()["folder"] == {"id": folder["id"], "name": "Plans"}

    def test_empty_folder_id_means_unfiled(self, admin):
        client, token, _ = admin
        response = _publish_into(client, token, "")
        assert response.status_code == 201
        assert response.json()["folder"] is None

    @pytest.mark.parametrize(("folder_id", "status"), [(MISSING, 404), ("not-an-id", 400)])
    def test_bad_or_unknown_folder_stores_nothing(self, admin, tmp_path, folder_id, status):
        client, token, _ = admin
        response = _publish_into(client, token, folder_id)
        assert response.status_code == status
        assert _list(client, token).json()["items"] == []
        blobs = [p for p in (tmp_path / "data" / "blobs").rglob("*") if p.is_file()]
        assert blobs == []


class TestListFilter:
    def test_filter_by_folder_and_unfiled(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        loose = _item(client, token)
        filed = _item(client, token)
        _move(client, token, filed["id"], folder["id"])
        by_folder = _list(client, token, folder=folder["id"]).json()["items"]
        assert [i["id"] for i in by_folder] == [filed["id"]]
        assert by_folder[0]["folder"] == {"id": folder["id"], "name": "Plans"}
        unfiled = _list(client, token, folder="unfiled").json()["items"]
        assert [i["id"] for i in unfiled] == [loose["id"]]
        everything = _list(client, token).json()["items"]
        assert {i["id"] for i in everything} == {loose["id"], filed["id"]}

    def test_filter_combines_with_state_and_paging(self, admin):
        client, token, _ = admin
        folder = _folder(client, token, "Plans")
        ids = []
        for _ in range(3):
            item = _item(client, token)
            _move(client, token, item["id"], folder["id"])
            ids.append(item["id"])
        first = _list(client, token, folder=folder["id"], limit="2").json()
        second = _list(
            client, token, folder=folder["id"], limit="2", cursor=first["next_cursor"]
        ).json()
        assert [i["id"] for i in first["items"] + second["items"]] == list(reversed(ids))
        assert second["next_cursor"] is None
        trashed = _list(client, token, folder=folder["id"], state="trashed").json()
        assert trashed["items"] == []

    @pytest.mark.parametrize(("value", "status"), [("", 400), ("Unfiled", 400), ("x", 400)])
    def test_bad_filter_is_400(self, admin, value, status):
        client, token, _ = admin
        assert _list(client, token, folder=value).status_code == status

    def test_unknown_folder_is_404(self, admin):
        client, token, _ = admin
        assert _list(client, token, folder=MISSING).status_code == 404
