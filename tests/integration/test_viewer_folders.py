"""Integration tests for the viewer's read-only folder API (ADR 0027, C40) over real SQLite.

The admin core (the only writer of folders) and the viewer core share one
tmp data dir, exactly as the two processes share the database in
production; the dashboard app is built from the real `ViewerCore`. Covers
`GET/HEAD /api/folders` (exact shape, name order, active counts, ETag/304),
the `?folder=` filter of `/api/items` and `folder` in item JSON.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from preview_dashboard.application import IncomingFile, PublishCommand
from preview_dashboard.bootstrap import AdminCore, ViewerCore, build_core
from preview_dashboard.domain.models import Item
from preview_dashboard.interfaces.viewer.app_factory import build_dashboard_app
from tests.admin_support import make_settings
from tests.viewer_support import (
    DASH_HOST,
    OWNER,
    PREVIEW_ORIGIN,
    csrf_headers,
    dashboard_client,
    owner_headers,
)

pytestmark = pytest.mark.integration

MISSING = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"


@dataclass
class Rig:
    """Admin core (writes) + viewer dashboard client (reads) over one database."""

    admin: AdminCore
    viewer: ViewerCore
    client: TestClient

    def publish(self, title: str = "A title", folder_id: str | None = None) -> Item:
        return self.admin.publish.publish(
            PublishCommand(
                title=title,
                files=[IncomingFile(relpath="a.txt", chunks=[b"x"])],
                folder_id=folder_id,
            )
        )

    def get(self, path: str, **params: str) -> Any:
        return self.client.get(path, params=params, headers=owner_headers())


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[Rig]:
    settings = make_settings(
        tmp_path,
        owner_login=OWNER,
        allowed_hosts=frozenset({DASH_HOST}),
        preview_origin=PREVIEW_ORIGIN,
        viewer_port=8787,
        preview_port=8788,
    )
    with (
        build_core(settings, role="admin") as admin,
        build_core(settings, role="viewer") as viewer,
    ):
        client = dashboard_client(build_dashboard_app(settings, viewer))
        yield Rig(admin=admin, viewer=viewer, client=client)


class TestFoldersEndpoint:
    def test_exact_shape_name_order_and_active_counts(self, rig: Rig) -> None:
        beta = rig.admin.folders.create("beta")
        alpha = rig.admin.folders.create("Alpha")
        rig.publish(folder_id=beta.id)
        trashed = rig.publish(folder_id=beta.id)
        rig.admin.lifecycle.trash(trashed.id)
        rig.publish()
        response = rig.get("/api/folders")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "folders": [
                {"id": alpha.id, "name": "Alpha", "count": 0},
                {"id": beta.id, "name": "beta", "count": 1},
            ],
            "unfiled_count": 1,
        }

    def test_empty(self, rig: Rig) -> None:
        assert rig.get("/api/folders").json() == {"folders": [], "unfiled_count": 0}

    def test_etag_304_and_change_on_rename(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        first = rig.get("/api/folders")
        etag = first.headers["etag"]
        same = rig.client.get("/api/folders", headers=owner_headers({"If-None-Match": etag}))
        assert same.status_code == 304
        assert same.content == b""
        rig.admin.folders.rename(folder.id, "Later")
        changed = rig.client.get("/api/folders", headers=owner_headers({"If-None-Match": etag}))
        assert changed.status_code == 200
        assert changed.headers["etag"] != etag

    def test_head(self, rig: Rig) -> None:
        rig.admin.folders.create("Plans")
        head = rig.client.head("/api/folders", headers=owner_headers())
        assert head.status_code == 200
        assert head.content == b""
        assert head.headers["etag"] == rig.get("/api/folders").headers["etag"]

    @pytest.mark.parametrize("query", ["state=trashed", "x=1", "folder=unfiled"])
    def test_takes_no_query_parameters(self, rig: Rig, query: str) -> None:
        response = rig.client.get(f"/api/folders?{query}", headers=owner_headers())
        assert response.status_code == 400

    def test_names_are_the_sanitized_ones(self, rig: Rig) -> None:
        rig.admin.folders.create("\u202eevil\u200b name")
        assert rig.get("/api/folders").json()["folders"][0]["name"] == "evil name"


class TestItemsFilter:
    def test_filter_by_folder_unfiled_and_all(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        filed = rig.publish(folder_id=folder.id)
        loose = rig.publish()
        by_folder = rig.get("/api/items", folder=folder.id).json()["items"]
        assert [i["id"] for i in by_folder] == [filed.id]
        unfiled = rig.get("/api/items", folder="unfiled").json()["items"]
        assert [i["id"] for i in unfiled] == [loose.id]
        assert {i["id"] for i in rig.get("/api/items").json()["items"]} == {filed.id, loose.id}

    def test_filter_combines_with_state_kind_limit_and_cursor(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        ids = [rig.publish(folder_id=folder.id).id for _ in range(3)]
        rig.publish()
        first = rig.get("/api/items", folder=folder.id, limit="2", kind="text").json()
        second = rig.get(
            "/api/items", folder=folder.id, limit="2", kind="text", cursor=first["next_cursor"]
        ).json()
        assert [i["id"] for i in first["items"] + second["items"]] == list(reversed(ids))
        rig.admin.lifecycle.trash(ids[0])
        trashed = rig.get("/api/items", folder=folder.id, state="trashed").json()["items"]
        assert [i["id"] for i in trashed] == [ids[0]]

    @pytest.mark.parametrize("value", ["", "Unfiled", "UNFILED", "abc", MISSING.lower()])
    def test_bad_value_is_400(self, rig: Rig, value: str) -> None:
        assert rig.get("/api/items", folder=value).status_code == 400

    def test_unknown_folder_is_404(self, rig: Rig) -> None:
        assert rig.get("/api/items", folder=MISSING).status_code == 404

    def test_repeated_folder_parameter_is_400(self, rig: Rig) -> None:
        response = rig.client.get(
            "/api/items?folder=unfiled&folder=unfiled", headers=owner_headers()
        )
        assert response.status_code == 400

    def test_empty_folder_lists_nothing(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        rig.publish()
        assert rig.get("/api/items", folder=folder.id).json() == {
            "items": [],
            "next_cursor": None,
        }


class TestFolderInItemJson:
    def test_list_detail_and_state_change_carry_the_folder(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        filed = rig.publish(folder_id=folder.id)
        loose = rig.publish()
        ref = {"id": folder.id, "name": "Plans"}
        listed = {i["id"]: i["folder"] for i in rig.get("/api/items").json()["items"]}
        assert listed == {filed.id: ref, loose.id: None}
        assert rig.get(f"/api/items/{filed.id}").json()["folder"] == ref
        assert rig.get(f"/api/items/{loose.id}").json()["folder"] is None
        trashed = rig.client.post(f"/api/items/{filed.id}/trash", headers=csrf_headers())
        assert trashed.status_code == 200
        assert trashed.json()["item"]["folder"] == ref
        restored = rig.client.post(f"/api/items/{filed.id}/restore", headers=csrf_headers())
        assert restored.json()["item"]["folder"] == ref

    def test_several_folders_in_one_page(self, rig: Rig) -> None:
        a = rig.admin.folders.create("A")
        b = rig.admin.folders.create("B")
        in_a = rig.publish(folder_id=a.id)
        in_b = rig.publish(folder_id=b.id)
        listed = {i["id"]: i["folder"] for i in rig.get("/api/items").json()["items"]}
        assert listed == {in_a.id: {"id": a.id, "name": "A"}, in_b.id: {"id": b.id, "name": "B"}}

    def test_rename_changes_the_item_etag(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        item = rig.publish(folder_id=folder.id)
        before = rig.get(f"/api/items/{item.id}")
        rig.admin.folders.rename(folder.id, "Later")
        after = rig.client.get(
            f"/api/items/{item.id}",
            headers=owner_headers({"If-None-Match": before.headers["etag"]}),
        )
        assert after.status_code == 200
        assert after.json()["folder"] == {"id": folder.id, "name": "Later"}

    def test_trashed_item_detail_keeps_its_folder(self, rig: Rig) -> None:
        folder = rig.admin.folders.create("Plans")
        item = rig.publish(folder_id=folder.id)
        rig.admin.lifecycle.trash(item.id)
        detail = rig.get(f"/api/items/{item.id}", t="1").json()
        assert detail["folder"] == {"id": folder.id, "name": "Plans"}
