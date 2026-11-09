"""Security tests for the folder interfaces (unit F2): C12/C33 on the new admin routes,
C40 (the viewer only reads folders), C39 at the HTTP boundary.

Admin: every folder route and the move route need the admin token (none or
wrong → 401, the notifier token → 403, a notifier-only peer uid → 403) and
change nothing when refused. Viewer: no route writes folders — POST, PUT,
PATCH, DELETE on folder paths are 404/405 even with a perfect CSRF header
set, and the route inventory only has `GET/HEAD /api/folders`. Names are
sanitized and secret-scanned at the boundary and never echoed in errors; a
folder the read side does not list renders `folder: null`, never an error.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import pytest
from starlette.testclient import TestClient

from preview_dashboard.application import FolderListing, IncomingFile, PublishCommand
from preview_dashboard.bootstrap import FolderReader
from preview_dashboard.domain.errors import NotFoundError
from preview_dashboard.domain.folders import Folder
from preview_dashboard.domain.models import Item, ItemState
from preview_dashboard.interfaces.admin import api, folders_api
from preview_dashboard.interfaces.admin.api import item_json
from preview_dashboard.interfaces.admin.auth import PeerCredentials
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from preview_dashboard.interfaces.folder_refs import FolderLookup, folder_names
from preview_dashboard.interfaces.viewer.app_factory import build_dashboard_app
from tests.admin_support import admin_client, auth
from tests.app_support import make_publish
from tests.mcp_support import fake_aws_key
from tests.notify_admin_support import asgi_client, bearer, notify_app
from tests.viewer_support import (
    StubServices,
    csrf_headers,
    make_env,
    make_settings,
    owner_headers,
    route_paths,
)

pytestmark = pytest.mark.security

ADMIN, NOTIFIER, NONE, WRONG = "admin", "notifier", "none", "wrong"


def _publish(core: Any, folder_id: str | None = None) -> Item:
    item: Item = core.publish.publish(
        PublishCommand(
            title="T", files=[IncomingFile(relpath="a.txt", chunks=[b"x"])], folder_id=folder_id
        )
    )
    return item


# --- C12 / C33: the new admin routes -------------------------------------------------

# (method, path template, JSON body)
ADMIN_ROUTES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("GET", "/v1/folders", None),
    ("POST", "/v1/folders", {"name": "New"}),
    ("PATCH", "/v1/folders/{fid}", {"name": "Renamed"}),
    ("DELETE", "/v1/folders/{fid}", None),
    ("POST", "/v1/items/{iid}/move", {"folder_id": "{fid}"}),
    ("GET", "/v1/items?folder={fid}", None),
]


def _fill(body: dict[str, Any] | None, fid: str) -> dict[str, Any] | None:
    if body is None:
        return None
    return {k: v.format(fid=fid) if isinstance(v, str) else v for k, v in body.items()}


@pytest.mark.parametrize("token_kind", [ADMIN, NOTIFIER, NONE, WRONG])
@pytest.mark.parametrize(("method", "template", "body"), ADMIN_ROUTES)
def test_c33_folder_routes_need_the_admin_token(tmp_path, token_kind, method, template, body):
    with notify_app(tmp_path) as rig, TestClient(rig.app) as client:
        folder = rig.core.folders.create("Plans")
        item = _publish(rig.core)
        headers = {
            ADMIN: bearer(rig.admin_token),
            NOTIFIER: bearer(rig.notifier_token),
            WRONG: bearer(secrets.token_urlsafe(32)),
            NONE: {},
        }[token_kind]
        path = template.format(fid=folder.id, iid=item.id)
        response = client.request(method, path, json=_fill(body, folder.id), headers=headers)
        folders_after = rig.core.folders.list()
        item_after = rig.core.queries.get(item.id)
    if token_kind in (NONE, WRONG):
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    elif token_kind == NOTIFIER:
        assert response.status_code == 403
    else:
        assert response.status_code in (200, 201), response.text
        return
    # Refused: nothing changed.
    assert [(e.folder.id, e.folder.name) for e in folders_after.folders] == [(folder.id, "Plans")]
    assert item_after == item


async def test_c33_folder_routes_are_in_the_admin_peer_family(tmp_path):
    with notify_app(tmp_path, allowed_peer_uids=[1000], notifier_peer_uids=[2000]) as rig:
        notifier_peer = PeerCredentials(pid=1, uid=2000, gid=1)
        async with asgi_client(rig.app, peer=notifier_peer) as client:
            response = await client.post(
                "/v1/folders", json={"name": "X"}, headers=bearer(rig.admin_token)
            )
        assert response.status_code == 403
        assert rig.core.folders.list().folders == ()


# --- C40: the viewer only reads folders -------------------------------------------------


@dataclass
class _ViewerRig:
    services: StubServices
    client: TestClient
    folder: Folder
    item: Item


@pytest.fixture
def viewer() -> Iterator[_ViewerRig]:
    env = make_env()
    folder = env.services.folder_admin.create("Plans")
    item = env.publish({"a.txt": b"x"}, folder_id=folder.id)
    yield _ViewerRig(env.services, env.dash_client(), folder, item)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "template",
    [
        "/api/folders",
        "/api/folders/{fid}",
        "/api/folders/{fid}/delete",
        "/api/folders/{fid}/rename",
        "/api/items/{iid}/move",
        "/api/items/{iid}/folder",
    ],
)
def test_c40_no_viewer_route_writes_folders(viewer: _ViewerRig, method: str, template: str) -> None:
    path = template.format(fid=viewer.folder.id, iid=viewer.item.id)
    body = {"name": "Hijacked", "folder_id": None}
    # A perfect CSRF header set: only the missing route can refuse it.
    response = viewer.client.request(method, path, json=body, headers=csrf_headers())
    assert response.status_code in (404, 405), response.text
    assert viewer.services.folder_admin.get(viewer.folder.id) == viewer.folder
    assert viewer.services.queries.get(viewer.item.id) == viewer.item


def test_c40_folder_route_inventory_is_read_only() -> None:
    app = build_dashboard_app(make_settings(), StubServices())
    folder_paths = {p for p in route_paths(app) if "folder" in p}
    assert folder_paths == {"/api/folders"}
    methods: set[str] = set()
    pending: list[Any] = list(app.inner.routes)
    while pending:
        route = pending.pop()
        if getattr(route, "path", None) == "/api/folders":
            methods |= set(route.methods)
        pending.extend(getattr(getattr(route, "original_router", None), "routes", []))
    assert methods == {"GET", "HEAD"}


def test_c40_viewer_folder_capability_is_read_only() -> None:
    members = {name for name in dir(FolderLookup) if not name.startswith("_")}
    assert members == {"list", "get", "names"}
    assert StubServices().folders.__class__ is FolderReader


# --- C33: folder/move routes recheck the token role themselves -------------------------


async def test_c33_folder_and_move_routes_recheck_the_token_role() -> None:
    """Defense in depth (S-F2 review, item 3): each route calls `require_admin` itself,
    before touching anything else on the request — not only relying on the middleware.
    """

    class _NotifierOnlyRequest:
        scope: ClassVar[dict[str, Any]] = {"state": {"pdash.token_role": "notifier"}}

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"touched request.{name} before the admin-role check")

    request = _NotifierOnlyRequest()
    calls: Iterable[Any] = (
        folders_api.list_folders(request),  # type: ignore[arg-type]
        folders_api.create_folder(request),  # type: ignore[arg-type]
        folders_api.rename_folder(request, "x"),  # type: ignore[arg-type]
        folders_api.delete_folder(request, "x"),  # type: ignore[arg-type]
        api.move_item(request, "x"),  # type: ignore[arg-type]
    )
    for coro in calls:
        with pytest.raises(ForbiddenError):
            await coro


# --- C39 at the boundary ------------------------------------------------------------------


def test_c39_names_are_sanitized_on_the_way_in_and_out(tmp_path: Path) -> None:
    raw = "\u202egnp.exe\u200b Plans\u2066"
    with admin_client(tmp_path) as (client, token, core):
        created = client.post("/v1/folders", json={"name": raw}, headers=auth(token))
        assert created.status_code == 201
        assert created.json()["name"] == "gnp.exe Plans"
        listed = client.get("/v1/folders", headers=auth(token)).json()
        assert listed["folders"][0]["name"] == "gnp.exe Plans"
        assert core.folders.get(created.json()["id"]).name == "gnp.exe Plans"


@pytest.mark.parametrize("hide", ["", "\u200b"])
def test_c39_secret_names_are_refused_without_echo(tmp_path: Path, hide: str) -> None:
    key = fake_aws_key()
    name = f"keys {key[:6]}{hide}{key[6:]}"
    with admin_client(tmp_path) as (client, token, core):
        response = client.post("/v1/folders", json={"name": name}, headers=auth(token))
        assert response.status_code == 422
        body = response.json()
        assert body["error"] == "secret_detected"
        assert "relpath" not in body
        assert key not in response.text and key[6:] not in response.text
        assert core.folders.list().folders == ()
        folder = core.folders.create("Plans")
        renamed = client.patch(f"/v1/folders/{folder.id}", json={"name": name}, headers=auth(token))
        assert renamed.status_code == 422
        assert core.folders.get(folder.id).name == "Plans"


def test_c39_error_bodies_never_echo_the_name(tmp_path: Path) -> None:
    with admin_client(tmp_path) as (client, token, _):
        client.post("/v1/folders", json={"name": "Marker-Name-42"}, headers=auth(token))
        dup = client.post("/v1/folders", json={"name": "marker-name-42"}, headers=auth(token))
        long = client.post("/v1/folders", json={"name": "Marker" * 20}, headers=auth(token))
    assert dup.status_code == 409 and long.status_code == 400
    for response in (dup, long):
        assert "arker" not in response.text


# --- a folder the read side does not list renders null ---------------------------------------


class _HidingLookup:
    """A read side whose listing omits every folder (e.g. rows skipped as invalid)."""

    def __init__(self, inner: FolderLookup) -> None:
        self._inner = inner

    def list(self, *, state: ItemState = ItemState.ACTIVE) -> FolderListing:
        listing = self._inner.list(state=state)
        return FolderListing(folders=(), unfiled_count=listing.unfiled_count)

    def get(self, folder_id: str) -> Folder:
        raise NotFoundError("folder not found")

    def names(self) -> tuple[Folder, ...]:
        return ()


class _HidingServices(StubServices):
    @property
    def folders(self) -> FolderLookup:
        return _HidingLookup(super().folders)


def test_unlisted_folder_renders_null_in_viewer_json() -> None:
    harness = make_publish()
    services = _HidingServices(harness.repo, harness.blobs, harness.clock, harness.folders)
    env = make_env(services, publisher=harness.service)
    folder = services.folder_admin.create("Plans")
    item = env.publish({"a.txt": b"x"}, folder_id=folder.id)
    client = env.dash_client()
    listed = client.get("/api/items", headers=owner_headers())
    assert listed.status_code == 200
    assert listed.json()["items"][0]["folder"] is None
    detail = client.get(f"/api/items/{item.id}", headers=owner_headers())
    assert detail.status_code == 200
    assert detail.json()["folder"] is None
    assert client.get("/api/folders", headers=owner_headers()).json()["folders"] == []


def test_unlisted_folder_renders_null_in_admin_json() -> None:
    env = make_env()
    folder = env.services.folder_admin.create("Plans")
    item = env.publish({"a.txt": b"x"}, folder_id=folder.id)
    names = folder_names(_HidingLookup(env.services.folders), [item])
    assert names == {}
    assert item_json(item, None, names)["folder"] is None
    assert item_json(item, None, {folder.id: "Plans"})["folder"] == {
        "id": folder.id,
        "name": "Plans",
    }
