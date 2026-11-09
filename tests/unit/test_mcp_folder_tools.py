"""Tests for the folder MCP tools (`tools/folders.py`, `dashboard_move`, folder args) and client.

End to end: the real `MCPServer` through the SDK's in-process client, the
real intake policy and a real admin API on a tmp Unix socket. Client unit
tests (httpx `MockTransport`) pin the request shapes and the local id
checks that run before any URL is built. Folder names must always come back
nested under `untrusted_item_data`, never beside server-controlled fields.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from preview_dashboard.interfaces.mcp.client import AdminClient, AdminInputError
from preview_dashboard.interfaces.mcp.server import DashboardTools, build_server
from tests.mcp_support import LiveAdmin, fake_aws_key, live_admin, write_file

pytestmark = pytest.mark.unit

FOLDER_ID = "01J0000000000000000000000F"
ITEM_ID = "01J00000000000000000000001"
MISSING = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
TOKEN = b"t" * 43


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[LiveAdmin]:
    with live_admin(tmp_path) as live:
        yield live


@pytest.fixture
def server(admin: LiveAdmin) -> Iterator[MCPServer]:
    with admin.client() as http:
        yield build_server(DashboardTools(intake=admin.intake(), admin=http))


def _text(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


async def _ok(client: Client, tool: str, **args: Any) -> Any:
    result = await client.call_tool(tool, args)
    assert not result.is_error, _text(result)
    return json.loads(_text(result))


async def _err(client: Client, tool: str, **args: Any) -> str:
    result = await client.call_tool(tool, args)
    assert result.is_error
    text = _text(result)
    assert "Traceback" not in text
    return text


async def _publish(mcp: Client, admin: LiveAdmin, name: str = "a.txt", **args: Any) -> Any:
    f = write_file(admin.outbox / name, "hello")
    return await _ok(mcp, "dashboard_publish", paths=[str(f)], title="Doc", **args)


# --- end to end ------------------------------------------------------------------------


async def test_folder_lifecycle(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        created = (await _ok(mcp, "dashboard_folder_create", name="Plans"))["folder"]
        assert set(created) == {"id", "created_at", "updated_at", "untrusted_item_data"}
        assert created["untrusted_item_data"] == {"name": "Plans"}
        fid = created["id"]
        item = await _publish(mcp, admin, folder_id=fid)
        assert item["folder_id"] == fid
        assert item["untrusted_item_data"]["folder_name"] == "Plans"
        listed = await _ok(mcp, "dashboard_folder_list")
        assert listed == {
            "folders": [
                {
                    "id": fid,
                    "count": 1,
                    "trashed_count": 0,
                    "created_at": created["created_at"],
                    "updated_at": created["updated_at"],
                    "untrusted_item_data": {"name": "Plans"},
                }
            ],
            "unfiled_count": 0,
            "unfiled_trashed_count": 0,
        }
        renamed = (await _ok(mcp, "dashboard_folder_rename", folder_id=fid, name="Later"))["folder"]
        assert renamed["untrusted_item_data"] == {"name": "Later"}
        refused = await _err(mcp, "dashboard_folder_delete", folder_id=fid)
        assert "409" in refused and "conflict" in refused
        moved = await _ok(mcp, "dashboard_move", item_id=item["id"], folder_id=None)
        assert moved["folder_id"] is None
        assert moved["untrusted_item_data"]["folder_name"] is None
        assert await _ok(mcp, "dashboard_folder_delete", folder_id=fid) == {"deleted": fid}
        assert (await _ok(mcp, "dashboard_folder_list"))["folders"] == []


async def test_list_by_folder_and_unfiled(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        fid = (await _ok(mcp, "dashboard_folder_create", name="Plans"))["folder"]["id"]
        filed = await _publish(mcp, admin, "a.txt", folder_id=fid)
        loose = await _publish(mcp, admin, "b.txt")
        in_folder = await _ok(mcp, "dashboard_list", folder=fid)
        assert [i["id"] for i in in_folder["items"]] == [filed["id"]]
        assert in_folder["items"][0]["untrusted_item_data"]["folder_name"] == "Plans"
        unfiled = await _ok(mcp, "dashboard_list", folder="unfiled")
        assert [i["id"] for i in unfiled["items"]] == [loose["id"]]
        missing = await _err(mcp, "dashboard_list", folder=MISSING)
        assert "404" in missing


async def test_move_works_on_trashed_items(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        fid = (await _ok(mcp, "dashboard_folder_create", name="Plans"))["folder"]["id"]
        item = await _publish(mcp, admin)
        await _ok(mcp, "dashboard_trash", item_id=item["id"])
        moved = await _ok(mcp, "dashboard_move", item_id=item["id"], folder_id=fid)
        assert (moved["state"], moved["folder_id"]) == ("trashed", fid)
        restored = await _ok(mcp, "dashboard_restore", item_id=item["id"])
        assert restored["folder_id"] == fid


async def test_errors_are_clean(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        await _ok(mcp, "dashboard_folder_create", name="Plans")
        dup = await _err(mcp, "dashboard_folder_create", name="PLANS")
        assert "409" in dup and "PLANS" not in dup
        secret = await _err(mcp, "dashboard_folder_create", name=f"k {fake_aws_key()}")
        assert "secret" in secret and fake_aws_key() not in secret
        assert "404" in await _err(mcp, "dashboard_folder_delete", folder_id=MISSING)
        assert "404" in await _err(mcp, "dashboard_folder_rename", folder_id=MISSING, name="X")
        item = await _publish(mcp, admin)
        assert "404" in await _err(mcp, "dashboard_move", item_id=item["id"], folder_id=MISSING)
        unknown = await _err(
            mcp,
            "dashboard_publish",
            paths=[str(admin.outbox / "a.txt")],
            title="X",
            folder_id=MISSING,
        )
        assert "404" in unknown


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("dashboard_folder_rename", {"folder_id": "../items", "name": "X"}),
        ("dashboard_folder_delete", {"folder_id": "abc"}),
        ("dashboard_move", {"item_id": ITEM_ID, "folder_id": "01j0000000000000000000000f"}),
        ("dashboard_list", {"folder": "Unfiled"}),
        ("dashboard_folder_create", {"name": ""}),
        ("dashboard_folder_create", {"name": "x" * 321}),
    ],
)
async def test_arguments_are_schema_checked(
    server: MCPServer, tool: str, args: dict[str, Any]
) -> None:
    async with Client(server) as mcp:
        await _err(mcp, tool, **args)


def test_instructions_mention_folders_and_their_untrusted_names(server: MCPServer) -> None:
    instructions = server.instructions or ""
    assert "dashboard_move" in instructions
    assert "folder names" in instructions and "untrusted_item_data" in instructions


# --- client request shapes ----------------------------------------------------------------


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> AdminClient:
    return AdminClient(Path("/unused.sock"), TOKEN, transport=httpx.MockTransport(handler))


def _recording() -> tuple[list[httpx.Request], AdminClient]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        seen.append(request)
        return httpx.Response(200, json={"id": FOLDER_ID, "deleted": True})

    return seen, _client(handler)


def test_folder_requests() -> None:
    seen, client = _recording()
    client.list_folders()
    client.create_folder("Plans")
    client.rename_folder(FOLDER_ID, "Later")
    client.delete_folder(FOLDER_ID)
    client.move_item(ITEM_ID, FOLDER_ID)
    client.move_item(ITEM_ID, None)
    client.list_items(folder="unfiled")
    client.list_items(folder=FOLDER_ID)
    shapes = [(r.method, r.url.path, r.content) for r in seen]
    assert shapes[:6] == [
        ("GET", "/v1/folders", b""),
        ("POST", "/v1/folders", b'{"name":"Plans"}'),
        ("PATCH", f"/v1/folders/{FOLDER_ID}", b'{"name":"Later"}'),
        ("DELETE", f"/v1/folders/{FOLDER_ID}", b""),
        ("POST", f"/v1/items/{ITEM_ID}/move", f'{{"folder_id":"{FOLDER_ID}"}}'.encode()),
        ("POST", f"/v1/items/{ITEM_ID}/move", b'{"folder_id":null}'),
    ]
    assert seen[6].url.params["folder"] == "unfiled"
    assert seen[7].url.params["folder"] == FOLDER_ID
    assert all(r.headers["authorization"] == "Bearer " + TOKEN.decode() for r in seen)


@pytest.mark.parametrize("bad", ["../items", "abc", "", FOLDER_ID.lower(), f"{FOLDER_ID}/x"])
def test_folder_ids_are_checked_before_any_request(bad: str) -> None:
    seen, client = _recording()
    calls: list[Callable[[], object]] = [
        lambda: client.rename_folder(bad, "x"),
        lambda: client.delete_folder(bad),
        lambda: client.move_item(ITEM_ID, bad),
        lambda: client.list_items(folder=bad),
    ]
    for call in calls:
        with pytest.raises(AdminInputError):
            call()
    assert seen == []


class _Upload:
    relpath = "a.txt"
    size = 1

    def open_reader(self, chunk_size: int = 65536) -> Any:
        return nullcontext(iter([b"x"]))


def test_publish_sends_folder_id_before_the_manifest() -> None:
    bodies: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.read())
        return httpx.Response(201, json={"id": ITEM_ID})

    _client(handler).publish([_Upload()], title="t", folder_id=FOLDER_ID)
    body = bodies[0]
    assert body.index(b'name="folder_id"') < body.index(b'name="manifest"')
    assert FOLDER_ID.encode() in body
    seen, client = _recording()
    with pytest.raises(AdminInputError):
        client.publish([_Upload()], title="t", folder_id="bad")
    assert seen == []
