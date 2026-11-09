"""Tests for the permanent-delete MCP tools (ADR 0030): `dashboard_prune_revisions`, `_empty_trash`.

End to end over a real admin socket, plus client request shapes; titles only
under `untrusted_item_data`, descriptions say permanent, bad args refused.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from preview_dashboard.interfaces.mcp.client import AdminClient, AdminInputError
from preview_dashboard.interfaces.mcp.server import DashboardTools, build_server
from tests.mcp_support import LiveAdmin, live_admin, write_file

pytestmark = pytest.mark.unit

ITEM_ID = "01J00000000000000000000001"
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


async def _item_with_revisions(mcp: Client, admin: LiveAdmin, count: int) -> Any:
    page = write_file(admin.outbox / "page" / "index.html", "<h1>v1</h1>")
    item = await _ok(mcp, "dashboard_publish", paths=[str(page.parent)], title="Page")
    for n in range(2, count + 1):
        write_file(page, f"<h1>v{n}</h1>")
        item = await _ok(
            mcp, "dashboard_update_content", item_id=item["id"], paths=[str(page.parent)]
        )
    return item


async def test_prune_revisions_end_to_end(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        item = await _item_with_revisions(mcp, admin, 3)
        result = await _ok(mcp, "dashboard_prune_revisions", item_id=item["id"])
        assert set(result) == {"revisions_removed", "bytes_freed", "item"}
        assert result["revisions_removed"] == 2
        assert result["bytes_freed"] == len("<h1>v1</h1>") + len("<h1>v2</h1>")
        pruned = result["item"]
        assert (pruned["id"], pruned["revision"], pruned["viewer_url"]) == (
            item["id"],
            3,
            item["viewer_url"],
        )
        assert "title" not in pruned
        assert pruned["untrusted_item_data"]["title"] == "Page"
        again = await _ok(mcp, "dashboard_prune_revisions", item_id=item["id"], keep=5)
        assert (again["revisions_removed"], again["bytes_freed"]) == (0, 0)


async def test_prune_keep_and_expected_revision(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        item = await _item_with_revisions(mcp, admin, 4)
        stale = await _err(
            mcp, "dashboard_prune_revisions", item_id=item["id"], expected_revision=3
        )
        assert "409" in stale and "conflict" in stale
        result = await _ok(
            mcp, "dashboard_prune_revisions", item_id=item["id"], keep=2, expected_revision=4
        )
        assert result["revisions_removed"] == 2


async def test_prune_of_a_trashed_item_is_refused(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        item = await _item_with_revisions(mcp, admin, 2)
        await _ok(mcp, "dashboard_trash", item_id=item["id"])
        refused = await _err(mcp, "dashboard_prune_revisions", item_id=item["id"])
        assert "409" in refused


async def test_empty_trash_end_to_end(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        kept = await _ok(
            mcp, "dashboard_publish", paths=[str(write_file(admin.outbox / "a.txt"))], title="A"
        )
        gone = await _ok(
            mcp, "dashboard_publish", paths=[str(write_file(admin.outbox / "b.txt"))], title="B"
        )
        await _ok(mcp, "dashboard_trash", item_id=gone["id"])
        result = await _ok(mcp, "dashboard_empty_trash")
        assert result == {"items_purged": 1, "blobs_deleted": 1}
        assert "404" in await _err(mcp, "dashboard_get", item_id=gone["id"])
        assert (await _ok(mcp, "dashboard_get", item_id=kept["id"]))["state"] == "active"
        assert await _ok(mcp, "dashboard_empty_trash") == {"items_purged": 0, "blobs_deleted": 0}


@pytest.mark.parametrize(
    "args",
    [
        {"item_id": ITEM_ID, "keep": 0},
        {"item_id": ITEM_ID, "keep": 21},
        {"item_id": ITEM_ID, "expected_revision": 0},
        {"item_id": "../kinds"},
        {"item_id": ITEM_ID.lower()},
    ],
)
async def test_prune_arguments_are_schema_checked(server: MCPServer, args: dict[str, Any]) -> None:
    async with Client(server) as mcp:
        await _err(mcp, "dashboard_prune_revisions", **args)


async def test_descriptions_say_permanent(server: MCPServer) -> None:
    async with Client(server) as mcp:
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
    for name in ("dashboard_prune_revisions", "dashboard_empty_trash"):
        tool = tools[name]
        assert tool.description is not None
        assert "PERMANENTLY" in tool.description and "CANNOT be undone" in tool.description
        assert tool.annotations is not None and tool.annotations.destructive_hint is True
    assert "PERMANENT" in (server.instructions or "")


# --- client request shapes ----------------------------------------------------------------


def _recording() -> tuple[list[httpx.Request], AdminClient]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        seen.append(request)
        return httpx.Response(200, json={"items_purged": 0, "blobs_deleted": 0})

    transport = httpx.MockTransport(handler)
    return seen, AdminClient(Path("/unused.sock"), TOKEN, transport=transport)


def test_cleanup_requests() -> None:
    seen, client = _recording()
    client.prune_revisions(ITEM_ID)
    client.prune_revisions(ITEM_ID, keep=3, expected_revision=7)
    client.empty_trash()
    shapes = [(r.method, r.url.path, r.content) for r in seen]
    assert shapes == [
        ("POST", f"/v1/items/{ITEM_ID}/revisions/prune", b'{"keep":1}'),
        ("POST", f"/v1/items/{ITEM_ID}/revisions/prune", b'{"keep":3,"expected_revision":7}'),
        ("POST", "/v1/trash/empty", b""),
    ]
    assert all(r.headers["authorization"] == "Bearer " + TOKEN.decode() for r in seen)


@pytest.mark.parametrize("bad", ["../kinds", "abc", "", ITEM_ID.lower(), f"{ITEM_ID}/x"])
def test_item_id_is_checked_before_any_request(bad: str) -> None:
    seen, client = _recording()
    with pytest.raises(AdminInputError):
        client.prune_revisions(bad)
    assert seen == []
