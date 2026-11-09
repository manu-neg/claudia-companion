"""Tests for the MCP tools (interfaces/mcp/server.py) through the SDK's in-process client.

Each test drives the real `MCPServer` with `mcp.Client(server)`; the tools
use the real intake policy and a real admin API on a tmp Unix socket, so a
publish goes file -> intake -> multipart -> admin core -> SQLite/blobs.
Failures must come back as clean tool errors (no stack traces, no secrets).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from preview_dashboard.interfaces.mcp.server import DashboardTools, build_server, main
from tests.mcp_support import LiveAdmin, fake_aws_key, live_admin, write_file

pytestmark = pytest.mark.unit

EXPECTED_TOOLS = {
    "dashboard_publish",
    "dashboard_update_content",
    "dashboard_list",
    "dashboard_get",
    "dashboard_update",
    "dashboard_trash",
    "dashboard_restore",
    "dashboard_kinds",
    "dashboard_move",
    "dashboard_prune_revisions",
    "dashboard_empty_trash",
    "dashboard_folder_create",
    "dashboard_folder_list",
    "dashboard_folder_rename",
    "dashboard_folder_delete",
}


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[LiveAdmin]:
    with live_admin(tmp_path) as live:
        yield live


@pytest.fixture
def server(admin: LiveAdmin) -> Iterator[MCPServer]:
    # Sync fixture: the in-process Client is entered inside each test's own
    # task (anyio cancel scopes can't span pytest-asyncio fixture tasks).
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


async def test_tools_are_listed_with_descriptions(server: MCPServer) -> None:
    async with Client(server) as mcp:
        tools = (await mcp.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        for tool in tools:
            assert tool.description and len(tool.description) > 30


async def test_publish_single_file(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "notes" / "report.md", "# Report\n\nhello")
        item = await _ok(mcp, "dashboard_publish", paths=[str(f)], title="Report")
        assert item["kind"] == "markdown"
        assert item["untrusted_item_data"]["files"] == ["report.md"]
        assert item["file_count"] == 1
        assert item["viewer_url"] == f"https://dash.example.ts.net/#/item/{item['id']}"


async def test_publish_html_bundle_directory(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        site = admin.outbox / "site"
        write_file(site / "index.html", '<link rel="stylesheet" href="css/app.css"><h1>Hi</h1>')
        write_file(site / "css" / "app.css", "h1{color:red}")
        write_file(site / "img" / "logo.svg", "<svg xmlns='http://www.w3.org/2000/svg'/>")
        item = await _ok(
            mcp,
            "dashboard_publish",
            paths=[str(site)],
            title="Site",
            description="A *bundle*",
            pinned=True,
        )
        assert item["kind"] == "html"
        assert item["untrusted_item_data"]["entry_file"] == "index.html"
        assert item["pinned"] is True
        assert sorted(item["untrusted_item_data"]["files"]) == [
            "css/app.css",
            "img/logo.svg",
            "index.html",
        ]


async def test_publish_several_paths_with_base(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        base = admin.outbox / "proj"
        a = write_file(base / "src" / "a.py", "print(1)\n")
        b = write_file(base / "docs" / "b.txt", "b")
        item = await _ok(
            mcp, "dashboard_publish", paths=[str(a), str(b)], title="Two", base=str(base)
        )
        assert sorted(item["untrusted_item_data"]["files"]) == ["docs/b.txt", "src/a.py"]


async def test_publish_kind_override(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "data.txt", "plain")
        item = await _ok(mcp, "dashboard_publish", paths=[str(f)], title="t", kind="text")
        assert item["kind"] == "text"


async def test_update_content_publishes_a_new_revision(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f1 = write_file(admin.outbox / "page" / "index.html", "<h1>v1</h1>")
        item = await _ok(
            mcp, "dashboard_publish", paths=[str(f1.parent)], title="Page", pinned=True
        )
        item_id, viewer_url = item["id"], item["viewer_url"]
        assert item["revision"] == 1

        f2 = write_file(admin.outbox / "page2" / "index.html", "<h1>v2</h1>")
        revised = await _ok(
            mcp,
            "dashboard_update_content",
            item_id=item_id,
            paths=[str(f2.parent)],
            expected_revision=1,
        )
        assert revised["id"] == item_id
        assert revised["revision"] == 2
        assert revised["viewer_url"] == viewer_url  # stable link across revisions
        assert revised["pinned"] is True  # metadata untouched by a content update
        assert revised["untrusted_item_data"]["files"] == ["index.html"]

        got = await _ok(mcp, "dashboard_get", item_id=item_id)
        assert got["revision"] == 2


async def test_update_content_stale_expected_revision_is_a_clean_conflict(
    server: MCPServer, admin: LiveAdmin
) -> None:
    async with Client(server) as mcp:
        f1 = write_file(admin.outbox / "a" / "index.html", "<h1>v1</h1>")
        item = await _ok(mcp, "dashboard_publish", paths=[str(f1.parent)], title="A")
        f2 = write_file(admin.outbox / "b" / "index.html", "<h1>v2</h1>")
        text = await _err(
            mcp,
            "dashboard_update_content",
            item_id=item["id"],
            paths=[str(f2.parent)],
            expected_revision=99,
        )
        assert "409" in text and "conflict" in text


async def test_update_content_on_trashed_item_is_invalid_state(
    server: MCPServer, admin: LiveAdmin
) -> None:
    async with Client(server) as mcp:
        f1 = write_file(admin.outbox / "a" / "index.html", "<h1>v1</h1>")
        item = await _ok(mcp, "dashboard_publish", paths=[str(f1.parent)], title="A")
        await _ok(mcp, "dashboard_trash", item_id=item["id"])
        f2 = write_file(admin.outbox / "b" / "index.html", "<h1>v2</h1>")
        text = await _err(
            mcp, "dashboard_update_content", item_id=item["id"], paths=[str(f2.parent)]
        )
        assert "409" in text and "invalid_state" in text


async def test_update_content_unknown_item(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "a" / "index.html", "hi")
        text = await _err(
            mcp,
            "dashboard_update_content",
            item_id="01J0000000000000000000000Z",
            paths=[str(f.parent)],
        )
        assert "404" in text


async def test_update_content_secret_content_refused_without_echo(
    server: MCPServer, admin: LiveAdmin
) -> None:
    async with Client(server) as mcp:
        f1 = write_file(admin.outbox / "a" / "index.html", "<h1>v1</h1>")
        item = await _ok(mcp, "dashboard_publish", paths=[str(f1.parent)], title="A")
        secret = write_file(admin.outbox / "conf.txt", f"aws = {fake_aws_key()}\n")
        text = await _err(mcp, "dashboard_update_content", item_id=item["id"], paths=[str(secret)])
        assert "AWS access key id" in text and "conf.txt" in text
        assert fake_aws_key() not in text
        # The failed attempt must not have changed the item.
        got = await _ok(mcp, "dashboard_get", item_id=item["id"])
        assert got["revision"] == 1


async def test_lifecycle_list_get_update_trash_restore(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "a.txt", "alpha")
        item_id = (await _ok(mcp, "dashboard_publish", paths=[str(f)], title="Alpha"))["id"]

        page = await _ok(mcp, "dashboard_list")
        assert [i["id"] for i in page["items"]] == [item_id]
        assert page["next_cursor"] is None

        got = await _ok(mcp, "dashboard_get", item_id=item_id)
        assert got["untrusted_item_data"]["files"] == [
            {"relpath": "a.txt", "size": 5, "media_type": "text/plain"}
        ]
        assert got["untrusted_item_data"]["description"] == ""

        updated = await _ok(
            mcp, "dashboard_update", item_id=item_id, title="Beta", pinned=True, description="d"
        )
        assert (updated["untrusted_item_data"]["title"], updated["pinned"]) == ("Beta", True)

        trashed = await _ok(mcp, "dashboard_trash", item_id=item_id)
        assert trashed["state"] == "trashed" and trashed["trashed_at"]
        assert (await _ok(mcp, "dashboard_list"))["items"] == []
        assert len((await _ok(mcp, "dashboard_list", state="trashed"))["items"]) == 1

        text = await _err(mcp, "dashboard_update", item_id=item_id, title="x")
        assert "409" in text

        restored = await _ok(mcp, "dashboard_restore", item_id=item_id)
        assert restored["state"] == "active"
        assert "trashed_at" not in restored


async def test_list_filters_and_paging(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        for i in range(3):
            f = write_file(admin.outbox / f"f{i}.txt", str(i))
            await _ok(mcp, "dashboard_publish", paths=[str(f)], title=f"t{i}")
        img = write_file(admin.outbox / "p.png", b"\x89PNG\r\n\x1a\n")
        await _ok(mcp, "dashboard_publish", paths=[str(img)], title="img")
        first = await _ok(mcp, "dashboard_list", limit=2)
        assert len(first["items"]) == 2 and first["next_cursor"]
        second = await _ok(mcp, "dashboard_list", limit=2, cursor=first["next_cursor"])
        assert len(second["items"]) == 2
        images = await _ok(mcp, "dashboard_list", kind="image")
        assert [i["untrusted_item_data"]["title"] for i in images["items"]] == ["img"]
        assert "description" not in images["items"][0]["untrusted_item_data"]


async def test_kinds(server: MCPServer) -> None:
    async with Client(server) as mcp:
        kinds = await _ok(mcp, "dashboard_kinds")
        assert {"html", "image", "markdown"} <= {k["name"] for k in kinds}


# --- clean errors --------------------------------------------------------------------


async def test_intake_rejection_is_a_clean_tool_error(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        secret = write_file(admin.outbox / ".env", "API_KEY=do-not-leak")
        text = await _err(mcp, "dashboard_publish", paths=[str(secret)], title="env")
        assert "intake refused (denied)" in text
        assert "do-not-leak" not in text
        assert (await _ok(mcp, "dashboard_list"))["items"] == []


async def test_path_outside_roots_refused(server: MCPServer, tmp_path: Path) -> None:
    async with Client(server) as mcp:
        outside = write_file(tmp_path / "elsewhere" / "x.txt", "nope")
        text = await _err(mcp, "dashboard_publish", paths=[str(outside)], title="t")
        assert "outside_roots" in text


async def test_bad_name_explains_rename(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "100%.txt", "x")
        text = await _err(mcp, "dashboard_publish", paths=[str(f)], title="t")
        assert "U+0025 PERCENT SIGN" in text and "Rename" in text


async def test_secret_content_refused_without_echo(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "conf.txt", f"aws = {fake_aws_key()}\n")
        text = await _err(mcp, "dashboard_publish", paths=[str(f)], title="conf")
        assert "AWS access key id" in text and "conf.txt" in text
        assert fake_aws_key() not in text


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("dashboard_get", {"item_id": "../kinds"}),
        ("dashboard_trash", {"item_id": "x"}),
        ("dashboard_list", {"limit": 0}),
        ("dashboard_list", {"state": "purged"}),
        ("dashboard_publish", {"paths": [], "title": "t"}),
        ("dashboard_publish", {"paths": ["/x"], "title": ""}),
        ("dashboard_publish", {"paths": ["/x"], "title": "t", "kind": "../x"}),
        ("dashboard_update_content", {"item_id": "x", "paths": ["/x"]}),
        ("dashboard_update_content", {"item_id": "01J0000000000000000000000A", "paths": []}),
        (
            "dashboard_update_content",
            {
                "item_id": "01J0000000000000000000000A",
                "paths": ["/x"],
                "expected_revision": 0,
            },
        ),
    ],
)
async def test_invalid_arguments_rejected(
    server: MCPServer, tool: str, args: dict[str, Any]
) -> None:
    async with Client(server) as mcp:
        await _err(mcp, tool, **args)


async def test_unknown_item(server: MCPServer) -> None:
    async with Client(server) as mcp:
        text = await _err(mcp, "dashboard_get", item_id="01J0000000000000000000000Z")
        assert "404" in text


async def test_update_without_fields(server: MCPServer, admin: LiveAdmin) -> None:
    async with Client(server) as mcp:
        f = write_file(admin.outbox / "a.txt", "a")
        item_id = (await _ok(mcp, "dashboard_publish", paths=[str(f)], title="A"))["id"]
        text = await _err(mcp, "dashboard_update", item_id=item_id)
        assert "nothing to update" in text


class _ExplodingAdmin:
    def kinds(self) -> dict[str, object]:
        raise RuntimeError("internal detail /etc/preview-dashboard/admin.token")


async def test_unexpected_errors_are_generic(admin: LiveAdmin) -> None:
    server = build_server(DashboardTools(intake=admin.intake(), admin=_ExplodingAdmin()))  # type: ignore[arg-type]
    async with Client(server) as client:
        text = await _err(client, "dashboard_kinds")
    assert "internal detail" not in text
    assert "admin.token" not in text


async def test_admin_down_is_a_clean_error(tmp_path: Path) -> None:
    with live_admin(tmp_path) as live:
        http = live.client()
    # The server stopped: the socket is gone.
    server = build_server(DashboardTools(intake=live.intake(), admin=http))
    async with Client(server) as client:
        text = await _err(client, "dashboard_kinds")
    assert "unreachable" in text
    http.close()


def test_main_rejects_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--port", "80"]) == 1
    assert capsys.readouterr().out == ""
