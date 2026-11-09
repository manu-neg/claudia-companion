"""Tests for the MCP progress tools (`interfaces/mcp/tools/progress.py`, ADR 0029).

`ProgressTools` runs with the real intake policy over a tmp outbox and a
fake admin (`tests/progress_support.py`); one contract scenario also runs
against the live admin API, so the fake can't drift from it. The MCP
registration is exercised through the SDK's in-process client.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from preview_dashboard.interfaces.mcp.server import DashboardTools, build_server
from preview_dashboard.interfaces.mcp.tools.progress import ProgressTools
from preview_dashboard.kinds.progress import decode_progress
from tests.mcp_support import live_admin
from tests.progress_support import STATUS, FakeProgressAdmin, make_tools

pytestmark = pytest.mark.unit


@pytest.fixture
def outbox(tmp_path: Path) -> Path:
    path = tmp_path / "outbox"
    path.mkdir()
    return path


@pytest.fixture
def fake() -> FakeProgressAdmin:
    return FakeProgressAdmin()


@pytest.fixture
def tools(outbox: Path, fake: FakeProgressAdmin) -> ProgressTools:
    return make_tools(outbox, fake)


def _stage_dirs(outbox: Path) -> list[str]:
    return sorted(p.name for p in (outbox / "progress-state").glob("stage-*"))


def _state(outbox: Path, item_id: str) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(
        (outbox / "progress-state" / item_id / "state.json").read_bytes()
    )
    return result


# --- dashboard_progress_set -----------------------------------------------------------


def test_set_publishes_a_new_progress_item(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path
) -> None:
    out = json.loads(tools.set(STATUS, pinned=True))
    assert out["kind"] == "progress" and out["revision"] == 1 and out["pinned"] is True
    assert out["viewer_url"].endswith(out["id"])
    assert out["units_done"] == "0/2" and out["updated_at"] == "2026-09-30T09:15:00Z"
    assert out["untrusted_item_data"]["title"] == "Progress tool"
    item = fake.items[out["id"]]
    assert item.title == "Progress tool"  # defaults to status.title
    doc = decode_progress(fake.latest(out["id"]))
    assert doc["units"][1]["detail"] == "after schema"
    assert _state(outbox, out["id"]) == {"revision": 1, "status": doc}
    assert _stage_dirs(outbox) == []  # staged file removed after publish


def test_set_new_with_title_and_folder(tools: ProgressTools, fake: FakeProgressAdmin) -> None:
    folder = "01J00000000000000000000000"
    out = json.loads(tools.set(STATUS, title="Owner title", folder_id=folder))
    assert fake.items[out["id"]].title == "Owner title"
    assert out["folder_id"] == folder
    assert fake.calls == ["publish"]


def test_set_with_item_id_publishes_a_revision(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path
) -> None:
    first = json.loads(tools.set(STATUS))
    changed = {**STATUS, "note": "second"}
    out = json.loads(tools.set(changed, item_id=first["id"], expected_revision=1))
    assert out["id"] == first["id"] and out["revision"] == 2
    assert decode_progress(fake.latest(first["id"]))["note"] == "second"
    assert _state(outbox, first["id"])["revision"] == 2
    assert fake.calls == ["publish", "get_item", "publish_revision"]


def test_set_on_existing_applies_title_pin_and_folder(
    tools: ProgressTools, fake: FakeProgressAdmin
) -> None:
    first = json.loads(tools.set(STATUS))
    folder = "01J00000000000000000000000"
    out = json.loads(
        tools.set(STATUS, item_id=first["id"], title="New", pinned=True, folder_id=folder)
    )
    assert fake.calls == ["publish", "get_item", "publish_revision", "update_item", "move_item"]
    assert out["pinned"] is True and out["folder_id"] == folder and out["revision"] == 2
    assert fake.items[first["id"]].title == "New"


def test_set_expected_revision_conflict(tools: ProgressTools, fake: FakeProgressAdmin) -> None:
    first = json.loads(tools.set(STATUS))
    with pytest.raises(ToolError, match=r"409.*dashboard_progress_set"):
        tools.set(STATUS, item_id=first["id"], expected_revision=5)
    assert len(fake.items[first["id"]].revisions) == 1


@pytest.mark.parametrize("kind", ["html", "markdown", "file"])
def test_set_refuses_an_item_of_another_kind(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path, kind: str
) -> None:
    # dashboard_progress_set must not silently turn someone's page into a tracker.
    item_id = json.loads(tools.set(STATUS))["id"]
    fake.items[item_id].kind = kind
    fake.calls.clear()
    with pytest.raises(ToolError, match=r"not a progress tracker.*dashboard_update_content"):
        tools.set(STATUS, item_id=item_id)
    with pytest.raises(ToolError, match="not a progress tracker"):
        tools.set(STATUS, item_id=item_id, expected_revision=1, title="T", pinned=True)
    assert fake.calls == ["get_item", "get_item"]  # nothing published or edited
    assert len(fake.items[item_id].revisions) == 1
    assert _state(outbox, item_id)["revision"] == 1
    assert _stage_dirs(outbox) == []


@pytest.mark.parametrize("expected", [None, 2])
def test_set_guards_the_checked_revision(
    tools: ProgressTools, fake: FakeProgressAdmin, expected: int | None
) -> None:
    # The revision whose kind was checked guards the publish -- also when the
    # caller's expected_revision names the racing (non-progress) revision.
    item_id = json.loads(tools.set(STATUS))["id"]
    checked = fake.get_item

    def racing_get(iid: str) -> dict[str, object]:
        item = checked(iid)
        fake.items[iid].revisions.append({"index.html": b"<p>x</p>"})  # a racing writer
        fake.items[iid].kind = "html"
        return item

    fake.get_item = racing_get  # type: ignore[method-assign,assignment]
    with pytest.raises(ToolError, match="409"):
        tools.set(STATUS, item_id=item_id, expected_revision=expected)
    assert fake.items[item_id].kind == "html"
    assert len(fake.items[item_id].revisions) == 2  # nothing published over it


def test_set_stale_expected_revision_is_refused_before_publishing(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path
) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    fake.calls.clear()
    with pytest.raises(ToolError, match=r"409.*revision 1, not expected_revision 3.*dashboard_get"):
        tools.set(STATUS, item_id=item_id, expected_revision=3, title="T")
    assert fake.calls == ["get_item"]  # no publish, no metadata edit
    assert _stage_dirs(outbox) == []


@pytest.mark.parametrize("bad", [None, 0, "1", True, 2**31])
def test_set_refuses_an_unexpected_revision_from_the_admin(
    tools: ProgressTools, fake: FakeProgressAdmin, bad: object
) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    checked = fake.get_item

    def lying_get(iid: str) -> dict[str, object]:
        return {**checked(iid), "revision": bad}

    fake.get_item = lying_get  # type: ignore[method-assign,assignment]
    for expected in (None, 1):
        with pytest.raises(ToolError, match="unexpected item"):
            tools.set(STATUS, item_id=item_id, expected_revision=expected)
    assert len(fake.items[item_id].revisions) == 1


def test_set_expected_revision_needs_item_id(tools: ProgressTools, fake: FakeProgressAdmin) -> None:
    with pytest.raises(ToolError, match="needs item_id"):
        tools.set(STATUS, expected_revision=1)
    assert fake.calls == []


def test_set_invalid_status_publishes_nothing(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path
) -> None:
    with pytest.raises(ToolError, match=r"invalid progress status: units.0..state"):
        tools.set({**STATUS, "units": [{"id": "X", "name": "n", "state": "bogus"}]})
    with pytest.raises(ToolError, match="unknown key 'colour'"):
        tools.set({**STATUS, "colour": "red"})
    assert fake.calls == []
    assert not (outbox / "progress-state").exists()


def test_set_unknown_item_is_a_clean_error(tools: ProgressTools, outbox: Path) -> None:
    with pytest.raises(ToolError, match="404"):
        tools.set(STATUS, item_id="01J00000000000000000000000")
    assert _stage_dirs(outbox) == []


# --- dashboard_progress_update ---------------------------------------------------------


def test_update_patches_unit_and_note(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path
) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    out = json.loads(tools.update(item_id, "P1", state="done", detail="shipped"))
    assert out["revision"] == 2 and out["units_done"] == "1/2"
    out = json.loads(tools.update(item_id, note="P2 next"))
    assert out["revision"] == 3
    doc = decode_progress(fake.latest(item_id))
    assert doc["units"][0] == {
        "id": "P1",
        "name": "kind + tools",
        "who": "",
        "state": "done",
        "detail": "shipped",
    }
    assert doc["units"][1]["state"] == "waiting"  # untouched
    assert doc["note"] == "P2 next" and doc["phases"] == ["Build", "Review"]
    assert _state(outbox, item_id) == {"revision": 3, "status": doc}


def test_update_can_clear_detail(tools: ProgressTools, fake: FakeProgressAdmin) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    tools.update(item_id, "P2", detail="")
    assert decode_progress(fake.latest(item_id))["units"][1]["detail"] == ""


def test_update_refuses_when_item_changed_elsewhere(
    tools: ProgressTools, fake: FakeProgressAdmin, outbox: Path
) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    fake.items[item_id].revisions.append({"progress.json": b"{}"})  # someone else's revision
    with pytest.raises(ToolError, match=r"changed since.*dashboard_progress_set"):
        tools.update(item_id, "P1", state="done")
    assert _state(outbox, item_id)["revision"] == 1  # state untouched


def test_update_without_local_state_is_fetch_free(
    tools: ProgressTools, fake: FakeProgressAdmin
) -> None:
    with pytest.raises(ToolError, match=r"no local progress state.*dashboard_progress_set"):
        tools.update("01J00000000000000000000000", "P1", state="done")
    assert fake.calls == []


@pytest.mark.parametrize(
    ("args", "match"),
    [
        ({}, "nothing to change"),
        ({"state": "done"}, "need unit_id"),
        ({"detail": "x"}, "need unit_id"),
        ({"unit_id_arg": "P1"}, "needs state"),
        ({"unit_id_arg": "P9", "state": "done"}, "'P9' is not in this tracker"),
        ({"unit_id_arg": "P1", "state": "finished"}, "state must be one of"),
        ({"unit_id_arg": "P1", "detail": "x" * 601}, "must be 1..600"),
        ({"note": "x" * 501}, "must be 1..500"),
    ],
)
def test_update_argument_errors(
    tools: ProgressTools, fake: FakeProgressAdmin, args: dict[str, Any], match: str
) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    with pytest.raises(ToolError, match=match):
        tools.update(item_id, **args)
    assert fake.calls == ["publish"]


def test_update_corrupt_state_asks_for_set(tools: ProgressTools, outbox: Path) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    (outbox / "progress-state" / item_id / "state.json").write_text('{"revision": 1}')
    with pytest.raises(ToolError, match=r"corrupt.*dashboard_progress_set"):
        tools.update(item_id, note="x")


def test_state_file_is_replaced_atomically_without_leftovers(
    tools: ProgressTools, outbox: Path
) -> None:
    item_id = json.loads(tools.set(STATUS))["id"]
    tools.update(item_id, note="a")
    assert sorted(os.listdir(outbox / "progress-state" / item_id)) == ["state.json"]


# --- contract: fake admin vs live admin ------------------------------------------------


@pytest.fixture(params=["fake", "live"])
def backend(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[ProgressTools]:
    if request.param == "fake":
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        yield make_tools(outbox, FakeProgressAdmin())
        return
    with live_admin(tmp_path) as live, live.client() as http:
        yield make_tools(live.outbox, http)


def test_contract_set_update_conflict(backend: ProgressTools) -> None:
    first = json.loads(backend.set(STATUS))
    assert (first["kind"], first["revision"]) == ("progress", 1)
    second = json.loads(backend.set(STATUS, item_id=first["id"], expected_revision=1))
    assert (second["id"], second["revision"]) == (first["id"], 2)
    third = json.loads(backend.update(first["id"], "P1", state="blocked"))
    assert third["revision"] == 3 and third["units_done"] == "0/2"
    with pytest.raises(ToolError, match="409"):
        backend.set(STATUS, item_id=first["id"], expected_revision=2)
    with pytest.raises(ToolError, match="404"):
        backend.set(STATUS, item_id="01J00000000000000000000000")


# --- MCP registration -------------------------------------------------------------------


@pytest.fixture
def server(tmp_path: Path) -> Iterator[MCPServer]:
    with live_admin(tmp_path) as live, live.client() as http:
        yield build_server(
            DashboardTools(intake=live.intake(), admin=http),
            progress=make_tools(live.outbox, http),
        )


def _text(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


async def test_tools_are_registered_with_schema(server: MCPServer) -> None:
    async with Client(server) as mcp:
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
        set_tool = tools["dashboard_progress_set"]
        assert "LIVE WORK TRACKER" in (set_tool.description or "")
        status = set_tool.input_schema["properties"]["status"]
        assert status["additionalProperties"] is False
        assert status["required"] == ["title"]
        assert "dashboard_progress_update" in tools


async def test_tools_end_to_end_over_mcp(server: MCPServer) -> None:
    async with Client(server) as mcp:
        result = await mcp.call_tool("dashboard_progress_set", {"status": STATUS})
        assert not result.is_error, _text(result)
        item = json.loads(_text(result))
        result = await mcp.call_tool(
            "dashboard_progress_update", {"item_id": item["id"], "unit_id": "P1", "state": "done"}
        )
        assert not result.is_error, _text(result)
        assert json.loads(_text(result))["revision"] == 2
        got = await mcp.call_tool("dashboard_get", {"item_id": item["id"]})
        assert json.loads(_text(got))["kind"] == "progress"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("dashboard_progress_update", {"item_id": "../../etc", "note": "x"}),
        ("dashboard_progress_update", {"item_id": "01J00000000000000000000000", "state": "x"}),
        ("dashboard_progress_update", {"item_id": "01J00000000000000000000000", "unit_id": "a/b"}),
        ("dashboard_progress_set", {"status": STATUS, "item_id": "not-an-id"}),
    ],
)
async def test_schema_refuses_bad_ids_and_states(
    server: MCPServer, tool: str, args: dict[str, Any]
) -> None:
    async with Client(server) as mcp:
        result = await mcp.call_tool(tool, args)
        assert result.is_error
        assert "Traceback" not in _text(result)


# --- OSError mapping + post-publish state failure -------------------------------------


def test_os_errors_while_staging_become_tool_errors(
    outbox: Path, fake: FakeProgressAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError(28, "No space left on device", "/secret/path")

    tools = make_tools(outbox, fake)
    monkeypatch.setattr(os, "mkdir", boom)
    with pytest.raises(ToolError, match="I/O error") as info:
        tools.set(STATUS)
    assert "/secret/path" not in str(info.value)
    assert fake.items == {}


def test_os_error_replacing_state_after_publish_says_it_was_published(
    outbox: Path, fake: FakeProgressAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise OSError(5, "Input/output error")

    tools = make_tools(outbox, fake)
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(ToolError) as info:
        tools.set(STATUS)
    (item_id,) = fake.items
    msg = str(info.value)
    assert item_id in msg and "revision 1" in msg and "published" in msg
    assert "item_id=" + item_id in msg
    assert list((outbox / "progress-state" / item_id).glob("*.tmp")) == []
