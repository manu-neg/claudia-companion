"""Security tests for the MCP progress tools' private state (docs/security.md C42, ADR 0029).

The state dir lives under the intake root, is private (0700, owned by the
process user), is never reached through a symlink, is named only by
validated ULIDs (no caller path), and every staged file still passes the
normal intake policy and the admin-side secret scan.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from preview_dashboard.interfaces.mcp.denylist import DenyList
from preview_dashboard.interfaces.mcp.intake import IntakeLimits, IntakePolicy
from preview_dashboard.interfaces.mcp.server import DashboardTools, publish_intake
from preview_dashboard.interfaces.mcp.tools.progress import (
    ProgressStateError,
    ProgressStateStore,
    ProgressTools,
)
from tests.mcp_support import fake_aws_key, live_admin, write_file
from tests.progress_support import STATUS, FakeProgressAdmin, make_tools

pytestmark = pytest.mark.security

ITEM = "01J00000000000000000000000"


@pytest.fixture
def outbox(tmp_path: Path) -> Path:
    path = tmp_path / "outbox"
    path.mkdir()
    return path


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_state_dirs_and_file_are_private(outbox: Path) -> None:
    tools = make_tools(outbox, FakeProgressAdmin())
    item_id = json.loads(tools.set(STATUS))["id"]
    state_dir = outbox / "progress-state"
    assert _mode(state_dir) == 0o700
    assert _mode(state_dir / item_id) == 0o700
    assert _mode(state_dir / item_id / "state.json") == 0o600


def test_symlinked_state_dir_is_refused(outbox: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (outbox / "progress-state").symlink_to(elsewhere)
    fake = FakeProgressAdmin()
    with pytest.raises(ToolError, match="not a plain directory"):
        make_tools(outbox, fake).set(STATUS)
    assert fake.calls == [] and list(elsewhere.iterdir()) == []


def test_symlinked_item_dir_is_refused(outbox: Path, tmp_path: Path) -> None:
    store = ProgressStateStore(str(outbox))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (elsewhere / "state.json").write_text("{}")
    (outbox / "progress-state").mkdir(mode=0o700)
    (outbox / "progress-state" / ITEM).symlink_to(elsewhere)
    with pytest.raises(ProgressStateError):
        store.load(ITEM)


def test_symlinked_state_file_is_refused(outbox: Path, tmp_path: Path) -> None:
    target = tmp_path / "planted.json"
    target.write_text("{}")
    item_dir = outbox / "progress-state" / ITEM
    item_dir.mkdir(parents=True, mode=0o700)
    os.chmod(outbox / "progress-state", 0o700)
    (item_dir / "state.json").symlink_to(target)
    with pytest.raises(ProgressStateError, match="not a plain file"):
        ProgressStateStore(str(outbox)).load(ITEM)


@pytest.mark.parametrize("mode", [0o750, 0o755, 0o777, 0o701])
def test_shared_state_dir_is_refused(outbox: Path, mode: int) -> None:
    state_dir = outbox / "progress-state"
    state_dir.mkdir()
    os.chmod(state_dir, mode)
    with pytest.raises(ToolError, match="mode 0700"):
        make_tools(outbox, FakeProgressAdmin()).set(STATUS)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
def test_foreign_owned_state_dir_is_refused(outbox: Path) -> None:
    state_dir = outbox / "progress-state"
    state_dir.mkdir(mode=0o700)
    os.chown(state_dir, 65534, 65534)
    with pytest.raises(ToolError, match="owned by this user"):
        make_tools(outbox, FakeProgressAdmin()).set(STATUS)


@pytest.mark.parametrize(
    "bad", ["../x", "..", "/etc", "01j00000000000000000000000", "01J0000000000000000000000/", ""]
)
def test_only_ulids_name_state_dirs(outbox: Path, bad: str) -> None:
    store = ProgressStateStore(str(outbox))
    with pytest.raises(ValueError, match="invalid item id"):
        store.load(bad)
    with pytest.raises(ValueError, match="invalid item id"):
        store.save(bad, 1, json.loads("{}"))
    tools = make_tools(outbox, FakeProgressAdmin())
    with pytest.raises(ToolError, match="invalid item id"):
        tools.update(bad, note="x")
    with pytest.raises(ToolError, match="invalid item id"):
        tools.set(STATUS, item_id=bad)
    assert not (outbox / "progress-state").exists()


def test_admin_response_id_is_validated_before_use_as_a_path(outbox: Path) -> None:
    class LyingAdmin(FakeProgressAdmin):
        def publish(self, *args: object, **kwargs: object) -> dict[str, object]:
            item = super().publish(*args, **kwargs)  # type: ignore[arg-type]
            return {**item, "id": "../../escape"}

    with pytest.raises(ToolError, match="unexpected item"):
        make_tools(outbox, LyingAdmin()).set(STATUS)
    assert sorted(p.name for p in (outbox / "progress-state").iterdir()) == []


def test_staged_file_passes_the_intake_policy(outbox: Path) -> None:
    # An operator denylist entry covering the state dir blocks progress too:
    # the staged file goes through exactly the same intake checks (C10).
    policy = IntakePolicy(
        allowed_roots=(str(outbox),),
        denylist=DenyList({"progress-state"}),
        limits=IntakeLimits(max_files=10, max_file_bytes=1 << 20, max_item_bytes=1 << 20),
    )
    fake = FakeProgressAdmin()
    tools = ProgressTools(intake=policy, admin=fake, store=ProgressStateStore(str(outbox)))
    with pytest.raises(ToolError, match="intake refused"):
        tools.set(STATUS)
    assert fake.calls == []


def test_state_outside_intake_roots_is_refused(outbox: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    other.mkdir()
    policy = IntakePolicy(
        allowed_roots=(str(outbox),),
        denylist=DenyList(()),
        limits=IntakeLimits(max_files=10, max_file_bytes=1 << 20, max_item_bytes=1 << 20),
    )
    store = ProgressStateStore(str(other))
    tools = ProgressTools(intake=policy, admin=FakeProgressAdmin(), store=store)
    with pytest.raises(ToolError, match="intake refused"):
        tools.set(STATUS)


def test_secret_in_status_is_refused_by_the_admin_scan(tmp_path: Path) -> None:
    with live_admin(tmp_path) as live, live.client() as http:
        tools = make_tools(live.outbox, http)
        with pytest.raises(ToolError, match="looks like a secret"):
            tools.set({**STATUS, "note": f"key {fake_aws_key()}"})
        item_id = json.loads(tools.set(STATUS))["id"]
        with pytest.raises(ToolError, match="looks like a secret"):
            tools.update(item_id, "P1", detail=fake_aws_key())
        state = json.loads((live.outbox / "progress-state" / item_id / "state.json").read_text())
        assert state["revision"] == 1  # refused update left the state alone
        assert fake_aws_key() not in json.dumps(state)
        stages = list((live.outbox / "progress-state").glob("stage-*"))
        assert stages == []


def test_publish_tools_refuse_the_state_dir(tmp_path: Path) -> None:
    """C10/C42: dashboard_publish/_update_content never read progress-state/ (F-MCP #3)."""
    with live_admin(tmp_path) as live, live.client() as http:
        progress = ProgressTools(
            intake=IntakePolicy.from_settings(live.settings),  # as main() wires it
            admin=http,
            store=ProgressStateStore(str(live.outbox)),
        )
        tracker = json.loads(progress.set(STATUS))["id"]
        page = write_file(live.outbox / "page.md", "# page")
        tools = DashboardTools(intake=publish_intake(live.settings), admin=http)
        item = json.loads(tools.publish([str(page)], "Page"))["id"]
        state_dir = live.outbox / "progress-state"
        for paths, base in (
            ([str(state_dir / tracker / "state.json")], None),
            ([str(state_dir / tracker)], None),
            ([str(state_dir)], None),
            ([str(live.outbox)], None),  # the whole root: its tree contains the state dir
            ([str(page), str(state_dir / tracker / "state.json")], str(live.outbox)),
        ):
            with pytest.raises(ToolError, match=r"intake refused \(denied\).*progress-state"):
                tools.publish(paths, "State", base=base)
            with pytest.raises(ToolError, match=r"intake refused \(denied\)"):
                tools.update_content(item, paths, base=base)
        # A same-named dir elsewhere is refused too (fail closed, name-based).
        other = write_file(live.outbox / "proj" / "progress-state" / "notes.md", "# n")
        with pytest.raises(ToolError, match="denied"):
            tools.publish([str(other)], "Other")
        # The progress tools themselves still publish through their own intake.
        assert json.loads(progress.update(tracker, note="still works"))["revision"] == 2


def test_progress_set_refuses_a_non_progress_item(tmp_path: Path) -> None:
    """C42/ADR 0029: dashboard_progress_set with item_id only revises progress items."""
    with live_admin(tmp_path) as live, live.client() as http:
        page = write_file(live.outbox / "page.html", "<p>owner page</p>")
        tools = DashboardTools(intake=live.intake(), admin=http)
        item = json.loads(tools.publish([str(page)], "Page"))
        progress = make_tools(live.outbox, http)
        with pytest.raises(ToolError, match=r"not a progress tracker.*dashboard_update_content"):
            progress.set(STATUS, item_id=item["id"])
        with pytest.raises(ToolError, match="not a progress tracker"):
            progress.set(STATUS, item_id=item["id"], expected_revision=1)
        after = http.get_item(item["id"])
        assert (after["kind"], after["revision"]) == ("html", 1)
        assert not (live.outbox / "progress-state" / item["id"]).exists()


def _age(path: Path, seconds: int = 7200) -> None:
    old = time.time() - seconds
    os.utime(path, (old, old), follow_symlinks=False)


def test_sweep_removes_only_stale_own_leftovers(outbox: Path, tmp_path: Path) -> None:
    tools = make_tools(outbox, FakeProgressAdmin())
    item_id = json.loads(tools.set(STATUS))["id"]
    base = outbox / "progress-state"
    stale_stage = base / "stage-0123456789abcdef"
    stale_stage.mkdir(mode=0o700)
    (stale_stage / "progress.json").write_text("{}")
    _age(stale_stage)
    fresh_stage = base / "stage-fedcba9876543210"
    fresh_stage.mkdir(mode=0o700)
    stale_tmp = base / item_id / "state.json.0123456789abcdef.tmp"
    stale_tmp.write_text("x")
    _age(stale_tmp)
    fresh_tmp = base / item_id / "state.json.fedcba9876543210.tmp"
    fresh_tmp.write_text("x")
    stranger = base / item_id / "other.tmp"  # not a name this code creates
    stranger.write_text("x")
    _age(stranger)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep").write_text("x")
    link = base / "stage-aaaaaaaaaaaaaaaa"
    link.symlink_to(elsewhere)
    _age(link)

    assert ProgressStateStore(str(outbox)).sweep() == 2
    assert not stale_stage.exists() and not stale_tmp.exists()
    assert fresh_stage.exists() and fresh_tmp.exists() and stranger.exists()
    assert link.is_symlink() and (elsewhere / "keep").exists()
    assert (base / item_id / "state.json").exists()  # item state is never swept


def test_sweep_runs_at_startup_and_tolerates_a_missing_state_dir(outbox: Path) -> None:
    make_tools(outbox, FakeProgressAdmin())  # no state dir yet: no error
    base = outbox / "progress-state"
    base.mkdir(mode=0o700)
    stale = base / "stage-0123456789abcdef"
    stale.mkdir(mode=0o700)
    _age(stale)
    make_tools(outbox, FakeProgressAdmin())
    assert not stale.exists()


def test_sweep_refuses_an_unsafe_state_dir(outbox: Path) -> None:
    base = outbox / "progress-state"
    base.mkdir(mode=0o755)
    base.chmod(0o755)
    with pytest.raises(ProgressStateError):
        ProgressStateStore(str(outbox)).sweep()
