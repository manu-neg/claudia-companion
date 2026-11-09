"""Claudia host wiring (unit M5b; docs/security.md C50, C51, C53, C56, C59).

The host MCP config is verified before use (exactly the dashboard + KB
servers, `python -I -m kb_mcp --caller claudia`, no env blocks; root-owned
and not writable by others) and a recap copy (`--caller recap`, 0600) is
derived for window-close runs; `wire_host` builds the real object graph
(screen pipeline, hook gate behind the control socket, approval flow, KB
commits, voice) from tmp files. No real `claude` or admin.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from preview_dashboard.adapters.claude_cli import ClaudeCliConfig, build_run_argv
from preview_dashboard.adapters.claudia_admin_client import ClaudiaAdminClient
from preview_dashboard.application.claudia.runs import TOOL_SETS, ToolSetName
from preview_dashboard.application.claudia.voice import VoiceComposer
from preview_dashboard.interfaces.claudia.control_socket import ControlSocketError
from preview_dashboard.interfaces.claudia.hook import ask_host, read_reply
from preview_dashboard.interfaces.claudia.main import (
    HostConfig,
    PreflightChain,
    voice_composer,
    wire_host,
)
from preview_dashboard.interfaces.claudia.mcp_config import (
    McpConfigPreflight,
    load_mcp_config,
    pin_file,
    recap_data,
    verify_mcp_data,
    write_recap_config,
)
from preview_dashboard.interfaces.claudia.settings import (
    REQUIRED_DENY,
    HostSettings,
    HostSettingsError,
)
from preview_dashboard.ports.claudia_host import RunRefusedError, RunRequest
from tests.claudia_host_support import WINDOW_A, FakePreflight

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "deploy" / "claudia" / "mcp.json.in"


def deploy_mcp() -> dict[str, object]:
    """The installed MCP config: install.sh drops `#` lines and fills the KB gid."""
    lines = [line for line in TEMPLATE.read_text().splitlines() if not line.startswith("#")]
    data = json.loads("\n".join(lines).replace("@KB_GID@", "1234"))
    assert isinstance(data, dict)
    return data


def kb_args(data: dict[str, object]) -> list[str]:
    servers = data["mcpServers"]
    assert isinstance(servers, dict)
    args = servers["claudia-kb"]["args"]
    assert isinstance(args, list)
    return args


# --- C51/C53: the MCP config -----------------------------------------------------------


def test_c53_deploy_mcp_config_passes_and_names_the_kb() -> None:
    config = verify_mcp_data(deploy_mcp(), TEMPLATE)
    assert config.kb_root == Path("/var/lib/claudia-kb")
    assert config.kb_gid == 1234


def _mutations() -> Iterator[tuple[str, dict[str, object]]]:
    def mutate(name: str, change: object) -> tuple[str, dict[str, object]]:
        data = copy.deepcopy(deploy_mcp())
        change(data)  # type: ignore[operator]
        return name, data

    def kb(data: dict[str, object]) -> dict[str, object]:
        servers = data["mcpServers"]
        assert isinstance(servers, dict)
        entry = servers["claudia-kb"]
        assert isinstance(entry, dict)
        return entry

    yield mutate("no -I", lambda d: kb(d).__setitem__("args", kb_args(d)[1:]))
    yield mutate("caller recap", lambda d: kb_args(d).__setitem__(6, "recap"))
    yield mutate("relative root", lambda d: kb_args(d).__setitem__(4, "kb"))
    yield mutate("env block", lambda d: kb(d).__setitem__("env", {"X": "1"}))
    yield mutate("relative command", lambda d: kb(d).__setitem__("command", "python"))
    yield mutate("extra option", lambda d: kb_args(d).extend(["--evil", "1"]))
    yield mutate("dangling option", lambda d: kb_args(d).append("--root"))
    yield mutate("bad gid", lambda d: kb_args(d).__setitem__(8, "pdash-kb"))
    yield mutate(
        "extra server",
        lambda d: d["mcpServers"].__setitem__("other", {"command": "/x", "args": []}),
    )
    yield mutate("no kb server", lambda d: d["mcpServers"].pop("claudia-kb"))
    yield mutate("extra top-level key", lambda d: d.__setitem__("hooks", {}))


MUTATIONS = list(_mutations())


@pytest.mark.parametrize(("name", "data"), MUTATIONS, ids=[name for name, _ in MUTATIONS])
def test_c53_unexpected_mcp_config_refuses_start(name: str, data: dict[str, object]) -> None:
    with pytest.raises(HostSettingsError):
        verify_mcp_data(data, TEMPLATE)


def test_c51_mcp_config_file_must_be_trusted(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(deploy_mcp()))
    path.chmod(0o644)
    assert load_mcp_config(path, trusted_uids=(os.getuid(),)).kb_gid == 1234
    with pytest.raises(HostSettingsError, match="trusted"):
        load_mcp_config(path, trusted_uids=(os.getuid() + 1,))
    path.chmod(0o664)
    with pytest.raises(HostSettingsError, match="writable"):
        load_mcp_config(path, trusted_uids=(os.getuid(),))
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(HostSettingsError):
        load_mcp_config(link, trusted_uids=(os.getuid(),))


def test_c53_recap_config_only_changes_the_caller(tmp_path: Path) -> None:
    config = verify_mcp_data(deploy_mcp(), TEMPLATE)
    recap = recap_data(config)
    assert kb_args(recap)[kb_args(recap).index("--caller") + 1] == "recap"
    assert kb_args(config.data)[6] == "claudia"  # the verified original is untouched
    target = write_recap_config(config, tmp_path)
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
    assert json.loads(target.read_text()) == recap
    assert sorted(p.name for p in tmp_path.iterdir()) == ["recap-mcp.json"]


def _pinned_recap(tmp_path: Path) -> tuple[Path, Path, McpConfigPreflight]:
    main = tmp_path / "mcp.json"
    main.write_text(json.dumps(deploy_mcp()))
    main.chmod(0o644)
    uid = (os.getuid(),)
    recap = write_recap_config(load_mcp_config(main, trusted_uids=uid), tmp_path)
    pins = (pin_file(main, trusted_uids=uid), pin_file(recap, trusted_uids=uid))
    return main, recap, McpConfigPreflight(pins, trusted_uids=uid)


def test_c53_unchanged_mcp_configs_pass_the_preflight(tmp_path: Path) -> None:
    _main, _recap, preflight = _pinned_recap(tmp_path)
    preflight.check()
    preflight.check()


def test_c53_recap_config_tamper_refuses_the_run(tmp_path: Path) -> None:
    """host-flow-1: a run rewrote the recap config (e.g. a planted server command)."""
    _main, recap, preflight = _pinned_recap(tmp_path)
    data = json.loads(recap.read_text())
    data["mcpServers"]["claudia-kb"]["command"] = "/bin/sh"
    recap.write_text(json.dumps(data))
    with pytest.raises(RunRefusedError, match="changed"):
        preflight.check()


def test_c53_main_mcp_config_tamper_refuses_the_run(tmp_path: Path) -> None:
    main, _recap, preflight = _pinned_recap(tmp_path)
    main.write_text(main.read_text() + " ")
    with pytest.raises(RunRefusedError, match="changed"):
        preflight.check()


def test_c53_recap_config_swapped_for_a_symlink_or_removed_refuses(tmp_path: Path) -> None:
    _main, recap, preflight = _pinned_recap(tmp_path)
    copy_path = tmp_path / "copy.json"
    copy_path.write_bytes(recap.read_bytes())
    copy_path.chmod(0o600)
    recap.unlink()
    recap.symlink_to(copy_path)  # same bytes, but not a regular file in place
    with pytest.raises(RunRefusedError):
        preflight.check()
    recap.unlink()
    with pytest.raises(RunRefusedError):
        preflight.check()


def test_c53_recap_config_made_writable_refuses(tmp_path: Path) -> None:
    _main, recap, preflight = _pinned_recap(tmp_path)
    recap.chmod(0o622)
    with pytest.raises(RunRefusedError, match="writable"):
        preflight.check()


def test_c53_preflight_chain_runs_every_check_and_stops_at_the_first_refusal(
    tmp_path: Path,
) -> None:
    _main, recap, pins = _pinned_recap(tmp_path)
    first = FakePreflight()
    PreflightChain(first, pins).check()
    assert first.checks == 1
    recap.write_text("{}")
    with pytest.raises(RunRefusedError):
        PreflightChain(first, pins).check()
    with pytest.raises(RunRefusedError):
        PreflightChain(FakePreflight(refuse=True), pins).check()


def test_c51_recap_run_uses_the_recap_mcp_config_only() -> None:
    cli = ClaudeCliConfig(
        claude_bin=Path("/usr/bin/claude"),
        mcp_config=Path("/etc/preview-dashboard/claudia-mcp.json"),
        settings=Path("/etc/preview-dashboard/claudia-settings.json"),
        workdir=Path("/var/lib/claudia-host/work"),
        recap_mcp_config=Path("/var/lib/claudia-host/recap-mcp.json"),
    )
    tools = TOOL_SETS[ToolSetName.RECAP]

    def argv(recap: bool) -> list[str]:
        request = RunRequest(
            window_id=WINDOW_A,
            resume=True,
            prompt="x",
            allowed_tools=tools.allowed,
            disallowed_tools=tools.disallowed,
            recap=recap,
        )
        return build_run_argv(cli, request)

    def mcp(args: list[str]) -> str:
        return args[args.index("--mcp-config") + 1]

    assert mcp(argv(True)) == "/var/lib/claudia-host/recap-mcp.json"
    assert mcp(argv(False)) == "/etc/preview-dashboard/claudia-mcp.json"
    assert "--strict-mcp-config" in argv(True)


def test_c50_install_tree_writes_are_denied() -> None:
    deploy = json.loads((REPO / "deploy" / "claudia" / "settings.json").read_text())
    for rule in ("Edit(//opt/preview-dashboard/**)", "Write(//opt/preview-dashboard/**)"):
        assert rule in REQUIRED_DENY
        assert rule in deploy["permissions"]["deny"]


# --- the wired host ----------------------------------------------------------------------


@pytest.fixture
def short_dir() -> Iterator[Path]:
    # AF_UNIX paths are short: pytest's tmp_path can be too long for a socket.
    path = Path(tempfile.mkdtemp(prefix="cw", dir="/tmp"))
    path.chmod(0o700)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _config(tmp_path: Path, run_dir: Path) -> HostConfig:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    data = deploy_mcp()
    kb_root = tmp_path / "kb"
    kb_root.mkdir()
    args = kb_args(data)
    args[4] = str(kb_root)
    args[8] = str(os.getgid())
    mcp = tmp_path / "mcp.json"
    mcp.write_text(json.dumps(data))
    mcp.chmod(0o644)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return HostConfig(
        admin_socket=tmp_path / "admin.sock",
        token_file=tmp_path / "token",
        settings_file=tmp_path / "settings.json",
        mcp_config=mcp,
        workdir=tmp_path,
        state_dir=state,
        claude_bin=tmp_path / "claude",
        home=tmp_path,
        hook_socket=run_dir / "hook.sock",
    )


def test_c59_wired_host_serves_the_gate_on_the_control_socket(
    tmp_path: Path, short_dir: Path
) -> None:
    config = _config(tmp_path, short_dir)
    admin = ClaudiaAdminClient(
        Path("/nonexistent.sock"),
        b"t" * 32,
        transport=httpx.MockTransport(lambda _r: httpx.Response(503)),
    )
    verified = HostSettings(path=config.settings_file, digest="0" * 64)
    parts = wire_host(config, {}, verified, admin, trusted_uids=(os.getuid(),))
    assert (config.state_dir / "recap-mcp.json").exists()
    parts.control.start()
    try:
        call = {
            "hook_event_name": "PreToolUse",
            "session_id": WINDOW_A,
            "cwd": "/root",
            "tool_name": "Bash",
            "tool_input": {"command": "gh pr merge 31 -R o/r"},
        }
        reply = ask_host(call, config.hook_socket, trusted_uids=(os.getuid(),))
        # No run in progress: the gate (not a stub) denies, fail closed.
        assert read_reply(reply) == "no Claudia run in progress for this session"
    finally:
        parts.control.close()
        admin.close()
    assert not config.hook_socket.exists()


def test_c59_unsafe_socket_directory_refuses(tmp_path: Path, short_dir: Path) -> None:
    short_dir.chmod(0o777)
    config = _config(tmp_path, short_dir)
    admin = ClaudiaAdminClient(Path("/nonexistent.sock"), b"t" * 32)
    verified = HostSettings(path=config.settings_file, digest="0" * 64)
    parts = wire_host(config, {}, verified, admin, trusted_uids=(os.getuid(),))
    with pytest.raises(ControlSocketError):
        parts.control.start()
    admin.close()


def test_c56_voice_replies_only_with_installed_models(tmp_path: Path) -> None:
    assert voice_composer(tmp_path / "voices") is None
    (tmp_path / "voices").mkdir()
    assert isinstance(voice_composer(tmp_path / "voices"), VoiceComposer)
