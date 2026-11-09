"""C49: subscription only, minimal env for every `claude` child (D15).

Each API credential variable refuses start (named, value never shown);
every child environment is the allowlist only, checked both on
`child_env` and on what a stand-in CLI actually receives; a settings
`env` block (applied by Claude Code on top of it) refuses the run.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

import preview_dashboard.interfaces.claudia.main as host_main
from preview_dashboard.adapters.claude_cli import (
    ALLOWED_ENV,
    FORBIDDEN_ENV,
    ISOLATION_ENV,
    ApiCredentialError,
    ClaudeCliConfig,
    CliClaudeRunner,
    child_env,
    refuse_api_credentials,
)
from preview_dashboard.application.claudia.runs import TOOL_SETS, ToolSetName
from preview_dashboard.interfaces.claudia.settings import (
    MANAGED_SETTINGS,
    HostSettingsError,
    check_settings_sources,
    load_host_settings,
    settings_sources,
)
from preview_dashboard.ports.claudia_host import RunRequest
from tests.claudia_host_support import WINDOW_A, read_record, write_fake_claude

pytestmark = pytest.mark.security

PLANTED_VALUE = "planted-value-DO-NOT-LEAK-0123456789"
BASE_ENV = {"HOME": "/root", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


@pytest.mark.parametrize("name", FORBIDDEN_ENV)
@pytest.mark.parametrize("value", [PLANTED_VALUE, "", "1"])
def test_c49_each_variable_refuses_start(name: str, value: str) -> None:
    with pytest.raises(ApiCredentialError) as caught:
        refuse_api_credentials({**BASE_ENV, name: value})
    assert name in str(caught.value)
    assert PLANTED_VALUE not in str(caught.value)


def test_c49_clean_env_starts() -> None:
    refuse_api_credentials(BASE_ENV)


@pytest.mark.parametrize("name", FORBIDDEN_ENV)
def test_c49_main_exits_refused_and_logs_name_only(
    name: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR)
    code = host_main.main(
        ["--settings", str(tmp_path / "missing.json")], environ={**BASE_ENV, name: PLANTED_VALUE}
    )
    assert code == host_main.EXIT_REFUSED
    assert name in caplog.text
    assert PLANTED_VALUE not in caplog.text


@pytest.mark.parametrize("name", FORBIDDEN_ENV)
@pytest.mark.parametrize("where", ["user", "managed"])
def test_c49_settings_env_block_refuses_run(name: str, where: str, tmp_path: Path) -> None:
    # host-flow-4: Claude Code applies a settings `env` block on top of child_env.
    home, work = tmp_path / "home", tmp_path / "work"
    (home / ".claude").mkdir(parents=True)
    user = home / ".claude" / "settings.json"
    managed = tmp_path / "managed-settings.json"
    target = user if where == "user" else managed
    target.write_text(json.dumps({"env": {name: PLANTED_VALUE}}), encoding="utf-8")
    sources = [p for p in settings_sources(home, work) if p != MANAGED_SETTINGS] + [managed]
    with pytest.raises(HostSettingsError) as caught:
        check_settings_sources(sources)
    assert PLANTED_VALUE not in str(caught.value)


def test_c49_host_settings_env_block_refused(tmp_path: Path) -> None:
    deploy = Path(__file__).resolve().parents[2] / "deploy" / "claudia" / "settings.json"
    data = json.loads(deploy.read_text(encoding="utf-8"))
    data["env"] = dict.fromkeys(FORBIDDEN_ENV, PLANTED_VALUE)
    path = tmp_path / "s.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(HostSettingsError) as caught:
        load_host_settings(path, trusted_uids=(os.geteuid(),))
    assert PLANTED_VALUE not in str(caught.value)


def test_c49_child_env_is_allowlist_only() -> None:
    source = {
        **BASE_ENV,
        "TERM": "xterm",
        "XDG_RUNTIME_DIR": "/run/user/0",
        "CLAUDE_CODE_OAUTH_TOKEN": PLANTED_VALUE,
        "PDASH_CONFIG": "/etc/preview-dashboard/config.toml",
        "GH_TOKEN": PLANTED_VALUE,
        "SSH_AUTH_SOCK": "/run/agent.sock",
        **dict.fromkeys(FORBIDDEN_ENV, PLANTED_VALUE),
    }
    env = child_env(source)
    # Plus the fixed F-CL1 isolation variables (set, never inherited).
    assert set(env) <= {*ALLOWED_ENV, "XDG_RUNTIME_DIR", *ISOLATION_ENV}
    assert PLANTED_VALUE not in env.values()
    assert env["HOME"] == "/root"


def test_c49_child_env_has_a_fixed_default_path() -> None:
    assert child_env({"HOME": "/root"})["PATH"] == "/usr/local/bin:/usr/bin:/bin"


def test_c49_run_child_receives_allowlist_only(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    workdir.mkdir()
    fake = write_fake_claude(tmp_path)
    source = {**BASE_ENV, "PATH": "/usr/bin:/bin", "GH_TOKEN": PLANTED_VALUE}
    source.update(dict.fromkeys(FORBIDDEN_ENV, PLANTED_VALUE))
    runner = CliClaudeRunner(
        ClaudeCliConfig(
            claude_bin=fake,
            mcp_config=tmp_path / "mcp.json",
            settings=tmp_path / "settings.json",
            workdir=workdir,
            run_timeout=30,
        ),
        source,
    )
    tools = TOOL_SETS[ToolSetName.FULL]
    outcome = runner.run(
        RunRequest(
            window_id=WINDOW_A,
            resume=False,
            prompt="hola",
            allowed_tools=tools.allowed,
            disallowed_tools=tools.disallowed,
        )
    )
    assert outcome.exit_code == 0
    env = read_record(workdir)["env"]
    assert isinstance(env, dict)
    # The interpreter may add a few of its own (e.g. LC_CTYPE); nothing inherited beyond the list.
    inherited = set(env) & set(source)
    assert inherited <= set(ALLOWED_ENV)
    assert PLANTED_VALUE not in env.values()
    assert not set(FORBIDDEN_ENV) & set(env)
