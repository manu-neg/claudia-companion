"""F-CL1 item 1: Claudia's runs never load the owner's CLAUDE.md files or auto memory.

Every `claude` child the host and the gardener spawn (runs, peer lookups,
the Haiku screen, the gardener pass) gets `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1`
and `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`, set explicitly so an inherited
value can't flip them; host and gardener refuse to start if the run env
lacks them; every run carries the host rules as `--append-system-prompt`.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import preview_dashboard.interfaces.claudia.gardener as gardener_main
import preview_dashboard.interfaces.claudia.main as host_main
from preview_dashboard.adapters import gardener_runner, haiku_screen
from preview_dashboard.adapters.claude_cli import (
    FORBIDDEN_FLAGS,
    ISOLATION_ENV,
    ClaudeCliConfig,
    CliClaudeRunner,
    RunIsolationError,
    build_run_argv,
    check_run_isolation,
    child_env,
)
from preview_dashboard.application.claudia.runs import HOST_RULES_PROMPT, TOOL_SETS, ToolSetName
from preview_dashboard.ports.claudia_host import RunRequest
from tests.claudia_host_support import WINDOW_A, read_record, write_fake_claude

pytestmark = pytest.mark.security

BASE_ENV = {"HOME": "/root", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
EXPECTED = {"CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1", "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"}
# An inherited "0" (or any other value) must never reach a run.
FLIPPED = {"CLAUDE_CODE_DISABLE_CLAUDE_MDS": "0", "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "false"}


def _request() -> RunRequest:
    tools = TOOL_SETS[ToolSetName.FULL]
    return RunRequest(
        window_id=WINDOW_A,
        resume=False,
        prompt="hola",
        allowed_tools=tools.allowed,
        disallowed_tools=tools.disallowed,
        builtin_tools=tools.builtins,
    )


def test_fcl1_isolation_env_is_exactly_the_two_documented_variables() -> None:
    assert dict(ISOLATION_ENV) == EXPECTED


@pytest.mark.parametrize("source", [BASE_ENV, {**BASE_ENV, **FLIPPED}, {}])
def test_fcl1_host_child_env_always_sets_isolation(source: dict[str, str]) -> None:
    env = child_env(source)
    assert {k: env[k] for k in EXPECTED} == EXPECTED
    check_run_isolation(env)


@pytest.mark.parametrize("source", [BASE_ENV, {**BASE_ENV, **FLIPPED}])
def test_fcl1_screen_child_env_always_sets_isolation(source: dict[str, str]) -> None:
    env = haiku_screen.child_env(source)
    assert {k: env[k] for k in EXPECTED} == EXPECTED


def test_fcl1_gardener_uses_the_isolated_child_env(tmp_path: Path) -> None:
    model = gardener_runner.ClaudeGardenModel(
        tmp_path / "claude", tmp_path, "prompt", {**BASE_ENV, **FLIPPED}
    )
    # The env every gardener run is spawned with.
    assert {k: model._env[k] for k in EXPECTED} == EXPECTED


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1"},
        {"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"},
        {**EXPECTED, "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "0"},
    ],
)
def test_fcl1_check_refuses_a_run_env_without_isolation(env: dict[str, str]) -> None:
    with pytest.raises(RunIsolationError):
        check_run_isolation(env)


def test_fcl1_run_child_receives_isolation_vars(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    workdir.mkdir()
    runner = CliClaudeRunner(
        ClaudeCliConfig(
            claude_bin=write_fake_claude(tmp_path),
            mcp_config=tmp_path / "mcp.json",
            settings=tmp_path / "settings.json",
            workdir=workdir,
            run_timeout=30,
        ),
        {**BASE_ENV, **FLIPPED},
    )
    assert runner.run(_request()).exit_code == 0
    env = read_record(workdir)["env"]
    assert isinstance(env, dict)
    assert {k: env.get(k) for k in EXPECTED} == EXPECTED


def test_fcl1_host_refuses_start_without_isolation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR)
    # A regression that drops the variables from the run env must stop the host.
    monkeypatch.setattr(host_main, "child_env", lambda environ: dict(BASE_ENV))
    # The isolation check runs before the settings file is read (it is missing here).
    code = host_main.main(["--settings", str(tmp_path / "missing.json")], environ=BASE_ENV)
    assert code == host_main.EXIT_REFUSED
    assert "CLAUDE_CODE_DISABLE_CLAUDE_MDS" in caplog.text


def test_fcl1_gardener_refuses_start_without_isolation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR)
    monkeypatch.setattr(gardener_main, "child_env", lambda environ: dict(BASE_ENV))
    code = gardener_main.main(["--socket", str(tmp_path / "admin.sock")], environ=BASE_ENV)
    assert code == gardener_main.EXIT_REFUSED
    assert "CLAUDE_CODE_DISABLE_CLAUDE_MDS" in caplog.text


def test_fcl1_run_argv_appends_the_host_rules() -> None:
    config = ClaudeCliConfig(
        claude_bin=Path("/root/.local/bin/claude"),
        mcp_config=Path("/etc/preview-dashboard/claudia-mcp.json"),
        settings=Path("/etc/preview-dashboard/claudia-settings.json"),
        workdir=Path("/var/lib/claudia-host/work"),
        system_append=HOST_RULES_PROMPT,
    )
    argv = build_run_argv(config, _request())
    assert argv[-1] == f"--append-system-prompt={HOST_RULES_PROMPT}"
    assert "--bare" not in argv


def test_fcl1_host_rules_say_reply_only_and_never_alert() -> None:
    text = HOST_RULES_PROMPT.casefold()
    for phrase in ("precedence", "final reply", "never send alerts", "preview-dashboard-mcp"):
        assert phrase in text
    assert "when a tool call is denied or blocked" in text
    assert not any(flag in HOST_RULES_PROMPT for flag in FORBIDDEN_FLAGS)


def test_fcl1_host_wires_the_rules_into_every_run() -> None:
    source = Path(host_main.__file__).read_text(encoding="utf-8")
    assert "system_append=HOST_RULES_PROMPT" in source
