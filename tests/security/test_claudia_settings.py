"""C50 (+ C59 "hooks cannot be switched off"): the host settings file and every settings source.

The shipped `deploy/claudia/settings.json` passes; removing any deny rule,
the hook entry, or making the file unsafe refuses start; `disableAllHooks`,
`allowManagedHooksOnly` or an overriding hook in any other source (user,
project, local, managed) refuses the run, with a `failed` alert and no run.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest

import preview_dashboard.interfaces.claudia.main as host_main
from preview_dashboard.interfaces.claudia.main import HostConfig, parse_args, startup_checks
from preview_dashboard.interfaces.claudia.settings import (
    CREDENTIAL_HELPER_KEYS,
    HOOK_COMMAND,
    HOST_SETTINGS_PATH,
    KB_ROOT,
    REQUIRED_DENY,
    REQUIRED_HOOK,
    HostSettingsError,
    SettingsPreflight,
    check_hook_command,
    check_settings_sources,
    hook_module_files,
    is_broad_allow,
    load_host_settings,
    settings_sources,
)
from preview_dashboard.ports.claudia_host import RunRefusedError
from tests.claudia_host_support import FakePreflight, host_rig, message

pytestmark = pytest.mark.security

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "claudia" / "settings.json"
ME = (os.geteuid(),)


def shipped() -> dict[str, Any]:
    data = json.loads(DEPLOY.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def write(path: Path, data: object, mode: int = 0o644) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(mode)
    return path


def test_c50_shipped_file_passes(tmp_path: Path) -> None:
    verified = load_host_settings(write(tmp_path / "s.json", shipped()), trusted_uids=ME)
    assert len(verified.digest) == 64


def test_c50_every_rule_present_in_the_shipped_file() -> None:
    deny = shipped()["permissions"]["deny"]
    assert set(REQUIRED_DENY) <= set(deny)
    for rule in (
        "Read(//etc/preview-dashboard/**)",
        "Read(//root/.claude/.credentials.json)",
        "Edit(//root/.claude/projects/*/memory/**)",
        "Write(//root/.claude/projects/*/memory/**)",
        f"Write(/{KB_ROOT}/**)",
        f"Edit(/{HOST_SETTINGS_PATH})",
        f"Write(/{HOOK_COMMAND})",
    ):
        assert rule in REQUIRED_DENY


def test_c50_hook_entry_points_at_the_m5_hook() -> None:
    assert shipped()["hooks"]["PreToolUse"] == [REQUIRED_HOOK]
    # host-flow-3 / hook-9: every tool (MultiEdit, Monitor, ...), not a named list.
    assert REQUIRED_HOOK["matcher"] == "*"


def test_c50_host_state_outside_work_denied() -> None:
    deny = shipped()["permissions"]["deny"]
    for pattern in ("*.*", "audit/**", "voices/**"):
        for tool in ("Edit", "Write"):
            assert f"{tool}(//var/lib/claudia-host/{pattern})" in REQUIRED_DENY
            assert f"{tool}(//var/lib/claudia-host/{pattern})" in deny
    # Her cwd stays writable: no rule covers `work/`.
    assert not any(rule.endswith("claudia-host/**)") for rule in deny)
    assert not any("claudia-host/work" in rule for rule in deny)


@pytest.mark.parametrize("rule", REQUIRED_DENY)
def test_c50_start_refused_without_any_rule(rule: str, tmp_path: Path) -> None:
    data = shipped()
    data["permissions"]["deny"].remove(rule)
    with pytest.raises(HostSettingsError, match="misses deny rule"):
        load_host_settings(write(tmp_path / "s.json", data), trusted_uids=ME)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("hooks"),
        lambda d: d["hooks"].pop("PreToolUse"),
        lambda d: d["hooks"]["PreToolUse"][0]["hooks"][0].update(command="/var/hook"),
        lambda d: d["hooks"]["PreToolUse"][0].update(matcher="Bash"),
        lambda d: d["hooks"]["PreToolUse"].append(copy.deepcopy(REQUIRED_HOOK)),
        lambda d: d["hooks"].update(PermissionRequest=[{"matcher": "*", "hooks": []}]),
        lambda d: d.update(disableAllHooks=True),
        lambda d: d.update(allowManagedHooksOnly=True),
        lambda d: d["permissions"].update(defaultMode="bypassPermissions"),
        lambda d: d.pop("permissions"),
        lambda d: d["permissions"].update(deny="Edit(**)"),
    ],
    ids=[
        "no-hooks",
        "no-pretooluse",
        "hook-command-altered",
        "matcher-narrowed",
        "extra-entry",
        "permission-request-hook",
        "disable-all-hooks",
        "managed-only",
        "bypass-mode",
        "no-permissions",
        "deny-not-list",
    ],
)
def test_c50_start_refused_on_altered_file(mutate: Any, tmp_path: Path) -> None:
    data = shipped()
    mutate(data)
    with pytest.raises(HostSettingsError):
        load_host_settings(write(tmp_path / "s.json", data), trusted_uids=ME)


def test_c50_missing_file_refused(tmp_path: Path) -> None:
    with pytest.raises(HostSettingsError, match="cannot open"):
        load_host_settings(tmp_path / "absent.json", trusted_uids=ME)


def test_c50_unparseable_file_refused(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(HostSettingsError, match="valid JSON"):
        load_host_settings(path, trusted_uids=ME)


@pytest.mark.parametrize("mode", [0o664, 0o646])
def test_c50_writable_file_refused(mode: int, tmp_path: Path) -> None:
    with pytest.raises(HostSettingsError, match="writable"):
        load_host_settings(write(tmp_path / "s.json", shipped(), mode), trusted_uids=ME)


def test_c50_untrusted_owner_refused(tmp_path: Path) -> None:
    with pytest.raises(HostSettingsError, match="owner"):
        load_host_settings(write(tmp_path / "s.json", shipped()), trusted_uids=(ME[0] + 12345,))


def test_c50_symlink_refused(tmp_path: Path) -> None:
    real = write(tmp_path / "real.json", shipped())
    link = tmp_path / "s.json"
    link.symlink_to(real)
    with pytest.raises(HostSettingsError, match="cannot open"):
        load_host_settings(link, trusted_uids=ME)


def test_c50_main_refuses_start_without_the_file(tmp_path: Path) -> None:
    code = host_main.main(["--settings", str(tmp_path / "absent.json")], environ={"HOME": "/x"})
    assert code == host_main.EXIT_REFUSED


# --- other settings sources (C59 M-c) ------------------------------------------------------


def sources(tmp_path: Path) -> dict[str, Path]:
    home, work = tmp_path / "home", tmp_path / "work"
    for d in (home / ".claude", work / ".claude"):
        d.mkdir(parents=True)
    listed = settings_sources(home, work)
    return {
        "user": listed[0],
        "user-local": listed[1],
        "project": listed[2],
        "local": listed[3],
        "managed": tmp_path / "managed-settings.json",
    }


def all_sources(paths: dict[str, Path]) -> list[Path]:
    return list(paths.values())


@pytest.mark.parametrize("source", ["user", "user-local", "project", "local", "managed"])
@pytest.mark.parametrize(
    "content",
    [
        {"disableAllHooks": True},
        {"allowManagedHooksOnly": True},
        {
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "x"}]}]
            }
        },
        {"hooks": {"PermissionRequest": [{"matcher": "*", "hooks": []}]}},
    ],
    ids=["disable-all", "managed-only", "pretooluse", "permission-request"],
)
def test_c59_disable_all_hooks_refuses_run(source: str, content: object, tmp_path: Path) -> None:
    paths = sources(tmp_path)
    write(paths[source], content)
    with pytest.raises(HostSettingsError, match=r"sets|registers"):
        check_settings_sources(all_sources(paths))


def test_c59_harmless_sources_pass(tmp_path: Path) -> None:
    paths = sources(tmp_path)
    write(paths["user"], {"permissions": {"allow": ["Read"]}, "disableAllHooks": False})
    write(paths["project"], {"hooks": {"PostToolUse": [{"matcher": "*", "hooks": []}]}})
    check_settings_sources(all_sources(paths))  # missing files are fine too


def test_c59_unparseable_source_refuses(tmp_path: Path) -> None:
    paths = sources(tmp_path)
    paths["local"].write_text("{", encoding="utf-8")
    with pytest.raises(HostSettingsError, match="valid JSON"):
        check_settings_sources(all_sources(paths))


def fake_hook(tmp_path: Path) -> Path:
    """A hook file + interpreter laid out like the install (root-owned, 0755)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    interpreter = bin_dir / "python-real"
    interpreter.write_bytes(b"\x7fELF")
    interpreter.chmod(0o755)
    link = bin_dir / "python"
    link.symlink_to(interpreter)
    hook = bin_dir / "preview-dashboard-claudia-hook"
    hook.write_text(f"#!{link}\nimport sys\n", encoding="utf-8")
    hook.chmod(0o755)
    return hook


def test_c59_preflight_detects_a_changed_host_file(tmp_path: Path) -> None:
    path = write(tmp_path / "s.json", shipped())
    preflight = SettingsPreflight(
        load_host_settings(path, trusted_uids=ME),
        [],
        trusted_uids=ME,
        hook_command=fake_hook(tmp_path),
    )
    preflight.check()
    data = shipped()
    data["permissions"]["deny"].append("Bash(curl *)")
    write(path, data)
    with pytest.raises(RunRefusedError, match="changed"):
        preflight.check()


def test_c59_preflight_checks_sources_before_every_run(tmp_path: Path) -> None:
    paths = sources(tmp_path)
    path = write(tmp_path / "s.json", shipped())
    preflight = SettingsPreflight(
        load_host_settings(path, trusted_uids=ME),
        all_sources(paths),
        trusted_uids=ME,
        hook_command=fake_hook(tmp_path),
    )
    preflight.check()
    write(paths["user"], {"disableAllHooks": True})
    with pytest.raises(RunRefusedError, match="disableAllHooks"):
        preflight.check()


# --- hook-5: the hook command itself ------------------------------------------------------


def _replace_interpreter_mode(hook: Path) -> None:
    (hook.parent / "python-real").chmod(0o775)


def _symlink_hook(hook: Path) -> None:
    real = hook.with_name("real-hook")
    hook.rename(real)
    hook.symlink_to(real)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda h: h.unlink(),
        lambda h: h.chmod(0o775),
        lambda h: h.chmod(0o757),
        lambda h: h.chmod(0o644),
        _symlink_hook,
        lambda h: h.write_text("import sys\n", encoding="utf-8"),
        lambda h: h.write_text("#!python3\n", encoding="utf-8"),
        lambda h: h.write_text("#!/usr/bin/env python3\n", encoding="utf-8"),
        lambda h: h.write_text(f"#!{h.parent}/missing\n", encoding="utf-8"),
        _replace_interpreter_mode,
        lambda h: (h.parent / "python-real").unlink(),
        lambda h: h.parent.chmod(0o777),
    ],
    ids=[
        "missing",
        "group-writable",
        "world-writable",
        "not-executable",
        "symlink",
        "no-shebang",
        "relative-interpreter",
        "env-interpreter",
        "interpreter-missing",
        "interpreter-writable",
        "interpreter-link-dangling",
        "dir-writable",
    ],
)
def test_c59_preflight_refuses_a_broken_hook_command(mutate: Any, tmp_path: Path) -> None:
    hook = fake_hook(tmp_path)
    check_hook_command(hook, trusted_uids=ME)
    mutate(hook)
    with pytest.raises(HostSettingsError):
        check_hook_command(hook, trusted_uids=ME)
    path = write(tmp_path / "s.json", shipped())
    preflight = SettingsPreflight(
        load_host_settings(path, trusted_uids=ME), [], trusted_uids=ME, hook_command=hook
    )
    with pytest.raises(RunRefusedError, match="hook"):
        preflight.check()


def test_c59_hook_command_untrusted_owner_refused(tmp_path: Path) -> None:
    with pytest.raises(HostSettingsError, match="owner"):
        check_hook_command(fake_hook(tmp_path), trusted_uids=(ME[0] + 12345,))


def test_c59_preflight_checks_the_installed_hook_by_default(tmp_path: Path) -> None:
    path = write(tmp_path / "s.json", shipped())
    preflight = SettingsPreflight(load_host_settings(path, trusted_uids=ME), [], trusted_uids=ME)
    assert preflight._hook == Path(HOOK_COMMAND)


# --- hook-8 / host-flow-4: other sources can't widen the guard or bypass C49 ---------------


def plugin(plugins: Path, name: str, market: str, *, hooks: bool, manifest: object = None) -> Path:
    root = plugins / "cache" / market / name / "1.0.0"
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(manifest if manifest is not None else {"name": name}), encoding="utf-8"
    )
    if hooks:
        (root / "hooks").mkdir()
        (root / "hooks" / "hooks.json").write_text("{}", encoding="utf-8")
    return root


@pytest.mark.parametrize("source", ["user", "user-local", "project", "local", "managed"])
@pytest.mark.parametrize(
    "content",
    [
        {"enabledPlugins": {"hooky@market": True}},
        {"enabledPlugins": {"inline@market": True}},
        {"enabledPlugins": {"missing@market": True}},
        {"enabledPlugins": {"../x@market": True}},
        {"enabledPlugins": {"clean@market": "yes"}},
        {"enabledPlugins": ["clean@market"]},
        {"permissions": {"allow": ["Bash"]}},
        {"permissions": {"allow": ["Bash(*)"]}},
        {"permissions": {"allow": ["Bash(:*)"]}},
        {"permissions": {"allow": ["Edit"]}},
        {"permissions": {"allow": ["Write(//**)"]}},
        {"permissions": {"allow": ["mcp__preview-dashboard"]}},
        {"permissions": {"allow": ["mcp__*"]}},
        {"permissions": {"allow": ["*"]}},
        {"permissions": {"allow": "Bash"}},
        {"permissions": {"defaultMode": "bypassPermissions"}},
        {"permissions": {"defaultMode": "acceptEdits"}},
        {"permissions": "all"},
    ],
    ids=[
        "plugin-hooks-file",
        "plugin-inline-hooks",
        "plugin-not-installed",
        "plugin-id-traversal",
        "plugin-not-bool",
        "plugins-not-object",
        "allow-bash",
        "allow-bash-star",
        "allow-bash-colon-star",
        "allow-edit",
        "allow-write-everything",
        "allow-mcp-server",
        "allow-mcp-wildcard",
        "allow-star",
        "allow-not-list",
        "bypass-mode",
        "accept-edits-mode",
        "permissions-not-object",
    ],
)
def test_c59_source_widening_the_guard_refuses_run(
    source: str, content: object, tmp_path: Path
) -> None:
    paths = sources(tmp_path)
    plugins = tmp_path / "plugins"
    plugin(plugins, "hooky", "market", hooks=True)
    plugin(plugins, "inline", "market", hooks=False, manifest={"hooks": "./h.json"})
    plugin(plugins, "clean", "market", hooks=False)
    write(paths[source], content)
    with pytest.raises(HostSettingsError):
        check_settings_sources(all_sources(paths), plugins_dir=plugins)


def test_c59_harmless_plugins_and_allow_rules_pass(tmp_path: Path) -> None:
    paths = sources(tmp_path)
    plugins = tmp_path / "plugins"
    plugin(plugins, "clean", "market", hooks=False)
    market = plugins / "marketplaces" / "other" / "plugins" / "skills"
    market.mkdir(parents=True)
    write(
        paths["user"],
        {
            "enabledPlugins": {"clean@market": True, "skills@other": True, "off@x": False},
            "permissions": {
                "allow": ["Read", "Grep(*)", "Bash(git status:*)", "mcp__srv__tool"],
                "defaultMode": "default",
            },
            "env": {},
        },
    )
    check_settings_sources(all_sources(paths), plugins_dir=plugins)


def test_c59_plugins_dir_defaults_next_to_the_user_settings(tmp_path: Path) -> None:
    paths = sources(tmp_path)
    plugin(paths["user"].parent / "plugins", "hooky", "market", hooks=True)
    write(paths["project"], {"enabledPlugins": {"hooky@market": True}})
    with pytest.raises(HostSettingsError, match="ships hooks"):
        check_settings_sources(all_sources(paths))


@pytest.mark.parametrize(
    ("rule", "broad"),
    [
        ("Bash", True),
        ("Bash()", True),
        ("Bash( * )", True),
        ("WebFetch", True),
        ("Agent", True),
        ("mcp__srv", True),
        ("bad rule (", True),
        # fixcheck-b-5: a shell, interpreter, wrapper or opaque runner runs any code ...
        ("Bash(bash:*)", True),
        ("Bash(sh -c:*)", True),
        ("Bash(python3:*)", True),
        ("Bash(node *)", True),
        ("Bash(sudo:*)", True),
        ("Bash(env:*)", True),
        ("Bash(/usr/bin/env:*)", True),
        ("Bash(xargs:*)", True),
        ("Bash(eval:*)", True),
        ("Bash(ssh:*)", True),
        ("Bash(find:*)", True),
        ("Bash(awk:*)", True),
        ("Bash(FOO=1 rm:*)", True),
        ("Bash(*rm:*)", True),
        # ... and so does writing anywhere under /, /root, /etc or /opt.
        ("Edit(//root/**)", True),
        ("Write(//etc/**)", True),
        ("MultiEdit(//opt/**)", True),
        ("Edit(~/**)", True),
        ("Edit(//r*/**)", True),
        ("Write(//root)", True),
        ("Edit(/**)", True),
        ("Edit(**)", True),
        ("Read", False),
        ("Bash(npm run test:*)", False),
        ("Bash(git status:*)", False),
        ("Edit(/src/**)", False),
        ("Edit(//root/notes/**)", False),
        ("Write(//etc/hosts)", False),
        ("Edit(src/**)", False),
        ("mcp__srv__tool", False),
    ],
)
def test_c59_broad_allow_rules(rule: str, broad: bool) -> None:
    assert is_broad_allow(rule) is broad


@pytest.mark.parametrize("rule", ["Bash(bash:*)", "Bash(env:*)", "Edit(//root/**)"])
def test_c59_code_running_allow_rule_refuses_run(rule: str, tmp_path: Path) -> None:
    paths = sources(tmp_path)
    write(paths["project"], {"permissions": {"allow": [rule]}})
    with pytest.raises(HostSettingsError, match="broad"):
        check_settings_sources(all_sources(paths))


# --- newcode-3: managed drop-ins are listed again before every run -------------------------


def preflight_for(tmp_path: Path, managed: Path, listed: list[Path]) -> SettingsPreflight:
    path = write(tmp_path / "s.json", shipped())
    return SettingsPreflight(
        load_host_settings(path, trusted_uids=ME),
        listed,
        trusted_uids=ME,
        hook_command=fake_hook(tmp_path),
        managed_dir=managed,
    )


def test_c59_dropin_created_after_start_refuses_run(tmp_path: Path) -> None:
    managed = tmp_path / "managed-settings.d"
    listed = settings_sources(tmp_path / "home", tmp_path / "work", managed_dir=managed)
    preflight = preflight_for(tmp_path, managed, listed)
    preflight.check()  # no drop-in dir at start
    managed.mkdir()
    write(managed / "50.json", {"allowManagedHooksOnly": True})
    with pytest.raises(RunRefusedError, match="allowManagedHooksOnly"):
        preflight.check()


def test_c59_removed_dropin_is_not_a_failure(tmp_path: Path) -> None:
    managed = tmp_path / "managed-settings.d"
    managed.mkdir()
    write(managed / "10.json", {})
    listed = settings_sources(tmp_path / "home", tmp_path / "work", managed_dir=managed)
    assert managed / "10.json" in listed
    preflight = preflight_for(tmp_path, managed, listed)
    (managed / "10.json").unlink()
    preflight.check()


def test_c59_unlistable_dropin_dir_refuses(tmp_path: Path) -> None:
    managed = tmp_path / "managed-settings.d"
    managed.write_text("not a directory", encoding="utf-8")
    with pytest.raises(HostSettingsError, match="cannot be listed"):
        settings_sources(tmp_path / "home", tmp_path / "work", managed_dir=managed)
    preflight = preflight_for(tmp_path, managed, [])
    with pytest.raises(RunRefusedError, match="cannot be listed"):
        preflight.check()


# --- fixcheck-b-3: the hook's content is pinned at start -----------------------------------


def test_c59_rewritten_hook_or_module_refuses_run(tmp_path: Path) -> None:
    hook = fake_hook(tmp_path)
    module = tmp_path / "hook.py"
    module.write_text("def main(): ...\n", encoding="utf-8")
    path = write(tmp_path / "s.json", shipped())
    preflight = SettingsPreflight(
        load_host_settings(path, trusted_uids=ME),
        [],
        trusted_uids=ME,
        hook_command=hook,
        managed_dir=tmp_path / "none",
        hook_modules=[module],
    )
    preflight.check()
    module.write_text("def main(): return 0\n", encoding="utf-8")  # same owner and mode
    with pytest.raises(RunRefusedError, match="changed since start"):
        preflight.check()
    module.write_text("def main(): ...\n", encoding="utf-8")
    preflight.check()
    hook.write_text(hook.read_text(encoding="utf-8") + "# patched\n", encoding="utf-8")
    with pytest.raises(RunRefusedError, match="changed since start"):
        preflight.check()


def test_c59_unpinnable_hook_refuses_every_run(tmp_path: Path) -> None:
    hook = fake_hook(tmp_path)
    path = write(tmp_path / "s.json", shipped())
    preflight = SettingsPreflight(
        load_host_settings(path, trusted_uids=ME),
        [],
        trusted_uids=ME,
        hook_command=hook,
        managed_dir=tmp_path / "none",
        hook_modules=[tmp_path / "missing.py"],
    )
    with pytest.raises(RunRefusedError, match="pinned"):
        preflight.check()


def test_c59_pin_covers_the_hook_modules_by_default() -> None:
    names = [p.name for p in hook_module_files()]
    assert names == ["__init__.py", "__init__.py", "__init__.py", "hook.py"]
    assert all(p.is_file() for p in hook_module_files())
    # The hook module is stdlib-only past these files: nothing else to pin.
    source = (hook_module_files()[-1]).read_text(encoding="utf-8")
    assert "preview_dashboard" not in "".join(
        line for line in source.splitlines() if line.startswith(("import ", "from "))
    )


@pytest.mark.parametrize("key", [*CREDENTIAL_HELPER_KEYS, "env"])
@pytest.mark.parametrize("source", ["user", "project", "managed"])
def test_c49_source_env_or_credential_helper_refuses_run(
    key: str, source: str, tmp_path: Path
) -> None:
    paths = sources(tmp_path)
    value: object = {"FOO": "1"} if key == "env" else "/usr/local/bin/helper"
    write(paths[source], {key: value})
    with pytest.raises(HostSettingsError, match=r"env block|" + key):
        check_settings_sources(all_sources(paths))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(env={"ANTHROPIC_API_KEY": "x"}),
        lambda d: d.update(apiKeyHelper="/bin/helper"),
        lambda d: d.update(awsAuthRefresh="aws sso login"),
        lambda d: d.update(enabledPlugins={"p@m": True}),
        lambda d: d["permissions"].update(allow=["Bash"]),
        lambda d: d["permissions"].update(defaultMode="acceptEdits"),
    ],
    ids=["env", "api-key-helper", "aws-refresh", "plugins", "broad-allow", "accept-edits"],
)
def test_c49_host_file_env_helpers_plugins_refused(mutate: Any, tmp_path: Path) -> None:
    data = shipped()
    mutate(data)
    with pytest.raises(HostSettingsError):
        load_host_settings(write(tmp_path / "s.json", data), trusted_uids=ME)


def test_c59_refused_preflight_means_no_run_and_one_alert() -> None:
    rig = host_rig(preflight=FakePreflight(refuse=True))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.runner.requests == []
    assert len(rig.alerts.titles) == 1
    assert "disableAllHooks" not in rig.alerts.titles[0]  # fixed text only
    assert rig.admin.replies[0][0].startswith("I can't run right now")


def _start_config(tmp_path: Path) -> HostConfig:
    work = tmp_path / "work"
    work.mkdir()
    settings = write(tmp_path / "s.json", shipped())
    return parse_args(
        [
            *("--settings", str(settings), "--home", str(tmp_path)),
            *("--workdir", str(work), "--claude-bin", "/usr/bin/claude"),
        ]
    )


def test_hook5_startup_checks_the_hook_command(tmp_path: Path) -> None:
    config = _start_config(tmp_path)
    verified = startup_checks(config, {}, trusted_uids=ME, hook_command=fake_hook(tmp_path))
    assert verified.path == config.settings_file


def test_hook5_startup_refuses_a_missing_or_writable_hook(tmp_path: Path) -> None:
    """Fail closed at start: a broken hook would let every call run unchecked."""
    config = _start_config(tmp_path)
    with pytest.raises(HostSettingsError):
        startup_checks(config, {}, trusted_uids=ME, hook_command=tmp_path / "absent-hook")
    hook = fake_hook(tmp_path)
    hook.chmod(0o777)
    with pytest.raises(HostSettingsError):
        startup_checks(config, {}, trusted_uids=ME, hook_command=hook)
