"""Static checks on `deploy/`: systemd units, nftables rule, scripts, config
template (unit 11a). These tests never install, start a service, touch
`/etc`/`/opt`, load nftables, create users, or touch Tailscale — they only
parse and lint the artifacts and run `--dry-run` on the shell scripts
(docs/security.md C1, C14, C16, C23, C28, C29, C30; unit-11 rows).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from preview_dashboard.config import Settings
from preview_dashboard.interfaces.cli import build_parser
from preview_dashboard.interfaces.token_file import TokenKind

pytestmark = pytest.mark.unit

# Resolved absolute paths (or None): avoids "partial executable path" (S607)
# and lets skipif conditions and the calls that need them share one lookup.
BASH = shutil.which("bash")
NFT = shutil.which("nft")
SHELLCHECK = shutil.which("shellcheck")
SYSTEMD_ANALYZE = shutil.which("systemd-analyze")

DEPLOY_DIR = Path(__file__).resolve().parents[2] / "deploy"
SYSTEMD_DIR = DEPLOY_DIR / "systemd"
NFT_FILE = DEPLOY_DIR / "nftables" / "preview-dashboard.nft"
SERVE_SH = DEPLOY_DIR / "tailscale" / "serve.sh"
ACL_SNIPPET = DEPLOY_DIR / "tailscale" / "acl-snippet.json"
INSTALL_SH = DEPLOY_DIR / "install.sh"
UNINSTALL_SH = DEPLOY_DIR / "uninstall.sh"
CHECK_SH = DEPLOY_DIR / "check.sh"
WIZARD_SH = DEPLOY_DIR / "setup-wizard.sh"
CONFIG_EXAMPLE = DEPLOY_DIR / "config.example.toml"
NOTIFY_EGRESS_TEMPLATE = DEPLOY_DIR / "nftables" / "notifier-egress.nft.in"
NOTIFY_CONFIG_PY = DEPLOY_DIR / "lib" / "notify_config.py"

ADMIN_UNIT = SYSTEMD_DIR / "preview-dashboard-admin.service"
VIEWER_UNIT = SYSTEMD_DIR / "preview-dashboard-viewer.service"
PURGE_UNIT = SYSTEMD_DIR / "preview-dashboard-purge.service"
PURGE_TIMER = SYSTEMD_DIR / "preview-dashboard-purge.timer"
FIREWALL_UNIT = SYSTEMD_DIR / "preview-dashboard-firewall.service"
NOTIFIER_UNIT = SYSTEMD_DIR / "preview-dashboard-notifier.service"
CLAUDIA_HOST_UNIT = SYSTEMD_DIR / "claudia-host.service"
GARDENER_UNIT = SYSTEMD_DIR / "claudia-gardener.service"
GARDENER_TIMER = SYSTEMD_DIR / "claudia-gardener.timer"
CLAUDIA_SETTINGS = DEPLOY_DIR / "claudia" / "settings.json"
CLAUDIA_MCP_TEMPLATE = DEPLOY_DIR / "claudia" / "mcp.json.in"
VOICE_PINS = DEPLOY_DIR / "claudia" / "voices.sha256"
WHISPER_PINS = DEPLOY_DIR / "claudia" / "whisper.sha256"
WHISPER_BUILD_REQS = DEPLOY_DIR / "claudia" / "whisper-build-requirements.txt"
ALL_SYSTEMD_FILES = (
    ADMIN_UNIT,
    VIEWER_UNIT,
    PURGE_UNIT,
    PURGE_TIMER,
    FIREWALL_UNIT,
    NOTIFIER_UNIT,
    CLAUDIA_HOST_UNIT,
    GARDENER_UNIT,
    GARDENER_TIMER,
)
ALL_SERVICE_FILES = (ADMIN_UNIT, VIEWER_UNIT, PURGE_UNIT)
# The shared-group services (share UMask=0007 for group-readable files, C28);
# the notifier writes nothing, shares no group, and is checked separately.
SHARED_GROUP_SERVICE_FILES = (ADMIN_UNIT, VIEWER_UNIT, PURGE_UNIT)
ALL_SERVICE_FILES_INCL_NOTIFIER = (ADMIN_UNIT, VIEWER_UNIT, PURGE_UNIT, NOTIFIER_UNIT)


def parse_unit(path: Path) -> dict[tuple[str, str], list[str]]:
    """Minimal INI-ish parser for systemd unit files.

    Keyed by (section, key) -> list of raw values (systemd directives like
    `SystemCallFilter=` or `ReadOnlyPaths=` legitimately repeat, which
    `configparser` rejects by default -- so this keeps every occurrence
    instead of just the last one.
    """
    result: dict[tuple[str, str], list[str]] = {}
    section = ""
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        result.setdefault((section, key.strip()), []).append(value.strip())
    return result


def directives(path: Path) -> set[str]:
    """Every directive key (e.g. 'SystemCallFilter') that appears anywhere."""
    return {key for _section, key in parse_unit(path)}


# --- file headers ------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        ADMIN_UNIT,
        VIEWER_UNIT,
        PURGE_UNIT,
        PURGE_TIMER,
        FIREWALL_UNIT,
        NOTIFIER_UNIT,
        NFT_FILE,
        SERVE_SH,
        INSTALL_SH,
        UNINSTALL_SH,
        CHECK_SH,
        WIZARD_SH,
        CONFIG_EXAMPLE,
        NOTIFY_EGRESS_TEMPLATE,
        CLAUDIA_HOST_UNIT,
        GARDENER_UNIT,
        GARDENER_TIMER,
        CLAUDIA_MCP_TEMPLATE,
        VOICE_PINS,
        WHISPER_PINS,
        WHISPER_BUILD_REQS,
    ],
)
def test_every_artifact_has_a_file_header_comment(path: Path) -> None:
    """CLAUDE.md: every file (incl. sh/unit/toml) starts with a 2-4 line comment."""
    lines = path.read_text().splitlines()
    # install.sh/serve.sh start with a shebang; the header follows immediately.
    start = 1 if lines[0].startswith("#!") else 0
    assert lines[start].lstrip().startswith("#"), f"{path} has no header comment"
    assert path.name.split(".")[0] in lines[start] or "deploy/" in lines[start], (
        f"{path} header should name the file"
    )


# --- systemd: structural / hardening directives -------------------------------------


def test_admin_unit_identity_and_socket_peer_policy() -> None:
    unit = parse_unit(ADMIN_UNIT)
    assert unit[("Service", "User")] == ["pdash-admin"]
    # "pdash", not "pdash-admin": interfaces/mcp/server.py no longer
    # hardcodes a group name at all — it trusts whatever gid owns the admin
    # socket (ADR 0017 amendment "G", unit 10b M1).
    assert unit[("Service", "Group")] == ["pdash"]
    (exec_start,) = unit[("Service", "ExecStart")]
    # $PDASH_NOTIFIER_ADMIN_ARGS, UNBRACED (S-B H1): expands to zero words on
    # a host without the notifier, or to "--notifier-peer-uid <uid>
    # --token-group notifier=pdash-notifytok" as separate words (ADR 0023).
    # ${PDASH_VIEWER_UID}, BRACED: exactly one word, "" when unset -> exit 2 (ADR 0025).
    # $PDASH_CLAUDIA_ADMIN_ARGS (M9, ADR 0036) follows the notifier's pattern.
    # --viewer-peer-uid ${PDASH_VIEWER_UID} (F-CL6, ADR 0043): braced, same file.
    assert exec_start.endswith(
        "/opt/preview-dashboard/.venv/bin/preview-dashboard serve-admin "
        "--allowed-peer-uid 0 --trusted-sidecar-uid ${PDASH_VIEWER_UID} "
        "--token-group admin=pdash --viewer-peer-uid ${PDASH_VIEWER_UID} "
        "--token-group viewer=pdash-viewtok $PDASH_NOTIFIER_ADMIN_ARGS $PDASH_CLAUDIA_ADMIN_ARGS"
    )


# --- H1 (S-B): systemd's ExecStart= expansion, simulated --------------------------

_LONE_VAR_WORD = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_]*)$")
_BRACED_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def systemd_expand(exec_line: str, env: dict[str, str]) -> list[str]:
    """Expand variables the way systemd.service(5) documents for ExecStart=.

    A lone `$VAR` word is split at whitespace into zero or more arguments;
    `${VAR}` anywhere in a word substitutes the exact value into that ONE
    word ("" when unset). Only valid for lines without quotes (asserted).
    """
    assert '"' not in exec_line and "'" not in exec_line
    argv: list[str] = []
    for word in exec_line.split():
        lone = _LONE_VAR_WORD.match(word)
        if lone:
            argv.extend(env.get(lone.group(1), "").split())
        else:
            argv.append(_BRACED_VAR.sub(lambda m: env.get(m.group(1), ""), word))
    return argv


_VIEWER_ENV = {"PDASH_VIEWER_UID": "997"}  # viewer-uid.env (always written, ADR 0025)
# Static in the admin unit: its own token, then viewer.token's group (F-CL6).
_BASE_GROUPS = ("admin=pdash", "viewer=pdash-viewtok")


def _env_file_line(uid: str) -> dict[str, str]:
    """The notifier-admin.env line install.sh writes, parsed like systemd does."""
    key, _, value = (
        f"PDASH_NOTIFIER_ADMIN_ARGS=--notifier-peer-uid {uid} "
        "--token-group notifier=pdash-notifytok"
    ).partition("=")
    return {key: value.strip(), **_VIEWER_ENV}


def test_install_sh_writes_the_env_file_line_the_simulation_uses() -> None:
    text = INSTALL_SH.read_text()
    assert (
        "printf 'PDASH_NOTIFIER_ADMIN_ARGS=--notifier-peer-uid %s "
        "--token-group notifier=%s\\n'" in text
    )


@pytest.mark.parametrize(
    ("env", "notifier_uids", "token_groups"),
    [
        (_VIEWER_ENV, None, [*_BASE_GROUPS]),  # no notifier env file: unset
        ({"PDASH_NOTIFIER_ADMIN_ARGS": "", **_VIEWER_ENV}, None, [*_BASE_GROUPS]),  # empty
        (_env_file_line("998"), [998], [*_BASE_GROUPS, "notifier=pdash-notifytok"]),
    ],
)
def test_admin_execstart_expands_to_argv_serve_admin_accepts(
    env: dict[str, str], notifier_uids: list[int] | None, token_groups: list[str]
) -> None:
    (exec_start,) = parse_unit(ADMIN_UNIT)[("Service", "ExecStart")]
    argv = systemd_expand(exec_start, env)
    assert "" not in argv
    args = build_parser().parse_args(argv[1:])
    assert args.command == "serve-admin"
    assert args.allowed_peer_uid == [0]
    assert args.trusted_sidecar_uid == [997]
    assert args.notifier_peer_uid == notifier_uids
    assert args.viewer_peer_uid == [997]  # pdash-viewer only, from viewer-uid.env
    assert args.token_group == token_groups
    # Every value is the scoped KIND=GROUP form with a real token kind (ADR 0024),
    # or the TOTP secret's own group (totp=, S-C1 S2).
    for value in args.token_group:
        kind, sep, _group = value.partition("=")
        assert sep
        if kind != "totp":
            TokenKind(kind)


@pytest.mark.parametrize("env", [_VIEWER_ENV, _env_file_line("998")])
def test_braced_notifier_args_would_break_serve_admin(env: dict[str, str]) -> None:
    """Regression guard for H1: the braced form is one word, "" when unset."""
    exec_start = parse_unit(ADMIN_UNIT)[("Service", "ExecStart")][0].replace(
        "$PDASH_NOTIFIER_ADMIN_ARGS", "${PDASH_NOTIFIER_ADMIN_ARGS}"
    )
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(systemd_expand(exec_start, env)[1:])
    assert exc.value.code == 2


def test_admin_unit_has_an_optional_notifier_env_file() -> None:
    """N5: the unit file itself never changes per host; install.sh writes
    this env file only when --telegram-chat-id was given (ADR 0023)."""
    unit = parse_unit(ADMIN_UNIT)
    assert unit[("Service", "EnvironmentFile")] == [
        "/etc/preview-dashboard/viewer-uid.env",  # required: fail closed (ADR 0025)
        "-/etc/preview-dashboard/notifier-admin.env",
        "-/etc/preview-dashboard/claudia-admin.env",  # M9: same optional pattern
    ]


@pytest.mark.parametrize("unit_path", [ADMIN_UNIT, PURGE_UNIT])
def test_missing_viewer_uid_fails_closed(unit_path: Path) -> None:
    """ADR 0025: no PDASH_VIEWER_UID -> "" -> argparse exit 2, never "trust nobody extra"."""
    (exec_start,) = parse_unit(unit_path)[("Service", "ExecStart")]
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(systemd_expand(exec_start, {})[1:])
    assert exc.value.code == 2


def test_purge_execstart_trusts_the_viewer_uid_for_sidecars() -> None:
    unit = parse_unit(PURGE_UNIT)
    assert unit[("Service", "EnvironmentFile")] == ["/etc/preview-dashboard/viewer-uid.env"]
    (exec_start,) = unit[("Service", "ExecStart")]
    args = build_parser().parse_args(systemd_expand(exec_start, _VIEWER_ENV)[1:])
    assert args.command == "purge"
    assert args.trusted_sidecar_uid == [997]


def test_install_sh_writes_viewer_uid_and_migrates_with_it() -> None:
    text = INSTALL_SH.read_text()
    assert 'VIEWER_UID_ENV="$ETC_DIR/viewer-uid.env"' in text
    assert 'VIEWER_UID="$(id -u "$VIEWER_USER")"' in text
    assert "printf 'PDASH_VIEWER_UID=%s\\n' \"$VIEWER_UID\" | write_file" in text
    assert '--trusted-sidecar-uid "$VIEWER_UID"' in text.split("migrate", 1)[1]


def test_admin_unit_grants_notifier_socket_access_via_acl_not_group() -> None:
    """N5/ADR 0023: pdash-notify is not in group pdash, so it needs an
    explicit, narrow grant to reach the admin socket; this must never fail
    the admin unit itself (guarded, and always exits 0).

    Reads the raw text, not `parse_unit` (whose simple line parser doesn't
    join `\\`-continued values the way systemd itself does)."""
    text = ADMIN_UNIT.read_text()
    assert "ExecStartPost=/bin/sh -c" in text
    assert "setfacl -m u:pdash-notify:X" in text
    assert "setfacl -m u:pdash-notify:rw" in text
    assert "command -v setfacl" in text  # logs (M3) instead of failing if absent
    assert "apt install acl" in text
    assert "id -u pdash-notify" in text  # no-op if the notifier isn't installed
    # The ACL script always exits 0: it must never fail the admin unit itself.
    assert "    exit 0'" in text


def _exec_start_post_script() -> str:
    text = ADMIN_UNIT.read_text()
    start = text.index("ExecStartPost=")
    end = text.index("exit 0'\n", start)
    return text[start:end]


def test_admin_acl_script_escapes_every_shell_dollar_for_systemd() -> None:
    """systemd expands `$NAME`/`${NAME}` in Exec lines itself, even inside
    quotes: a bare shell `$d` or `${RUNTIME_DIRECTORY:-...}` would reach
    /bin/sh blanked out. Every `$` meant for the shell must be `$$`."""
    script = _exec_start_post_script()
    assert "$$d" in script
    assert "$" not in script.replace("$$", ""), "unescaped $ in ExecStartPost"


def test_admin_acl_script_targets_the_fixed_socket_path_and_waits_bounded() -> None:
    script = _exec_start_post_script()
    assert "d=/run/preview-dashboard;" in script
    assert "admin.sock" in script
    assert "-lt 300 ]" in script  # 300 x 0.1 s


def test_viewer_unit_identity_and_trusted_owner_uid() -> None:
    unit = parse_unit(VIEWER_UNIT)
    assert unit[("Service", "User")] == ["pdash-viewer"]
    assert unit[("Service", "Group")] == ["pdash"]
    (exec_start,) = unit[("Service", "ExecStart")]
    assert "serve-viewer" in exec_start
    assert "--trusted-owner-uid ${PDASH_ADMIN_UID}" in exec_start
    assert unit[("Service", "EnvironmentFile")] == ["/etc/preview-dashboard/admin-uid.env"]
    # StateDirectory= is deliberately absent here (see the unit's own
    # comment): systemd recursively re-chowns a *Directory= path to the
    # unit's own User/Group on mismatch, which would break the
    # trusted-owner model (pdash-admin owns data_dir, not pdash-viewer).
    assert ("Service", "StateDirectory") not in unit


def test_purge_service_runs_as_admin_oneshot() -> None:
    unit = parse_unit(PURGE_UNIT)
    assert unit[("Service", "Type")] == ["oneshot"]
    assert unit[("Service", "User")] == ["pdash-admin"]
    assert unit[("Service", "Group")] == ["pdash"]
    (exec_start,) = unit[("Service", "ExecStart")]
    assert exec_start.endswith("preview-dashboard purge --trusted-sidecar-uid ${PDASH_VIEWER_UID}")


def test_purge_timer_is_hourly_persistent_with_jitter() -> None:
    unit = parse_unit(PURGE_TIMER)
    assert unit[("Timer", "OnCalendar")] == ["hourly"]
    assert unit[("Timer", "Persistent")] == ["true"]
    (delay,) = unit[("Timer", "RandomizedDelaySec")]
    seconds = int(delay.rstrip("s"))
    assert 0 < seconds <= 300, "jitter should be small relative to the hourly period"
    assert unit[("Install", "WantedBy")] == ["timers.target"]


_COMMON_HARDENING = (
    "NoNewPrivileges",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "PrivateDevices",
    "ProtectProc",
    "ProcSubset",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "RestrictNamespaces",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "SystemCallFilter",
    "SystemCallArchitectures",
    "RemoveIPC",
    "UMask",
    "MemoryMax",
    "TasksMax",
    "LimitNOFILE",
)


@pytest.mark.parametrize("unit_path", ALL_SERVICE_FILES_INCL_NOTIFIER)
def test_every_service_has_the_common_hardening_directives(unit_path: Path) -> None:
    """docs/security.md C28: the full hardening list, on every service unit."""
    present = directives(unit_path)
    missing = [d for d in _COMMON_HARDENING if d not in present]
    assert not missing, f"{unit_path.name} is missing: {missing}"


@pytest.mark.parametrize("unit_path", ALL_SERVICE_FILES_INCL_NOTIFIER)
def test_system_call_filter_denies_privileged_and_resources(unit_path: Path) -> None:
    unit = parse_unit(unit_path)
    values = unit[("Service", "SystemCallFilter")]
    assert "@system-service" in values
    assert "~@privileged @resources" in values


@pytest.mark.parametrize("unit_path", ALL_SERVICE_FILES_INCL_NOTIFIER)
def test_capability_bounding_set_and_ambient_capabilities_are_empty(unit_path: Path) -> None:
    unit = parse_unit(unit_path)
    assert unit[("Service", "CapabilityBoundingSet")] == [""]
    assert unit[("Service", "AmbientCapabilities")] == [""]


def test_admin_and_purge_are_network_isolated_to_af_unix() -> None:
    for unit_path in (ADMIN_UNIT, PURGE_UNIT):
        unit = parse_unit(unit_path)
        assert unit[("Service", "PrivateNetwork")] == ["yes"]
        assert unit[("Service", "RestrictAddressFamilies")] == ["AF_UNIX"]


def test_viewer_network_is_loopback_only() -> None:
    unit = parse_unit(VIEWER_UNIT)
    assert unit[("Service", "RestrictAddressFamilies")] == ["AF_INET AF_INET6 AF_UNIX"]
    assert unit[("Service", "IPAddressDeny")] == ["any"]
    assert unit[("Service", "IPAddressAllow")] == ["localhost"]


# --- notifier unit (N5, docs/security.md C33/C38) -----------------------------------


def test_notifier_unit_identity_and_least_privilege_groups() -> None:
    unit = parse_unit(NOTIFIER_UNIT)
    assert unit[("Service", "User")] == ["pdash-notify"]
    # Own primary group, never "pdash" (C33): must never gain admin.token/
    # db/blobs access through group membership.
    assert unit[("Service", "Group")] == ["pdash-notify"]
    assert unit[("Service", "SupplementaryGroups")] == ["pdash-notifytok"]
    (exec_start,) = unit[("Service", "ExecStart")]
    assert exec_start.endswith("serve-notifier --token-group notifier=pdash-notifytok")


def test_notifier_unit_conditions_on_both_token_files() -> None:
    unit = parse_unit(NOTIFIER_UNIT)
    conditions = unit[("Unit", "ConditionPathExists")]
    assert "/etc/preview-dashboard/notifier.token" in conditions
    assert "/etc/preview-dashboard/telegram.token" in conditions


def test_notifier_unit_requires_the_firewall_and_has_no_db_blob_access() -> None:
    unit = parse_unit(NOTIFIER_UNIT)
    assert "preview-dashboard-firewall.service" in unit[("Unit", "Requires")][0]
    assert ("Service", "ReadWritePaths") not in unit
    assert ("Service", "StateDirectory") not in unit
    assert ("Service", "RuntimeDirectory") not in unit
    inaccessible = unit[("Service", "InaccessiblePaths")]
    assert any("/var/lib/preview-dashboard" in v for v in inaccessible)
    assert any("/etc/preview-dashboard/admin.token" in v for v in inaccessible)


def test_notifier_unit_network_is_outbound_only_no_ip_allowlist() -> None:
    """Egress is enforced by the nft uid rule (C38), not by systemd's own IP
    allowlist, which can't express "port 443 to anywhere"."""
    unit = parse_unit(NOTIFIER_UNIT)
    assert unit[("Service", "RestrictAddressFamilies")] == ["AF_UNIX AF_INET AF_INET6"]
    assert ("Service", "IPAddressDeny") not in unit
    assert ("Service", "IPAddressAllow") not in unit


def test_notifier_unit_only_started_when_flag_given() -> None:
    """docs/security.md C33/C38: install.sh only ever installs/enables this
    unit conditionally; static presence of the file in the repo is fine
    (it's the templates), but nothing here is Enable=d by default."""
    unit = parse_unit(NOTIFIER_UNIT)
    assert unit[("Install", "WantedBy")] == ["multi-user.target"]


def test_viewer_blobs_are_read_only() -> None:
    unit = parse_unit(VIEWER_UNIT)
    ro = unit[("Service", "ReadOnlyPaths")]
    assert any("blobs" in v for v in ro)
    assert any("staging" in v for v in ro)
    rw = unit[("Service", "ReadWritePaths")]
    assert rw == ["/var/lib/preview-dashboard/db"]


def test_viewer_cannot_reach_the_admin_token() -> None:
    """The viewer has no admin API client and must never be able to read the
    bearer token, even via a bug: mask it explicitly under InaccessiblePaths=
    even though ReadOnlyPaths=/etc/preview-dashboard would otherwise expose it."""
    unit = parse_unit(VIEWER_UNIT)
    inaccessible = unit[("Service", "InaccessiblePaths")]
    assert any("/etc/preview-dashboard/admin.token" in v for v in inaccessible)


def test_admin_has_full_read_write_on_data_dir() -> None:
    unit = parse_unit(ADMIN_UNIT)
    assert unit[("Service", "ReadWritePaths")] == ["/var/lib/preview-dashboard"]


def test_viewer_reaches_the_admin_socket_with_its_scoped_token_only() -> None:
    """The static viewer unit keeps unit 12's L1 mask on /run/preview-dashboard;
    only the Claudia drop-in (F-CL6, ADR 0043) lifts it, so the viewer's one
    admin client posts dashboard Approve/Deny there on Claudia hosts only. The
    scope is the admin's: viewer.token (its own group, scoped KIND=GROUP) from
    the viewer's uid only. admin.token, /root and /home stay masked."""
    unit = parse_unit(VIEWER_UNIT)
    inaccessible = " ".join(unit[("Service", "InaccessiblePaths")]).split()
    assert "/run/preview-dashboard" in inaccessible
    assert {"/root", "/home", "/etc/preview-dashboard/admin.token"} <= set(inaccessible)
    (exec_start,) = unit[("Service", "ExecStart")]
    assert exec_start.endswith(
        "serve-viewer --trusted-owner-uid ${PDASH_ADMIN_UID} --token-group viewer=pdash-viewtok"
    )
    args = build_parser().parse_args(systemd_expand(exec_start, {"PDASH_ADMIN_UID": "996"})[1:])
    assert args.token_group == ["viewer=pdash-viewtok"]
    # The admin admits that uid on /v1/viewer/* only (PeerPolicyMiddleware).
    (admin_exec,) = parse_unit(ADMIN_UNIT)[("Service", "ExecStart")]
    assert "--viewer-peer-uid ${PDASH_VIEWER_UID}" in admin_exec


@pytest.mark.parametrize("unit_path", ALL_SERVICE_FILES_INCL_NOTIFIER)
def test_journald_only_logging(unit_path: Path) -> None:
    """docs/security.md C29: journald only, never a file."""
    unit = parse_unit(unit_path)
    assert unit[("Service", "StandardOutput")] == ["journal"]
    assert unit[("Service", "StandardError")] == ["journal"]


@pytest.mark.parametrize("unit_path", SHARED_GROUP_SERVICE_FILES)
def test_umask_matches_shared_group_model(unit_path: Path) -> None:
    """ADR 0013: UMask=0007 keeps group-write bits so the shared group (pdash) can share files."""
    unit = parse_unit(unit_path)
    assert unit[("Service", "UMask")] == ["0007"]


def test_notifier_umask_has_no_group_or_world_bits() -> None:
    """The notifier shares no group and writes nothing (docs/security.md C33):
    unlike the shared-group services, its UMask should grant nothing to
    group/other."""
    unit = parse_unit(NOTIFIER_UNIT)
    assert unit[("Service", "UMask")] == ["0077"]


@pytest.mark.parametrize("unit_path", (ADMIN_UNIT, VIEWER_UNIT))
def test_long_running_services_restart_on_failure_with_backoff(unit_path: Path) -> None:
    unit = parse_unit(unit_path)
    assert unit[("Service", "Restart")] == ["on-failure"]
    assert ("Service", "RestartSec") in unit
    assert ("Service", "RestartSteps") in unit


# --- ExecStart flags exist on the actual CLI parser ----------------------------------


def _subparser_choices(parser: object) -> dict[str, object]:
    for action in parser._actions:  # type: ignore[attr-defined]
        if hasattr(action, "choices") and action.choices:
            return dict(action.choices)
    raise AssertionError("no subparsers action found")


def _option_strings(subcommands: dict[str, object], name: str) -> set[str]:
    """Every `--flag` name a subcommand's parser accepts."""
    actions = subcommands[name]._actions  # type: ignore[attr-defined]
    return {opt for action in actions for opt in action.option_strings}


def test_execstart_commands_and_flags_exist_on_the_cli() -> None:
    parser = build_parser()
    subcommands = _subparser_choices(parser)

    admin_exec = parse_unit(ADMIN_UNIT)[("Service", "ExecStart")][0]
    assert "serve-admin" in subcommands
    admin_opts = _option_strings(subcommands, "serve-admin")
    assert "--allowed-peer-uid" in admin_opts
    assert "--allowed-peer-uid" in admin_exec
    assert "--token-group" in admin_opts
    assert "--token-group admin=pdash" in admin_exec

    viewer_exec = parse_unit(VIEWER_UNIT)[("Service", "ExecStart")][0]
    assert "serve-viewer" in subcommands
    viewer_opts = _option_strings(subcommands, "serve-viewer")
    assert "--trusted-owner-uid" in viewer_opts
    assert "--trusted-owner-uid" in viewer_exec

    purge_exec = parse_unit(PURGE_UNIT)[("Service", "ExecStart")][0]
    assert "purge" in subcommands
    assert " purge --trusted-sidecar-uid " in purge_exec
    for name in ("serve-admin", "purge", "migrate"):
        assert "--trusted-sidecar-uid" in _option_strings(subcommands, name)
    assert "--trusted-sidecar-uid" in admin_exec

    notifier_exec = parse_unit(NOTIFIER_UNIT)[("Service", "ExecStart")][0]
    assert "serve-notifier" in subcommands
    notifier_opts = _option_strings(subcommands, "serve-notifier")
    assert "--token-group" in notifier_opts
    assert "--token-group notifier=pdash-notifytok" in notifier_exec


def test_install_sh_uses_real_cli_commands_and_flags() -> None:
    parser = build_parser()
    subcommands = _subparser_choices(parser)
    text = INSTALL_SH.read_text()

    assert "gen-token" in subcommands
    gen_token_opts = _option_strings(subcommands, "gen-token")
    assert {"--out", "--group"} <= gen_token_opts
    assert "gen-token --out" in text
    assert "--group" in text

    assert "migrate" in subcommands
    assert "migrate" in text.split("gen-token", 1)[1] or " migrate" in text

    assert "check-config" in subcommands
    check_config_opts = _option_strings(subcommands, "check-config")
    assert "--token-group" in check_config_opts
    assert 'check-config --token-group "admin=$SERVICE_GROUP" "${_check_extra[@]}"' in text
    assert '_check_extra=(--token-group "notifier=$NOTIFY_TOK_GROUP")' in text  # H2 (S-B)


# --- H2 (unit 12 audit): enable, then restart, then verify -------------------------

_RESTART_LINE = (
    "systemctl restart preview-dashboard-firewall preview-dashboard-admin preview-dashboard-viewer"
)


def test_install_sh_enables_before_restarting_the_long_running_units() -> None:
    """`systemctl enable --now` on an already-active unit does NOT restart
    it, so a re-run after `git pull` must explicitly `restart` — separately
    from `enable` — or a code/unit-file update would never take effect."""
    text = INSTALL_SH.read_text()
    for unit in (
        "preview-dashboard-firewall.service",
        "preview-dashboard-admin.service",
        "preview-dashboard-viewer.service",
    ):
        assert f"systemctl enable {unit}" in text, f"missing explicit enable for {unit}"
        # Not "enable --now": that would skip the explicit restart step below
        # on a re-run against an already-active unit.
        assert f"systemctl enable --now {unit}" not in text

    assert _RESTART_LINE in text
    enable_idx = text.index("systemctl enable preview-dashboard-viewer.service")
    restart_idx = text.index(_RESTART_LINE)
    assert enable_idx < restart_idx, "enable must happen before the restart"


def test_install_sh_verifies_units_after_restart() -> None:
    """H2: after restarting, install.sh must confirm each unit is current
    (no pending daemon-reload) and active, not just fire-and-forget."""
    text = INSTALL_SH.read_text()
    restart_idx = text.index(_RESTART_LINE)
    verify_idx = text.index("NeedDaemonReload")
    assert restart_idx < verify_idx
    assert "systemctl is-active --quiet" in text
    assert "exit 1" in text[verify_idx : text.index("report", verify_idx)]


def test_install_sh_runs_check_sh_at_the_end() -> None:
    """M2: a completed (re-)install is confirmed live, not just statically
    checked (docs/security.md C1/C14/C20/C28 rows)."""
    text = INSTALL_SH.read_text()
    assert '"$SCRIPT_DIR/check.sh"' in text
    check_idx = text.index('"$SCRIPT_DIR/check.sh"')
    restart_idx = text.index(_RESTART_LINE)
    assert restart_idx < check_idx, "check.sh must run only after the services are (re)started"


# --- M1 (unit 12 audit): sync must delete files removed from the source ------------


def test_install_sh_sync_uses_a_fresh_temp_dir_and_deletes_removed_files() -> None:
    """A plain `tar -x`/`cp` over an existing tree only ever adds/updates
    files; re-running install.sh after a file was removed from the repo
    must remove it from /opt too. `rsync -a --delete` is what makes that
    true, and the fresh temp dir means the git-checkout and non-git-checkout
    code paths both land in the same second, deleting rsync step."""
    text = INSTALL_SH.read_text()
    sync_start = text.index("sync $REPO_ROOT -> $OPT_DIR")
    sync_section = text[sync_start : text.index("uv sync --frozen", sync_start)]
    assert "mktemp -d" in sync_section
    assert "rsync -a --delete" in sync_section
    assert "chmod -R go-w" in sync_section


def test_install_sh_sync_keeps_production_files_excludes_dev_only_trees() -> None:
    text = INSTALL_SH.read_text()
    sync_start = text.index("mktemp -d")
    sync_section = text[sync_start : text.index("uv sync --frozen", sync_start)]
    for excluded in (".venv/", ".claude/", "tests/", "HANDOFF.md", ".github/"):
        assert f"--exclude='{excluded}'" in sync_section, f"{excluded} should be excluded from /opt"
    # Never excluded: these are needed to run in production.
    for kept in ("src/", "deploy/", "docs/", "pyproject.toml", "uv.lock"):
        assert f"--exclude='{kept}'" not in sync_section


# --- nftables rule -------------------------------------------------------------------


def test_nft_rule_shape() -> None:
    text = NFT_FILE.read_text()
    assert "table inet preview_dashboard" in text
    assert "hook output" in text
    assert 'oif "lo"' in text
    assert "dport { 8787, 8788 }" in text
    assert "ct state new" in text
    assert "meta skuid 0 accept" in text
    assert "reject" in text
    # established/related traffic isn't re-checked per packet.
    assert "ct state established,related accept" in text


def test_nft_rule_gates_local_selfconnect_to_the_tailnet_ports() -> None:
    """Unit 12 audit, High 1: `tailscale serve` self-attributes a local
    connection to this host's own tailnet address as the owner, so the
    loopback-only rule above isn't enough — a second rule pair must gate new
    connections to `fib daddr type local` on 443/8443 the same way."""
    text = NFT_FILE.read_text()
    assert "fib daddr type local" in text
    assert "dport { 443, 8443 }" in text
    # Both the fib-local accept and its matching reject exist, each scoped
    # to `ct state new` and `meta skuid 0`, same shape as the loopback rule.
    fib_lines = [
        line
        for line in text.splitlines()
        if "fib daddr type local" in line and "dport { 443, 8443 }" in line
    ]
    assert any("ct state new" in line and "meta skuid 0 accept" in line for line in fib_lines)
    assert any("ct state new" in line and "reject" in line for line in fib_lines)


def test_nft_rule_orders_local_selfconnect_rule_after_loopback_rule() -> None:
    """The two accept/reject pairs must appear loopback-rule first, in the
    same `output` chain — first match wins in nftables, and ordering them
    this way keeps the (unmodified) loopback rule's own established/related
    fast path meaningful for both port sets without repeating it."""
    text = NFT_FILE.read_text()
    loopback = 'oif "lo" tcp dport { 8787, 8788 } ct state new'
    fib = "fib daddr type local tcp dport { 443, 8443 } ct state new"
    loopback_accept = text.index(f"{loopback} meta skuid 0 accept")
    loopback_reject = text.index(f"{loopback} reject")
    fib_accept = text.index(f"{fib} meta skuid 0 accept")
    fib_reject = text.index(f"{fib} reject")
    assert loopback_accept < loopback_reject < fib_accept < fib_reject


@pytest.mark.skipif(NFT is None, reason="nft not installed")
def test_nft_file_parses_with_nft_check_mode() -> None:
    """`nft -c` only parses/validates syntax; it never loads the ruleset."""
    assert NFT is not None  # guaranteed by the skipif above; narrows for mypy
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [NFT, "-c", "-f", str(NFT_FILE)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


# --- notifier egress (C38, N5): the base file is inert; install.sh substitutes -------


def test_nft_file_has_the_inert_notifier_marker() -> None:
    """A plain `#` comment (no-op for `nft -f`) so a host without the
    notifier loads exactly this table -- install.sh substitutes it only
    when --telegram-chat-id was given (ADR 0023)."""
    text = NFT_FILE.read_text()
    assert "# __PDASH_NOTIFIER_EGRESS__" in text


def test_install_sh_substitutes_the_notifier_marker_with_a_numeric_uid() -> None:
    """The rule must never reference a bare username: `nft -f` resolves
    usernames at *load* time, which would fail the whole table on a host
    where pdash-notify doesn't exist yet."""
    text = INSTALL_SH.read_text()
    assert "__PDASH_NOTIFIER_EGRESS__" in text
    assert 'id -u "$NOTIFY_USER"' in text
    assert '"$NOTIFY_UID" =~ ^[0-9]+$' in text  # numeric, or the install stops
    assert 'NOTIFY_EGRESS_TEMPLATE="$SCRIPT_DIR/nftables/notifier-egress.nft.in"' in text
    assert "gsub(/@NOTIFY_UID@/, uid, line)" in text
    assert "if (line ~ /^#/) continue" in text  # the template's own header


def render_notifier_nft(uid: str) -> str:
    """What install.sh's awk step writes: header dropped, uid substituted, spliced."""
    rules = [
        line.replace("@NOTIFY_UID@", uid)
        for line in NOTIFY_EGRESS_TEMPLATE.read_text().splitlines()
        if not line.startswith("#")
    ]
    out: list[str] = []
    for line in NFT_FILE.read_text().splitlines():
        out.extend(rules if "# __PDASH_NOTIFIER_EGRESS__" in line else [line])
    return "\n".join(out) + "\n"


def test_install_sh_awk_splice_matches_the_reference_rendering() -> None:
    """Runs install.sh's own awk program (cut out of the script) so the
    reference rendering the other tests use can't drift from it."""
    awk = shutil.which("awk")
    assert awk is not None, "awk is required by install.sh itself"
    text = INSTALL_SH.read_text()
    opener = 'awk -v uid="$NOTIFY_UID" -v tpl="$NOTIFY_EGRESS_TEMPLATE" \''
    start = text.index(opener) + len(opener)
    program = text[start : text.index('\' "$SCRIPT_DIR/nftables/preview-dashboard.nft"', start)]
    generated = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which
        [awk, "-v", "uid=4242", "-v", f"tpl={NOTIFY_EGRESS_TEMPLATE}", program, str(NFT_FILE)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    assert generated == render_notifier_nft("4242")


def _deploy_copy(tmp_path: Path) -> Path:
    """A throwaway copy of `deploy/` a test can corrupt without touching the repo."""
    copy = tmp_path / "deploy_copy"
    shutil.copytree(DEPLOY_DIR, copy)
    return copy


def test_install_sh_refuses_when_the_egress_template_is_unreadable(tmp_path: Path) -> None:
    """F-C item 1: `[[ -r ]]` guards the splice -- a missing/unreadable
    template must stop the install, not silently ship a table without
    pdash-notify's egress rules (C38)."""
    deploy_copy = _deploy_copy(tmp_path)
    (deploy_copy / "nftables" / "notifier-egress.nft.in").unlink()
    result = run_install_dry_run(
        tmp_path / "prefix", *_TELEGRAM_ARGS, install_sh=deploy_copy / "install.sh"
    )
    assert result.returncode != 0
    assert "notifier-egress.nft.in" in result.stdout + result.stderr


def test_install_sh_refuses_when_the_egress_template_splices_no_rules(tmp_path: Path) -> None:
    """F-C item 1: the awk splice itself exits 1 (through `pipefail`) if the
    template is readable but yields zero rule lines, e.g. truncated to only
    its comment header."""
    deploy_copy = _deploy_copy(tmp_path)
    (deploy_copy / "nftables" / "notifier-egress.nft.in").write_text("# only a header\n")
    result = run_install_dry_run(
        tmp_path / "prefix", *_TELEGRAM_ARGS, install_sh=deploy_copy / "install.sh"
    )
    assert result.returncode != 0
    assert "no notifier egress rules spliced" in result.stdout + result.stderr


def _egress_rules(uid: str) -> list[str]:
    return [
        line.strip()
        for line in render_notifier_nft(uid).splitlines()
        if line.strip().startswith(f"meta skuid {uid} ")
    ]


def test_notifier_egress_template_uses_only_the_uid_placeholder() -> None:
    text = NOTIFY_EGRESS_TEMPLATE.read_text()
    assert "pdash-notify " not in text.replace("pdash-notify's", "")  # never a username
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            assert line.strip().startswith("meta skuid @NOTIFY_UID@ "), line


def test_notifier_egress_order_dns_then_private_refusals_then_443() -> None:
    """C38 + S-B L2: first match wins, so loopback DNS is accepted first,
    then tailnet/private/loopback/link-local/ULA destinations are refused,
    and only then is TCP 443 accepted; everything else is rejected."""
    rules = _egress_rules("4242")

    def index_of(*needles: str) -> int:
        return next(i for i, rule in enumerate(rules) if all(n in rule for n in needles))

    dns_udp = index_of("127.0.0.0/8 udp dport 53", "accept")
    dns_tcp = index_of("127.0.0.0/8 tcp dport 53", "accept")
    tailnet4 = index_of("100.64.0.0/10", "reject")
    tailnet6 = index_of("fd7a:115c:a1e0::/48", "reject")
    private4 = index_of("10.0.0.0/8", "reject")
    private6 = index_of("fc00::/7", "reject")
    https = index_of("tcp dport 443", "accept")
    assert max(dns_udp, dns_tcp) < min(tailnet4, tailnet6, private4, private6)
    assert max(tailnet4, tailnet6, private4, private6) < https
    assert rules[-1] == "meta skuid 4242 ct state new reject"
    assert https == len(rules) - 2
    for cidr in (
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fe80::/10",
        "::/127",
    ):
        assert cidr in rules[private4] or cidr in rules[private6], cidr
    # The only accepts are DNS to loopback and 443.
    accepts = [r for r in rules if r.endswith("accept")]
    assert len(accepts) == 3


@pytest.mark.skipif(NFT is None, reason="nft not installed")
def test_nft_file_with_notifier_rules_substituted_parses() -> None:
    """Reproduces install.sh's own splice and checks the result with `nft -c`
    (never loaded) -- the shape a notifier install actually writes to
    /etc/preview-dashboard/preview-dashboard.nft."""
    assert NFT is not None  # guaranteed by the skipif above; narrows for mypy
    generated = render_notifier_nft("4242")
    assert "@NOTIFY_UID@" not in generated
    assert "meta skuid 4242 tcp dport 443 ct state new accept" in generated
    assert "meta skuid 4242 ct state new reject" in generated
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [NFT, "-c", "-f", "-"],
        input=generated,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


# --- tailscale artifacts ---------------------------------------------------------------


def test_acl_snippet_is_valid_json_and_scopes_to_the_owner() -> None:
    data = json.loads(ACL_SNIPPET.read_text())
    assert "tagOwners" in data
    assert "tag:pdash" in data["tagOwners"]
    (grant,) = data["grants"]
    assert grant["dst"] == ["tag:pdash"]
    assert set(grant["ip"]) == {"443", "8443"}
    # Placeholder, not a real login: install docs must tell the operator to
    # replace it, and it must not look like a real value that got left in.
    assert grant["src"] == ["OWNER_LOGIN"]


def test_acl_snippet_warns_grants_are_additive_and_tests_the_denial() -> None:
    # setup-1: a merged grant alone leaves a default allow-all in force.
    data = json.loads(ACL_SNIPPET.read_text())
    note = " ".join(data["//"])
    assert "ADDITIVE" in note
    assert '"src":["*"],"dst":["*"]' in note  # names the rule to remove
    assert "nodeAttrs" in note and "funnel" in note
    ports = ["tag:pdash:443", "tag:pdash:8443"]
    assert {"src": "OWNER_LOGIN", "accept": ports} in data["tests"]
    assert {"src": "OTHER_LOGIN", "deny": ports} in data["tests"]


def test_setup_doc_covers_the_acl_and_secret_handling() -> None:
    text = (DEPLOY_DIR.parent / "docs" / "setup.md").read_text()
    assert "additive" in text and "allow-all" in text  # setup-1
    assert "non-owner" in text
    assert "shred -u" in text  # setup-2
    assert "notify_owner_chat_id" in text and "notify test" in text  # setup-3
    assert "--claude-bin" in text  # setup-4
    assert "scrollback" in text and "screenshot" in text  # setup-5
    assert "allowed_hosts" in text  # setup-7


def test_serve_sh_targets_both_origins_and_checks_funnel() -> None:
    text = SERVE_SH.read_text()
    assert "--https=443 http://127.0.0.1:8787" in text
    assert "--https=8443 http://127.0.0.1:8788" in text
    assert "funnel" in text.lower()


def test_serve_sh_does_not_hang_when_serve_is_not_enabled() -> None:
    """Deploy follow-up: `tailscale serve` must be run under a timeout, with
    its output inspected, instead of a bare call that can hang forever."""
    text = SERVE_SH.read_text()
    assert "timeout " in text
    run_serve_calls = [line for line in text.splitlines() if line.startswith("run_serve ")]
    assert len(run_serve_calls) == 2  # dashboard (443) and preview (8443) targets
    assert "not enabled" in text.lower()


# --- shell script syntax / dry-run behavior --------------------------------------------


@pytest.mark.parametrize("script", [INSTALL_SH, UNINSTALL_SH, SERVE_SH, CHECK_SH, WIZARD_SH])
def test_shell_scripts_pass_bash_syntax_check(script: Path) -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, "-n", str(script)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("script", [INSTALL_SH, UNINSTALL_SH, SERVE_SH, CHECK_SH, WIZARD_SH])
def test_shell_scripts_use_strict_mode(script: Path) -> None:
    first_directive = next(
        line for line in script.read_text().splitlines() if line.strip().startswith("set ")
    )
    assert first_directive.strip() == "set -euo pipefail"


@pytest.mark.skipif(SHELLCHECK is None, reason="shellcheck not installed")
@pytest.mark.parametrize("script", [INSTALL_SH, UNINSTALL_SH, SERVE_SH, CHECK_SH, WIZARD_SH])
def test_shellcheck(script: Path) -> None:
    assert SHELLCHECK is not None  # guaranteed by the skipif above
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [SHELLCHECK, str(script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_install_sh_dry_run_requires_no_root_and_prints_every_action() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [
            BASH,
            str(INSTALL_SH),
            "--dry-run",
            "--owner-login",
            "owner@example.com",
            "--host",
            "example.tailnet.ts.net",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for expected in (
        "pdash-admin",
        "pdash-viewer",
        "install -d -m 0750",
        "/var/lib/preview-dashboard",
        "check-config --token-group admin=pdash",
        "migrate",
        "--trusted-sidecar-uid",
        "viewer-uid.env",
        "systemctl daemon-reload",
        "systemctl enable preview-dashboard-firewall.service",
        "systemctl enable preview-dashboard-admin.service",
        "systemctl enable preview-dashboard-viewer.service",
        "systemctl enable --now preview-dashboard-purge.timer",
        _RESTART_LINE,
        "NeedDaemonReload",
        "deploy/check.sh --config",
    ):
        assert expected in out, f"dry-run output missing {expected!r}"
    # Host-dependent: on a host where the accounts already exist (re-install),
    # the script reports that instead of creating them.
    assert "groupadd --system pdash" in out or "group pdash already exists" in out
    assert ("gen-token --out" in out and "--group pdash" in out) or (
        "admin.token already exists" in out
    )
    for user in ("pdash-admin", "pdash-viewer"):
        assert "useradd" in out or f"user {user} already exists" in out
    # Nothing should have been touched for real.
    assert not Path("/opt/preview-dashboard-does-not-exist-marker").exists()


def test_install_sh_dry_run_requires_owner_login_and_host() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(INSTALL_SH), "--dry-run"], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 2
    assert "--owner-login" in result.stderr


# --- notifier install flags (N5) ------------------------------------------------------

_TELEGRAM_ARGS = [
    "--telegram-chat-id",
    "123456789",
    "--telegram-token-file",
    "/etc/hostname",  # any readable file; content is never inspected by --dry-run
]


_SETFACL_STUB = shutil.which("true")  # any executable: only `command -v` probes it
# `false` ignores its args and always exits 1: id_exists/group_exists then
# report "not found" for every name, so install.sh always takes the fresh-
# install branch regardless of *this host's* real accounts (e.g. a
# live-deployed pdash/pdash-notify) -- G3, backlog.md.
_NOT_FOUND_STUB = shutil.which("false")


def run_install_dry_run(
    prefix: Path,
    *extra: str,
    setfacl: str | None = _SETFACL_STUB,
    install_sh: Path = INSTALL_SH,
    getent: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """`install.sh --dry-run` isolated under PDASH_PREFIX=`prefix`.

    `setfacl` is what the preflight looks for (PDASH_SETFACL_BIN); the
    notifier helper runs under this interpreter (PDASH_PYTHON_BIN); user/group
    existence (PDASH_ID_BIN/PDASH_GETENT_BIN) is forced to "nothing exists
    yet" so output never depends on this host's real accounts.
    `install_sh` lets a test run a modified copy of the script/its deploy/
    directory (e.g. a corrupted `nftables/notifier-egress.nft.in`) without
    ever touching the real one.
    """
    assert BASH is not None
    assert _NOT_FOUND_STUB is not None
    env = {
        **os.environ,
        "PDASH_PREFIX": str(prefix),
        "PDASH_SETFACL_BIN": setfacl or "/nonexistent/setfacl",
        "PDASH_PYTHON_BIN": sys.executable,
        "PDASH_ID_BIN": _NOT_FOUND_STUB,
        "PDASH_GETENT_BIN": getent or _NOT_FOUND_STUB,
    }
    return subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [
            BASH,
            str(install_sh),
            "--dry-run",
            "--owner-login",
            "o@e.com",
            "--host",
            "h.ts.net",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )


def _actions(out: str) -> list[str]:
    return [line for line in out.splitlines() if line.startswith("+ ")]


def _prefix_file(prefix: Path, rel: str, content: str) -> Path:
    path = prefix / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_install_sh_dry_run_without_telegram_flags_never_mentions_the_notifier(
    tmp_path: Path,
) -> None:
    """The default path (no notifier on the host, no --telegram-chat-id)
    must stay exactly what it was before N5 -- the notifier is optional.

    PDASH_ID_BIN/PDASH_GETENT_BIN (run_install_dry_run) force "pdash-notify
    doesn't exist" so this holds regardless of whether it's real on this host.
    """
    result = run_install_dry_run(tmp_path, setfacl=None)  # no setfacl needed either
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for absent in (
        "pdash-notify",
        "pdash-notifytok",
        "notifier.token",
        "telegram.token",
        "preview-dashboard-notifier",
        "notifier egress",
    ):
        assert absent not in out, f"{absent!r} should not appear without the notifier"


def test_install_sh_dry_run_with_telegram_flags_installs_the_notifier(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, *_TELEGRAM_ARGS)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    etc = f"{tmp_path}/etc/preview-dashboard"
    for expected in (
        "-G pdash-notifytok",
        "usermod -aG pdash-notifytok pdash-admin",
        f"gen-token --out {etc}/notifier.token --group pdash-notifytok",
        "install -m 0640 -o root -g pdash-notify /etc/hostname",
        f"write {etc}/notifier-admin.env",
        "notifier egress rules (C38)",
        "preview-dashboard-notifier.service",
        "systemctl enable preview-dashboard-notifier.service",
        "systemctl restart preview-dashboard-notifier",
        "systemctl is-active --quiet preview-dashboard-notifier.service",
        # pair runs as root: telegram.token's group is trusted for that file only.
        "notify pair --token-group telegram=pdash-notify",
    ):
        assert expected in out, f"dry-run output (--telegram-chat-id) missing {expected!r}"
    # PDASH_ID_BIN/PDASH_GETENT_BIN (run_install_dry_run) force "doesn't exist
    # yet" so this is deterministic, regardless of this host's real accounts.
    assert "groupadd --system pdash-notifytok" in out
    assert "useradd --system --no-create-home --user-group" in out
    # Fresh config (none under the prefix): written from the template.
    assert f"write {etc}/config.toml" in out


def test_install_sh_check_config_trusts_the_notifier_token_group(tmp_path: Path) -> None:
    """H2 (S-B): check-config (run as root) loads notifier.token, which is
    root:pdash-notifytok -- that group must be trusted too."""
    result = run_install_dry_run(tmp_path, *_TELEGRAM_ARGS)
    assert result.returncode == 0, result.stderr
    assert (
        "check-config --token-group admin=pdash --token-group notifier=pdash-notifytok"
        in result.stdout
    )


@pytest.mark.parametrize("hook", ["PDASH_ID_BIN", "PDASH_GETENT_BIN", "PDASH_CGROUP_FILE"])
def test_install_sh_honours_account_hooks_only_with_dry_run(tmp_path: Path, hook: str) -> None:
    """A real install must never let a caller-chosen id/getent decide which accounts exist."""
    assert BASH is not None
    assert _NOT_FOUND_STUB is not None
    # Safety net: a stub `id` reports a non-root uid, so should the hook check
    # ever regress the script stops at its root check (exit 1), never installs.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    fake_id = stub_dir / "id"
    fake_id.write_text("#!/bin/sh\necho 1000\n")
    fake_id.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "PDASH_PREFIX": str(tmp_path / "prefix"),
        "PDASH_UV_BIN": "/nonexistent/uv",
        hook: _NOT_FOUND_STUB,
    }
    args = [BASH, str(INSTALL_SH), "--owner-login", "o@e.com", "--host", "h.ts.net"]
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        args, capture_output=True, text=True, timeout=30, env=env, check=False
    )
    assert result.returncode == 2, result.stderr
    assert "only honoured with --dry-run" in result.stderr
    assert result.stdout == ""
    assert not (tmp_path / "prefix").exists()
    # With --dry-run the same hook is accepted (and still takes no action).
    dry = run_install_dry_run(tmp_path / "prefix")
    assert dry.returncode == 0, dry.stderr


def test_install_sh_rerun_without_flags_keeps_the_notifier(tmp_path: Path) -> None:
    """M2 (S-B): host state (the installed unit file) decides, not the flag:
    a plain re-run keeps the egress block, the env file, both token groups
    and the unit -- and, with notify_enabled off, leaves it disabled."""
    _prefix_file(tmp_path, "etc/systemd/system/preview-dashboard-notifier.service", "[Unit]\n")
    result = run_install_dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    etc = f"{tmp_path}/etc/preview-dashboard"
    for expected in (
        f"write {etc}/notifier-admin.env",
        "notifier egress rules (C38)",
        "check-config --token-group admin=pdash --token-group notifier=pdash-notifytok",
        f"{tmp_path}/etc/systemd/system/preview-dashboard-notifier.service",
        "systemctl disable --now preview-dashboard-notifier.service",
    ):
        assert expected in out, f"re-run output missing {expected!r}"
    assert "systemctl restart preview-dashboard-notifier" not in out


def test_install_sh_rerun_without_flags_restarts_an_enabled_notifier(tmp_path: Path) -> None:
    _prefix_file(tmp_path, "etc/systemd/system/preview-dashboard-notifier.service", "[Unit]\n")
    _prefix_file(
        tmp_path,
        "etc/preview-dashboard/config.toml",
        'owner_login = "o@e.com"\nnotify_enabled = true\nnotify_owner_chat_id = 5\n',
    )
    _prefix_file(tmp_path, "etc/preview-dashboard/telegram.token", "placeholder\n")
    result = run_install_dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "systemctl enable preview-dashboard-notifier.service" in out
    assert "systemctl restart preview-dashboard-notifier" in out
    assert "telegram.token already exists" in out
    assert "+ edit " not in out  # no flag: config.toml is never touched


def test_install_sh_enabled_notifier_without_bot_token_is_not_started(tmp_path: Path) -> None:
    _prefix_file(tmp_path, "etc/systemd/system/preview-dashboard-notifier.service", "[Unit]\n")
    _prefix_file(
        tmp_path,
        "etc/preview-dashboard/config.toml",
        "notify_enabled = true\nnotify_owner_chat_id = 5\n",
    )
    result = run_install_dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "notifier enabled but not started" in result.stdout
    assert "systemctl restart preview-dashboard-notifier" not in result.stdout


def test_install_sh_removes_a_stale_notifier_env_file(tmp_path: Path) -> None:
    """No notifier on the host (e.g. after `uninstall.sh --purge-users`): a
    leftover env file naming a deleted uid/group would break serve-admin.

    PDASH_ID_BIN (run_install_dry_run) forces "pdash-notify doesn't exist"
    so this holds regardless of whether it's real on this host.
    """
    env_file = _prefix_file(tmp_path, "etc/preview-dashboard/notifier-admin.env", "X=1\n")
    result = run_install_dry_run(tmp_path, setfacl=None)
    assert result.returncode == 0, result.stderr
    assert f"+ rm -f {env_file}" in result.stdout


@pytest.mark.parametrize("state", ["flag", "unit-file"])
def test_install_sh_refuses_the_notifier_without_setfacl(tmp_path: Path, state: str) -> None:
    """M3 (S-B): no setfacl -> refuse before any action, name the package,
    install nothing itself."""
    extra: tuple[str, ...] = ()
    if state == "flag":
        extra = tuple(_TELEGRAM_ARGS)
    else:
        _prefix_file(tmp_path, "etc/systemd/system/preview-dashboard-notifier.service", "")
    result = run_install_dry_run(tmp_path, *extra, setfacl=None)
    assert result.returncode == 1
    assert "apt install acl" in result.stderr
    assert _actions(result.stdout) == []


def test_install_sh_never_installs_packages() -> None:
    """Installing packages (acl) stays an explicit owner step (§5.6)."""
    for line in INSTALL_SH.read_text().splitlines():
        assert not re.match(r"^\s*(run\s+)?(apt|apt-get|dpkg|snap)\s", line), line


def test_install_sh_adds_notifier_keys_to_an_existing_config(tmp_path: Path) -> None:
    """§5.6: an existing config.toml gets the two keys (dry-run: only shown)."""
    original = 'owner_login = "o@e.com"\nallowed_hosts = ["h.ts.net"]\n'
    config = _prefix_file(tmp_path, "etc/preview-dashboard/config.toml", original)
    result = run_install_dry_run(tmp_path, *_TELEGRAM_ARGS)
    assert result.returncode == 0, result.stderr
    assert f"+ edit {config}: add notify_enabled = true" in result.stdout
    assert f"+ edit {config}: add notify_owner_chat_id = 123456789" in result.stdout
    assert config.read_text() == original  # dry-run


def test_install_sh_refuses_a_conflicting_chat_id_before_any_action(tmp_path: Path) -> None:
    config = _prefix_file(
        tmp_path,
        "etc/preview-dashboard/config.toml",
        "notify_enabled = true\nnotify_owner_chat_id = 42\n",
    )
    result = run_install_dry_run(tmp_path, *_TELEGRAM_ARGS)
    assert result.returncode == 2
    assert "notify_owner_chat_id = 42" in result.stderr
    assert _actions(result.stdout) == []
    assert "42" in config.read_text()


@pytest.mark.parametrize("bad", ["0", "0123", "-5", "12a"])
def test_install_sh_rejects_malformed_chat_ids(tmp_path: Path, bad: str) -> None:
    result = run_install_dry_run(tmp_path, "--telegram-chat-id", bad)
    assert result.returncode == 2
    assert "--telegram-chat-id" in result.stderr


def test_install_sh_rejects_non_numeric_telegram_chat_id() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [
            BASH,
            str(INSTALL_SH),
            "--dry-run",
            "--owner-login",
            "o@e.com",
            "--host",
            "h.ts.net",
            "--telegram-chat-id",
            "not-a-number",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "--telegram-chat-id" in result.stderr


def test_install_sh_rejects_telegram_token_file_without_chat_id() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [
            BASH,
            str(INSTALL_SH),
            "--dry-run",
            "--owner-login",
            "o@e.com",
            "--host",
            "h.ts.net",
            "--telegram-token-file",
            "/etc/hostname",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "--telegram-token-file" in result.stderr


def test_uninstall_sh_dry_run_keeps_data_without_purge_flags() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(UNINSTALL_SH), "--dry-run"], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    assert "keeping data" in result.stdout
    assert "keeping users" in result.stdout
    assert "rm -rf /var/lib/preview-dashboard" not in result.stdout


def test_uninstall_sh_dry_run_purge_data_removes_var_and_etc() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(UNINSTALL_SH), "--dry-run", "--purge-data"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "rm -rf /var/lib/preview-dashboard" in result.stdout
    assert "rm -rf /etc/preview-dashboard" in result.stdout


def test_uninstall_sh_stops_and_removes_the_notifier_unconditionally() -> None:
    """Safe even when the notifier was never installed (systemctl calls are
    `|| true`, rm -f is idempotent) -- no flag needed to remove it."""
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(UNINSTALL_SH), "--dry-run"], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    assert "preview-dashboard-notifier.service" in result.stdout


def test_uninstall_sh_purge_users_removes_notifier_account_and_group() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(UNINSTALL_SH), "--dry-run", "--purge-users"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "userdel pdash-notify" in result.stdout
    assert "groupdel pdash-notifytok" in result.stdout


# --- systemd-analyze verify (real, available on this host) ---------------------------


@pytest.mark.skipif(SYSTEMD_ANALYZE is None, reason="systemd-analyze not present")
def test_systemd_analyze_verify(tmp_path: Path) -> None:
    """Structural validation only; the venv binary and service users don't
    exist on the test host, so filter exactly those two expected complaints.
    """
    assert SYSTEMD_ANALYZE is not None  # guaranteed by the skipif above
    for unit_path in ALL_SYSTEMD_FILES:
        shutil.copy(unit_path, tmp_path / unit_path.name)
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [SYSTEMD_ANALYZE, "verify", *(str(tmp_path / p.name) for p in ALL_SYSTEMD_FILES)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    allowed_substrings = (
        "is not executable",  # the venv binary isn't installed on this host
        "Failed to resolve user",  # pdash-admin/pdash-viewer don't exist on this host
        "Failed to resolve group",
    )
    offending = [
        line
        for line in result.stderr.splitlines()
        if line.strip() and not any(s in line for s in allowed_substrings)
    ]
    assert not offending, f"unexpected systemd-analyze verify output:\n{result.stderr}"


# --- config.example.toml -------------------------------------------------------------


def test_config_example_documents_every_settings_field() -> None:
    text = CONFIG_EXAMPLE.read_text()
    data = tomllib.loads(text)
    # A field whose default is None can't be written in TOML: it is documented
    # as a commented-out example line (`# name = ...`) instead.
    commented = {
        name
        for name, field in Settings.model_fields.items()
        if field.default is None and f"\n# {name} = " in text
    }
    documented = set(data.keys()) | commented
    expected = set(Settings.model_fields.keys())
    missing = expected - documented
    assert not missing, f"config.example.toml is missing fields: {missing}"
    unexpected = documented - expected
    assert not unexpected, f"config.example.toml has unknown fields: {unexpected}"


def test_config_example_every_field_has_a_comment_above_it() -> None:
    lines = CONFIG_EXAMPLE.read_text().splitlines()
    for i, line in enumerate(lines):
        if "=" not in line or line.strip().startswith("#"):
            continue
        key = line.split("=", 1)[0].strip()
        if key not in Settings.model_fields:
            continue
        # At least one of the few lines immediately above is a comment.
        window = lines[max(0, i - 3) : i]
        assert any(w.strip().startswith("#") for w in window), f"{key} is undocumented"


def test_config_example_is_a_valid_settings_override() -> None:
    """Every value in the template must be acceptable to `Settings` directly
    (constructor kwargs bypass the TOML file source but hit the same field
    validators TomlConfigSettingsSource output would)."""
    settings = Settings(**tomllib.loads(CONFIG_EXAMPLE.read_text()))
    assert settings.data_dir == Path("/var/lib/preview-dashboard")
    assert settings.intake_allowed_roots == (Path("/root/outbox"),)


# --- loopback firewall unit (C14) ----------------------------------------------------


def test_nft_file_replaces_only_its_own_table_atomically() -> None:
    """`nft -f` appends rules, so the file must declare+delete+redefine its
    own table (idempotent reloads) and must never flush the whole ruleset
    (that would wipe tailscaled's rules)."""
    text = NFT_FILE.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "flush ruleset" not in code
    declare = code.index("table inet preview_dashboard\n")
    delete = code.index("delete table inet preview_dashboard")
    define = code.index("table inet preview_dashboard {")
    assert declare < delete < define


def test_firewall_unit_loads_only_its_table_and_viewer_requires_it() -> None:
    fw = parse_unit(FIREWALL_UNIT)
    assert fw[("Service", "Type")] == ["oneshot"]
    assert fw[("Service", "RemainAfterExit")] == ["yes"]
    assert fw[("Service", "ExecStart")] == [
        "/usr/sbin/nft -f /etc/preview-dashboard/preview-dashboard.nft"
    ]
    # Leading "-": a later `flush ruleset` elsewhere (nftables.service, ufw,
    # firewalld) can remove this table out from under the unit; ExecStop
    # must not fail on that no-op (docs/operations.md "Network exposure").
    assert fw[("Service", "ExecStop")] == ["-/usr/sbin/nft delete table inet preview_dashboard"]
    viewer = parse_unit(VIEWER_UNIT)
    assert "preview-dashboard-firewall.service" in viewer[("Unit", "Requires")][0]
    assert "preview-dashboard-firewall.service" in viewer[("Unit", "After")][0]


def test_firewall_unit_documents_a_manual_health_check() -> None:
    """No ExecStartPre= health check (ExecStart already fails closed); the
    unit instead documents how to check the table by hand."""
    assert ("Service", "ExecStartPre") not in parse_unit(FIREWALL_UNIT)
    text = FIREWALL_UNIT.read_text()
    assert "nft list table inet preview_dashboard" in text


def test_install_never_touches_system_nftables() -> None:
    """Ubuntu's /etc/nftables.conf starts with `flush ruleset`; enabling
    nftables.service would wipe tailscaled's rules at every boot."""
    for script in (DEPLOY_DIR / "install.sh", DEPLOY_DIR / "uninstall.sh"):
        code = "\n".join(
            line for line in script.read_text().splitlines() if not line.lstrip().startswith("#")
        )
        assert "nftables.service" not in code
        assert "nftables.conf" not in code


def test_install_creates_etc_dir_before_writing_into_it() -> None:
    """Regression: admin-uid.env was written before /etc/preview-dashboard existed."""
    assert BASH is not None
    out = subprocess.run(  # noqa: S603 - fixed argv, dry-run only
        [
            BASH,
            str(DEPLOY_DIR / "install.sh"),
            "--dry-run",
            "--owner-login",
            "owner@example.com",
            "--host",
            "x.ts.net",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    ).stdout
    mkdir = out.index("install -d -m 0755 -o root -g root /etc/preview-dashboard")
    write = out.index("write /etc/preview-dashboard/admin-uid.env")
    assert mkdir < write


# --- deploy/check.sh (M2, unit 12 audit): static coverage only -----------------------
# check.sh needs root, a real installed host, and a running systemd/nftables/tailscale
# to execute meaningfully (see the file's own docstring) — exactly like install.sh's
# real (non-dry-run) path, it is never *run* by this test suite. These tests only
# confirm, statically, that every required check (docs/security.md C1/C14/C20/C28,
# unit-12 backlog M2) is actually present in the script.


def test_check_sh_requires_root() -> None:
    text = CHECK_SH.read_text()
    assert '"$(id -u)" -ne 0' in text


def test_check_sh_covers_every_required_check() -> None:
    text = CHECK_SH.read_text()
    # nft table + tailscaled's own chains intact
    assert "nft list table inet preview_dashboard" in text
    assert "chain ts-input" in text
    # 'nobody' refused, both on loopback and on the self-tailnet https ports
    assert "runuser -u nobody" in text
    assert "127.0.0.1:8787" in text and "127.0.0.1:8788" in text
    assert "https://${host}/" in text and "https://${host}:8443/" in text
    # no-identity request -> 403
    assert '"$code" == "403"' in text
    # services active, current, and actually restarted since their unit file
    assert "NeedDaemonReload" in text
    assert "ActiveEnterTimestamp" in text
    assert "stat -c %Y" in text
    # viewer cannot read /root or the admin token, checked inside its own
    # mount namespace (not just "the file is group-unreadable from here")
    assert "nsenter --mount=" in text
    assert "pdash-viewer" in text
    assert "/etc/preview-dashboard/admin.token" in text
    assert "test -r /root" in text
    # systemd-analyze security <= 2.0
    assert "systemd-analyze security" in text
    assert '_SECURITY_THRESHOLD="2.0"' in text
    # funnel off
    assert "tailscale funnel status" in text
    # host comes from config.toml's allowed_hosts (via the real settings loader)
    assert "check-config --skip-token" in text
    assert "allowed_hosts" in text
    # exits non-zero on any failure
    assert "FAILURES" in text
    assert "exit 1" in text


def test_check_sh_covers_the_notifier_when_enabled() -> None:
    """docs/security.md C33/C34/C36/C38: notifier checks, but never printing
    a token (only owner/mode/nft/HTTP-status facts)."""
    text = CHECK_SH.read_text()
    assert "notify_enabled" in text
    assert "preview-dashboard-notifier.service" in text
    assert "pdash-notify" in text
    assert "telegram.token" in text and "notifier.token" in text
    assert "pdash-admin" in text  # can't read telegram.token
    assert "meta skuid $notify_uid tcp dport 443" in text
    assert "100\\.64\\.0\\.0/10" in text  # L2 refusal present and before the 443 accept
    assert "/v1/notifier/" in text


def test_check_sh_never_puts_a_token_on_argv() -> None:
    """M1 (S-B): tokens reach curl only on stdin (`-H @-`), fed by the
    printf builtin; read with the `read` builtin (no `head`/`cat` argv)."""
    text = CHECK_SH.read_text()
    assert 'IFS= read -r tok <"$token_file"' in text
    assert "printf 'Authorization: Bearer %s\\n' \"$tok\"" in text
    assert "-H @-" in text
    assert "unset tok" in text
    for line in text.splitlines():
        if "curl" in line:
            assert "Bearer" not in line and "$tok" not in line, line
    assert "head -n1 /etc/preview-dashboard/admin.token" not in text


def test_check_sh_probes_token_scope_from_each_family_allowed_uid() -> None:
    """M1 (S-B): the notifier token is probed on an admin route as root (so
    the peer-uid policy passes and only the token scope can refuse), with a
    control on each family. S-C/F-C item 2: the admin token is never handed
    to a curl running as pdash-notify -- that direction (C33) is proven by
    tests/security/test_admin_notifier_routes.py::test_c33_* instead."""
    text = CHECK_SH.read_text()
    assert 'runuser -u "$user" -- curl' in text
    assert 'probe_admin_socket pdash-notify "$notify_tok_file" POST "$zero_task"' in text
    assert 'probe_admin_socket root "$notify_tok_file" GET /v1/health' in text
    assert 'probe_admin_socket root "$admin_tok_file" GET /v1/health' in text
    assert 'probe_admin_socket pdash-notify "$admin_tok_file"' not in text


def test_check_sh_verifies_the_notifier_can_reach_the_admin_socket() -> None:
    """M3 (S-B): the ACL grant is checked live, as the notifier's own user."""
    text = CHECK_SH.read_text()
    assert "runuser -u pdash-notify -- test -w /run/preview-dashboard/admin.sock" in text


def test_install_sh_restores_opt_dir_mode_after_sync() -> None:
    """Regression (first redeploy): `rsync -a <mktemp dir>/ /opt/...` copied
    mode 0700 onto /opt/preview-dashboard, so service users couldn't exec."""
    text = (DEPLOY_DIR / "install.sh").read_text()
    sync = text.index("rsync -a --delete")
    pin = text.index('chmod 0755 "$OPT_DIR"')
    assert sync < pin


# --- deploy/lib/notify_config.py (§5.6: idempotent notifier keys) -------------------


def test_notify_config_helper_has_a_header_docstring() -> None:
    first = NOTIFY_CONFIG_PY.read_text().splitlines()[0]
    assert first.startswith('"""deploy/lib/notify_config.py')


def run_notify_config(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter + a repo script, fixed args
        [sys.executable, str(NOTIFY_CONFIG_PY), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def _config(tmp_path: Path, text: str, mode: int = 0o640) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text)
    path.chmod(mode)
    return path


def test_notify_config_adds_both_keys_and_keeps_mode(tmp_path: Path) -> None:
    path = _config(tmp_path, 'owner_login = "o@e.com"\nallowed_hosts = ["h.ts.net"]')
    result = run_notify_config("ensure", str(path), "777")
    assert result.returncode == 0, result.stderr
    data = tomllib.loads(path.read_text())
    assert data == {
        "owner_login": "o@e.com",
        "allowed_hosts": ["h.ts.net"],
        "notify_enabled": True,
        "notify_owner_chat_id": 777,
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert "add notify_enabled = true" in result.stdout


def test_notify_config_is_idempotent(tmp_path: Path) -> None:
    path = _config(tmp_path, 'owner_login = "o@e.com"\n')
    assert run_notify_config("ensure", str(path), "777").returncode == 0
    once = path.read_text()
    again = run_notify_config("ensure", str(path), "777")
    assert again.returncode == 0
    assert path.read_text() == once
    assert "already enables the notifier" in again.stdout


def test_notify_config_flips_the_template_default_and_uncomments_nothing(tmp_path: Path) -> None:
    """A config installed from the N-era template: `notify_enabled = false`
    and a commented example chat id."""
    path = _config(tmp_path, CONFIG_EXAMPLE.read_text())
    result = run_notify_config("ensure", str(path), "777")
    assert result.returncode == 0, result.stderr
    text = path.read_text()
    assert "\nnotify_enabled = true\n" in text
    assert "notify_enabled = false" not in text
    assert "# notify_owner_chat_id = 123456789" in text  # the example stays a comment
    expected = {**tomllib.loads(CONFIG_EXAMPLE.read_text())}
    expected.update(notify_enabled=True, notify_owner_chat_id=777)
    assert tomllib.loads(text) == expected
    Settings(**tomllib.loads(text))  # still a valid Settings override


def test_notify_config_inserts_before_the_first_table(tmp_path: Path) -> None:
    path = _config(tmp_path, 'owner_login = "o"\n\n[extra]\nkey = 1\n')
    assert run_notify_config("ensure", str(path), "9").returncode == 0
    data = tomllib.loads(path.read_text())
    assert data["notify_enabled"] is True
    assert data["notify_owner_chat_id"] == 9
    assert data["extra"] == {"key": 1}


def test_notify_config_keeps_a_matching_chat_id_and_enables(tmp_path: Path) -> None:
    path = _config(tmp_path, "notify_enabled = false  # off for now\nnotify_owner_chat_id = 9\n")
    assert run_notify_config("ensure", str(path), "9").returncode == 0
    assert path.read_text() == "notify_enabled = true  # off for now\nnotify_owner_chat_id = 9\n"


def test_notify_config_refuses_a_different_chat_id(tmp_path: Path) -> None:
    original = "notify_enabled = true\nnotify_owner_chat_id = 42\n"
    path = _config(tmp_path, original)
    for command in ("check", "ensure"):
        result = run_notify_config(command, str(path), "9")
        assert result.returncode == 3
        assert "notify_owner_chat_id = 42" in result.stderr
    assert path.read_text() == original


@pytest.mark.parametrize(
    "text",
    [
        "notify_enabled = [\n",  # not TOML
        'notify_enabled = "yes"\n',  # wrong type
        "notify_owner_chat_id = true\n",  # bool is not a chat id
    ],
)
def test_notify_config_refuses_what_it_cannot_edit_safely(tmp_path: Path, text: str) -> None:
    path = _config(tmp_path, text)
    result = run_notify_config("ensure", str(path), "9")
    assert result.returncode == 1
    assert path.read_text() == text


def test_notify_config_refuses_a_symlink(tmp_path: Path) -> None:
    target = _config(tmp_path, 'owner_login = "o"\n')
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    result = run_notify_config("ensure", str(link), "9")
    assert result.returncode == 1
    assert "not a regular file" in result.stderr
    assert target.read_text() == 'owner_login = "o"\n'


def test_notify_config_dry_run_and_check_never_write(tmp_path: Path) -> None:
    original = 'owner_login = "o"\n'
    path = _config(tmp_path, original)
    dry = run_notify_config("ensure", str(path), "9", "--dry-run")
    assert dry.returncode == 0
    assert "add notify_owner_chat_id = 9" in dry.stdout
    check = run_notify_config("check", str(path), "9")
    assert check.returncode == 0
    assert check.stdout == ""
    assert path.read_text() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.toml"]  # no temp left


@pytest.mark.parametrize("bad", ["0", "-1", "x"])
def test_notify_config_rejects_bad_chat_ids(tmp_path: Path, bad: str) -> None:
    path = _config(tmp_path, "")
    assert run_notify_config("ensure", str(path), bad).returncode == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (None, "false"),
        ("", "false"),
        ("notify_enabled = false\n", "false"),
        ("notify_enabled = true\n", "true"),
    ],
)
def test_notify_config_enabled_query(tmp_path: Path, text: str | None, expected: str) -> None:
    path = tmp_path / "config.toml"
    if text is not None:
        path.write_text(text)
    result = run_notify_config("enabled", str(path))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (None, "false"),
        ("claudia_enabled = false\n", "false"),
        ('claudia_enabled = "true"\n', "false"),  # only a real TOML true counts
        ("notify_enabled = true\n", "false"),  # the other key never leaks in
        ("claudia_enabled = true\n", "true"),
    ],
)
def test_notify_config_claudia_enabled_query(
    tmp_path: Path, text: str | None, expected: str
) -> None:
    path = tmp_path / "config.toml"
    if text is not None:
        path.write_text(text)
    result = run_notify_config("enabled", str(path), "--key", "claudia_enabled")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


# --- Claudia companion (unit M9, ADR 0036; C45 C47 C49 C54 C57 C58) -------------------

_CLAUDIA_ADMIN_LINE = (
    "PDASH_CLAUDIA_ADMIN_ARGS=--claudia-peer-uid 0 "
    "--token-group claudia=pdash-claudiatok --token-group totp=pdash-totp"
)
_CLAUDIA_ENV = {"PDASH_CLAUDE_BIN": "/root/.local/bin/claude", "PDASH_KB_GID": "990"}
_UNSET_C49 = [
    "ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_USE_BEDROCK CLAUDE_CODE_USE_VERTEX"
]


def test_install_sh_writes_the_claudia_admin_env_line_the_simulation_uses() -> None:
    text = INSTALL_SH.read_text()
    assert (
        "printf 'PDASH_CLAUDIA_ADMIN_ARGS=--claudia-peer-uid 0 --token-group claudia=%s "
        "--token-group totp=%s\\n'" in text
    )
    assert 'CLAUDIA_TOK_GROUP="pdash-claudiatok"' in text
    assert 'TOTP_GROUP="pdash-totp"' in text


def test_c45_c47_admin_execstart_with_claudia_args_is_accepted() -> None:
    """Both optional env files present: one peer uid per family, each group
    scoped to its own file (claudia.token, totp.secret)."""
    key, _, value = _CLAUDIA_ADMIN_LINE.partition("=")
    env = {**_env_file_line("998"), key: value}
    (exec_start,) = parse_unit(ADMIN_UNIT)[("Service", "ExecStart")]
    argv = systemd_expand(exec_start, env)
    assert "" not in argv
    args = build_parser().parse_args(argv[1:])
    assert args.claudia_peer_uid == [0]
    assert args.notifier_peer_uid == [998]
    assert args.viewer_peer_uid == [997]
    assert args.token_group == [
        "admin=pdash",
        "viewer=pdash-viewtok",
        "notifier=pdash-notifytok",
        "claudia=pdash-claudiatok",
        "totp=pdash-totp",
    ]


def test_c58_host_unit_restarts_and_kills_the_whole_group() -> None:
    unit = parse_unit(CLAUDIA_HOST_UNIT)
    assert unit[("Service", "Restart")] == ["on-failure"]
    assert unit[("Service", "KillMode")] == ["control-group"]
    assert unit[("Install", "WantedBy")] == ["multi-user.target"]


def test_c58_host_unit_delegates_per_run_cgroups() -> None:
    """host-flow-5: runs get sibling cgroups of the `host` leaf; the host refuses without."""
    from preview_dashboard.adapters.claude_cli import HOST_SUBGROUP
    from preview_dashboard.interfaces.claudia.main import parse_args

    unit = parse_unit(CLAUDIA_HOST_UNIT)
    assert unit[("Service", "Delegate")] == ["yes"]
    assert unit[("Service", "DelegateSubgroup")] == [HOST_SUBGROUP]
    (exec_start,) = unit[("Service", "ExecStart")]
    assert parse_args(systemd_expand(exec_start, _CLAUDIA_ENV)[4:]).require_run_cgroups


def test_c49_host_and_gardener_unset_every_api_credential() -> None:
    for unit_path in (CLAUDIA_HOST_UNIT, GARDENER_UNIT):
        unit = parse_unit(unit_path)
        assert unit[("Service", "UnsetEnvironment")] == _UNSET_C49, unit_path.name
        # No unit ever *sets* one of them, in any form.
        text = unit_path.read_text()
        for var in _UNSET_C49[0].split():
            assert f"{var}=" not in text, f"{unit_path.name} sets {var}"
        assert unit[("Service", "Environment")] == ["HOME=/root"]


def test_c45_host_unit_identity_trusts_its_own_token_group() -> None:
    """Root (subscription login), egid = the claudia token's group: the only
    non-root group TokenLoader trusts for the process's own token."""
    unit = parse_unit(CLAUDIA_HOST_UNIT)
    assert unit[("Service", "User")] == ["root"]
    assert unit[("Service", "Group")] == ["pdash-claudiatok"]
    conditions = unit[("Unit", "ConditionPathExists")]
    for path in ("claudia.token", "claudia-settings.json", "claudia-mcp.json", "totp.secret"):
        assert f"/etc/preview-dashboard/{path}" in conditions
    assert "preview-dashboard-admin.service" in unit[("Unit", "Requires")][0]


def test_host_execstart_is_isolated_python_and_parses_on_the_host_cli() -> None:
    from preview_dashboard.interfaces.claudia.main import parse_args
    from preview_dashboard.interfaces.claudia.settings import HOST_SETTINGS_PATH

    (exec_start,) = parse_unit(CLAUDIA_HOST_UNIT)[("Service", "ExecStart")]
    argv = systemd_expand(exec_start, _CLAUDIA_ENV)
    assert argv[:4] == [
        "/opt/preview-dashboard/.venv/bin/python",
        "-I",
        "-m",
        "preview_dashboard.interfaces.claudia.main",
    ]
    config = parse_args(argv[4:])
    assert config.settings_file == HOST_SETTINGS_PATH
    assert config.mcp_config == Path("/etc/preview-dashboard/claudia-mcp.json")
    assert config.token_file == Path("/etc/preview-dashboard/claudia.token")
    assert config.claude_bin == Path("/root/.local/bin/claude")
    assert config.state_dir == Path("/var/lib/claudia-host")
    assert parse_unit(CLAUDIA_HOST_UNIT)[("Service", "EnvironmentFile")] == [
        "/etc/preview-dashboard/claudia.env"  # required: no "-"
    ]


def test_host_execstart_without_claude_bin_fails_closed() -> None:
    from preview_dashboard.interfaces.claudia.main import parse_args

    (exec_start,) = parse_unit(CLAUDIA_HOST_UNIT)[("Service", "ExecStart")]
    argv = systemd_expand(exec_start, {})
    with pytest.raises(SystemExit) as exc:
        parse_args(argv[4:])
    assert exc.value.code == 2


def test_host_unit_never_passes_a_bypass_flag() -> None:
    text = CLAUDIA_HOST_UNIT.read_text()
    for flag in ("dangerously", "bypassPermissions", "--channels", "--debug"):
        assert flag not in text


def test_c54_gardener_unit_is_confined_and_parses() -> None:
    from preview_dashboard.interfaces.claudia.gardener import parse_args

    unit = parse_unit(GARDENER_UNIT)
    assert unit[("Service", "Type")] == ["oneshot"]
    assert unit[("Service", "User")] == ["root"]
    assert unit[("Service", "Group")] == ["pdash-kb"]
    assert unit[("Service", "CapabilityBoundingSet")] == [""]
    assert unit[("Service", "ProtectSystem")] == ["strict"]
    assert unit[("Service", "ProtectHome")] == ["read-only"]
    rw = " ".join(unit[("Service", "ReadWritePaths")]).split()
    assert rw[0] == "/var/lib/claudia-kb"
    # Writes nothing of the dashboard: no data dir, no /etc, no project trees.
    assert all(p.lstrip("-").startswith(("/var/lib/claudia-kb", "/root/.c")) for p in rw)
    (exec_start,) = unit[("Service", "ExecStart")]
    argv = systemd_expand(exec_start, _CLAUDIA_ENV)
    assert argv[1:4] == ["-I", "-m", "preview_dashboard.interfaces.claudia.gardener"]
    args = parse_args(argv[4:])
    assert args.kb_root == Path("/var/lib/claudia-kb")
    assert args.viewer_gid == 990
    assert args.claude_bin == Path("/root/.local/bin/claude")
    with pytest.raises(SystemExit):
        parse_args(systemd_expand(exec_start, {})[4:])


def test_c54_gardener_timer_is_weekly_and_persistent() -> None:
    unit = parse_unit(GARDENER_TIMER)
    (calendar,) = unit[("Timer", "OnCalendar")]
    assert calendar.startswith("Sun ")
    assert unit[("Timer", "Persistent")] == ["true"]
    assert unit[("Timer", "Unit")] == ["claudia-gardener.service"]
    assert unit[("Install", "WantedBy")] == ["timers.target"]


def test_c57_viewer_reads_the_kb_only_and_masks_claudia_secrets() -> None:
    unit = parse_unit(VIEWER_UNIT)
    # pdash-viewtok: viewer.token only (F-CL6, C46); nothing else is added.
    assert unit[("Service", "SupplementaryGroups")] == ["pdash-kb pdash-viewtok"]
    assert "-/var/lib/claudia-kb" in unit[("Service", "ReadOnlyPaths")]
    assert not any("claudia" in v for v in unit[("Service", "ReadWritePaths")])
    masked = " ".join(unit[("Service", "InaccessiblePaths")]).split()
    for path in (
        "-/var/lib/preview-dashboard/claudia",  # S-C1 S1: admin-only DB
        "-/etc/preview-dashboard/totp.secret",  # S-C1 S2
        "-/etc/preview-dashboard/claudia.token",
        "-/var/lib/preview-dashboard/voice",
        "-/var/lib/claudia-host",
    ):
        assert path in masked, path


def test_c47_notifier_and_admin_masks() -> None:
    notifier = " ".join(parse_unit(NOTIFIER_UNIT)[("Service", "InaccessiblePaths")]).split()
    assert "-/etc/preview-dashboard/totp.secret" in notifier
    assert "-/etc/preview-dashboard/claudia.token" in notifier
    admin = " ".join(parse_unit(ADMIN_UNIT)[("Service", "InaccessiblePaths")]).split()
    assert "-/var/lib/claudia-kb" in admin


def render_claudia_mcp(gid: str) -> dict[str, object]:
    """What install.sh's sed step writes: header dropped, gid substituted."""
    lines = [
        line.replace("@KB_GID@", gid)
        for line in CLAUDIA_MCP_TEMPLATE.read_text().splitlines()
        if not line.startswith("#")
    ]
    data = json.loads("\n".join(lines))
    assert isinstance(data, dict)
    return data


def test_install_sh_mcp_sed_matches_the_reference_rendering() -> None:
    text = INSTALL_SH.read_text()
    assert 'sed -e \'/^#/d\' -e "s|@KB_GID@|${KB_GID}|" "$CLAUDIA_MCP_TEMPLATE"' in text
    sed = shutil.which("sed")
    assert sed is not None
    out = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which
        [sed, "-e", "/^#/d", "-e", "s|@KB_GID@|990|", str(CLAUDIA_MCP_TEMPLATE)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    ).stdout
    assert json.loads(out) == render_claudia_mcp("990")


def test_c51_host_mcp_config_has_no_env_no_token_and_a_pinned_kb() -> None:
    data = render_claudia_mcp("990")
    servers = data["mcpServers"]
    assert isinstance(servers, dict)
    assert set(servers) == {"preview-dashboard", "claudia-kb"}
    for server in servers.values():
        assert set(server) == {"command", "args"}  # no env block (C30)
    assert servers["preview-dashboard"] == {
        "command": "/opt/preview-dashboard/.venv/bin/preview-dashboard-mcp",
        "args": [],  # the MCP server refuses any argument
    }
    kb = servers["claudia-kb"]
    assert kb["command"] == "/opt/preview-dashboard/.venv/bin/python"
    assert kb["args"] == [
        "-I",
        "-m",
        "preview_dashboard.interfaces.claudia.kb_mcp",
        "--root",
        "/var/lib/claudia-kb",
        "--caller",
        "claudia",
        "--viewer-gid",
        "990",
    ]
    assert "token" not in CLAUDIA_MCP_TEMPLATE.read_text().lower().replace("no tokens", "")


def test_c50_shipped_host_settings_pass_the_hosts_own_check() -> None:
    """The file install.sh copies verbatim is exactly what the host accepts,
    and its hook path is the venv console script install.sh checks for."""
    from preview_dashboard.interfaces.claudia.settings import (
        HOOK_COMMAND,
        verify_host_settings_data,
    )

    data = json.loads(CLAUDIA_SETTINGS.read_text())
    verify_host_settings_data(data, CLAUDIA_SETTINGS)
    text = INSTALL_SH.read_text()
    assert 'HOOK_BIN="$VENV_BIN/preview-dashboard-claudia-hook"' in text
    assert HOOK_COMMAND == "/opt/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook"
    assert (
        'run install -m 0644 -o root -g root "$CLAUDIA_SETTINGS_SRC" "$CLAUDIA_SETTINGS_DEST"'
        in text
    )


_CLAUDIA_ARGS = [*_TELEGRAM_ARGS, "--claudia"]


def test_install_sh_dry_run_with_claudia_installs_every_piece(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    etc = f"{tmp_path}/etc/preview-dashboard"
    var = f"{tmp_path}/var/lib"
    for expected in (
        "groupadd --system pdash-claudiatok",
        "groupadd --system pdash-totp",
        "groupadd --system pdash-kb",
        "usermod -aG pdash-claudiatok pdash-admin",
        "usermod -aG pdash-totp pdash-admin",
        # C45: token file root:pdash-claudiatok 0640 via gen-token
        f"gen-token --out {etc}/claudia.token --group pdash-claudiatok",
        # C47: setup is printed for the owner, never run
        "claudia totp setup --group pdash-totp",
        f"install -m 0644 -o root -g root {DEPLOY_DIR}/claudia/settings.json "
        f"{etc}/claudia-settings.json",
        f"write {etc}/claudia-mcp.json (mode 0644, owner root:root)",
        f"write {etc}/claudia.env (mode 0644, owner root:root)",
        f"write {etc}/claudia-admin.env (mode 0644, owner root:root)",
        f"install -d -m 0750 -o root -g pdash-kb {var}/claudia-kb",
        f"install -d -m 0700 -o root -g root {var}/claudia-host",
        # deploy-1: inside the admin's data dir only pdash-admin creates dirs
        f"runuser -u pdash-admin -- mkdir -m 0700 -- {var}/preview-dashboard/claudia",
        f"runuser -u pdash-admin -- mkdir -m 0700 -- {var}/preview-dashboard/voice",
        f"runuser -u pdash-admin -- mkdir -m 0750 -- {var}/preview-dashboard/claudia-view",
        "test -x /",  # hook console script checked after uv sync
        "claudia-host.service",
        "claudia-gardener.timer",
        "--token-group claudia=pdash-claudiatok",
    ):
        assert expected in out, f"dry-run (--claudia) missing {expected!r}"
    actions = "\n".join(_actions(out))
    assert "totp setup" not in actions  # only ever printed, never executed
    assert "totp.secret" not in actions  # install.sh never creates it


def test_claudia_is_off_by_default_install_never_enables_it(tmp_path: Path) -> None:
    """`claudia_enabled = false` (template default, or no config yet): the
    units are installed but disabled; install.sh never writes the key."""
    result = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "Claudia installed but not enabled" in out
    assert "systemctl disable --now claudia-host.service claudia-gardener.timer" in out
    assert "systemctl enable claudia-host.service" not in out
    assert "systemctl restart claudia-host" not in out
    assert tomllib.loads(CONFIG_EXAMPLE.read_text()).get("claudia_enabled", False) is False
    assert Settings.model_fields["claudia_enabled"].default is False
    text = INSTALL_SH.read_text()
    assert 'claudia_enabled = true"' not in text
    assert "s|^claudia_enabled" not in text and "s|^# claudia_enabled" not in text


def _claudia_host_state(prefix: Path, *, enabled: bool, totp: bool) -> None:
    _prefix_file(prefix, "etc/systemd/system/preview-dashboard-notifier.service", "[Unit]\n")
    _prefix_file(prefix, "etc/systemd/system/claudia-host.service", "[Unit]\n")
    _prefix_file(
        prefix,
        "etc/preview-dashboard/config.toml",
        "notify_enabled = true\nnotify_owner_chat_id = 5\n"
        f"claudia_enabled = {'true' if enabled else 'false'}\n",
    )
    _prefix_file(prefix, "etc/preview-dashboard/telegram.token", "placeholder\n")
    if totp:
        _prefix_file(prefix, "etc/preview-dashboard/totp.secret", "placeholder\n")


def test_install_sh_rerun_keeps_claudia_and_starts_it_when_enabled(tmp_path: Path) -> None:
    _claudia_host_state(tmp_path, enabled=True, totp=True)
    result = run_install_dry_run(tmp_path)  # no flags: host state decides
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for expected in (
        "systemctl enable claudia-host.service",
        "systemctl enable --now claudia-gardener.timer",
        "systemctl restart claudia-host",
        "systemctl is-active --quiet claudia-host.service",
        "totp.secret already exists",
    ):
        assert expected in out, expected
    restart_admin = out.index(_RESTART_LINE)
    assert restart_admin < out.index("systemctl restart claudia-host")


def test_c47_enabled_claudia_without_totp_secret_is_not_started(tmp_path: Path) -> None:
    _claudia_host_state(tmp_path, enabled=True, totp=False)
    result = run_install_dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "claudia-host enabled but not started" in result.stdout
    assert "systemctl restart claudia-host" not in result.stdout


def test_install_sh_refuses_claudia_without_the_notifier(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, "--claudia", setfacl=None)
    assert result.returncode == 2
    assert "needs the Telegram notifier" in result.stderr
    assert _actions(result.stdout) == []


@pytest.mark.parametrize("bad", ["claude", "./claude", "/root/my claude", "/x;rm"])
def test_install_sh_rejects_unsafe_claude_bin(tmp_path: Path, bad: str) -> None:
    result = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS, "--claude-bin", bad)
    assert result.returncode == 2
    assert "--claude-bin" in result.stderr


def test_install_sh_default_path_has_no_claudia_pieces(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, setfacl=None)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "groupadd --system pdash-kb" in out  # the viewer unit needs the group
    for absent in (
        "claudia.token",
        "claudia-host",
        "pdash-totp",
        "claudia-mcp.json",
        "claudia-voice",
    ):
        assert absent not in out, absent


def test_install_sh_removes_a_stale_claudia_admin_env(tmp_path: Path) -> None:
    env_file = _prefix_file(tmp_path, "etc/preview-dashboard/claudia-admin.env", "X=1\n")
    result = run_install_dry_run(tmp_path, setfacl=None)
    assert result.returncode == 0, result.stderr
    assert f"+ rm -f {env_file}" in result.stdout


def test_voice_models_refused_until_pinned(tmp_path: Path) -> None:
    """A pin file without hashes fails closed: nothing installed."""
    deploy_copy = _deploy_copy(tmp_path)
    (deploy_copy / "claudia" / "voices.sha256").write_text("# no pins\n")
    models = tmp_path / "models"
    models.mkdir()
    result = run_install_dry_run(
        tmp_path / "p",
        *_CLAUDIA_ARGS,
        "--voice-models",
        str(models),
        install_sh=deploy_copy / "install.sh",
    )
    assert result.returncode == 2
    assert "is not pinned" in result.stderr
    assert _actions(result.stdout) == []


def test_shipped_voice_pins_are_well_formed() -> None:
    """V-PIN: exactly the four owner voices, `<64 lowercase hex>  <name>`."""
    pin_lines = [
        line for line in VOICE_PINS.read_text().splitlines() if line and not line.startswith("#")
    ]
    pin_re = re.compile(r"[0-9a-f]{64}  [A-Za-z0-9._-]+")
    assert all(pin_re.fullmatch(line) for line in pin_lines), pin_lines
    assert sorted(line.split("  ")[1] for line in pin_lines) == sorted(
        [
            "es_MX-claude-high.onnx",
            "es_MX-claude-high.onnx.json",
            "en_US-amy-medium.onnx",
            "en_US-amy-medium.onnx.json",
        ]
    )


def test_voice_models_need_claudia(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, *_TELEGRAM_ARGS, "--voice-models", "/tmp/x")  # noqa: S108
    assert result.returncode == 2
    assert "--voice-models needs --claudia" in result.stderr


# --- F-CL4 C: whisper.cpp install (C62, ADR 0042) -------------------------------------


def test_whisper_pins_are_well_formed_and_exact() -> None:
    """The repo file pins exactly the tarball and the model (binary hash is install-time)."""
    pin_lines = [
        line for line in WHISPER_PINS.read_text().splitlines() if line and not line.startswith("#")
    ]
    assert all(re.fullmatch(r"[0-9a-f]{64}  (tarball|model)", line) for line in pin_lines)
    assert pin_lines == [
        "ff1a9053feb509ff9d7729703355541ae9690073a6b1c40eb692c962e0dc1720  tarball",
        "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe  model",
    ]


def test_whisper_install_urls_match_the_pinned_release() -> None:
    text = INSTALL_SH.read_text()
    assert (
        'WHISPER_TARBALL_URL="https://github.com/ggml-org/whisper.cpp/archive/refs/tags/v1.9.5.tar.gz"'
        in text
    )
    assert (
        'WHISPER_MODEL_URL="https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.bin"'
        in text
    )


def test_whisper_hashes_are_verified_before_the_tarball_is_extracted() -> None:
    """Fail closed: both sha256 checks sit before `tar -x`, which sits before the build."""
    text = INSTALL_SH.read_text()
    body = text[text.index("install_whisper() {") :]
    tar_pos = body.index('\n    tar -xzf "$work/whisper.tar.gz"')
    assert body.index('verify_sha256 "$work/whisper.tar.gz"') < tar_pos
    assert body.index('verify_sha256 "$work/ggml-base.bin"') < tar_pos
    assert tar_pos < body.index('"$work/tools/bin/cmake" -S')


def test_whisper_build_flags_and_tools_are_pinned_and_cpu_only() -> None:
    text = INSTALL_SH.read_text()
    for flag in (
        "-DCMAKE_BUILD_TYPE=Release",
        "-DGGML_NATIVE=OFF",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DWHISPER_BUILD_TESTS=OFF",
        "-DWHISPER_BUILD_SERVER=OFF",
        "--target whisper-cli",
    ):
        assert flag in text, flag
    assert "GGML_CUDA" not in text
    # No package manager anywhere in the new path (also see the apt guard test).
    assert not re.search(r"^\s*(run\s+)?(apt|apt-get|dpkg|snap)\s", text, re.MULTILINE)


def test_whisper_build_tools_are_hash_pinned_and_hashes_are_enforced() -> None:
    """cmake and ninja: exact versions, every wheel hashed, installed with --require-hashes."""
    reqs = WHISPER_BUILD_REQS.read_text()
    hash_lines = r"((?:\s+--hash=sha256:[0-9a-f]{64}\s*\\?\n?)+)"
    pins = re.findall(rf"^(cmake|ninja)==([\d.]+) \\\n{hash_lines}", reqs, re.M)
    assert {name: version for name, version, _h in pins} == {
        "cmake": "3.31.6",
        "ninja": "1.11.1.4",
    }
    for name, _version, hashes in pins:
        assert hashes.count("--hash=sha256:") >= 1, name
    # Every requirement line is pinned with hashes; no sdist, no unpinned extra.
    entries = [ln for ln in reqs.splitlines() if ln and not ln.startswith(("#", " "))]
    assert len(entries) == 2 and all("==" in ln for ln in entries)
    text = INSTALL_SH.read_text()
    body = text[text.index("install_whisper() {") :]
    # `uv run --with-requirements` ignores --hash, so the venv + pip route is the check.
    assert "--require-hashes --no-deps --only-binary :all:" in body
    assert '-r "$WHISPER_BUILD_REQS"' in body
    assert "uv run" not in body.split("\n}\n")[0] and "$UV_BIN run" not in body.split("\n}\n")[0]
    assert body.index("--require-hashes") < body.index('"$work/tools/bin/cmake" -S')


def test_whisper_dry_run_builds_with_the_hash_pinned_tools(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path / "p", *_CLAUDIA_ARGS, "--whisper")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "pip install --python <temp dir>/tools/bin/python --require-hashes" in out
    assert "whisper-build-requirements.txt" in out
    assert out.index("--require-hashes") < out.index("<temp dir>/tools/bin/cmake -S")


def test_whisper_implies_the_voice_extra(tmp_path: Path) -> None:
    """Voice-note decoding needs soundfile/numpy: --whisper installs the claudia-voice extra."""
    with_whisper = run_install_dry_run(tmp_path / "w", *_CLAUDIA_ARGS, "--whisper")
    assert with_whisper.returncode == 0, with_whisper.stderr
    assert "sync --frozen --no-dev --extra claudia-voice" in with_whisper.stdout
    # It does not demand Piper voices (no voice model is installed or checked).
    assert "voice models (pinned SHA-256" not in with_whisper.stdout
    without = run_install_dry_run(tmp_path / "n", *_CLAUDIA_ARGS)
    assert without.returncode == 0, without.stderr
    assert "--extra claudia-voice" not in without.stdout


def test_whisper_flag_needs_claudia(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, *_TELEGRAM_ARGS, "--whisper")
    assert result.returncode == 2
    assert "--whisper needs --claudia" in result.stderr


def test_whisper_refused_until_both_inputs_are_pinned(tmp_path: Path) -> None:
    deploy_copy = _deploy_copy(tmp_path)
    (deploy_copy / "claudia" / "whisper.sha256").write_text("# no pins\n")
    result = run_install_dry_run(
        tmp_path / "p", *_CLAUDIA_ARGS, "--whisper", install_sh=deploy_copy / "install.sh"
    )
    assert result.returncode == 2
    assert "not both pinned" in result.stderr
    assert _actions(result.stdout) == []


def test_whisper_dry_run_installs_the_fixed_paths_and_never_touches_config(
    tmp_path: Path,
) -> None:
    result = run_install_dry_run(tmp_path / "p", *_CLAUDIA_ARGS, "--whisper")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    root = f"{tmp_path}/p/opt/claudia-whisper"
    assert (
        f"install -m 0755 -o root -g root <temp dir>/build/bin/whisper-cli {root}/bin/whisper-cli"
        in out
    )
    assert f"{root}/models/ggml-base.bin" in out
    assert f"write {root}/whisper.sha256 (mode 0644, owner root:root" in out
    assert out.index("sha256sum check of both downloads") < out.index("tar -xzf")
    # The live config is only ever read/created by the existing steps, never edited for whisper.
    assert "claudia_voice_input_enabled" not in out


def test_whisper_does_nothing_without_the_flag(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path / "p", *_CLAUDIA_ARGS)
    assert result.returncode == 0, result.stderr
    assert "claudia-whisper" not in result.stdout
    assert "whisper.sha256" not in result.stdout
    assert not (tmp_path / "p" / "opt" / "claudia-whisper").exists()


def test_config_example_has_the_media_keys() -> None:
    text = CONFIG_EXAMPLE.read_text()
    data = tomllib.loads(text)
    # Owner decision 2026-11-09: both inputs on by default (with claudia_enabled).
    assert data["claudia_voice_input_enabled"] is True
    assert data["claudia_photo_input_enabled"] is True
    assert data["claudia_photo_turn_tools"] == "read_only"
    assert '\n# claudia_whisper_dir = "/opt/claudia-whisper"' in text


def test_check_sh_verifies_whisper_pins_and_warns_on_switches() -> None:
    text = CHECK_SH.read_text()
    assert "check_media_input" in text
    assert "/opt/claudia-whisper" in text
    assert 'warn "claudia_voice_input_enabled = true (the default) but $dir is missing:' in text
    assert 'warn "claudia_voice_input_enabled = true but $dir does not match its pins:' in text
    assert "switches act only with claudia_enabled" in text


def test_check_sh_checks_soundfile_imports_when_voice_input_is_on() -> None:
    text = CHECK_SH.read_text()
    assert 'VENV_PYTHON="${VENV_PYTHON:-/opt/preview-dashboard/.venv/bin/python}"' in text
    block = text[text.index("# Voice notes are decoded with soundfile/numpy") :]
    block = block[: block.index('if [[ "$photo" == "True" ]]')]
    assert 'if [[ "$voice" == "True" ]]' in block
    assert "import numpy, soundfile" in block
    assert 'warn "claudia_voice_input_enabled = true but soundfile/numpy do not import' in block


def test_voice_models_pinned_install_the_extra_and_files(tmp_path: Path) -> None:
    deploy_copy = _deploy_copy(tmp_path)
    models = tmp_path / "models"
    models.mkdir()
    names = (
        "es_MX-claude-high.onnx",
        "es_MX-claude-high.onnx.json",
        "en_US-amy-medium.onnx",
        "en_US-amy-medium.onnx.json",
    )
    for name in names:
        (models / name).write_text("x")
    pins = "".join(f"{'a' * 64}  {name}\n" for name in names)
    (deploy_copy / "claudia" / "voices.sha256").write_text("# header\n" + pins)
    result = run_install_dry_run(
        tmp_path / "p",
        *_CLAUDIA_ARGS,
        "--voice-models",
        str(models),
        install_sh=deploy_copy / "install.sh",
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "sync --frozen --no-dev --extra claudia-voice" in out
    staging = f"{tmp_path}/p/var/lib/claudia-host/voices.incoming"
    voices = f"{tmp_path}/p/var/lib/claudia-host/voices"
    for name in names:
        assert f"install -m 0600 -o root -g root {models}/{name} {staging}/{name}" in out
        assert f"mv -f -- {staging}/{name} {voices}/{name}" in out
    # Voice models are never downloaded; only the opt-in --whisper path may fetch (F-CL4 C).
    text = INSTALL_SH.read_text()
    voice_step = text[text.index('log "voice models') : text.index("# Every run re-verifies")]
    assert "curl" not in voice_step and "wget" not in text
    assert (
        text.count("curl -fsSL") == 2 + 2
    )  # two real calls + two dry-run echoes, all in install_whisper
    assert text.index("curl -fsSL") > text.index("install_whisper() {")


def test_deploy6_voice_hashes_are_checked_on_the_copies(tmp_path: Path) -> None:
    """deploy-6: copy into the root-only staging dir, THEN hash the copies
    there, then move them into place; the operator's dir is never hashed."""
    deploy_copy = _deploy_copy(tmp_path)
    models = tmp_path / "models"
    models.mkdir()
    names = (
        "es_MX-claude-high.onnx",
        "es_MX-claude-high.onnx.json",
        "en_US-amy-medium.onnx",
        "en_US-amy-medium.onnx.json",
    )
    for name in names:
        (models / name).write_text("x")
    pins = "".join(f"{'a' * 64}  {name}\n" for name in names)
    (deploy_copy / "claudia" / "voices.sha256").write_text("# header\n" + pins)
    result = run_install_dry_run(
        tmp_path / "p",
        *_CLAUDIA_ARGS,
        "--voice-models",
        str(models),
        install_sh=deploy_copy / "install.sh",
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    staging = f"{tmp_path}/p/var/lib/claudia-host/voices.incoming"
    last_copy = max(out.index(f"{staging}/{name}") for name in names)
    check = out.index(f"sha256sum --check --strict (pinned hashes) in {staging}")
    first_move = out.index("+ mv -f -- ")
    assert last_copy < check < first_move
    assert f"(pinned hashes) in {models}" not in out
    text = INSTALL_SH.read_text()
    # On a mismatch the copies are deleted before the install stops.
    assert 'run rm -f -- "$VOICES_STAGING/$f"' in text
    # Every run re-verifies the installed copies.
    assert 'if [[ "$VOICE" -eq 1 ]] && ! verify_voices "$VOICES_DIR"; then' in text


def test_deploy6_installed_voices_are_reverified_on_a_plain_rerun(tmp_path: Path) -> None:
    deploy_copy = _deploy_copy(tmp_path)
    names = (
        "es_MX-claude-high.onnx",
        "es_MX-claude-high.onnx.json",
        "en_US-amy-medium.onnx",
        "en_US-amy-medium.onnx.json",
    )
    pins = "".join(f"{'a' * 64}  {name}\n" for name in names)
    (deploy_copy / "claudia" / "voices.sha256").write_text(pins)
    prefix = tmp_path / "p"
    _claudia_host_state(prefix, enabled=False, totp=False)
    (prefix / "var/lib/claudia-host/voices").mkdir(parents=True)
    result = run_install_dry_run(prefix, install_sh=deploy_copy / "install.sh")
    assert result.returncode == 0, result.stderr
    assert f"(pinned hashes) in {prefix}/var/lib/claudia-host/voices\n" in result.stdout
    # Unpinned: an installed voice dir stops the install.
    (deploy_copy / "claudia" / "voices.sha256").write_text("# no pins\n")
    result = run_install_dry_run(prefix, install_sh=deploy_copy / "install.sh")
    assert result.returncode == 1
    assert "does not match its pinned SHA-256" in result.stderr


def test_uninstall_sh_removes_claudia_units_groups_and_data() -> None:
    assert BASH is not None
    result = subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(UNINSTALL_SH), "--dry-run", "--purge-data", "--purge-users"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    out = result.stdout
    for expected in (
        "systemctl disable --now claudia-host.service",
        "systemctl disable --now claudia-gardener.timer",
        "/etc/systemd/system/claudia-gardener.timer",
        "rm -rf /var/lib/claudia-kb",
        "groupdel pdash-claudiatok",
        "groupdel pdash-totp",
        "groupdel pdash-kb",
    ):
        assert expected in out, expected


def test_check_sh_warns_when_claudia_approvals_snapshot_is_unset() -> None:
    """The viewer's approvals panel needs the snapshot path; a missing one warns (F-CL2b)."""
    text = CHECK_SH.read_text()
    assert "claudia_approvals_snapshot_set" in text
    assert 'warn "claudia_approvals_snapshot is unset' in text
    assert "claudia_approvals_snapshot" in (DEPLOY_DIR.parent / "docs/operations.md").read_text()


def test_check_sh_covers_claudia_when_enabled() -> None:
    """Static coverage of the live Claudia checks (never run here)."""
    text = CHECK_SH.read_text()
    assert 'check_claudia "$config_json"' in text
    assert '["claudia_enabled"]' in text
    for expected in (
        "claudia-host.service",
        "claudia-gardener.timer",
        "UnsetEnvironment=ANTHROPIC_API_KEY",  # C49, unit file
        '"/proc/${pid}/environ"',  # C49, running process
        "check_owner_mode /etc/preview-dashboard/claudia.token root:pdash-claudiatok 640",
        "check_owner_mode /etc/preview-dashboard/totp.secret root:pdash-totp 640",
        "check_owner_mode /var/lib/claudia-kb root:pdash-kb 750",
        "check_owner_mode /var/lib/preview-dashboard/claudia pdash-admin:pdash 700",
        "check_owner_mode /var/lib/preview-dashboard/claudia-view pdash-admin:pdash 750",
        "test -r /var/lib/preview-dashboard/claudia-view",
        "-G pdash-kb",
        "test -r /var/lib/claudia-kb",
    ):
        assert expected in text, expected
    # C58 / ADR 0039: the live host process must sit in the leaf "host" cgroup.
    assert '"/proc/${pid}/cgroup"' in text
    assert '"/claudia-host.service/host"' in text
    # Never prints an environment value: only grep -q on names.
    assert 'environ" 2>/dev/null | grep -q' in text


def test_deploy5_check_sh_proves_kb_read_only_by_mount_and_exact_members() -> None:
    text = CHECK_SH.read_text()
    # `test -w` on a 0750 dir proves nothing: the mount table must say ro.
    assert "test -w /var/lib/claudia-kb" not in text
    assert 'findmnt --task "$vpid" -rn -o OPTIONS -T /var/lib/claudia-kb' in text
    assert '",${opts}," == *",ro,"*' in text
    for line in (
        "check_group_members pdash-totp pdash-admin",
        "check_group_members pdash-claudiatok pdash-admin",
        'check_group_members pdash-kb ""',
    ):
        assert line in text, line
    # Primary-group users count as members too.
    assert "getent passwd | awk -F: -v g=\"$gid\" '$4 == g { print $1 }'" in text


def test_deploy3_check_sh_verifies_every_viewer_mask_is_mounted() -> None:
    text = CHECK_SH.read_text()
    assert 'findmnt --task "$vpid" -rn -M "$path"' in text
    start = text.index(
        "for path in /var/lib/preview-dashboard/claudia /var/lib/preview-dashboard/voice"
    )
    block = text[start : text.index("done", start)]
    for path in (
        "/var/lib/preview-dashboard/claudia",
        "/var/lib/preview-dashboard/voice",
        "/var/lib/claudia-host",
        "/etc/preview-dashboard/totp.secret",
        "/etc/preview-dashboard/claudia.token",
    ):
        assert path in block, path
        assert f"-{path}" in " ".join(parse_unit(VIEWER_UNIT)[("Service", "InaccessiblePaths")])
    # The step-up state lives under the masked claudia/ dir: no file mask, owner + mode checked,
    # and the pre-migration path must be gone.
    viewer_masks = " ".join(parse_unit(VIEWER_UNIT)[("Service", "InaccessiblePaths")])
    assert "stepup-state.json" not in viewer_masks
    for name in ("stepup-state.json", "stepup-state.lock"):
        assert (
            f"check_owner_only_mode /var/lib/preview-dashboard/claudia/{name} pdash-admin 600"
            in text
        )
    assert "-e /var/lib/preview-dashboard/stepup-state.json" in text


def test_makefile_check_audits_the_voice_extra() -> None:
    makefile = (DEPLOY_DIR.parent / "Makefile").read_text()
    assert "--extra claudia-voice" in makefile
    assert "pip-audit --progress-spinner off --disable-pip -r" in makefile
    assert "audit-voice" in makefile.split("check:")[1].split("fmt:")[0]


def test_deploy3_voice_dir_exists_before_the_viewer_restarts(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    mkdir_voice = out.index(f"mkdir -m 0700 -- {tmp_path}/var/lib/preview-dashboard/voice")
    assert mkdir_voice < out.index(_RESTART_LINE)


# --- deploy-1: no root install -d inside the admin-owned data dir ------------------


def test_deploy1_root_never_creates_dirs_inside_the_data_dir() -> None:
    text = INSTALL_SH.read_text()
    assert not re.search(r'install -d[^\n]*"\$VAR_DIR/', text)
    for sub, mode in (
        ("blobs", "0750"),
        ("staging", "0750"),
        ("claudia", "0700"),
        ("voice", "0700"),
        ("claudia-view", "0750"),
    ):
        assert f'ensure_admin_dir "$VAR_DIR/{sub}" {mode}' in text, sub
    # Created and fixed AS pdash-admin; checked with a no-follow stat.
    assert 'run runuser -u "$ADMIN_USER" -- mkdir -m "$mode" -- "$dir"' in text
    assert "stat -c '%F %U:%G %a' -- \"$dir\"" in text


@pytest.mark.parametrize("kind", ["symlink", "file"])
def test_deploy1_refuses_a_planted_symlink_or_file_in_the_data_dir(
    tmp_path: Path, kind: str
) -> None:
    var = tmp_path / "var/lib/preview-dashboard"
    var.mkdir(parents=True)
    target = var / "blobs"
    if kind == "symlink":
        (tmp_path / "etc-ish").mkdir()
        target.symlink_to(tmp_path / "etc-ish")
    else:
        target.write_text("x")
    result = run_install_dry_run(tmp_path, setfacl=None)
    assert result.returncode == 1
    assert "is a symlink or not a directory" in result.stderr
    assert f"{target}" not in "\n".join(_actions(result.stdout))


def test_claudia_view_is_admin_owned_group_pdash_and_viewer_read_only(tmp_path: Path) -> None:
    """M5b relay: the snapshot dir is pdash-admin:pdash 0750, created safely,
    readable (not masked) by the viewer, whose Group= is pdash."""
    result = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS)
    assert result.returncode == 0, result.stderr
    view = f"{tmp_path}/var/lib/preview-dashboard/claudia-view"
    assert f"stat -c '%F %U:%G %a' {view}   (must be: directory pdash-admin:pdash 750)" in (
        result.stdout
    )
    unit = parse_unit(VIEWER_UNIT)
    assert unit[("Service", "Group")] == ["pdash"]
    assert "/var/lib/preview-dashboard" in unit[("Service", "ReadOnlyPaths")]
    masked = " ".join(unit[("Service", "InaccessiblePaths")])
    assert "claudia-view" not in masked
    assert not any("claudia-view" in v for v in unit[("Service", "ReadWritePaths")])


# --- deploy-2 / deploy-7: masks on the two root Claudia units ------------------------


def test_deploy2_gardener_cannot_see_the_data_dir_host_state_or_other_secrets() -> None:
    unit = parse_unit(GARDENER_UNIT)
    masked = " ".join(unit[("Service", "InaccessiblePaths")]).split()
    for path in (
        "/var/lib/preview-dashboard",  # no "-": always present, fail closed
        "-/var/lib/claudia-host",
        "-/etc/preview-dashboard/totp.secret",
        "-/etc/preview-dashboard/claudia.token",
        "-/etc/preview-dashboard/notifier.token",
        "-/etc/preview-dashboard/telegram.token",
    ):
        assert path in masked, path
    # What it does need stays reachable.
    assert not any("admin.token" in p or "/run/preview-dashboard" in p for p in masked)
    assert not any(p.lstrip("-").startswith("/var/lib/claudia-kb") for p in masked)


def test_deploy7_host_masks_the_step_up_secrets_it_never_reads() -> None:
    masked = " ".join(parse_unit(CLAUDIA_HOST_UNIT)[("Service", "InaccessiblePaths")]).split()
    assert masked == [
        "-/etc/preview-dashboard/totp.secret",
        "-/etc/preview-dashboard/notifier.token",
        "-/etc/preview-dashboard/telegram.token",
    ]
    # Its own token and the dashboard MCP's admin token must stay readable.
    assert all("claudia.token" not in p and "admin.token" not in p for p in masked)


# --- deploy-4: install.sh refuses to run inside claudia-host.service ---------------


@pytest.mark.parametrize(
    "line",
    [
        "0::/system.slice/claudia-host.service\n",
        "0::/system.slice/claudia-host.service/run-1.scope\n",
    ],
)
def test_deploy4_install_refuses_inside_the_claudia_host_cgroup(
    tmp_path: Path, line: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    cgroup = tmp_path / "cgroup"
    cgroup.write_text(line)
    monkeypatch.setenv("PDASH_CGROUP_FILE", str(cgroup))
    result = run_install_dry_run(tmp_path / "p", setfacl=None)
    assert result.returncode == 2
    assert "inside claudia-host.service" in result.stderr
    assert _actions(result.stdout) == []


def test_deploy4_install_runs_outside_the_host_cgroup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cgroup = tmp_path / "cgroup"
    cgroup.write_text("0::/user.slice/user-0.slice/session-1.scope\n")
    monkeypatch.setenv("PDASH_CGROUP_FILE", str(cgroup))
    result = run_install_dry_run(tmp_path / "p", setfacl=None)
    assert result.returncode == 0, result.stderr


# --- deploy-5: install.sh refuses reused groups with unexpected members ------------


def _getent_stub(tmp_path: Path, group_lines: dict[str, str], passwd: str = "") -> str:
    """A `getent` stand-in (PDASH_GETENT_BIN, dry-run only): known groups
    print their line, everything else is "not found"."""
    stub = tmp_path / "getent-stub"
    cases = "".join(
        f"    {name}) printf '%s\\n' '{line}' ;;\n" for name, line in group_lines.items()
    )
    stub.write_text(
        "#!/bin/sh\n"
        "# test stub for install.sh --dry-run (group/passwd lookups only)\n"
        'if [ "$1" = passwd ]; then\n'
        f"    printf '%s' '{passwd}'\n"
        "    exit 0\n"
        "fi\n"
        'case "$2" in\n'
        f"{cases}"
        "    *) exit 2 ;;\n"
        "esac\n"
    )
    stub.chmod(0o755)
    return str(stub)


@pytest.mark.parametrize(
    ("groups", "passwd", "bad"),
    [
        ({"pdash-kb": "pdash-kb:x:990:mallory"}, "", "mallory"),
        ({"pdash-kb": "pdash-kb:x:990:"}, "eve:x:1001:990::/home/eve:/bin/sh\n", "eve"),
        (
            {"pdash-claudiatok": "pdash-claudiatok:x:991:pdash-admin,mallory"},
            "",
            "mallory",
        ),
        ({"pdash-totp": "pdash-totp:x:992:pdash-viewer"}, "", "pdash-viewer"),
        # F-CL6: the viewer holds pdash-viewtok via its unit, never as a member.
        ({"pdash-viewtok": "pdash-viewtok:x:993:pdash-admin,pdash-viewer"}, "", "pdash-viewer"),
    ],
)
def test_deploy5_install_refuses_a_group_with_unexpected_members(
    tmp_path: Path,
    groups: dict[str, str],
    passwd: str,
    bad: str,
) -> None:
    stub = _getent_stub(tmp_path, groups, passwd)
    result = run_install_dry_run(tmp_path / "p", *_CLAUDIA_ARGS, getent=stub)
    assert result.returncode == 2, result.stdout + result.stderr
    assert f"unexpected member '{bad}'" in result.stderr
    assert _actions(result.stdout) == []


def test_deploy5_install_accepts_groups_holding_only_the_admin(tmp_path: Path) -> None:
    groups = {
        "pdash-kb": "pdash-kb:x:990:",
        "pdash-claudiatok": "pdash-claudiatok:x:991:pdash-admin",
        "pdash-totp": "pdash-totp:x:992:pdash-admin",
        "pdash-viewtok": "pdash-viewtok:x:993:pdash-admin",
    }
    stub = _getent_stub(tmp_path, groups)
    result = run_install_dry_run(tmp_path / "p", *_CLAUDIA_ARGS, getent=stub)
    assert result.returncode == 0, result.stderr
    assert "group pdash-claudiatok already exists" in result.stdout
    assert "group pdash-viewtok already exists" in result.stdout


# --- F-CL6 (ADR 0043, C46): dashboard decisions are wired by install/check ----------


def test_fcl6_install_creates_the_viewer_token_and_group(tmp_path: Path) -> None:
    result = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    etc = f"{tmp_path}/etc/preview-dashboard"
    for expected in (
        "groupadd --system pdash-viewtok",
        "usermod -aG pdash-viewtok pdash-admin",
        # root:pdash-viewtok 0640 via gen-token, like the notifier/claudia tokens
        f"gen-token --out {etc}/viewer.token --group pdash-viewtok",
        "--token-group viewer=pdash-viewtok",  # check-config validates it
    ):
        assert expected in out, f"dry-run (--claudia) missing {expected!r}"
    text = INSTALL_SH.read_text()
    assert 'chown root:"$VIEWER_TOK_GROUP" "$VIEWER_TOKEN_FILE"' in text
    assert 'chmod "$TOKEN_FILE_MODE" "$VIEWER_TOKEN_FILE"' in text


def test_fcl6_viewer_group_exists_without_claudia_but_no_token(tmp_path: Path) -> None:
    """Both static units name pdash-viewtok, so it exists on every host; the
    token file and the admin's membership come only with --claudia."""
    result = run_install_dry_run(tmp_path)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "groupadd --system pdash-viewtok" in out
    assert "viewer.token" not in out
    assert "usermod -aG pdash-viewtok" not in out


def test_fcl6_decisions_default_on_in_settings_and_example() -> None:
    assert Settings.model_fields["claudia_dashboard_decisions"].default is True
    example = tomllib.loads(CONFIG_EXAMPLE.read_text())
    assert example["claudia_dashboard_decisions"] is True
    assert example["viewer_token_file"] == str(Settings.model_fields["viewer_token_file"].default)


def test_fcl6_check_sh_verifies_decisions_wiring() -> None:
    text = CHECK_SH.read_text()
    assert 'check_dashboard_decisions "$config_json"' in text
    for expected in (
        "check_owner_mode /etc/preview-dashboard/viewer.token root:pdash-viewtok 640",
        "check_group_members pdash-viewtok pdash-admin",
        "-G pdash-viewtok --)",
        "test -w /run/preview-dashboard/admin.sock",
        'warn "dashboard decisions are on but $viewer_unit / $dropin are not wired',
        'warn "dashboard decisions are on but $admin_unit is not wired',
        "/v1/viewer/approvals/00000000000000000000000000/decision",
        "an admin route refuses the viewer token (403",
    ):
        assert expected in text, expected


VIEWER_DROPIN = SYSTEMD_DIR / "preview-dashboard-viewer.service.d" / "claudia-decisions.conf"


def test_fcl6_dropin_restates_the_viewer_masks_minus_the_run_mask() -> None:
    """Only Claudia hosts drop the L1 mask; the drop-in must not lose any other
    mask (an empty InaccessiblePaths= resets the whole list)."""
    static = " ".join(parse_unit(VIEWER_UNIT)[("Service", "InaccessiblePaths")]).split()
    values = parse_unit(VIEWER_DROPIN)[("Service", "InaccessiblePaths")]
    assert values[0] == ""  # the reset
    dropin = " ".join(values).split()
    assert "/run/preview-dashboard" not in dropin
    assert sorted(dropin) == sorted(p for p in static if p != "/run/preview-dashboard")


def test_fcl6_install_sh_writes_the_dropin_on_claudia_hosts_only(tmp_path: Path) -> None:
    claudia = run_install_dry_run(tmp_path, *_CLAUDIA_ARGS)
    assert claudia.returncode == 0, claudia.stderr
    etc_systemd = f"{tmp_path}/etc/systemd/system"
    assert (
        f"install -m 0644 {DEPLOY_DIR}/systemd/preview-dashboard-viewer.service.d/"
        f"claudia-decisions.conf {etc_systemd}/preview-dashboard-viewer.service.d/"
        "claudia-decisions.conf"
    ) in claudia.stdout
    (tmp_path / "plain").mkdir()
    plain = run_install_dry_run(tmp_path / "plain")
    assert plain.returncode == 0, plain.stderr
    assert "claudia-decisions.conf" not in plain.stdout
    assert "claudia-decisions.conf" in UNINSTALL_SH.read_text()


def test_fcl6_check_sh_requires_the_dropin() -> None:
    text = CHECK_SH.read_text()
    assert "preview-dashboard-viewer.service.d/claudia-decisions.conf" in text
    assert "are not wired for them (re-run install.sh)" in text


def test_fcl6_uninstall_purges_the_viewer_token_group() -> None:
    assert "pdash-viewtok" in UNINSTALL_SH.read_text()


# --- voice-4: the voice extra is bounded and audited in CI ---------------------------


def test_voice4_extra_has_upper_bounds_and_ci_audits_it() -> None:
    pyproject = tomllib.loads((DEPLOY_DIR.parent / "pyproject.toml").read_text())
    extra = pyproject["project"]["optional-dependencies"]["claudia-voice"]
    assert extra, "claudia-voice extra missing"
    for spec in extra:
        assert ">=" in spec and ",<" in spec, spec
    ci = (DEPLOY_DIR.parent / ".github" / "workflows" / "ci.yml").read_text()
    assert "uv export --locked --no-dev --extra claudia-voice" in ci
    assert "pip-audit --progress-spinner off --disable-pip \\\n" in ci
    assert '-r "$RUNNER_TEMP/voice-requirements.txt"' in ci


# --- R1: deploy/setup-wizard.sh (only ever run with --dry-run here) ------------------

_UV_STUB = shutil.which("true")  # any absolute executable passes the wizard's uv check


def run_wizard_dry_run(prefix: Path, answers: str, *extra: str) -> subprocess.CompletedProcess[str]:
    """`setup-wizard.sh --dry-run --no-detect` with `answers` on stdin.

    Same hermetic env as `run_install_dry_run`, since the wizard ends by
    running `install.sh --dry-run`. Never run without --dry-run in tests.
    """
    assert BASH is not None
    assert _NOT_FOUND_STUB is not None
    env = {
        **os.environ,
        "PDASH_PREFIX": str(prefix),
        "PDASH_SETFACL_BIN": _SETFACL_STUB or "/nonexistent/setfacl",
        "PDASH_PYTHON_BIN": sys.executable,
        "PDASH_ID_BIN": _NOT_FOUND_STUB,
        "PDASH_GETENT_BIN": _NOT_FOUND_STUB,
    }
    return subprocess.run(  # noqa: S603 - argv[0] resolved via shutil.which, fixed args
        [BASH, str(WIZARD_SH), "--dry-run", "--no-detect", *extra],
        input=answers,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )


def test_wizard_runs_install_dry_run_with_the_validated_answers(tmp_path: Path) -> None:
    assert _UV_STUB is not None
    result = run_wizard_dry_run(
        tmp_path, f"owner@example.com\ndashboard.example.ts.net\n{_UV_STUB}\n"
    )
    assert result.returncode == 0, result.stderr
    assert "Will run:" in result.stderr
    for part in ("--owner-login owner@example.com", "--host dashboard.example.ts.net",
                 f"--uv-bin {_UV_STUB}", "--dry-run"):  # fmt: skip
        assert part in result.stderr
    # install.sh itself ran (dry-run) with those values.
    assert "systemctl daemon-reload" in result.stdout
    assert f"{_UV_STUB} sync --frozen --no-dev" in result.stdout
    assert "Proceed?" not in result.stderr  # no confirmation in dry-run
    # setup-6: the login is the one the owner browses with (= ACL OWNER_LOGIN).
    assert "Tailscale login you will open the dashboard with" in result.stderr
    assert "OWNER_LOGIN" in result.stderr


@pytest.mark.parametrize(
    "answers",
    [
        "not a login\nx\ny\n",  # owner login: three invalid answers
        "o@example.com\nHOST.ts.net\nexample.com\n-x.ts.net\n",  # host never valid
        "o@example.com\nh.ts.net\nuv\n/nonexistent/uv\n/tmp\n",  # uv: relative, missing, a dir
    ],
)
def test_wizard_refuses_invalid_answers_before_running_install(
    tmp_path: Path, answers: str
) -> None:
    result = run_wizard_dry_run(tmp_path, answers)
    assert result.returncode == 2
    assert "too many invalid answers" in result.stderr
    assert "Will run:" not in result.stderr
    assert _actions(result.stdout) == []


def test_wizard_reasks_after_an_invalid_answer(tmp_path: Path) -> None:
    assert _UV_STUB is not None
    result = run_wizard_dry_run(tmp_path, f"o@example.com\nbad host\nh.ts.net\n{_UV_STUB}\n")
    assert result.returncode == 0, result.stderr
    assert "invalid: a lowercase MagicDNS name" in result.stderr


def test_wizard_end_of_input_stops(tmp_path: Path) -> None:
    result = run_wizard_dry_run(tmp_path, "o@example.com\n")
    assert result.returncode == 2
    assert "no answer" in result.stderr


def test_wizard_passes_extra_install_options_through(tmp_path: Path) -> None:
    assert _UV_STUB is not None
    result = run_wizard_dry_run(
        tmp_path, f"o@example.com\nh.ts.net\n{_UV_STUB}\n", "--", *_TELEGRAM_ARGS
    )
    assert result.returncode == 0, result.stderr
    assert "--telegram-chat-id 123456789" in result.stderr
    assert "preview-dashboard-notifier" in result.stdout


@pytest.mark.parametrize("flag", ["--owner-login", "--host", "--uv-bin", "--dry-run"])
def test_wizard_refuses_prompted_flags_after_the_separator(tmp_path: Path, flag: str) -> None:
    result = run_wizard_dry_run(tmp_path, "", "--", flag, "x")
    assert result.returncode == 2
    assert "via the prompts" in result.stderr


def test_wizard_never_handles_secrets_and_confirms_real_runs() -> None:
    text = WIZARD_SH.read_text()
    # Every redirection goes to stderr/stdout or /dev/null: the wizard writes no file.
    targets = re.findall(r"\d?>>?\s*(\S+)", text)
    assert targets and all(t in {"&1", "&2", "/dev/null"} for t in targets), targets
    assert "read -s" not in text  # never asks for a secret
    assert 'exec "${BASH:-bash}" "${CMD[@]}"' in text  # runs exactly the printed command
    assert "Proceed? [y/N]" in text  # a real install needs an explicit yes
    assert 'if [[ "$DRY_RUN" -eq 0 && "$(id -u)" -ne 0 ]]' in text  # root before any prompt
