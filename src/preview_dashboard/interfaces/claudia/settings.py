"""Host settings checks for Claudia's runs (docs/security.md C49, C50; C59 hooks stay on).

`load_host_settings` verifies the host-owned settings file passed with
`--settings` (`deploy/claudia/settings.json`): root-owned, not group/world
writable, no symlink, parseable, every C50 deny rule and the C59/C60 hook
entry present, no hook switch-off, no bypass mode, no `env` block or
credential helper, no broad allow rule, no plugins; anything else refuses
start. `check_settings_sources` refuses a run if any other settings source
(user, project, local, managed) switches hooks off, registers its own
`PreToolUse` / `PermissionRequest` hooks, enables a plugin that ships
hooks, sets a broad allow rule or a bypass mode, or sets `env` /
`apiKeyHelper`-style credential helpers (they bypass the C49 env
allow-list). `check_hook_command` verifies the hook file and its
interpreter. `SettingsPreflight` re-runs all of them before every run,
lists the managed drop-ins again each time and compares the hook file and
its package modules with a digest pinned at start.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import posixpath
import re
import stat
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from preview_dashboard.domain.risky_actions import runs_any_code
from preview_dashboard.ports.claudia_host import RunRefusedError

HOST_SETTINGS_PATH: Final = Path("/etc/preview-dashboard/claudia-settings.json")
# The C59 hook command (unit M5 provides it; root 0755, Edit/Write denied below).
HOOK_COMMAND: Final = "/opt/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook"
KB_ROOT: Final = "/var/lib/claudia-kb"
INSTALL_ROOT: Final = "/opt/preview-dashboard"
# The host's state dir; only `work/` (her cwd) is hers (host-flow-1).
HOST_STATE_DIR: Final = "/var/lib/claudia-host"
# Every tool: the gate denies the ones it does not know (host-flow-3, hook-9).
HOOK_MATCHER: Final = "*"
HOOK_TIMEOUT_SECONDS: Final = 10
MANAGED_SETTINGS: Final = Path("/etc/claude-code/managed-settings.json")
MANAGED_SETTINGS_DIR: Final = Path("/etc/claude-code/managed-settings.d")
MAX_SETTINGS_BYTES: Final = 256 * 1024
_MAX_SHEBANG_BYTES: Final = 256


def _edit_write(pattern: str) -> tuple[str, str]:
    # `//` = absolute path in Claude Code permission rules (`/x` is settings-relative).
    return (f"Edit(/{pattern})", f"Write(/{pattern})")


# C50: every rule must be present in the host file's `permissions.deny`.
REQUIRED_DENY: Final = (
    *_edit_write("/root/.claude/projects/*/memory/**"),
    *_edit_write("/**/.claude/settings*.json"),
    *_edit_write("/root/.claude/settings*.json"),
    *_edit_write("/etc/preview-dashboard/**"),
    *_edit_write(f"{KB_ROOT}/**"),
    *_edit_write(HOST_SETTINGS_PATH.as_posix()),
    *_edit_write(HOOK_COMMAND),
    # The whole install (venv, hook, host code): her runs must not patch what checks them.
    *_edit_write(f"{INSTALL_ROOT}/**"),
    # Host state minus `work/`: rules can't negate, so the files (all with a
    # dot, e.g. recap-mcp.json) and the known subdirs. is_protected_path is exact.
    *_edit_write(f"{HOST_STATE_DIR}/*.*"),
    *_edit_write(f"{HOST_STATE_DIR}/audit/**"),
    *_edit_write(f"{HOST_STATE_DIR}/voices/**"),
    "Read(//etc/preview-dashboard/**)",
    "Read(//root/.claude/.credentials.json)",
)
REQUIRED_HOOK: Final = {
    "matcher": HOOK_MATCHER,
    "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": HOOK_TIMEOUT_SECONDS}],
}
# Hook events whose answer could stand in for the permission guard.
OVERRIDING_HOOK_EVENTS: Final = ("PreToolUse", "PermissionRequest")
_SWITCH_OFF_KEYS: Final = ("disableAllHooks", "allowManagedHooksOnly")
# Commands Claude Code runs for credentials or headers: outside the hook and
# the C49 env allow-list (host-flow-4).
CREDENTIAL_HELPER_KEYS: Final = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
)
_ALLOWED_DEFAULT_MODES: Final = frozenset({"default", "auto"})
# Other sources may also pick a stricter mode; never bypass / accept-edits.
_SOURCE_DEFAULT_MODES: Final = _ALLOWED_DEFAULT_MODES | {"plan", "dontAsk"}
# Allow rules for these never weaken the guard (they only read).
_READ_ONLY_TOOLS: Final = frozenset(
    {"Read", "Grep", "Glob", "LS", "ListAgents", "ToolSearch", "TodoWrite", "NotebookRead"}
)
_RULE_RE: Final = re.compile(r"([A-Za-z0-9_*-]+)(?:\((.*)\))?", re.DOTALL)
# Allow rules over these dirs (or above them) cover settings, hooks or the install.
_BROAD_ROOTS: Final = frozenset({"/", "/root", "/etc", "/opt"})
_PATH_TOOLS: Final = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
_GLOB_RE: Final = re.compile(r"[*?\[{]")
_PLUGIN_ID_RE: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}@[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
)
_UNTRUSTED_BITS: Final = stat.S_IWGRP | stat.S_IWOTH


class HostSettingsError(RuntimeError):
    """The host settings file or another settings source is unsafe; refuse (fail closed).

    Messages name the file and the rule, never file content.
    """


@dataclass(frozen=True, slots=True)
class HostSettings:
    """A verified host settings file: its path and the SHA-256 of the verified bytes."""

    path: Path
    digest: str


def _read_private(path: Path, trusted_uids: Collection[int]) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise HostSettingsError(f"cannot open host settings {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise HostSettingsError(f"host settings {path} is not a regular file")
        if st.st_uid not in trusted_uids:
            raise HostSettingsError(f"host settings {path} has an untrusted owner")
        if st.st_mode & _UNTRUSTED_BITS:
            raise HostSettingsError(f"host settings {path} must not be group/world-writable")
        raw = os.read(fd, MAX_SETTINGS_BYTES + 1)
    finally:
        os.close(fd)
    _check_trusted_dir(path.parent, trusted_uids, f"directory of host settings {path}")
    if len(raw) > MAX_SETTINGS_BYTES:
        raise HostSettingsError(f"host settings {path} is too large")
    return raw


def _check_trusted_dir(path: Path, trusted_uids: Collection[int], what: str) -> None:
    try:
        st = os.stat(path)
    except OSError:
        raise HostSettingsError(f"{what} is missing") from None
    if st.st_uid not in trusted_uids or st.st_mode & _UNTRUSTED_BITS:
        raise HostSettingsError(f"{what} is not trusted")


def _parse_object(raw: bytes, path: Path) -> dict[str, object]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise HostSettingsError(f"settings {path} is not valid JSON") from None
    if not isinstance(data, dict):
        raise HostSettingsError(f"settings {path} is not a JSON object")
    return data


def _hook_events(data: dict[str, object]) -> dict[str, object]:
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise HostSettingsError("settings `hooks` must be an object")
    return hooks


def _check_credentials(data: dict[str, object], path: Path) -> None:
    """C49: no `env` block and no credential/header helper command (host-flow-4)."""
    env = data.get("env")
    if env not in (None, {}):
        # Any name: Claude Code applies it on top of child_env (e.g. ANTHROPIC_API_KEY).
        raise HostSettingsError(f"settings {path} sets an env block")
    for key in CREDENTIAL_HELPER_KEYS:
        if data.get(key) is not None:
            raise HostSettingsError(f"settings {path} sets {key}")


def _bash_rule_broad(spec: str) -> bool:
    """A Bash rule whose program runs any code (`bash:*`, `env:*`, `sudo *`) (fixcheck-b-5)."""
    words = spec.strip().split()
    first = words[0].partition(":")[0].strip("'\"\\") if words else ""
    # A glob or an assignment as the program: it may match any command.
    if not first or any(ch in first for ch in "*?[=$`"):
        return True
    return runs_any_code(first)


def _path_rule_broad(spec: str) -> bool:
    """An Edit/Write rule over `/`, `/root`, `/etc`, `/opt` or a whole relative base (b-5)."""
    pattern = spec.strip()
    if pattern.startswith("//"):
        absolute: str | None = "/" + pattern[2:].lstrip("/")
    elif pattern.startswith("~"):
        absolute = "/root" + pattern[1:]  # her runs' home
    else:
        absolute = None  # relative to the cwd or the settings file
    head = _GLOB_RE.split(absolute or pattern, maxsplit=1)[0]
    globbed = head != (absolute or pattern)
    if absolute is None:
        return globbed and head.strip("/.") == ""  # `**`, `/**`, `./**`
    if not globbed:
        return posixpath.normpath(absolute) in _BROAD_ROOTS
    covered = head if head.endswith("/") else posixpath.dirname(head)
    return posixpath.normpath(covered) in _BROAD_ROOTS


def is_broad_allow(rule: str) -> bool:
    """True if an allow rule pre-approves a whole mutating tool or a wildcard (hook-8, b-5).

    `Bash`, `Bash(*)`, `Bash(bash:*)`, `Bash(env:*)`, `Edit(//**)`,
    `Edit(//root/**)`, `mcp__srv`, `mcp__*`, `*` are broad; `Bash(git
    status:*)`, `Edit(/src/**)`, `Read`, `mcp__srv__tool` are not.
    Unparseable rules count as broad (fail closed).
    """
    match = _RULE_RE.fullmatch(rule.strip())
    if match is None:
        return True
    tool, spec = match.group(1), match.group(2)
    if tool in _READ_ONLY_TOOLS:
        return False
    if "*" in tool:
        return True
    if spec is None:
        # One named MCP tool is exact; a bare built-in or a whole server is not.
        return not (tool.startswith("mcp__") and tool.count("__") >= 2)
    if set(spec.strip()) <= set("*:/.~ "):
        return True
    if tool == "Bash":
        return _bash_rule_broad(spec)
    if tool in _PATH_TOOLS:
        return _path_rule_broad(spec)
    return False


def _check_permissions(data: dict[str, object], path: Path, modes: frozenset[str]) -> None:
    permissions = data.get("permissions")
    if permissions is None:
        return
    if not isinstance(permissions, dict):
        raise HostSettingsError(f"settings {path} has a malformed permissions object")
    mode = permissions.get("defaultMode")
    if mode is not None and mode not in modes:
        raise HostSettingsError(f"settings {path} sets a forbidden defaultMode")
    allow = permissions.get("allow")
    if allow is None:
        return
    if not isinstance(allow, list) or not all(isinstance(rule, str) for rule in allow):
        raise HostSettingsError(f"settings {path} has a malformed permissions.allow list")
    if any(is_broad_allow(rule) for rule in allow):
        raise HostSettingsError(f"settings {path} has a broad permissions.allow rule")


def verify_host_settings_data(data: dict[str, object], path: Path) -> None:
    """Check the parsed host settings against C49/C50/C59.

    Raises:
        HostSettingsError: a deny rule or the hook entry is missing/altered,
            hooks are switched off, a bypass mode, broad allow rule, `env`
            block, credential helper or plugin is set.
    """
    for key in _SWITCH_OFF_KEYS:
        if data.get(key) not in (None, False):
            raise HostSettingsError(f"host settings {path} sets {key}")
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        raise HostSettingsError(f"host settings {path} has no permissions object")
    _check_permissions(data, path, _ALLOWED_DEFAULT_MODES)
    _check_credentials(data, path)
    if data.get("enabledPlugins") not in (None, {}):
        raise HostSettingsError(f"host settings {path} enables plugins")
    deny = permissions.get("deny")
    if not isinstance(deny, list) or not all(isinstance(rule, str) for rule in deny):
        raise HostSettingsError(f"host settings {path} has no permissions.deny list")
    for rule in REQUIRED_DENY:
        if rule not in deny:
            raise HostSettingsError(f"host settings {path} misses deny rule {rule}")
    entries = _hook_events(data).get("PreToolUse")
    if not isinstance(entries, list) or entries != [REQUIRED_HOOK]:
        raise HostSettingsError(
            f"host settings {path}: the PreToolUse hook entry is missing or altered"
        )
    for event in OVERRIDING_HOOK_EVENTS[1:]:
        if _hook_events(data).get(event):
            raise HostSettingsError(f"host settings {path} registers a {event} hook")


def load_host_settings(path: Path, *, trusted_uids: Collection[int] = (0,)) -> HostSettings:
    """Verify the host settings file (C50); call at start and before every run.

    Args:
        path: the file passed to `claude --settings`.
        trusted_uids: allowed owners (root; tests pass their own uid).

    Raises:
        HostSettingsError: missing, unsafe file, unparseable, or a rule fails.
    """
    raw = _read_private(path, trusted_uids)
    verify_host_settings_data(_parse_object(raw, path), path)
    return HostSettings(path=path, digest=hashlib.sha256(raw).hexdigest())


def managed_dropins(directory: Path = MANAGED_SETTINGS_DIR) -> list[Path]:
    """The `*.json` drop-ins in the managed settings directory, sorted; [] if it doesn't exist.

    Raises:
        HostSettingsError: it exists but can't be listed (newcode-3: Claude
            Code might load a file we never checked, so fail closed).
    """
    try:
        entries = list(directory.iterdir())
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise HostSettingsError(
            f"managed settings directory {directory} cannot be listed: {exc.strerror}"
        ) from None
    return sorted(p for p in entries if p.suffix == ".json")


def settings_sources(
    home: Path, workdir: Path, *, managed_dir: Path = MANAGED_SETTINGS_DIR
) -> list[Path]:
    """Every other settings source a run in `workdir` loads (user, project, local, managed).

    The user `settings.json` comes first (`check_settings_sources` finds the
    plugin directory next to it). The drop-ins are listed now; the preflight
    lists them again before every run.

    Raises:
        HostSettingsError: see `managed_dropins`.
    """
    sources = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        workdir / ".claude" / "settings.json",
        workdir / ".claude" / "settings.local.json",
        MANAGED_SETTINGS,
    ]
    return sources + managed_dropins(managed_dir)


def _plugin_dirs(plugins_dir: Path, name: str, market: str) -> list[Path]:
    """Where Claude Code keeps an installed plugin (cache versions, marketplace checkout)."""
    found: list[Path] = []
    with contextlib.suppress(OSError):
        cache = plugins_dir / "cache" / market / name
        found += sorted(p for p in cache.iterdir() if p.is_dir())
    for sub in ("plugins", "external_plugins"):
        candidate = plugins_dir / "marketplaces" / market / sub / name
        if candidate.is_dir():
            found.append(candidate)
    return found


def _declares_hooks(plugin: Path) -> bool:
    """True if a plugin ships hooks (or we can't tell: fail closed)."""
    if os.path.lexists(plugin / "hooks" / "hooks.json"):
        return True
    manifest = plugin / ".claude-plugin" / "plugin.json"
    if not os.path.lexists(manifest):
        return False
    try:
        with manifest.open("rb") as handle:
            raw = handle.read(MAX_SETTINGS_BYTES + 1)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return True
    return len(raw) > MAX_SETTINGS_BYTES or not isinstance(data, dict) or "hooks" in data


def _check_plugins(data: dict[str, object], path: Path, plugins_dir: Path | None) -> None:
    """hook-8: an enabled plugin's hooks could answer before (or instead of) ours."""
    enabled = data.get("enabledPlugins")
    if enabled is None:
        return
    if not isinstance(enabled, dict):
        raise HostSettingsError(f"settings {path} has a malformed enabledPlugins object")
    for plugin_id, on in enabled.items():
        if on is False:
            continue
        if on is not True or not _PLUGIN_ID_RE.fullmatch(plugin_id) or ".." in plugin_id:
            raise HostSettingsError(f"settings {path} has a malformed enabledPlugins entry")
        name, _, market = plugin_id.partition("@")
        dirs = [] if plugins_dir is None else _plugin_dirs(plugins_dir, name, market)
        if not dirs:
            raise HostSettingsError(
                f"settings {path} enables a plugin whose hooks can't be checked"
            )
        if any(_declares_hooks(d) for d in dirs):
            raise HostSettingsError(f"settings {path} enables a plugin that ships hooks")


def check_settings_sources(sources: Sequence[Path], *, plugins_dir: Path | None = None) -> None:
    """Refuse if any source could switch the hook or the C49 env allow-list off (C49, C59).

    Refused: `disableAllHooks` / `allowManagedHooksOnly`, its own `PreToolUse`
    / `PermissionRequest` hook, an enabled plugin that ships hooks, a broad
    allow rule, a bypass / accept-edits `defaultMode`, an `env` block or a
    credential helper. A missing file is fine; an unreadable, oversized or
    unparseable one refuses (Claude Code would read something we could not check).

    Args:
        sources: `settings_sources(...)`.
        plugins_dir: where plugins are installed; default `<dir of sources[0]>/plugins`
            (the user's `~/.claude/plugins`).

    Raises:
        HostSettingsError: naming the file and the rule.
    """
    if plugins_dir is None and sources:
        plugins_dir = sources[0].parent / "plugins"
    for path in sources:
        try:
            with path.open("rb") as handle:
                raw = handle.read(MAX_SETTINGS_BYTES + 1)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise HostSettingsError(f"settings {path} could not be read: {exc.strerror}") from None
        if len(raw) > MAX_SETTINGS_BYTES:
            raise HostSettingsError(f"settings {path} is too large to check")
        data = _parse_object(raw, path)
        for key in _SWITCH_OFF_KEYS:
            if data.get(key) not in (None, False):
                raise HostSettingsError(f"settings {path} sets {key}")
        events = _hook_events(data)
        for event in OVERRIDING_HOOK_EVENTS:
            if events.get(event):
                raise HostSettingsError(f"settings {path} registers its own {event} hook")
        _check_credentials(data, path)
        _check_permissions(data, path, _SOURCE_DEFAULT_MODES)
        _check_plugins(data, path, plugins_dir)


def _check_trusted_file(path: Path, trusted_uids: Collection[int], what: str) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        raise HostSettingsError(f"{what} {path} is missing") from None
    if not stat.S_ISREG(st.st_mode):
        raise HostSettingsError(f"{what} {path} is not a regular file")
    if st.st_uid not in trusted_uids:
        raise HostSettingsError(f"{what} {path} has an untrusted owner")
    if st.st_mode & _UNTRUSTED_BITS:
        raise HostSettingsError(f"{what} {path} must not be group/world-writable")
    if not st.st_mode & stat.S_IXUSR:
        raise HostSettingsError(f"{what} {path} is not executable")


def _shebang_interpreter(path: Path) -> Path:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise HostSettingsError(f"cannot open hook command {path}: {exc.strerror}") from None
    try:
        head = os.read(fd, _MAX_SHEBANG_BYTES)
    finally:
        os.close(fd)
    line = head.split(b"\n", 1)[0]
    try:
        parts = line.removeprefix(b"#!").decode("utf-8").split()
    except UnicodeDecodeError:
        parts = []
    if not line.startswith(b"#!") or not parts or not parts[0].startswith("/"):
        raise HostSettingsError(f"hook command {path} has no absolute #! interpreter")
    if os.path.basename(parts[0]) == "env":
        raise HostSettingsError(f"hook command {path} picks its interpreter from PATH")
    return Path(parts[0])


def check_hook_command(
    path: Path = Path(HOOK_COMMAND), *, trusted_uids: Collection[int] = (0,)
) -> None:
    """hook-5: the hook file and its `#!` interpreter exist and only root can change them.

    A missing or broken hook exits with a code other than 2, which Claude Code
    treats as a non-blocking error: the call would run unchecked.

    Raises:
        HostSettingsError: missing, not a regular file (no symlink for the hook
            itself), untrusted owner, group/world-writable, not executable,
            or no absolute interpreter.
    """
    _check_trusted_file(path, trusted_uids, "hook command")
    _check_trusted_dir(path.parent, trusted_uids, f"directory of hook command {path}")
    interpreter = Path(os.path.realpath(_shebang_interpreter(path)))
    _check_trusted_file(interpreter, trusted_uids, "hook interpreter")


def hook_module_files() -> tuple[Path, ...]:
    """The package files the hook command imports (it is stdlib-only past these).

    The console script runs `preview_dashboard.interfaces.claudia.hook:main`,
    which loads the three package `__init__` files on the way.
    """
    here = Path(__file__).resolve().parent  # .../preview_dashboard/interfaces/claudia
    return (
        here.parent.parent / "__init__.py",
        here.parent / "__init__.py",
        here / "__init__.py",
        here / "hook.py",
    )


def hook_digest(hook: Path, modules: Sequence[Path]) -> str:
    """SHA-256 over the hook file and its package modules (path, length, bytes each).

    Raises:
        HostSettingsError: a file is missing, a symlink, not regular or too large.
    """
    digest = hashlib.sha256()
    for path in (hook, *modules):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError as exc:
            raise HostSettingsError(f"cannot open hook file {path}: {exc.strerror}") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise HostSettingsError(f"hook file {path} is not a regular file")
            raw = os.read(fd, MAX_SETTINGS_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_SETTINGS_BYTES:
            raise HostSettingsError(f"hook file {path} is too large")
        name = str(path).encode("utf-8", "surrogateescape")
        digest.update(len(name).to_bytes(8, "big") + name + len(raw).to_bytes(8, "big") + raw)
    return digest.hexdigest()


class SettingsPreflight:
    """`RunPreflight`: before every run, the host file is unchanged and still valid,
    the hook command and its modules are intact and unchanged since start, and no
    other source (managed drop-ins listed again each time) switches the hooks off
    (C50, C59).

    Args:
        verified: the host settings verified at start.
        sources: the other settings sources (`settings_sources`); entries in
            `managed_dir` are replaced by a fresh listing on every check (newcode-3).
        trusted_uids: allowed owners of the host file and the hook.
        hook_command: the hook file (the fixed install path by default).
        plugins_dir: see `check_settings_sources`.
        managed_dir: the managed drop-in directory.
        hook_modules: the package files pinned with the hook (`hook_module_files()`).
            If they can't be read at start, every check refuses.
    """

    def __init__(
        self,
        verified: HostSettings,
        sources: Sequence[Path],
        *,
        trusted_uids: Collection[int] = (0,),
        hook_command: Path = Path(HOOK_COMMAND),
        plugins_dir: Path | None = None,
        managed_dir: Path = MANAGED_SETTINGS_DIR,
        hook_modules: Sequence[Path] | None = None,
    ) -> None:
        self._verified = verified
        self._fixed = tuple(p for p in sources if p.parent != managed_dir)
        self._managed_dir = managed_dir
        self._trusted = tuple(trusted_uids)
        self._hook = hook_command
        self._plugins = plugins_dir
        self._modules = tuple(hook_module_files() if hook_modules is None else hook_modules)
        # fixcheck-b-3: a root rewrite keeps owner and mode; only the content shows it.
        self._hook_pin: str | None = None
        with contextlib.suppress(HostSettingsError):
            self._hook_pin = hook_digest(hook_command, self._modules)

    def check(self) -> None:
        """Raise `RunRefusedError` (message names the rule) if a run must not start."""
        try:
            current = load_host_settings(self._verified.path, trusted_uids=self._trusted)
            if current.digest != self._verified.digest:
                raise HostSettingsError("host settings changed since start")
            check_hook_command(self._hook, trusted_uids=self._trusted)
            if self._hook_pin is None:
                raise HostSettingsError("hook command could not be pinned at start")
            if hook_digest(self._hook, self._modules) != self._hook_pin:
                raise HostSettingsError("hook command or its modules changed since start")
            sources = (*self._fixed, *managed_dropins(self._managed_dir))
            check_settings_sources(sources, plugins_dir=self._plugins)
        except HostSettingsError as exc:
            raise RunRefusedError(str(exc)) from None
