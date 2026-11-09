"""The Claudia host's MCP config checks (docs/security.md C51, C53; unit M5b).

`load_mcp_config` verifies the deploy file passed with `--mcp-config`
(root-owned, not group/world-writable, no symlink, <= 256 KiB, JSON): its
`mcpServers` hold exactly `preview-dashboard` and `claudia-kb`, no `env`
blocks, absolute commands, and the KB server is `<python> -I -m
preview_dashboard.interfaces.claudia.kb_mcp --root <abs> --caller claudia`
(optional `--viewer-gid N`; `-I` so no planted module loads). Anything else
refuses start. `write_recap_config` writes the same servers with `--caller
recap` into the host's state dir (0600, atomic) for window-close recaps.
`McpConfigPreflight` re-checks both files against their start-up digests
before every run (host-flow-1): a run could rewrite the recap copy.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from preview_dashboard.interfaces.claudia.settings import HostSettingsError
from preview_dashboard.ports.claudia_host import RunRefusedError

DASHBOARD_SERVER: Final = "preview-dashboard"
KB_SERVER: Final = "claudia-kb"
KB_MODULE: Final = "preview_dashboard.interfaces.claudia.kb_mcp"
KB_PREFIX: Final = ("-I", "-m", KB_MODULE)
CALLER_CLAUDIA: Final = "claudia"
CALLER_RECAP: Final = "recap"
RECAP_CONFIG_NAME: Final = "recap-mcp.json"
MAX_CONFIG_BYTES: Final = 256 * 1024
_KB_OPTIONS: Final = frozenset({"--root", "--caller", "--viewer-gid"})
_SERVER_KEYS: Final = frozenset({"command", "args"})
_GID_RE: Final = re.compile(r"[0-9]{1,10}")
_UNTRUSTED_BITS: Final = stat.S_IWGRP | stat.S_IWOTH


@dataclass(frozen=True, slots=True)
class McpConfig:
    """A verified host MCP config: the parsed data and the KB server's root and group."""

    path: Path
    data: dict[str, object]
    kb_root: Path
    kb_gid: int | None


def _read_trusted(path: Path, trusted_uids: Collection[int]) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise HostSettingsError(f"cannot open MCP config {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid not in trusted_uids:
            raise HostSettingsError(f"MCP config {path} is not a trusted regular file")
        if st.st_mode & _UNTRUSTED_BITS:
            raise HostSettingsError(f"MCP config {path} must not be group/world-writable")
        raw = os.read(fd, MAX_CONFIG_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_CONFIG_BYTES:
        raise HostSettingsError(f"MCP config {path} is too large")
    return raw


def _server(servers: dict[str, object], name: str, path: Path) -> tuple[str, list[str]]:
    entry = servers.get(name)
    if not isinstance(entry, dict) or set(entry) != _SERVER_KEYS:
        raise HostSettingsError(f"MCP config {path}: server {name} must have command + args only")
    command, args = entry["command"], entry["args"]
    if not isinstance(command, str) or not command.startswith("/"):
        raise HostSettingsError(f"MCP config {path}: server {name} needs an absolute command")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise HostSettingsError(f"MCP config {path}: server {name} args must be strings")
    return command, args


def _kb_options(args: list[str], path: Path) -> dict[str, str]:
    if tuple(args[: len(KB_PREFIX)]) != KB_PREFIX:
        raise HostSettingsError(f"MCP config {path}: {KB_SERVER} must run `python -I -m kb_mcp`")
    rest = args[len(KB_PREFIX) :]
    if len(rest) % 2:
        raise HostSettingsError(f"MCP config {path}: {KB_SERVER} has a dangling option")
    options: dict[str, str] = {}
    for flag, value in zip(rest[::2], rest[1::2], strict=True):
        if flag not in _KB_OPTIONS or flag in options:
            raise HostSettingsError(f"MCP config {path}: {KB_SERVER} has an unexpected option")
        options[flag] = value
    return options


def verify_mcp_data(data: dict[str, object], path: Path) -> McpConfig:
    """Check parsed MCP config data (see the module docstring).

    Raises:
        HostSettingsError: naming the file and the rule, never content.
    """
    servers = data.get("mcpServers")
    if set(data) != {"mcpServers"} or not isinstance(servers, dict):
        raise HostSettingsError(f"MCP config {path} must hold only `mcpServers`")
    if set(servers) != {DASHBOARD_SERVER, KB_SERVER}:
        raise HostSettingsError(f"MCP config {path} must list exactly the dashboard and KB servers")
    _server(servers, DASHBOARD_SERVER, path)
    _command, args = _server(servers, KB_SERVER, path)
    options = _kb_options(args, path)
    if options.get("--caller") != CALLER_CLAUDIA:
        raise HostSettingsError(f"MCP config {path}: {KB_SERVER} must say --caller claudia")
    root = options.get("--root", "")
    if not root.startswith("/"):
        raise HostSettingsError(f"MCP config {path}: {KB_SERVER} needs an absolute --root")
    gid = options.get("--viewer-gid")
    if gid is not None and not _GID_RE.fullmatch(gid):
        raise HostSettingsError(f"MCP config {path}: {KB_SERVER} --viewer-gid must be a number")
    return McpConfig(
        path=path, data=data, kb_root=Path(root), kb_gid=None if gid is None else int(gid)
    )


def load_mcp_config(path: Path, *, trusted_uids: Collection[int] = (0,)) -> McpConfig:
    """Read and verify the host MCP config (at start).

    Raises:
        HostSettingsError: unsafe file, bad JSON or a rule above fails.
    """
    raw = _read_trusted(path, trusted_uids)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise HostSettingsError(f"MCP config {path} is not valid JSON") from None
    if not isinstance(data, dict):
        raise HostSettingsError(f"MCP config {path} is not a JSON object")
    return verify_mcp_data(data, path)


def recap_data(config: McpConfig) -> dict[str, object]:
    """The same servers with the KB tool's caller set to `recap`."""
    data = copy.deepcopy(config.data)
    # Type narrowing only: verify_mcp_data already checked the shape.
    servers = data["mcpServers"]
    assert isinstance(servers, dict)  # noqa: S101  # nosec B101
    kb = servers[KB_SERVER]
    assert isinstance(kb, dict)  # noqa: S101  # nosec B101
    args = list(kb["args"])
    index = args.index("--caller", len(KB_PREFIX))
    args[index + 1] = CALLER_RECAP
    kb["args"] = args
    return data


def write_recap_config(config: McpConfig, directory: Path) -> Path:
    """Write the recap MCP config into `directory` (0600, atomic replace); return its path.

    Raises:
        OSError: the directory is missing or not writable.
    """
    target = directory / RECAP_CONFIG_NAME
    tmp = directory / f".{RECAP_CONFIG_NAME}.{secrets.token_hex(6)}"
    payload = json.dumps(recap_data(config), indent=2).encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(tmp, target)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    return target


@dataclass(frozen=True, slots=True)
class PinnedFile:
    """A config file and the SHA-256 of the bytes the host verified or wrote."""

    path: Path
    digest: str


def pin_file(path: Path, *, trusted_uids: Collection[int] = (0,)) -> PinnedFile:
    """Read `path` with the same trust checks as `load_mcp_config` and pin its digest.

    Raises:
        HostSettingsError: the file is missing, untrusted or too large.
    """
    return PinnedFile(path, hashlib.sha256(_read_trusted(path, trusted_uids)).hexdigest())


class McpConfigPreflight:
    """`RunPreflight`: the host and recap MCP configs are unchanged since start (C51, C53).

    Runs execute as root, so a prompt-injected turn could rewrite the recap
    config Claude Code starts its MCP servers from (host-flow-1). Before every
    run each pinned file is re-read (trusted owner, no g/o write, no symlink)
    and its digest compared; any difference refuses the run.

    Args:
        files: the pinned configs (from `pin_file`).
        trusted_uids: owners a config may have.
    """

    def __init__(
        self, files: Sequence[PinnedFile], *, trusted_uids: Collection[int] = (0,)
    ) -> None:
        self._files = tuple(files)
        self._trusted = tuple(trusted_uids)

    def check(self) -> None:
        """Re-verify every pinned file.

        Raises:
            RunRefusedError: a file is unsafe, unreadable or changed (names the path only).
        """
        for pinned in self._files:
            try:
                raw = _read_trusted(pinned.path, self._trusted)
            except HostSettingsError as exc:
                raise RunRefusedError(str(exc)) from None
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), pinned.digest):
                raise RunRefusedError(f"MCP config {pinned.path} changed since the host started")


__all__ = [
    "KB_SERVER",
    "McpConfig",
    "McpConfigPreflight",
    "PinnedFile",
    "load_mcp_config",
    "pin_file",
    "recap_data",
    "verify_mcp_data",
    "write_recap_config",
]
