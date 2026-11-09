"""Application configuration: the frozen `Settings` model and config-file checks.

`Settings` is the single source of truth for runtime configuration. It is
frozen and validated fail-closed. Precedence, highest first: constructor
kwargs > `PDASH_`-prefixed env vars > TOML file
(`/etc/preview-dashboard/config.toml`, overridable via `PDASH_CONFIG`) >
field defaults — except that env vars may only *narrow* the intake policy
and limits (docs/security.md C10, C17). See docs/security.md for controls.
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any, Self
from urllib.parse import urlsplit

from pydantic import ValidationInfo, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    SettingsError,
    TomlConfigSettingsSource,
)

_DEFAULT_CONFIG_FILE = Path("/etc/preview-dashboard/config.toml")

_KIB = 1024
_MIB = 1024 * _KIB
_GIB = 1024 * _MIB

# Built-in secret denylist for MCP intake (docs/security.md C10, pattern
# semantics in "Intake denylist semantics"). It is a floor: every config
# source can only ADD patterns. Stored NFC-normalized and casefolded because
# matching is case-insensitive. Patterns containing "/" are "(full)"
# multi-segment patterns matched against consecutive path components.
_DENY_DIRS: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".gcloud",
    "gcloud",
    ".kube",
    ".docker",
    ".git",
    ".hg",
    ".svn",
    ".claude",
    ".config/gh",
    ".config/gcloud",
    ".password-store",
    ".terraform",
    ".vault*",
    "preview-dashboard",
    ".mozilla",
    ".config/google-chrome",
    "keyrings",
    ".config/rclone",
    ".config/op",
)
_DENY_FILES: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.ovpn",
    "*.gpg",
    "*.asc",
    "*.kdbx",
    "id_*",
    "*_rsa",
    "*_ed25519",
    "*_ecdsa",
    "authorized_keys",
    "known_hosts",
    "*.token",
    ".vault-token",
    "credentials*",
    ".credentials*",
    ".git-credentials",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".my.cnf",
    ".npmrc",
    ".pypirc",
    ".yarnrc*",
    ".claude.json",
    "kubeconfig",
    "*.tfstate*",
    "*.tfvars",
    "secret*",
    "*secret*.*",
    ".htpasswd",
    "shadow",
    "gshadow",
    ".*_history",
    "*.sqlite*",
    "Cookies",
    "Login Data",
    "*.ppk",
    "*.p8",
    "*service*account*.json",
    "token.json",
    ".dockercfg",
    ".s3cfg",
    ".boto",
    ".terraformrc",
    "terraform.rc",
    "rclone.conf",
    ".gitconfig",
    # Unit 10b follow-up (Info): host SSH keys and system credential files,
    # globbed (not just the exact "shadow"/"gshadow" already above) so
    # backups/rotations (shadow-, ssh_host_ed25519_key.pub, sudoers.d) match too.
    "ssh_host_*",
    "shadow*",
    "gshadow*",
    "sudoers*",
)

# Intake roots that are never acceptable (docs/security.md C10): whole-system
# or whole-home trees would make the allowlist meaningless.
_FORBIDDEN_EXACT_ROOTS = frozenset(
    PurePosixPath(p) for p in ("/", "/root", "/etc", "/home", "/var", "/usr")
)
# Pseudo-filesystems: forbidden as roots at any depth (device/kernel files).
_FORBIDDEN_ROOT_TREES = tuple(PurePosixPath(p) for p in ("/proc", "/sys", "/dev"))
_SSH_DIR = PurePosixPath("/root/.ssh")

# Limit fields env may only lower (upper bounds) or only raise (floors).
_ENV_UPPER_BOUND_FIELDS = (
    "max_files",
    "max_file_bytes",
    "max_item_bytes",
    "max_total_bytes",
    "max_items",
    "publish_rate_per_hour",
    "render_cap_bytes",
    "publish_timeout_seconds",
    "notify_rate_per_hour",
    "question_ttl_seconds",
)
_ENV_FLOOR_FIELDS = ("min_free_disk_bytes", "orphan_grace_seconds")

# One DNS hostname: dot-separated LDH labels, lowercase only (Host matching is
# exact, so a mixed-case config value would silently never match).
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")

# Question lifetime bounds (ADR 0021, owner decision D2): 60 s .. 7 days.
MIN_QUESTION_TTL_SECONDS = 60
MAX_QUESTION_TTL_SECONDS = 7 * 24 * 3600
# Telegram chat ids fit in 52 bits; a private chat id (the owner's) is positive.
_MAX_CHAT_ID = 2**53
_FALSE_WORDS = frozenset({"0", "false", "f", "no", "n", "off"})


def normalize_pattern(pattern: str) -> str:
    """Return the canonical (NFC, casefolded) form of a denylist pattern."""
    return unicodedata.normalize("NFC", pattern).casefold()


DEFAULT_INTAKE_DENIED_PATTERNS: frozenset[str] = frozenset(
    normalize_pattern(p) for p in _DENY_DIRS + _DENY_FILES
)


class ConfigError(ValueError):
    """Configuration is unsafe or invalid; the process must refuse to start."""


def _config_file_path() -> Path:
    """Resolve the TOML config path, honoring the PDASH_CONFIG override.

    Read directly from os.environ (not a Settings field) because this
    decides *which* TOML source to load, before Settings exists.
    """
    override = os.environ.get("PDASH_CONFIG")
    return Path(override) if override else _DEFAULT_CONFIG_FILE


def config_file_path() -> Path:
    """Return the TOML config path services must vet with `verify_config_file_secure`.

    `/etc/preview-dashboard/config.toml`, or `PDASH_CONFIG` if set (C16).
    """
    return _config_file_path()


def config_file_explicit() -> bool:
    """True when `PDASH_CONFIG` names the config file; that file must then exist (I6).

    The default path may be absent (TOML is optional), but an explicitly
    named file that is missing must not silently fall back to defaults.
    """
    return bool(os.environ.get("PDASH_CONFIG"))


def verify_config_file_secure(
    path: Path, *, expected_uid: int = 0, missing_ok: bool = True
) -> None:
    """Refuse a config file anyone but its (root) owner could have written.

    Services call this on the TOML path before trusting `Settings`
    (docs/security.md C16). Checks the file and its parent directory: a
    writable parent would let another user swap the file.

    Args:
        path: Config file to check.
        expected_uid: Required owner uid of file and parent (root in prod).
        missing_ok: If True, an absent file is fine (TOML is optional).

    Raises:
        ConfigError: symlink, non-regular file, wrong owner, or group/world
            writable file or parent directory.
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return
        raise ConfigError(f"config file {path} does not exist") from None
    # lstat, not stat: a symlink could be repointed by whoever owns its target dir.
    if stat.S_ISLNK(st.st_mode):
        raise ConfigError(f"config file {path} must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError(f"config file {path} is not a regular file")
    for target, target_st in ((path, st), (path.parent, os.stat(path.parent))):
        if target_st.st_uid != expected_uid:
            raise ConfigError(f"{target} must be owned by uid {expected_uid}")
        if target_st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigError(f"{target} must not be group- or world-writable")


def _reject_double_slash_root(raw: str, what: str) -> None:
    """Reject a path starting with exactly `//` (POSIX double-slash root, unit 10b L1).

    POSIX leaves a leading `//` implementation-defined; `os.path.normpath`
    deliberately preserves it as-is (only 3+ leading slashes collapse to
    one), so `PurePosixPath("//etc") != PurePosixPath("/etc")` even though
    the kernel treats them the same on this platform — a root or path
    configured as `//etc` would silently escape the `_FORBIDDEN_EXACT_ROOTS`
    / sensitive-path comparisons, which are done by parsed-path equality.
    """
    if raw.startswith("//") and not raw.startswith("///"):
        raise ValueError(f"{what} {raw!r} must not start with '//' (POSIX double-slash root)")


def _as_posix_root(value: object) -> PurePosixPath:
    """Parse and lexically validate one intake root (absolute, normalized)."""
    if not isinstance(value, str | PurePosixPath | Path):
        raise ValueError(f"intake root must be a path, got {type(value).__name__}")
    raw = str(value)
    if "\x00" in raw:
        raise ValueError("intake root contains NUL")
    _reject_double_slash_root(raw, "intake root")
    root = PurePosixPath(raw)
    # Lexical checks only: symlinks are resolved safely at walk time with
    # dir_fd + O_NOFOLLOW (unit 10), not here.
    if not root.is_absolute() or ".." in root.parts or os.path.normpath(raw) != raw:
        raise ValueError(f"intake root {raw!r} must be an absolute, normalized path")
    return root


def _validate_absolute_normalized_path(value: Path, what: str) -> Path:
    """Reject a filesystem-config path that is relative, `..`-bearing, or a `//` root.

    Applied to `data_dir`, `admin_token_file` and `admin_socket` (unit 10b
    L2): each is later compared lexically (e.g. against `intake_sensitive_paths`,
    C10) or handed straight to `os.open`/socket bind calls that treat a
    relative path as relative to the process's cwd (which can change) —
    both are unsafe unless the configured path is already absolute and in
    lexically-canonical form.
    """
    raw = str(value)
    if "\x00" in raw:
        raise ValueError(f"{what} contains NUL")
    _reject_double_slash_root(raw, what)
    if not value.is_absolute() or os.path.normpath(raw) != raw:
        raise ValueError(f"{what} {raw!r} must be an absolute, normalized path")
    return value


def _is_same_or_under(path: PurePosixPath, other: PurePosixPath) -> bool:
    return path == other or path.is_relative_to(other)


def intake_sensitive_paths(
    *, admin_token_file: Path, data_dir: Path, other_token_files: Iterable[Path] = ()
) -> tuple[PurePosixPath, ...]:
    """Paths no intake root may contain or lie inside (C10).

    `/root/.ssh`, the token/config directory (plus the directories of
    `other_token_files`, e.g. the notifier and Telegram tokens) and
    `data_dir`, lexically. The MCP intake re-checks symlink-resolved roots
    against these *and* their resolved forms at request time
    (`check_intake_root`).
    """
    return (
        _SSH_DIR,
        PurePosixPath(admin_token_file).parent,
        *(PurePosixPath(p).parent for p in other_token_files),
        PurePosixPath(data_dir),
    )


def check_intake_root(root: PurePosixPath, sensitive: Iterable[PurePosixPath]) -> None:
    """Reject intake roots that would expose system trees or known secret locations.

    Shared by config load (lexical roots) and MCP intake (realpath-resolved
    roots, docs/security.md C10), so both apply exactly the same rules.

    Raises:
        ValueError: `root` is too broad (`/`, `/root`, `/etc`, ...), inside
            `/proc` `/sys` `/dev`, or overlaps a `sensitive` path.
    """
    if root in _FORBIDDEN_EXACT_ROOTS:
        raise ValueError(f"intake root {root} is forbidden (too broad)")
    if any(_is_same_or_under(root, tree) for tree in _FORBIDDEN_ROOT_TREES):
        raise ValueError(f"intake root {root} is inside a pseudo-filesystem")
    for secret in sensitive:
        # Both directions: a root above a secret dir contains it; a root
        # inside one *is* secret material.
        if _is_same_or_under(secret, root) or _is_same_or_under(root, secret):
            raise ValueError(f"intake root {root} overlaps sensitive path {secret}")


class _NarrowOnlyEnvSource(PydanticBaseSettingsSource):
    """Env source wrapper that lets env vars only narrow intake policy/limits.

    Why: env is the easiest thing for a prompt-injected agent to influence
    (e.g. an MCP registration's env block). Widening the allowlist or
    raising limits must require editing the root-owned TOML file.

    Rules (docs/security.md "Env narrowing"):
    - `intake_allowed_roots` from env: every root must equal or lie under a
      base root (TOML value if set, else the default).
    - `intake_denied_patterns` from env: unioned with the TOML patterns (the
      field validator additionally unions the built-in defaults).
    - Upper-bound limits from env must be <= base; floors must be >= base.
    """

    def __init__(
        self,
        settings_cls: type[BaseSettings],
        env: PydanticBaseSettingsSource,
        base: PydanticBaseSettingsSource | None,
    ) -> None:
        super().__init__(settings_cls)
        self._env = env
        self._base = base

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        # Unused: __call__ delegates wholesale to the wrapped env source.
        # Any: mandated by the PydanticBaseSettingsSource signature.
        return None, field_name, False

    def _base_value(self, base: Mapping[str, Any], name: str) -> Any:  # noqa: ANN401 - raw source value
        if name in base:
            return base[name]
        return self.settings_cls.model_fields[name].get_default(call_default_factory=True)

    def __call__(self) -> dict[str, Any]:
        data = dict(self._env())
        base = dict(self._base()) if self._base is not None else {}

        if "intake_allowed_roots" in data:
            base_roots = [_as_posix_root(r) for r in self._base_value(base, "intake_allowed_roots")]
            for raw in data["intake_allowed_roots"]:
                root = _as_posix_root(raw)
                if not any(_is_same_or_under(root, b) for b in base_roots):
                    raise SettingsError(
                        f"PDASH_INTAKE_ALLOWED_ROOTS may only narrow the allowlist; "
                        f"{root} is not under a configured root"
                    )

        if "intake_denied_patterns" in data and "intake_denied_patterns" in base:
            data["intake_denied_patterns"] = [
                *base["intake_denied_patterns"],
                *data["intake_denied_patterns"],
            ]

        for name in (*_ENV_UPPER_BOUND_FIELDS, *_ENV_FLOOR_FIELDS):
            if name not in data:
                continue
            try:
                env_value = int(data[name])
                base_value = int(self._base_value(base, name))
            except (TypeError, ValueError):
                continue  # let field validation report the malformed value
            widened = (
                env_value > base_value
                if name in _ENV_UPPER_BOUND_FIELDS
                else env_value < base_value
            )
            if widened:
                raise SettingsError(f"PDASH_{name.upper()} may only tighten the configured limit")
        self._check_notify_env(data, base)
        self._check_viewer_paths_env(data)
        return data

    @staticmethod
    def _check_viewer_paths_env(data: Mapping[str, Any]) -> None:
        """The viewer's extra read-only roots come from the root-owned TOML only (C57)."""
        for name in ("kb_root", "claudia_approvals_snapshot"):
            if name in data:
                raise SettingsError(f"PDASH_{name.upper()} may only be set in the config file")

    def _check_notify_env(self, data: Mapping[str, Any], base: Mapping[str, Any]) -> None:
        """Env may switch notifications off, never on, and never pick the owner's chat (C16).

        Enabling sends prompts/titles off the host, and the chat id decides
        who may answer: both must come from the root-owned TOML only.
        """
        if "notify_owner_chat_id" in data:
            raise SettingsError("notify_owner_chat_id may only be set in the config file")
        # Same rule for the Claudia switch: it opens the owner-text and approval routes.
        for name, label in (("notify_enabled", "notifications"), ("claudia_enabled", "Claudia")):
            if name not in data:
                continue
            wants_off = str(data[name]).strip().lower() in _FALSE_WORDS
            if not wants_off and self._base_value(base, name) is not True:
                raise SettingsError(f"PDASH_{name.upper()} may only turn {label} off")


class Settings(BaseSettings):
    """Frozen application configuration for all preview-dashboard processes.

    `owner_login`, `allowed_hosts` and `preview_origin` default to empty on
    purpose: there is no sensible default, and empty values must make the
    viewer fail closed (deny everyone / refuse to start) rather than accept
    any Tailscale user or Host. See docs/security.md C2, C3.
    """

    model_config = SettingsConfigDict(
        env_prefix="PDASH_",
        frozen=True,
        extra="forbid",
        validate_default=True,
    )

    # --- storage ---------------------------------------------------------
    data_dir: Path = Path("/var/lib/preview-dashboard")

    # --- identity / network (docs/security.md C1-C3, C5) ------------------
    owner_login: str = ""
    allowed_hosts: frozenset[str] = frozenset()
    preview_origin: str = ""

    # --- process endpoints -------------------------------------------------
    viewer_host: str = "127.0.0.1"
    viewer_port: int = 8787
    preview_port: int = 8788
    admin_socket: Path = Path("/run/preview-dashboard/admin.sock")
    admin_token_file: Path = Path("/etc/preview-dashboard/admin.token")

    # --- lifecycle ---------------------------------------------------------
    trash_retention_days: int = 14

    # --- limits (docs/security.md C10, C17) ---------------------------------
    max_files: int = 500
    max_file_bytes: int = 100 * _MIB
    max_item_bytes: int = 500 * _MIB
    max_total_bytes: int = 20 * _GIB
    max_items: int = 5000
    publish_rate_per_hour: int = 120
    render_cap_bytes: int = 2 * _MIB
    min_free_disk_bytes: int = 1 * _GIB

    # --- publish deadline / orphan sweep (docs/security.md C11) -------------
    # A publish that hasn't committed within the timeout aborts and never
    # commits; the orphan sweep only touches blobs older than the grace, so
    # grace > timeout keeps it from deleting blobs of an in-flight publish.
    publish_timeout_seconds: int = 600
    orphan_grace_seconds: int = 3600

    # --- MCP intake policy (docs/security.md C10) ---------------------------
    intake_allowed_roots: tuple[Path, ...] = (Path("/root/outbox"),)
    intake_denied_patterns: frozenset[str] = DEFAULT_INTAKE_DENIED_PATTERNS

    # --- notifications (ADR 0021; docs/security.md C33-C37) -----------------
    # Off by default: questions are still stored, but nothing leaves the host.
    notify_enabled: bool = False
    # Who may answer: only from root-owned TOML, never env/runtime (C16, C34).
    notify_owner_chat_id: int | None = None
    notify_rate_per_hour: int = 20
    question_ttl_seconds: int = 86400
    notifier_token_file: Path = Path("/etc/preview-dashboard/notifier.token")
    telegram_token_file: Path = Path("/etc/preview-dashboard/telegram.token")

    # --- Claudia companion (ADR 0031; docs/security.md C45-C47) ---------------
    # Off by default; needs notifications (owner messages come via the notifier).
    claudia_enabled: bool = False
    claudia_token_file: Path = Path("/etc/preview-dashboard/claudia.token")
    totp_secret_file: Path = Path("/etc/preview-dashboard/totp.secret")

    # --- viewer knowledge map (ADR 0031; docs/security.md C57) ----------------
    # Unset = the map is off and the approvals panel shows nothing (fail closed).
    # TOML only: env may not point the viewer at another tree (`_check_viewer_paths_env`).
    kb_root: Path | None = None
    claudia_approvals_snapshot: Path | None = None

    @field_validator("kb_root", "claudia_approvals_snapshot")
    @classmethod
    def _validate_optional_paths(cls, value: Path | None, info: ValidationInfo) -> Path | None:
        """None, or an absolute normalized path (the reader re-checks owner/mode at use)."""
        if value is None:
            return None
        return _validate_absolute_normalized_path(value, info.field_name or "path")

    @field_validator(
        "data_dir",
        "admin_token_file",
        "admin_socket",
        "notifier_token_file",
        "telegram_token_file",
        "claudia_token_file",
        "totp_secret_file",
    )
    @classmethod
    def _validate_absolute_paths(cls, value: Path, info: ValidationInfo) -> Path:
        """Filesystem paths must be absolute and normalized (C10b L2)."""
        return _validate_absolute_normalized_path(value, info.field_name or "path")

    @field_validator("notify_owner_chat_id", mode="before")
    @classmethod
    def _validate_chat_id(cls, value: object) -> object:
        """None or a positive int below 2**53 (a private chat id = the owner's user id).

        Checked before coercion: a bool or a numeric string is refused, not converted.
        """
        if value is None:
            return value
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < _MAX_CHAT_ID:
            raise ValueError("notify_owner_chat_id must be a positive integer (a private chat)")
        return value

    @field_validator("question_ttl_seconds")
    @classmethod
    def _validate_question_ttl(cls, value: int) -> int:
        """A question lives 60 s .. 7 days (ADR 0021)."""
        if not MIN_QUESTION_TTL_SECONDS <= value <= MAX_QUESTION_TTL_SECONDS:
            raise ValueError(
                f"question_ttl_seconds must be in "
                f"{MIN_QUESTION_TTL_SECONDS}..{MAX_QUESTION_TTL_SECONDS}"
            )
        return value

    @field_validator("trash_retention_days")
    @classmethod
    def _validate_retention(cls, value: int) -> int:
        """Retention must be at least 1 day, or purge could race publish."""
        if value < 1:
            raise ValueError("trash_retention_days must be >= 1")
        return value

    @field_validator(
        "max_files",
        "max_file_bytes",
        "max_item_bytes",
        "max_total_bytes",
        "max_items",
        "publish_rate_per_hour",
        "render_cap_bytes",
        "min_free_disk_bytes",
        "publish_timeout_seconds",
        "orphan_grace_seconds",
        "notify_rate_per_hour",
    )
    @classmethod
    def _validate_positive(cls, value: int) -> int:
        """All size/count/rate limits must be strictly positive."""
        if value <= 0:
            raise ValueError("value must be > 0")
        return value

    @field_validator("viewer_port", "preview_port")
    @classmethod
    def _validate_port(cls, value: int) -> int:
        """Ports must be valid TCP ports."""
        if not 1 <= value <= 65535:
            raise ValueError("port must be in 1..65535")
        return value

    @field_validator("viewer_host")
    @classmethod
    def _validate_viewer_host(cls, value: str) -> str:
        """Viewer must bind a loopback IP literal (C1); never a name or 0.0.0.0."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            # Hostnames like "localhost" are rejected: resolution is outside our control.
            raise ValueError("viewer_host must be a loopback IP literal") from None
        if not address.is_loopback:
            raise ValueError("viewer_host must be a loopback address")
        return value

    @field_validator("owner_login")
    @classmethod
    def _validate_owner_login(cls, value: str) -> str:
        """Strip surrounding whitespace; reject control/format chars and inner spaces.

        The login is compared byte-exactly with a header (C2), so invisible
        characters would make the owner unmatchable or confusable.
        """
        value = value.strip()
        for char in value:
            if char.isspace() or unicodedata.category(char).startswith("C"):
                raise ValueError("owner_login contains whitespace or control characters")
        return value

    @field_validator("allowed_hosts")
    @classmethod
    def _validate_allowed_hosts(cls, value: frozenset[str]) -> frozenset[str]:
        """Exact lowercase hostnames only: no wildcards, ports, schemes (C3)."""
        for host in value:
            if not _HOSTNAME_RE.fullmatch(host):
                raise ValueError(
                    f"allowed_hosts entry {host!r} must be an exact lowercase hostname"
                )
        return value

    @field_validator("preview_origin")
    @classmethod
    def _validate_preview_origin(cls, value: str) -> str:
        """Empty (unconfigured) or exactly `https://<host>:<port>` (C5)."""
        if value == "":
            return value
        parts = urlsplit(value)
        try:
            port = parts.port
        except ValueError:
            port = None
        host = parts.hostname or ""
        if (
            parts.scheme != "https"
            or port is None
            or port == 443
            or not _HOSTNAME_RE.fullmatch(host)
            or value != f"https://{host}:{port}"
        ):
            raise ValueError(
                "preview_origin must be exactly https://<lowercase-host>:<port> "
                "with an explicit non-443 port, no path, query or credentials"
            )
        return value

    @field_validator("intake_denied_patterns", mode="before")
    @classmethod
    def _union_default_patterns(cls, value: object) -> object:
        """Built-in denylist is a floor: every source can only add patterns."""
        if isinstance(value, str) or not isinstance(value, Iterable):
            return value  # let type validation reject it
        patterns = set(DEFAULT_INTAKE_DENIED_PATTERNS)
        for pattern in value:
            if not isinstance(pattern, str):
                return value
            if not pattern or "\x00" in pattern or pattern.startswith("/") or pattern.endswith("/"):
                raise ValueError(f"invalid denylist pattern {pattern!r}")
            if ".." in pattern.split("/"):
                raise ValueError(f"invalid denylist pattern {pattern!r}")
            patterns.add(normalize_pattern(pattern))
        return frozenset(patterns)

    @model_validator(mode="after")
    def _validate_cross_field(self) -> Self:
        """Checks that span several fields."""
        if self.viewer_port == self.preview_port:
            raise ValueError("viewer_port and preview_port must differ (separate origins, C5)")
        if self.max_file_bytes > self.max_item_bytes:
            raise ValueError("max_file_bytes must be <= max_item_bytes")
        if self.max_item_bytes > self.max_total_bytes:
            raise ValueError("max_item_bytes must be <= max_total_bytes")
        if self.orphan_grace_seconds <= self.publish_timeout_seconds:
            raise ValueError("orphan_grace_seconds must exceed publish_timeout_seconds (C11)")
        if self.preview_origin:
            dashboard_origins = {f"https://{h}" for h in self.allowed_hosts} | {
                f"https://{h}:443" for h in self.allowed_hosts
            }
            if self.preview_origin in dashboard_origins:
                raise ValueError("preview_origin must differ from the dashboard origin")
        if not self.intake_allowed_roots:
            raise ValueError("intake_allowed_roots must not be empty")
        self._check_notify_settings()
        sensitive = intake_sensitive_paths(
            admin_token_file=self.admin_token_file,
            data_dir=self.data_dir,
            other_token_files=(
                self.notifier_token_file,
                self.telegram_token_file,
                self.claudia_token_file,
                self.totp_secret_file,
            ),
        )
        for root in self.intake_allowed_roots:
            check_intake_root(_as_posix_root(root), sensitive)
        return self

    def _check_notify_settings(self) -> None:
        """Fail closed on notification settings that would weaken C33/C34/C36."""
        if self.notify_enabled and self.notify_owner_chat_id is None:
            raise ValueError("notify_owner_chat_id is required when notify_enabled is true")
        # One file per token: a shared file would let the notifier token
        # pass as the admin token (or the bot token) and vice versa (C33).
        token_files = (self.admin_token_file, self.notifier_token_file, self.telegram_token_file)
        if len(set(token_files)) != len(token_files):
            raise ValueError(
                "admin_token_file, notifier_token_file and telegram_token_file must differ"
            )
        # Owner messages and taps arrive only through the notifier (C44, C46).
        if self.claudia_enabled and not self.notify_enabled:
            raise ValueError("claudia_enabled needs notify_enabled")
        secret_files = (*token_files, self.claudia_token_file, self.totp_secret_file)
        if len(set(secret_files)) != len(secret_files):
            raise ValueError("claudia_token_file and totp_secret_file must differ from every token")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Wire source precedence: init kwargs > env vars (narrow-only) > TOML.

        The TOML file is optional; when it's absent, no TOML source is
        added and defaults apply. `dotenv_settings` and
        `file_secret_settings` are intentionally unused: this project has
        no `.env` support and no per-field secret-file convention.
        """
        del dotenv_settings, file_secret_settings
        toml_path = _config_file_path()
        toml: PydanticBaseSettingsSource | None = None
        if toml_path.is_file():
            toml = TomlConfigSettingsSource(settings_cls, toml_file=toml_path)
        env = _NarrowOnlyEnvSource(settings_cls, env_settings, toml)
        sources: list[PydanticBaseSettingsSource] = [init_settings, env]
        if toml is not None:
            sources.append(toml)
        return tuple(sources)
