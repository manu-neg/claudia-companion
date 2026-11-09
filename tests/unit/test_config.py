"""Unit tests for Settings and config-file checks.

Covers defaults, source precedence, the narrow-only env rules, every
validator (docs/security.md C1-C3, C5, C10, C16, C17), and
`verify_config_file_secure`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from preview_dashboard.config import (
    DEFAULT_INTAKE_DENIED_PATTERNS,
    ConfigError,
    Settings,
    verify_config_file_secure,
)

pytestmark = pytest.mark.unit

GIB = 1024**3


@pytest.fixture(autouse=True)
def _clean_pdash_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Isolate each test from the real process env and any real config file.

    Without this, a stray PDASH_* var or an actual
    /etc/preview-dashboard/config.toml on the test host would leak into
    "default" assertions and make tests flaky.
    """
    for key in list(os.environ):
        if key.startswith("PDASH_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PDASH_CONFIG", "/nonexistent/preview-dashboard-test.toml")
    yield


def _use_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(body)
    monkeypatch.setenv("PDASH_CONFIG", str(config_file))


# --- defaults / precedence -------------------------------------------------


def test_defaults() -> None:
    settings = Settings()
    assert settings.data_dir == Path("/var/lib/preview-dashboard")
    assert settings.owner_login == ""
    assert settings.allowed_hosts == frozenset()
    assert settings.preview_origin == ""
    assert settings.viewer_host == "127.0.0.1"
    assert settings.viewer_port == 8787
    assert settings.preview_port == 8788
    assert settings.admin_socket == Path("/run/preview-dashboard/admin.sock")
    assert settings.admin_token_file == Path("/etc/preview-dashboard/admin.token")
    assert settings.trash_retention_days == 14
    assert settings.max_files == 500
    assert settings.max_file_bytes == 100 * 1024 * 1024
    assert settings.max_item_bytes == 500 * 1024 * 1024
    assert settings.max_total_bytes == 20 * GIB
    assert settings.max_items == 5000
    assert settings.publish_rate_per_hour == 120
    assert settings.render_cap_bytes == 2 * 1024 * 1024
    assert settings.min_free_disk_bytes == GIB
    assert settings.intake_allowed_roots == (Path("/root/outbox"),)
    assert settings.intake_denied_patterns == DEFAULT_INTAKE_DENIED_PATTERNS


def test_collections_are_immutable_types() -> None:
    settings = Settings()
    assert isinstance(settings.allowed_hosts, frozenset)
    assert isinstance(settings.intake_allowed_roots, tuple)
    assert isinstance(settings.intake_denied_patterns, frozenset)


# --- data_dir / admin_token_file / admin_socket must be absolute, normalized (unit 10b L2) ---


def _settings_with(field: str, value: str) -> Settings:
    # A single dynamic-field kwarg defeats mypy's static overload matching
    # for Settings.__init__; the field names are hardcoded in the tests
    # below (never attacker input), so one local ignore covers it.
    return Settings(**{field: value})  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["data_dir", "admin_token_file", "admin_socket"])
@pytest.mark.parametrize(
    # Only forms `pathlib.Path()` itself doesn't already normalize away on
    # construction (a lone "." segment, a run of interior/leading slashes
    # collapse to the same, already-safe `Path` before any validator runs;
    # only ".." segments and an *exactly two* leading-slash prefix, POSIX's
    # implementation-defined double-slash root, survive as literal, still
    # ambiguous text -- see `_reject_double_slash_root`).
    "value",
    ["relative/path", "./x", "a/../b", "/a/../b", "//a"],
)
def test_path_fields_must_be_absolute_and_normalized(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _settings_with(field, value)


@pytest.mark.parametrize("field", ["data_dir", "admin_token_file", "admin_socket"])
def test_path_fields_accept_absolute_normalized_paths(field: str) -> None:
    settings = _settings_with(field, "/srv/pdash/thing")
    assert getattr(settings, field) == Path("/srv/pdash/thing")


@pytest.mark.parametrize(
    "pattern",
    [
        ".ssh",
        ".config/gh",
        ".config/google-chrome",
        "*.pem",
        ".env.*",
        "id_*",
        "*.sqlite*",
        "preview-dashboard",
        ".*_history",
        "cookies",
        "login data",
        ".vault*",
        "secret*",
        "*secret*.*",
        "ssh_host_*",
        "shadow*",
        "gshadow*",
        "sudoers*",
    ],
)
def test_default_denylist_contains(pattern: str) -> None:
    assert pattern in DEFAULT_INTAKE_DENIED_PATTERNS


def test_default_denylist_is_casefolded() -> None:
    assert all(p == p.casefold() for p in DEFAULT_INTAKE_DENIED_PATTERNS)


def test_settings_are_frozen() -> None:
    settings = Settings()
    with pytest.raises(ValidationError):
        settings.owner_login = "someone"  # type: ignore[misc]


def test_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data_dir = tmp_path / "pdash-data"
    monkeypatch.setenv("PDASH_OWNER_LOGIN", "alice@example.ts.net")
    monkeypatch.setenv("PDASH_VIEWER_PORT", "9999")
    monkeypatch.setenv("PDASH_TRASH_RETENTION_DAYS", "30")
    monkeypatch.setenv("PDASH_DATA_DIR", str(data_dir))

    settings = Settings()

    assert settings.owner_login == "alice@example.ts.net"
    assert settings.viewer_port == 9999
    assert settings.trash_retention_days == 30
    assert settings.data_dir == data_dir


def test_toml_file_loading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(
        tmp_path,
        monkeypatch,
        """
        owner_login = "alice@example.ts.net"
        viewer_port = 8000
        preview_origin = "https://host.ts.net:8443"
        allowed_hosts = ["host.ts.net"]
        """,
    )
    settings = Settings()
    assert settings.owner_login == "alice@example.ts.net"
    assert settings.viewer_port == 8000
    assert settings.preview_origin == "https://host.ts.net:8443"
    assert settings.allowed_hosts == frozenset({"host.ts.net"})
    assert settings.trash_retention_days == 14  # untouched fields keep defaults


def test_env_overrides_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(tmp_path, monkeypatch, 'viewer_port = 8000\nowner_login = "from-toml"\n')
    monkeypatch.setenv("PDASH_VIEWER_PORT", "1234")
    settings = Settings()
    assert settings.viewer_port == 1234
    assert settings.owner_login == "from-toml"


def test_missing_toml_file_is_not_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_CONFIG", str(tmp_path / "does-not-exist.toml"))
    assert Settings().trash_retention_days == 14


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(totally_unknown_field="x")  # type: ignore[call-arg]


# --- simple limits ----------------------------------------------------------


@pytest.mark.parametrize("value", [0, -1, -14])
def test_retention_must_be_at_least_one_day(value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(trash_retention_days=value)


@pytest.mark.parametrize(
    "field",
    [
        "max_files",
        "max_file_bytes",
        "max_item_bytes",
        "max_total_bytes",
        "max_items",
        "publish_rate_per_hour",
        "render_cap_bytes",
        "min_free_disk_bytes",
        "viewer_port",
        "preview_port",
    ],
)
def test_limits_must_be_positive(field: str) -> None:
    # BaseSettings' generated __init__ signature defeats **kwargs typing here;
    # the ValidationError assertion is the actual point of the test.
    with pytest.raises(ValidationError):
        Settings(**{field: 0})  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        Settings(**{field: -1})  # type: ignore[arg-type]


def test_max_file_bytes_must_not_exceed_max_item_bytes() -> None:
    with pytest.raises(ValidationError):
        Settings(max_file_bytes=2000, max_item_bytes=1000)
    assert Settings(max_file_bytes=1000, max_item_bytes=1000).max_file_bytes == 1000


def test_max_item_bytes_must_not_exceed_max_total_bytes() -> None:
    with pytest.raises(ValidationError):
        Settings(max_file_bytes=10, max_item_bytes=2000, max_total_bytes=1000)


# --- network / identity (C1-C3, C5) --------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "::1"])
def test_viewer_host_accepts_loopback(host: str) -> None:
    assert Settings(viewer_host=host).viewer_host == host


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "100.64.0.1", "192.168.1.2", "localhost", ""])  # noqa: S104
def test_viewer_host_rejects_non_loopback(host: str) -> None:
    with pytest.raises(ValidationError):
        Settings(viewer_host=host)


@pytest.mark.parametrize("port", [65536, 100000])
def test_ports_must_be_in_range(port: int) -> None:
    with pytest.raises(ValidationError):
        Settings(viewer_port=port)
    with pytest.raises(ValidationError):
        Settings(preview_port=port)


def test_ports_must_differ() -> None:
    with pytest.raises(ValidationError):
        Settings(viewer_port=9000, preview_port=9000)


def test_owner_login_is_stripped() -> None:
    assert Settings(owner_login="  alice@github \n").owner_login == "alice@github"


@pytest.mark.parametrize(
    "login",
    ["alice\x00@github", "alice\r\n@github", "ali ce@github", "alice\u200b@github", "a\x7f"],
)
def test_owner_login_rejects_control_and_whitespace(login: str) -> None:
    with pytest.raises(ValidationError):
        Settings(owner_login=login)


@pytest.mark.parametrize("host", ["host.ts.net", "a", "my-host.tailxxxx.ts.net"])
def test_allowed_hosts_accepts_exact_hostnames(host: str) -> None:
    assert host in Settings(allowed_hosts=frozenset({host})).allowed_hosts


@pytest.mark.parametrize(
    "host",
    [
        "*.ts.net",
        "*",
        "host.ts.net:443",
        "https://host.ts.net",
        "Host.ts.net",
        "",
        "host..ts.net",
        "-host.ts.net",
        "host.ts.net/",
        "host ts.net",
    ],
)
def test_allowed_hosts_rejects_non_exact(host: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_hosts=frozenset({host}))


def test_allowed_hosts_from_env_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_ALLOWED_HOSTS", json.dumps(["host.ts.net"]))
    assert Settings().allowed_hosts == frozenset({"host.ts.net"})


def test_preview_origin_accepts_exact_origin() -> None:
    settings = Settings(
        preview_origin="https://host.ts.net:8443", allowed_hosts=frozenset({"host.ts.net"})
    )
    assert settings.preview_origin == "https://host.ts.net:8443"


@pytest.mark.parametrize(
    "origin",
    [
        "http://host.ts.net:8443",
        "https://host.ts.net",
        "https://host.ts.net:443",
        "https://host.ts.net:8443/",
        "https://host.ts.net:8443/path",
        "https://host.ts.net:8443?x=1",
        "https://user@host.ts.net:8443",
        "https://HOST.ts.net:8443",
        "https://host.ts.net:99999",
        "https://host.ts.net:abc",
        "https://*.ts.net:8443",
        "host.ts.net:8443",
    ],
)
def test_preview_origin_rejects_malformed(origin: str) -> None:
    with pytest.raises(ValidationError):
        Settings(preview_origin=origin)


# --- intake roots (C10) ----------------------------------------------------------


@pytest.mark.parametrize(
    "root",
    [
        "/",
        "/root",
        "/etc",
        "/home",
        "/var",
        "/usr",
        "/proc",
        "/proc/self",
        "/sys/kernel",
        "/dev",
        "/root/.ssh",
        "/root/.ssh/keys",
        "/etc/preview-dashboard",
        "/var/lib/preview-dashboard",
        "/var/lib/preview-dashboard/blobs",
        "/var/lib",
        # unit 10b L1: a POSIX double-slash root resolves to the same place
        # as its single-slash form on this platform, but compares unequal
        # lexically -- must be refused before it can slip past the
        # _FORBIDDEN_EXACT_ROOTS / sensitive-path equality checks.
        "//",
        "//etc",
        "//root",
    ],
)
def test_forbidden_intake_roots(root: str) -> None:
    with pytest.raises(ValidationError):
        Settings(intake_allowed_roots=(Path(root),))


@pytest.mark.parametrize(
    "root", ["relative/dir", "/root/outbox/../.ssh", "/root/outbox/..", "///etc"]
)
def test_intake_roots_must_be_absolute_and_normalized(root: str) -> None:
    with pytest.raises(ValidationError):
        Settings(intake_allowed_roots=(Path(root),))


def test_intake_roots_must_not_be_empty() -> None:
    with pytest.raises(ValidationError):
        Settings(intake_allowed_roots=())


def test_intake_root_ok() -> None:
    settings = Settings(intake_allowed_roots=(Path("/root/outbox"), Path("/srv/share")))
    assert settings.intake_allowed_roots == (Path("/root/outbox"), Path("/srv/share"))


# --- intake denylist (C10) -------------------------------------------------------


def test_custom_patterns_are_unioned_with_defaults() -> None:
    settings = Settings(intake_denied_patterns=frozenset({"*.Custom"}))
    assert "*.custom" in settings.intake_denied_patterns  # casefolded
    assert settings.intake_denied_patterns >= DEFAULT_INTAKE_DENIED_PATTERNS


def test_empty_patterns_cannot_remove_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_toml(tmp_path, monkeypatch, "intake_denied_patterns = []\n")
    assert Settings().intake_denied_patterns == DEFAULT_INTAKE_DENIED_PATTERNS


def test_patterns_are_nfc_normalized() -> None:
    decomposed = "cafe\u0301"  # "cafe" + combining acute (NFD)
    settings = Settings(intake_denied_patterns=frozenset({decomposed}))
    assert "caf\u00e9" in settings.intake_denied_patterns


@pytest.mark.parametrize("pattern", ["", "/abs", "trailing/", "a/../b", "nul\x00"])
def test_invalid_patterns_rejected(pattern: str) -> None:
    with pytest.raises(ValidationError):
        Settings(intake_denied_patterns=frozenset({pattern}))


# --- env may only narrow (C17) ------------------------------------------------------


def test_env_can_narrow_roots_under_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_INTAKE_ALLOWED_ROOTS", json.dumps(["/root/outbox/project"]))
    assert Settings().intake_allowed_roots == (Path("/root/outbox/project"),)


@pytest.mark.parametrize("root", ["/srv/share", "/root/outbox2", "/root/outbox/../dashboard"])
def test_env_cannot_widen_roots(monkeypatch: pytest.MonkeyPatch, root: str) -> None:
    monkeypatch.setenv("PDASH_INTAKE_ALLOWED_ROOTS", json.dumps([root]))
    with pytest.raises(ValueError, match=r"PDASH_INTAKE_ALLOWED_ROOTS|normalized"):
        Settings()


def test_env_roots_are_checked_against_toml_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_toml(tmp_path, monkeypatch, 'intake_allowed_roots = ["/srv/share"]\n')
    monkeypatch.setenv("PDASH_INTAKE_ALLOWED_ROOTS", json.dumps(["/srv/share/sub"]))
    assert Settings().intake_allowed_roots == (Path("/srv/share/sub"),)

    monkeypatch.setenv("PDASH_INTAKE_ALLOWED_ROOTS", json.dumps(["/root/outbox"]))
    with pytest.raises(SettingsError):
        Settings()


def test_env_patterns_union_with_toml_and_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_toml(tmp_path, monkeypatch, 'intake_denied_patterns = ["*.fromtoml"]\n')
    monkeypatch.setenv("PDASH_INTAKE_DENIED_PATTERNS", json.dumps(["*.fromenv"]))
    patterns = Settings().intake_denied_patterns
    assert {"*.fromtoml", "*.fromenv"} <= patterns
    assert patterns >= DEFAULT_INTAKE_DENIED_PATTERNS


@pytest.mark.parametrize(
    ("var", "value"),
    [
        ("PDASH_MAX_FILES", "501"),
        ("PDASH_MAX_FILE_BYTES", str(200 * 1024 * 1024)),
        ("PDASH_MAX_ITEMS", "9999"),
        ("PDASH_PUBLISH_RATE_PER_HOUR", "1000"),
        ("PDASH_MIN_FREE_DISK_BYTES", "1"),
    ],
)
def test_env_cannot_loosen_limits(monkeypatch: pytest.MonkeyPatch, var: str, value: str) -> None:
    monkeypatch.setenv(var, value)
    with pytest.raises(SettingsError):
        Settings()


def test_env_can_tighten_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PDASH_MAX_FILES", "10")
    monkeypatch.setenv("PDASH_MIN_FREE_DISK_BYTES", str(2 * GIB))
    settings = Settings()
    assert settings.max_files == 10
    assert settings.min_free_disk_bytes == 2 * GIB


def test_env_limits_compared_to_toml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_toml(tmp_path, monkeypatch, "max_files = 50\n")
    monkeypatch.setenv("PDASH_MAX_FILES", "100")
    with pytest.raises(SettingsError):
        Settings()


def test_kwargs_are_not_narrowed() -> None:
    # Constructor kwargs come from trusted code (bootstrap, tests), not env.
    assert Settings(max_files=10_000).max_files == 10_000


# --- config file ownership (C16) -----------------------------------------------------


def _secure_file(tmp_path: Path) -> Path:
    tmp_path.chmod(0o755)
    path = tmp_path / "config.toml"
    path.write_text("")
    path.chmod(0o640)
    return path


def test_secure_config_file_passes(tmp_path: Path) -> None:
    verify_config_file_secure(_secure_file(tmp_path), expected_uid=os.getuid())


def test_missing_config_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    verify_config_file_secure(missing, expected_uid=os.getuid())
    with pytest.raises(ConfigError):
        verify_config_file_secure(missing, expected_uid=os.getuid(), missing_ok=False)


@pytest.mark.parametrize("mode", [0o660, 0o646, 0o666])
def test_group_or_world_writable_file_rejected(tmp_path: Path, mode: int) -> None:
    path = _secure_file(tmp_path)
    path.chmod(mode)
    with pytest.raises(ConfigError, match="writable"):
        verify_config_file_secure(path, expected_uid=os.getuid())


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o1777])
def test_writable_parent_dir_rejected(tmp_path: Path, mode: int) -> None:
    path = _secure_file(tmp_path)
    tmp_path.chmod(mode)
    try:
        with pytest.raises(ConfigError, match="writable"):
            verify_config_file_secure(path, expected_uid=os.getuid())
    finally:
        tmp_path.chmod(0o755)


def test_wrong_owner_rejected(tmp_path: Path) -> None:
    path = _secure_file(tmp_path)
    with pytest.raises(ConfigError, match="owned"):
        verify_config_file_secure(path, expected_uid=os.getuid() + 1)


def test_symlink_rejected(tmp_path: Path) -> None:
    target = _secure_file(tmp_path)
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match="symlink"):
        verify_config_file_secure(link, expected_uid=os.getuid())


def test_non_regular_file_rejected(tmp_path: Path) -> None:
    _secure_file(tmp_path)
    directory = tmp_path / "dir.toml"
    directory.mkdir()
    with pytest.raises(ConfigError, match="regular"):
        verify_config_file_secure(directory, expected_uid=os.getuid())


def test_default_expected_uid_is_root(tmp_path: Path) -> None:
    path = _secure_file(tmp_path)
    if os.getuid() == 0:
        verify_config_file_secure(path)
    else:
        with pytest.raises(ConfigError):
            verify_config_file_secure(path)


# --- publish deadline / orphan grace (C11) ---------------------------------------------


def test_publish_timeout_and_grace_defaults() -> None:
    settings = Settings()
    assert settings.publish_timeout_seconds == 600
    assert settings.orphan_grace_seconds == 3600


@pytest.mark.parametrize(("timeout", "grace"), [(600, 600), (600, 599), (10, 1)])
def test_orphan_grace_must_exceed_publish_timeout(timeout: int, grace: int) -> None:
    with pytest.raises(ValidationError, match="orphan_grace_seconds"):
        Settings(publish_timeout_seconds=timeout, orphan_grace_seconds=grace)


@pytest.mark.parametrize("field", ["publish_timeout_seconds", "orphan_grace_seconds"])
def test_publish_timeout_and_grace_must_be_positive(field: str) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: 0})  # type: ignore[arg-type]


def test_env_may_only_shorten_timeout_and_lengthen_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PDASH_PUBLISH_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("PDASH_ORPHAN_GRACE_SECONDS", "7200")
    settings = Settings()
    assert (settings.publish_timeout_seconds, settings.orphan_grace_seconds) == (60, 7200)
    monkeypatch.setenv("PDASH_PUBLISH_TIMEOUT_SECONDS", "601")
    with pytest.raises(SettingsError):
        Settings()
    monkeypatch.setenv("PDASH_PUBLISH_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("PDASH_ORPHAN_GRACE_SECONDS", "3599")
    with pytest.raises(SettingsError):
        Settings()
