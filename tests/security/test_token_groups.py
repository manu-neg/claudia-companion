"""Security tests for C12/C36 per-file token groups (ADR 0024, S-B L1).

Each token file a process loads has its own trusted groups: the process's
own group only for its own token, `KIND=GROUP` groups only for that file,
and no two token files of one process in the same non-root group. So a
token readable by another process's group is refused. Plain
`--token-group GROUP` flags (what deploy passes) keep working.
"""

from __future__ import annotations

import grp
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from preview_dashboard.interfaces import cli
from preview_dashboard.interfaces.notifier.commands import NotifierError, build_notifier
from preview_dashboard.interfaces.token_file import (
    TokenFileError,
    TokenGroupPolicy,
    TokenKind,
    TokenLoader,
)
from tests.admin_support import write_token
from tests.notify_admin_support import notify_settings
from tests.telegram_support import FAKE_BOT_TOKEN, OWNER

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(os.geteuid() != 0, reason="chgrp to foreign groups needs root"),
]

# Arbitrary gids for the three service groups (need not exist for the loader).
ADMIN_G = 61001  # pdash: admin service's own group
NOTIFY_TOK_G = 61002  # pdash-notifytok: shared notifier.token group
NOTIFY_G = 61003  # pdash-notify: notifier service's own group


def token_file(path: Path, gid: int, data: bytes | None = None) -> Path:
    if data is None:
        write_token(path, mode=0o640)
    else:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, 0o640)
    os.chown(path, 0, gid)
    return path


# --- policy ---------------------------------------------------------------------------


def test_c12_own_group_only_for_own_token() -> None:
    policy = TokenGroupPolicy(own=TokenKind.ADMIN, egid=ADMIN_G, shared=frozenset({ADMIN_G}))
    assert ADMIN_G in policy.gids_for(TokenKind.ADMIN)
    # Even when also passed as a plain --token-group.
    assert ADMIN_G not in policy.gids_for(TokenKind.NOTIFIER)
    assert 0 in policy.gids_for(TokenKind.NOTIFIER)


def test_c12_scoped_group_is_trusted_for_that_file_only() -> None:
    policy = TokenGroupPolicy(
        own=TokenKind.ADMIN,
        egid=0,
        scoped={TokenKind.NOTIFIER: frozenset({NOTIFY_TOK_G})},
        shared=frozenset({NOTIFY_TOK_G, ADMIN_G}),
    )
    assert NOTIFY_TOK_G in policy.gids_for(TokenKind.NOTIFIER)
    assert NOTIFY_TOK_G not in policy.gids_for(TokenKind.ADMIN)
    assert ADMIN_G in policy.gids_for(TokenKind.ADMIN)


def test_c12_one_group_scoped_to_two_files_is_refused() -> None:
    with pytest.raises(TokenFileError, match="its own group"):
        TokenGroupPolicy(
            own=TokenKind.ADMIN,
            scoped={
                TokenKind.ADMIN: frozenset({ADMIN_G}),
                TokenKind.NOTIFIER: frozenset({ADMIN_G}),
            },
        )


# --- loader: the admin side (serve-admin / check-config) ---------------------------------


def admin_side() -> TokenLoader:
    # Exactly the deploy flags: serve-admin --token-group pdash --token-group pdash-notifytok.
    shared = frozenset({ADMIN_G, NOTIFY_TOK_G})
    return TokenLoader(TokenGroupPolicy(own=TokenKind.ADMIN, egid=ADMIN_G, shared=shared))


def test_c12_deploy_layout_loads(tmp_path: Path) -> None:
    loader = admin_side()
    loader.load(TokenKind.ADMIN, token_file(tmp_path / "admin.token", ADMIN_G))
    loader.load(TokenKind.NOTIFIER, token_file(tmp_path / "notifier.token", NOTIFY_TOK_G))


def test_c12_admin_token_in_the_notifier_token_group_is_refused(tmp_path: Path) -> None:
    loader = admin_side()
    loader.load(TokenKind.ADMIN, token_file(tmp_path / "admin.token", NOTIFY_TOK_G))
    with pytest.raises(TokenFileError, match="same group") as info:
        loader.load(TokenKind.NOTIFIER, token_file(tmp_path / "notifier.token", NOTIFY_TOK_G))
    assert "admin token" in str(info.value)


def test_c12_notifier_token_in_the_admin_group_is_refused(tmp_path: Path) -> None:
    # Swapped groups: the shared token would be readable by the admin's own group only.
    loader = admin_side()
    loader.load(TokenKind.ADMIN, token_file(tmp_path / "admin.token", NOTIFY_TOK_G))
    with pytest.raises(TokenFileError, match="untrusted group"):
        loader.load(TokenKind.NOTIFIER, token_file(tmp_path / "notifier.token", ADMIN_G))


def test_c12_notifier_service_group_is_refused_on_admin_token(tmp_path: Path) -> None:
    with pytest.raises(TokenFileError, match="untrusted group"):
        admin_side().load(TokenKind.ADMIN, token_file(tmp_path / "admin.token", NOTIFY_G))


def test_c12_root_group_may_own_every_file(tmp_path: Path) -> None:
    loader = admin_side()
    loader.load(TokenKind.ADMIN, token_file(tmp_path / "admin.token", 0))
    loader.load(TokenKind.NOTIFIER, token_file(tmp_path / "notifier.token", 0))


# --- loader: the notifier side (serve-notifier) -------------------------------------------


@dataclass(frozen=True)
class Config:
    admin_socket: Path
    notifier_token_file: Path
    telegram_token_file: Path
    notify_enabled: bool = True
    notify_owner_chat_id: int | None = OWNER
    allowed_hosts: frozenset[str] = frozenset({"dash.example.ts.net"})


def notifier_build(tmp_path: Path, *, telegram_gid: int, notifier_gid: int) -> None:
    config = Config(
        admin_socket=tmp_path / "admin.sock",
        notifier_token_file=token_file(tmp_path / "notifier.token", notifier_gid),
        telegram_token_file=token_file(
            tmp_path / "telegram.token", telegram_gid, FAKE_BOT_TOKEN.encode()
        ),
    )
    # Exactly the deploy flags: serve-notifier --token-group pdash-notifytok, run as pdash-notify.
    groups = TokenGroupPolicy(
        own=TokenKind.TELEGRAM, egid=NOTIFY_G, shared=frozenset({NOTIFY_TOK_G})
    )
    build_notifier(config, token_groups=groups, verify_socket=lambda _p: 0).close()


def test_c36_notifier_deploy_layout_loads(tmp_path: Path) -> None:
    notifier_build(tmp_path, telegram_gid=NOTIFY_G, notifier_gid=NOTIFY_TOK_G)


def test_c36_bot_token_readable_by_the_admin_is_refused(tmp_path: Path) -> None:
    # telegram.token in pdash-notifytok would be readable by the admin service.
    with pytest.raises(NotifierError, match="same group"):
        notifier_build(tmp_path, telegram_gid=NOTIFY_TOK_G, notifier_gid=NOTIFY_TOK_G)


def test_c36_bot_token_in_the_admin_group_is_refused(tmp_path: Path) -> None:
    with pytest.raises(NotifierError, match="untrusted group"):
        notifier_build(tmp_path, telegram_gid=ADMIN_G, notifier_gid=NOTIFY_TOK_G)


def test_c36_notifier_token_in_the_notifier_own_group_is_refused(tmp_path: Path) -> None:
    with pytest.raises(NotifierError, match="untrusted group"):
        notifier_build(tmp_path, telegram_gid=0, notifier_gid=NOTIFY_G)


# --- CLI: backward-compatible flags, scoped syntax ---------------------------------------


def two_groups() -> tuple[grp.struct_group, grp.struct_group]:
    groups = [g for g in grp.getgrall() if g.gr_gid not in {0, os.getegid()}]
    if len(groups) < 2:
        pytest.skip("needs two non-root groups on this host")
    return groups[0], groups[1]


def check_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *flags: str) -> dict[str, str]:
    settings = notify_settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    out = io.StringIO()
    cli.main(["check-config", *flags], out=out)
    report: dict[str, str] = json.loads(out.getvalue())
    return report


def test_c12_cli_plain_flags_still_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin, notifytok = two_groups()
    token_file(tmp_path / "secrets" / "admin.token", admin.gr_gid)
    token_file(tmp_path / "secrets" / "notifier.token", notifytok.gr_gid)
    flags = ("--token-group", admin.gr_name, "--token-group", notifytok.gr_name)
    report = check_config(tmp_path, monkeypatch, *flags)
    assert report["credentials_file"] == "ok"
    assert report["notifier_credentials_file"] == "ok"


def test_c12_cli_plain_flags_refuse_one_group_for_both(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin, notifytok = two_groups()
    token_file(tmp_path / "secrets" / "admin.token", notifytok.gr_gid)
    token_file(tmp_path / "secrets" / "notifier.token", notifytok.gr_gid)
    flags = ("--token-group", admin.gr_name, "--token-group", notifytok.gr_name)
    report = check_config(tmp_path, monkeypatch, *flags)
    assert "same group" in report["notifier_credentials_file"]


def test_c12_cli_scoped_flag_binds_the_group_to_one_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin, notifytok = two_groups()
    token_file(tmp_path / "secrets" / "admin.token", notifytok.gr_gid)
    token_file(tmp_path / "secrets" / "notifier.token", 0)
    flags = ("--token-group", admin.gr_name, "--token-group", f"notifier={notifytok.gr_name}")
    report = check_config(tmp_path, monkeypatch, *flags)
    assert "untrusted group" in report["credentials_file"]
    token_file(tmp_path / "secrets" / "admin.token", admin.gr_gid)
    token_file(tmp_path / "secrets" / "notifier.token", notifytok.gr_gid)
    report = check_config(tmp_path, monkeypatch, *flags)
    assert report["credentials_file"] == "ok" == report["notifier_credentials_file"]


def test_c12_cli_unknown_token_kind_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_settings", lambda: notify_settings(tmp_path))
    assert cli.main(["check-config", "--token-group", "viewer=root"]) == cli.EXIT_FAILED
    assert "token kind must be one of admin, notifier, telegram" in capsys.readouterr().err


def test_c12_cli_group_scoped_to_two_files_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    admin, _ = two_groups()
    monkeypatch.setattr(cli, "load_settings", lambda: notify_settings(tmp_path))
    flags = ["--token-group", f"admin={admin.gr_name}", "--token-group", f"notifier={admin.gr_gid}"]
    assert cli.main(["check-config", *flags]) == cli.EXIT_USAGE
    assert "its own group" in capsys.readouterr().err
