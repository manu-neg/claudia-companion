"""Command-line entry point for the `preview-dashboard` script (systemd + operator use).

Subcommands: `serve-admin`, `serve-viewer`, `serve-notifier`, `purge`,
`prune-revisions`, `empty-trash` (permanent deletes, ADR 0030), `gen-token`,
`migrate`, `check-config`, `question wait`, `notify pair`, `notify test`,
`claudia totp setup` (ADR 0031). Every command that reads configuration
vets the TOML file first (C16) and fails closed with a short message and a
non-zero exit code. Nothing here ever prints or logs a token; the TOTP
secret is shown exactly once, on the setup terminal.
"""

from __future__ import annotations

import argparse
import dataclasses
import grp
import importlib
import json
import logging
import os
import pwd
import secrets
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, TextIO, cast

from pydantic import ValidationError as PydanticValidationError
from pydantic_settings import SettingsError

from preview_dashboard.adapters.fs_blobstore import UnsafeStorageLayoutError
from preview_dashboard.adapters.sqlite import DatabaseSetupError, UnsafeDatabasePathError
from preview_dashboard.adapters.stepup_state import StepUpStateError, open_stepup_state
from preview_dashboard.adapters.totp_secret import TotpSecretFileError, write_totp_secret
from preview_dashboard.adapters.viewer_decision_client import AdminDecisionClient
from preview_dashboard.bootstrap import (
    StorageTrust,
    ViewerCore,
    build_core,
    effective_trust,
    migrate_database,
    verify_config,
)
from preview_dashboard.config import ConfigError, Settings
from preview_dashboard.domain.errors import DomainError, StorageUnavailableError, ValidationError
from preview_dashboard.domain.models import MAX_REVISIONS, is_ulid
from preview_dashboard.domain.totp import (
    SECRET_BYTES,
    encode_secret,
    matching_step,
    otpauth_uri,
    time_step,
)
from preview_dashboard.interfaces.admin.auth import TokenFileError, load_admin_token
from preview_dashboard.interfaces.mcp.admin_socket import AdminSocketTrustError, verify_admin_socket
from preview_dashboard.interfaces.mcp.client import AdminClient, AdminClientError
from preview_dashboard.interfaces.notifier.commands import (
    NOTIFIER_OWN_TOKEN,
    NotifierError,
    pair,
    send_test,
)
from preview_dashboard.interfaces.notifier.commands import serve_notifier as run_notifier
from preview_dashboard.interfaces.question_wait import (
    option_label,
    parse_duration,
    wait_for_question,
)
from preview_dashboard.interfaces.token_file import TokenGroupPolicy, TokenKind, TokenLoader
from preview_dashboard.ports.stepup import StepUpStateStore

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
# `question wait` outcomes (backlog 5.0): 0 answered, 3 expired, 4 cancelled, 5 timeout.
EXIT_EXPIRED = 3
EXIT_CANCELLED = 4
EXIT_TIMEOUT = 5
_WAIT_EXIT_CODES = {"answered": EXIT_OK, "expired": EXIT_EXPIRED, "cancelled": EXIT_CANCELLED}
DEFAULT_WAIT_TIMEOUT = "24h"
TOKEN_BYTES = 32  # secrets.token_urlsafe(32) -> 43 chars, 256 bits (C12)
TOKEN_FILE_MODE = 0o640
_TOKEN_OPEN_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
VIEWER_SERVER_MODULE = "preview_dashboard.interfaces.viewer.server"
# Labels the authenticator app shows for the step-up account (C47).
TOTP_ISSUER: Final = "Preview Dashboard"
TOTP_ACCOUNT: Final = "Claudia"
TOTP_SETUP_TRIES: Final = 3
# `--token-group totp=GROUP`: the TOTP secret's dedicated group (S-C1 S2), not a token kind.
TOTP_GROUP_KIND: Final = "totp"

# Startup failures we report as one line (no traceback): all fail-closed checks.
_STARTUP_ERRORS: tuple[type[Exception], ...] = (
    ConfigError,
    PydanticValidationError,
    SettingsError,
    TokenFileError,
    UnsafeStorageLayoutError,
    UnsafeDatabasePathError,
    DatabaseSetupError,
    NotifierError,
    FileNotFoundError,
    PermissionError,
)

# `question wait` reports all of these as exit 1 (its codes 2-5 mean outcomes).
_WAIT_ERRORS: tuple[type[Exception], ...] = (
    *_STARTUP_ERRORS,
    AdminSocketTrustError,
    AdminClientError,
)


class CliError(Exception):
    """A user-facing failure: printed as one line, exit code 1."""


class _ViewerServer(Protocol):
    def serve(self, core: ViewerCore, *, decider: AdminDecisionClient | None = None) -> None: ...


def load_settings() -> Settings:
    """Vet the config file (C16) *before* trusting it, then load `Settings`."""
    verify_config()
    return Settings()


def _trust(uids: Sequence[int], sidecar_uids: Sequence[int] = ()) -> StorageTrust:
    return effective_trust(extra_uids=uids, sidecar_uids=sidecar_uids)


def _sidecar_trust(args: argparse.Namespace) -> StorageTrust:
    """Admin-side roles: own euid, plus `--trusted-sidecar-uid`s for `-wal`/`-shm` (ADR 0025)."""
    return _trust((), args.trusted_sidecar_uid or ())


def resolve_group(value: str) -> int:
    """Return the gid of group `value` (a name, or a numeric gid that exists).

    Raises:
        CliError: no such group.
    """
    try:
        if value.isascii() and value.isdigit():
            return grp.getgrgid(int(value)).gr_gid
        return grp.getgrnam(value).gr_gid
    except (KeyError, OverflowError):
        raise CliError(f"unknown group {value!r}") from None


def token_groups(values: Sequence[str], *, own: TokenKind) -> TokenGroupPolicy:
    """Build the per-file token group policy from `--token-group` values (ADR 0024).

    Args:
        values: `GROUP` (unscoped, backward compatible) or `KIND=GROUP`
            with KIND one of admin, notifier, telegram (that file only).
        own: the command's own token file (this process's egid may own it).

    Raises:
        CliError: unknown group or token kind.
        TokenFileError: one group named for two different files.
    """
    scoped: dict[TokenKind, set[int]] = {}
    shared: set[int] = set()
    for value in values:
        kind_name, sep, group = value.partition("=")
        if not sep:
            shared.add(resolve_group(value))
            continue
        if kind_name == TOTP_GROUP_KIND:
            continue  # the TOTP secret's group, see `totp_groups`
        try:
            kind = TokenKind(kind_name)
        except ValueError:
            kinds = ", ".join(k.value for k in TokenKind)
            raise CliError(f"--token-group {value!r}: token kind must be one of {kinds}") from None
        scoped.setdefault(kind, set()).add(resolve_group(group))
    return TokenGroupPolicy(
        own=own,
        scoped={kind: frozenset(gids) for kind, gids in scoped.items()},
        shared=frozenset(shared),
    )


def _token_groups(args: argparse.Namespace, own: TokenKind) -> TokenGroupPolicy:
    return token_groups(args.token_group or (), own=own)


def totp_groups(values: Sequence[str], *, tokens: TokenGroupPolicy) -> frozenset[int]:
    """The groups trusted on the TOTP secret: every `--token-group totp=GROUP` (S-C1 S2).

    The secret's group must be the admin's alone (`pdash-totp`), so it is
    refused when it is root (nothing to add), the process's primary group
    (`tokens.egid`: `pdash`, shared with the viewer) or any group trusted
    for a token file (another service could read the secret).

    Args:
        values: all `--token-group` values (non-`totp=` ones are ignored).
        tokens: this process's token group policy (`token_groups`).

    Raises:
        CliError: unknown group, or one of the refused groups above.
    """
    token_gids = {tokens.egid, *tokens.shared}
    for gids in tokens.scoped.values():
        token_gids |= gids
    found: set[int] = set()
    for value in values:
        kind_name, sep, group = value.partition("=")
        if not sep or kind_name != TOTP_GROUP_KIND:
            continue
        gid = resolve_group(group)
        if gid == 0 or gid in token_gids:
            raise CliError(
                f"--token-group {value!r}: the TOTP secret needs its own group (not root, "
                "not this service's primary group, not a token file's group)"
            )
        found.add(gid)
    return frozenset(found)


# --- commands ---------------------------------------------------------------------


def cmd_serve_admin(args: argparse.Namespace, out: TextIO) -> int:
    """Run the admin API on the configured Unix socket until stopped."""
    # Lazy imports: only the admin process needs uvicorn/FastAPI loaded.
    from preview_dashboard.interfaces.admin.app import build_admin_app
    from preview_dashboard.interfaces.admin.server import serve

    settings = load_settings()
    # One loader: admin.token and notifier.token may not share a group (ADR 0024).
    policy = _token_groups(args, TokenKind.ADMIN)
    totp_gids = totp_groups(args.token_group or (), tokens=policy)
    if settings.claudia_enabled and not totp_gids:
        # Without its own group the secret is unreadable (root) or shared (pdash): fail closed.
        raise CliError("claudia_enabled needs --token-group totp=GROUP (the TOTP secret's group)")
    tokens = TokenLoader(policy)
    token = tokens.load(TokenKind.ADMIN, settings.admin_token_file)
    # The notifier token is only needed (and only accepted) with notifications on.
    notifier_token = (
        tokens.load(TokenKind.NOTIFIER, settings.notifier_token_file)
        if settings.notify_enabled
        else None
    )
    # Same for the claudia token (ADR 0031, C45): no file read unless enabled.
    claudia_token = (
        tokens.load(TokenKind.CLAUDIA, settings.claudia_token_file)
        if settings.claudia_enabled
        else None
    )
    # And the viewer token (F-CL6): only with dashboard decisions active.
    viewer_token = (
        tokens.load(TokenKind.VIEWER, settings.viewer_token_file)
        if settings.dashboard_decisions_active
        else None
    )
    allowed = tuple(args.allowed_peer_uid or ())
    notifier_peers = tuple(args.notifier_peer_uid or ())
    claudia_peers = tuple(args.claudia_peer_uid or ())
    # No viewer token = no /v1/viewer/* caller: the uid is not admitted either
    # (the static admin unit always passes it, F-CL6).
    viewer_peers = tuple(args.viewer_peer_uid or ()) if viewer_token is not None else ()
    with build_core(
        settings, role="admin", trust=_sidecar_trust(args), totp_gids=totp_gids
    ) as core:
        try:
            app = build_admin_app(
                core,
                token=token,
                notifier_token=notifier_token,
                allowed_peer_uids=allowed,
                notifier_peer_uids=notifier_peers,
                claudia_token=claudia_token,
                claudia_peer_uids=claudia_peers,
                viewer_token=viewer_token,
                viewer_peer_uids=viewer_peers,
            )
        except ValueError as exc:
            raise CliError(f"refusing to start: {exc}") from None
        del token, notifier_token, claudia_token, viewer_token  # verifiers keep only digests
        serve(
            app,
            settings.admin_socket,
            allowed_peer_uids=(*allowed, *notifier_peers, *claudia_peers, *viewer_peers),
        )
    return EXIT_OK


def cmd_serve_viewer(args: argparse.Namespace, out: TextIO) -> int:
    """Run the viewer apps (hook into the viewer interface's server module)."""
    try:
        module = importlib.import_module(VIEWER_SERVER_MODULE)
    except ModuleNotFoundError as exc:
        if exc.name != VIEWER_SERVER_MODULE:
            raise
        raise CliError(
            f"serve-viewer is not available yet: {VIEWER_SERVER_MODULE} (unit 8b) is missing"
        ) from None
    server = cast(_ViewerServer, module)
    settings = load_settings()
    decider = viewer_decider(settings, _token_groups(args, TokenKind.VIEWER))
    try:
        with build_core(
            settings, role="viewer", trust=_trust(args.trusted_owner_uid or ())
        ) as core:
            server.serve(core, decider=decider)
    finally:
        if decider is not None:
            decider.close()
    return EXIT_OK


def viewer_decider(settings: Settings, policy: TokenGroupPolicy) -> AdminDecisionClient | None:
    """The viewer's admin client for dashboard Approve/Deny (F-CL6), or None when off.

    On only when `dashboard_decisions_active` (Claudia on, switch not off) and
    an approvals snapshot is set (the owner must see what he decides). The
    viewer token is loaded with the C12 rules (refuse to start on a bad file,
    I6); the admin socket is verified
    before every call, so a viewer started before the admin still works.

    Raises:
        TokenFileError: the viewer token file breaks a C12 rule.
    """
    if not settings.dashboard_decisions_active or settings.claudia_approvals_snapshot is None:
        return None
    token = TokenLoader(policy).load(TokenKind.VIEWER, settings.viewer_token_file)
    try:
        return AdminDecisionClient(settings.admin_socket, token, socket_check=verify_admin_socket)
    finally:
        del token  # only the client's default header keeps it


def cmd_purge(args: argparse.Namespace, out: TextIO) -> int:
    """Run one purge pass and print its report as JSON.

    No `now` override on purpose: a future `now` would shorten the orphan
    grace period and could delete blobs of in-flight publishes.
    """
    settings = load_settings()
    with build_core(settings, role="purge", trust=_sidecar_trust(args)) as core:
        report = core.purge.run()
    # Every report field (items, blobs, questions, notifications, ...).
    fields = {f.name: getattr(report, f.name) for f in dataclasses.fields(report)}
    fields["maintenance"] = dict(report.maintenance)
    json.dump(fields, out, sort_keys=True)
    out.write("\n")
    return EXIT_OK


def cmd_prune_revisions(args: argparse.Namespace, out: TextIO) -> int:
    """Permanently delete an active item's old revisions; print a JSON report (ADR 0030).

    Runs in-process with the purge role: run it as `pdash-admin`, like the
    purge unit, never as plain root (root-created DB sidecars/blobs would
    break the storage trust checks). No title is printed (published text
    stays out of terminals and logs).
    """
    settings = load_settings()
    with build_core(settings, role="purge", trust=_sidecar_trust(args)) as core:
        try:
            result = core.history.prune_revisions(args.item_id, keep=args.keep)
        except DomainError as exc:
            raise CliError(f"prune-revisions refused: {exc}") from None
    report = {
        "item_id": result.item.id,
        "revision": result.item.revision,
        "revisions_kept": len(result.item.revisions),
        "revisions_removed": result.revisions_removed,
        "bytes_freed": result.bytes_freed,
    }
    json.dump(report, out, sort_keys=True)
    out.write("\n")
    return EXIT_OK


def cmd_empty_trash(args: argparse.Namespace, out: TextIO) -> int:
    """Permanently delete every trashed item now; print a JSON report (ADR 0030).

    Purge role: run it as `pdash-admin`, like the purge unit, never as plain root.
    """
    settings = load_settings()
    with build_core(settings, role="purge", trust=_sidecar_trust(args)) as core:
        report = core.purge.empty_trash()
    json.dump(
        {"items_purged": report.items_purged, "blobs_deleted": report.blobs_deleted},
        out,
        sort_keys=True,
    )
    out.write("\n")
    return EXIT_OK


def write_token_file(path: Path, *, group: str | None = None) -> None:
    """Create a new admin token file (0640), never overwriting or following symlinks.

    The finished file is re-read with the same checks the services apply
    (`load_admin_token`, trusting `group`), so a token that serve-admin or
    the MCP client would refuse (e.g. in an unsafe directory) is never left
    behind.

    Raises:
        CliError: the file exists (or is a symlink), the group is unknown,
            or the written file fails the loader's checks (it is removed).
    """
    gid = -1 if group is None else resolve_group(group)
    try:
        fd = os.open(path, _TOKEN_OPEN_FLAGS, TOKEN_FILE_MODE)
    except FileExistsError:
        raise CliError(f"{path} already exists; refusing to overwrite it") from None
    except OSError as exc:
        raise CliError(f"cannot create {path}: {exc.strerror}") from None
    try:
        os.fchmod(fd, TOKEN_FILE_MODE)  # exact mode, whatever the umask
        if gid != -1:
            os.fchown(fd, -1, gid)
        data = (secrets.token_urlsafe(TOKEN_BYTES) + "\n").encode("ascii")
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(path)
        raise
    os.close(fd)
    try:
        load_admin_token(path, trusted_gids=() if gid == -1 else (gid,))
    except TokenFileError as exc:
        os.unlink(path)
        raise CliError(f"refusing to keep the new token file: {exc}") from None


def cmd_gen_token(args: argparse.Namespace, out: TextIO) -> int:
    """Generate a new admin token file; prints the path, never the token."""
    path = Path(args.out)
    write_token_file(path, group=args.group)
    out.write(f"wrote new admin token to {path} (mode 0640)\n")
    return EXIT_OK


def cmd_migrate(args: argparse.Namespace, out: TextIO) -> int:
    """Create or migrate the database schema; print the schema version."""
    settings = load_settings()
    version = migrate_database(
        settings, _trust(args.trusted_owner_uid or (), args.trusted_sidecar_uid or ())
    )
    out.write(f"database schema at version {version}\n")
    return EXIT_OK


def cmd_check_config(args: argparse.Namespace, out: TextIO) -> int:
    """Validate config file, settings and (unless skipped) the admin token file."""
    settings = load_settings()
    report: dict[str, object] = {
        "config": "ok",
        "data_dir": str(settings.data_dir),
        "admin_socket": str(settings.admin_socket),
        "owner_login_set": bool(settings.owner_login),
        "allowed_hosts": sorted(settings.allowed_hosts),
        "preview_origin": settings.preview_origin,
        "notify_enabled": settings.notify_enabled,
        "notify_owner_chat_id_set": settings.notify_owner_chat_id is not None,
    }
    status = EXIT_OK
    if not args.skip_token:
        # Same per-file rules as serve-admin (ADR 0024).
        tokens = TokenLoader(_token_groups(args, TokenKind.ADMIN))
        try:
            tokens.load(TokenKind.ADMIN, settings.admin_token_file)
            report["credentials_file"] = "ok"
        except TokenFileError as exc:
            report["credentials_file"] = str(exc)
            status = EXIT_FAILED
        if settings.notify_enabled:
            # serve-admin loads it too when notifications are on.
            try:
                tokens.load(TokenKind.NOTIFIER, settings.notifier_token_file)
                report["notifier_credentials_file"] = "ok"
            except TokenFileError as exc:
                report["notifier_credentials_file"] = str(exc)
                status = EXIT_FAILED
        if settings.claudia_enabled:
            try:
                tokens.load(TokenKind.CLAUDIA, settings.claudia_token_file)
                report["claudia_credentials_file"] = "ok"
            except TokenFileError as exc:
                report["claudia_credentials_file"] = str(exc)
                status = EXIT_FAILED
        if settings.dashboard_decisions_active:
            # serve-admin verifies it; serve-viewer presents it (F-CL6).
            try:
                tokens.load(TokenKind.VIEWER, settings.viewer_token_file)
                report["viewer_credentials_file"] = "ok"
            except TokenFileError as exc:
                report["viewer_credentials_file"] = str(exc)
                status = EXIT_FAILED
    report["claudia_enabled"] = settings.claudia_enabled
    # The effective value (switch on and Claudia on): check.sh wires/warns on it.
    report["claudia_dashboard_decisions"] = settings.dashboard_decisions_active
    # C61/C62: check.sh warns when voice input is on without the whisper install.
    report["claudia_voice_input_enabled"] = settings.claudia_voice_input_enabled
    report["claudia_photo_input_enabled"] = settings.claudia_photo_input_enabled
    # Names only: check.sh warns when Claudia is on but the viewer panel has no snapshot path.
    report["claudia_approvals_snapshot_set"] = settings.claudia_approvals_snapshot is not None
    json.dump(report, out, sort_keys=True, indent=2)
    out.write("\n")
    return status


@dataclass(frozen=True, slots=True, kw_only=True)
class TerminalIO:
    """What `totp_setup` needs from its terminal (tests replace every part)."""

    out: TextIO
    stdin_isatty: Callable[[], bool]
    stdout_isatty: Callable[[], bool]
    read_code: Callable[[str], str]
    is_root: Callable[[], bool]
    now: Callable[[], float]


class GroupDb(Protocol):
    """The account lookups `vet_totp_group` needs (tests pass a fake)."""

    def user_name(self, uid: int) -> str:
        """Login name of `uid`; raise `KeyError` if unknown."""
        ...

    def primary_gid(self, uid: int) -> int:
        """Primary gid of `uid`; raise `KeyError` if unknown."""
        ...

    def members(self, gid: int) -> frozenset[str]:
        """Users in group `gid`: listed members plus users with it as primary group."""
        ...


class SystemGroupDb:
    """`GroupDb` over `pwd` / `grp` (the host's account database)."""

    def user_name(self, uid: int) -> str:
        """Login name of `uid` (`KeyError` if unknown)."""
        return pwd.getpwuid(uid).pw_name

    def primary_gid(self, uid: int) -> int:
        """Primary gid of `uid` (`KeyError` if unknown)."""
        return pwd.getpwuid(uid).pw_gid

    def members(self, gid: int) -> frozenset[str]:
        """Listed members of `gid` plus every user whose primary group it is."""
        listed = set(grp.getgrgid(gid).gr_mem)
        primary = {p.pw_name for p in pwd.getpwall() if p.pw_gid == gid}
        return frozenset(listed | primary)


def vet_totp_group(gid: int, *, admin_uid: int, groups: GroupDb) -> None:
    """Check that `gid` is the admin's own group for the TOTP secret (S-C1 S2/S6).

    It must not be root (the admin couldn't read the file) or the admin's
    primary group (`pdash`, shared with the viewer), the admin must be a
    member, and nobody else may be (e.g. `pdash-totp` with only `pdash-admin`).

    Raises:
        CliError: any rule fails (or an account is unknown).
    """
    try:
        admin = groups.user_name(admin_uid)
        primary = groups.primary_gid(admin_uid)
        members = groups.members(gid)
    except KeyError:
        raise CliError(f"cannot look up the admin user or group gid {gid}") from None
    if gid == 0 or gid == primary:
        raise CliError(
            f"group gid {gid} is root or the admin's primary group (shared with the viewer); "
            "use the admin-only TOTP group (e.g. --group pdash-totp)"
        )
    if admin not in members:
        raise CliError(f"the admin user {admin!r} is not in group gid {gid}; it couldn't read it")
    others = sorted(members - {admin})
    if others:
        raise CliError(f"group gid {gid} has other members ({', '.join(others)}); admin only")


def totp_setup(
    path: Path,
    term: TerminalIO,
    *,
    rotate: bool,
    group: str | None,
    state: StepUpStateStore,
    admin_uid: int,
    groups: GroupDb | None = None,
) -> int:
    """Create (or with `rotate` replace) the TOTP secret, interactively (C47).

    Root + an interactive TTY only. Shows the `otpauth://` URI and the key
    **once on the terminal** (never published, sent or logged; no QR: no
    QR library is a dependency), then needs one valid code from the app
    before anything is written (`O_EXCL`, 0640, `root:<group>`). `group`
    is required, except with `rotate`, which keeps the current file's group;
    either way it must pass `vet_totp_group` (admin-only group) before any
    secret is shown, and the written file must carry it.
    The accepted code's step is burnt in the admin's step-up `state`
    **before** the secret is written, so that code can never approve
    anything (no replay of a code seen on the terminal).

    Args:
        admin_uid: the admin service's uid (owner of `data_dir`).
        groups: account lookups (default `SystemGroupDb()`).

    Raises:
        CliError: not root, not a TTY, the file exists without `--rotate`
            (or is missing with it), no or a refused group, no valid code
            in 3 tries, the step-up state can't be read or saved (nothing
            written), or the written file fails the load checks.
    """
    if not term.is_root():
        raise CliError("claudia totp setup must run as root")
    if not (term.stdin_isatty() and term.stdout_isatty()):
        raise CliError("claudia totp setup needs an interactive terminal; refusing")
    exists = os.path.lexists(path)
    if exists and not rotate:
        raise CliError(f"{path} already exists; refusing to overwrite it (use --rotate)")
    if rotate and not exists:
        raise CliError(f"{path} does not exist; nothing to rotate (run without --rotate)")
    if group is not None:
        gid = resolve_group(group)
    elif rotate:
        gid = os.lstat(path).st_gid  # keep the group the admin already trusts
    else:
        raise CliError("--group is required (the admin-only TOTP group, e.g. pdash-totp)")
    vet_totp_group(gid, admin_uid=admin_uid, groups=groups or SystemGroupDb())
    try:
        # Fail before showing a secret the owner would enrol for nothing (lock included).
        with state.exclusive():
            state.load()
    except StorageUnavailableError as exc:
        raise CliError(f"step-up state is not usable ({exc}); nothing was written") from None
    secret = secrets.token_bytes(SECRET_BYTES)
    out = term.out
    out.write(
        "Add this account to your authenticator app (shown once, never stored elsewhere):\n"
        f"  {otpauth_uri(secret, issuer=TOTP_ISSUER, account=TOTP_ACCOUNT)}\n"
        f"  manual key: {encode_secret(secret)}\n"
    )
    out.flush()
    accepted: int | None = None
    for _ in range(TOTP_SETUP_TRIES):
        code = term.read_code("Enter the 6-digit code your app shows: ").replace(" ", "")
        try:
            accepted = matching_step(secret, code, time_step(term.now()), after_step=None)
        except ValidationError:
            accepted = None
        if accepted is not None:
            break
        out.write("That code does not match; try again.\n")
    if accepted is None:
        raise CliError("no valid code entered; nothing was written")
    # Burn first: if this fails nothing is written; if the write fails later,
    # a burnt step costs nothing (the next code is 30 s away). Re-loaded under
    # the admin's own state lock, so a code it handles meanwhile can neither
    # overwrite the burnt step nor lose its counters (storage-totp-3).
    try:
        with state.exclusive():
            state.save(state.load().with_burned_step(accepted))
    except StorageUnavailableError as exc:
        raise CliError(
            f"cannot record the setup code as used ({exc}); nothing was written"
        ) from None
    try:
        write_totp_secret(path, secret, gid=gid, replace=rotate)
    except FileExistsError:
        raise CliError(f"{path} (or its .new temp file) already exists; refusing") from None
    except TotpSecretFileError as exc:
        raise CliError(f"refusing to keep the new secret file: {exc}") from None
    except OSError as exc:
        raise CliError(f"cannot write {path}: {exc.strerror}") from None
    del secret
    out.write(
        f"wrote the TOTP secret to {path} (mode 0640, group gid {gid}); the admin reads it "
        "per code (serve-admin --token-group totp=<that group>)\n"
    )
    return EXIT_OK


def cmd_claudia_totp_setup(args: argparse.Namespace, out: TextIO) -> int:
    """Interactive TOTP secret setup for the Claudia companion (root, TTY only)."""
    settings = load_settings()
    term = TerminalIO(
        out=out,
        stdin_isatty=sys.stdin.isatty,
        stdout_isatty=out.isatty,
        read_code=input,
        is_root=lambda: os.geteuid() == 0,
        now=time.time,
    )
    data_dir = Path(settings.data_dir)
    try:
        # The admin owns its data dir; the burnt step must stay readable by it.
        admin_uid = os.lstat(data_dir).st_uid
    except OSError as exc:
        raise CliError(f"cannot use data_dir {data_dir}: {exc.strerror}") from None
    try:
        state = open_stepup_state(data_dir, owner_uid=admin_uid)
    except StepUpStateError as exc:
        raise CliError(str(exc)) from None
    return totp_setup(
        settings.totp_secret_file,
        term,
        rotate=args.rotate,
        group=args.group,
        state=state,
        admin_uid=admin_uid,
    )


def admin_client(settings: Settings, args: argparse.Namespace) -> AdminClient:
    """An admin-token client, after checking the admin socket (C12/C30, like the MCP server).

    The socket is verified before the token is read or sent; its gid (plus
    the `--token-group`s the admin token may have) is trusted on the token file.

    Raises:
        AdminSocketTrustError: the socket can't be trusted (or nothing answers).
        TokenFileError: the admin token file is unsafe.
    """
    gid = verify_admin_socket(settings.admin_socket)
    admin_gids = _token_groups(args, TokenKind.ADMIN).gids_for(TokenKind.ADMIN)
    return AdminClient.from_settings(settings, token_gids=(gid, *admin_gids))


def _question_id(value: str) -> str:
    if not is_ulid(value):
        raise argparse.ArgumentTypeError("question id must be a 26-character ULID")
    return value


def _item_id(value: str) -> str:
    if not is_ulid(value):
        raise argparse.ArgumentTypeError("item id must be a 26-character ULID")
    return value


def _keep(value: str) -> int:
    # ASCII digits only, like the admin API's integers.
    if not (value.isascii() and value.isdigit()) or not 1 <= int(value) <= MAX_REVISIONS:
        raise argparse.ArgumentTypeError(f"--keep must be an integer in 1..{MAX_REVISIONS}")
    return int(value)


def _duration(value: str) -> float:
    try:
        return parse_duration(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def cmd_question_wait(args: argparse.Namespace, out: TextIO) -> int:
    """Wait for a question's outcome; print one JSON line; exit 0/3/4/5 (1 on error).

    Loops `GET /v1/questions/{id}?wait=60` with the admin token and rides
    out admin restarts (backoff). Meant to run in the background for long waits.
    """
    try:
        settings = load_settings()
        with admin_client(settings, args) as client:
            outcome = wait_for_question(client, args.question_id, timeout=args.timeout)
    except _WAIT_ERRORS as exc:
        print(f"preview-dashboard: question wait failed: {exc}", file=sys.stderr)
        return EXIT_FAILED
    question = outcome.question
    state = question.get("state")
    line = {
        "id": question.get("id"),
        "state": state,
        "answer_key": question.get("answer_key"),
        "answer_label": option_label(question, question.get("answer_key")),
        "default_key": question.get("default_key"),
    }
    out.write(json.dumps(line, ensure_ascii=False) + "\n")
    if outcome.timed_out:
        return EXIT_TIMEOUT
    return _WAIT_EXIT_CODES.get(state if isinstance(state, str) else "", EXIT_FAILED)


def cmd_serve_notifier(args: argparse.Namespace, out: TextIO) -> int:
    """Run the notifier (Telegram deliveries + answer taps) until stopped."""
    settings = load_settings()
    return run_notifier(settings, token_groups=_token_groups(args, NOTIFIER_OWN_TOKEN))


def cmd_notify_pair(args: argparse.Namespace, out: TextIO) -> int:
    """Pair the bot with the owner's chat: print a code, wait, print the chat id to configure."""
    settings = load_settings()
    return pair(
        settings.telegram_token_file, out, token_groups=_token_groups(args, NOTIFIER_OWN_TOKEN)
    )


def cmd_notify_test(args: argparse.Namespace, out: TextIO) -> int:
    """Ask a two-option test question through the admin API; print its id and wait command."""
    settings = load_settings()
    try:
        with admin_client(settings, args) as client:
            return send_test(client.ask_question, out)
    except (AdminSocketTrustError, AdminClientError) as exc:
        raise CliError(f"notify test failed: {exc}") from None


# --- parser -----------------------------------------------------------------------------


def _uid(value: str) -> int:
    if not value.isdigit():
        raise argparse.ArgumentTypeError("uid must be a non-negative integer")
    return int(value)


def _add_token_group(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--token-group",
        action="append",
        metavar="[KIND=]GROUP",
        help="extra group allowed to own a token file (repeatable). KIND=GROUP "
        "(admin, notifier, telegram, claudia, viewer) trusts it for that file only; a plain "
        "GROUP may "
        "own at most one of the files this command loads. Root is always allowed; "
        "this process's own group only for its own token (admin, or telegram for the "
        "notifier). serve-admin also takes totp=GROUP: the TOTP secret's own group",
    )


def _add_trusted_sidecar_uid(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--trusted-sidecar-uid",
        type=_uid,
        action="append",
        help="extra uid allowed to own the database's -wal/-shm files only (the viewer "
        "service's uid: it recreates them when it opens the DB first; repeatable)",
    )


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser for every subcommand."""
    parser = argparse.ArgumentParser(
        prog="preview-dashboard", description="Private preview dashboard services and tools."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    admin = sub.add_parser("serve-admin", help="serve the admin API on its Unix socket")
    admin.add_argument(
        "--allowed-peer-uid",
        type=_uid,
        action="append",
        help="only serve socket peers with this uid (repeatable; default: socket perms decide)",
    )
    admin.add_argument(
        "--notifier-peer-uid",
        type=_uid,
        action="append",
        help="socket peer uid allowed on /v1/notifier/* (the notifier service user; "
        "repeatable). With any peer-uid flag, each route family only serves its own uids",
    )
    admin.add_argument(
        "--claudia-peer-uid",
        type=_uid,
        action="append",
        help="socket peer uid allowed on /v1/claudia/* (the Claudia host's user; repeatable)",
    )
    admin.add_argument(
        "--viewer-peer-uid",
        type=_uid,
        action="append",
        help="socket peer uid allowed on /v1/viewer/* (the viewer service user, for "
        "dashboard Approve/Deny; repeatable)",
    )
    _add_token_group(admin)
    _add_trusted_sidecar_uid(admin)
    admin.set_defaults(func=cmd_serve_admin)

    claudia = sub.add_parser("claudia", help="Claudia companion setup")
    claudia_sub = claudia.add_subparsers(dest="claudia_command", required=True)
    totp = claudia_sub.add_parser("totp", help="authenticator (TOTP) step-up")
    totp_sub = totp.add_subparsers(dest="totp_command", required=True)
    setup = totp_sub.add_parser(
        "setup",
        help="create the TOTP secret (root, interactive terminal only; shows the "
        "otpauth URI once and needs one valid code)",
    )
    setup.add_argument(
        "--rotate", action="store_true", help="replace an existing secret (old codes stop working)"
    )
    setup.add_argument(
        "--group",
        help="admin-only group to own the file (e.g. pdash-totp; required unless --rotate, "
        "which keeps the current group)",
    )
    setup.set_defaults(func=cmd_claudia_totp_setup)

    viewer = sub.add_parser("serve-viewer", help="serve the dashboard and preview apps")
    viewer.add_argument(
        "--trusted-owner-uid",
        type=_uid,
        action="append",
        help="extra uid allowed to own the data dir (the admin service's uid)",
    )
    # F-CL6: viewer.token's group (viewer=GROUP), read only with claudia_dashboard_decisions.
    _add_token_group(viewer)
    viewer.set_defaults(func=cmd_serve_viewer)

    notifier = sub.add_parser(
        "serve-notifier", help="run the Telegram notifier (deliveries and answer buttons)"
    )
    _add_token_group(notifier)
    notifier.set_defaults(func=cmd_serve_notifier)

    question = sub.add_parser("question", help="questions asked to the owner")
    question_sub = question.add_subparsers(dest="question_command", required=True)
    wait = question_sub.add_parser(
        "wait",
        help="wait for a question's answer; print one JSON line; "
        "exit 0 answered, 3 expired, 4 cancelled, 5 timeout, 1 error",
    )
    wait.add_argument("question_id", type=_question_id, help="id returned by dashboard_ask")
    wait.add_argument(
        "--timeout",
        type=_duration,
        default=_duration(DEFAULT_WAIT_TIMEOUT),
        metavar="DURATION",
        help=f"give up after this long, e.g. 90s, 30m, 24h, 2d (default {DEFAULT_WAIT_TIMEOUT})",
    )
    _add_token_group(wait)
    wait.set_defaults(func=cmd_question_wait)

    notify = sub.add_parser("notify", help="Telegram notification setup")
    notify_sub = notify.add_subparsers(dest="notify_command", required=True)
    pair_cmd = notify_sub.add_parser(
        "pair", help="pair the bot with your chat (root; notifier service stopped)"
    )
    _add_token_group(pair_cmd)
    pair_cmd.set_defaults(func=cmd_notify_pair)
    test_cmd = notify_sub.add_parser("test", help="send a test question (2 options)")
    _add_token_group(test_cmd)
    test_cmd.set_defaults(func=cmd_notify_test)

    purge = sub.add_parser("purge", help="purge expired trash once and print a JSON report")
    _add_trusted_sidecar_uid(purge)
    purge.set_defaults(func=cmd_purge)

    prune = sub.add_parser(
        "prune-revisions",
        help="PERMANENTLY delete an active item's old revisions (keeps the newest --keep, "
        "current one included); print a JSON report",
    )
    prune.add_argument("item_id", type=_item_id, help="the item's id")
    prune.add_argument(
        "--keep",
        type=_keep,
        default=1,
        metavar="N",
        help=f"revisions to keep, current one included (1..{MAX_REVISIONS}, default 1)",
    )
    _add_trusted_sidecar_uid(prune)
    prune.set_defaults(func=cmd_prune_revisions)

    empty = sub.add_parser(
        "empty-trash",
        help="PERMANENTLY delete every trashed item now; print a JSON report",
    )
    _add_trusted_sidecar_uid(empty)
    empty.set_defaults(func=cmd_empty_trash)

    token = sub.add_parser("gen-token", help="create a new admin token file (never overwrites)")
    token.add_argument("--out", required=True, help="path of the token file to create")
    token.add_argument("--group", help="group to own the file (e.g. the admin service group)")
    token.set_defaults(func=cmd_gen_token)

    migrate = sub.add_parser("migrate", help="create/migrate the database schema")
    migrate.add_argument("--trusted-owner-uid", type=_uid, action="append")
    _add_trusted_sidecar_uid(migrate)
    migrate.set_defaults(func=cmd_migrate)

    check = sub.add_parser("check-config", help="validate configuration and the token file")
    check.add_argument("--skip-token", action="store_true", help="don't check the token file")
    _add_token_group(check)
    check.set_defaults(func=cmd_check_config)
    return parser


def _configure_logging() -> None:
    # stderr only: systemd sends it to journald (C29). No file handlers.
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s"
    )


def main(argv: list[str] | None = None, *, out: TextIO | None = None) -> int:
    """Entry point for the `preview-dashboard` console script.

    Args:
        argv: arguments without the program name (default: `sys.argv[1:]`).
        out: where command output goes (default: stdout).

    Returns:
        Process exit code: 0 ok, 1 failed check / refused action, 2 usage
        or configuration error.
    """
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    _configure_logging()
    func: Callable[[argparse.Namespace, TextIO], int] = args.func
    try:
        return func(args, out or sys.stdout)
    except CliError as exc:
        print(f"preview-dashboard: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except _STARTUP_ERRORS as exc:
        print(f"preview-dashboard: refusing to start: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
