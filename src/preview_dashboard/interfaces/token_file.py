"""Loading bearer/bot token files (admin, notifier, Telegram), shared by every process.

One implementation of the C12 file checks (private mode, trusted owner,
group and directory, no symlink, no POSIX ACL, long high-variety
visible-ASCII token) so both ends of the admin socket (and the notifier,
C36) refuse exactly the same unsafe files. `what=` names the token in
errors ("notifier token", ...). `TokenGroupPolicy` + `TokenLoader` give
each token file its own trusted groups, so a token readable by another
process's group is refused (ADR 0024). Framework-free on purpose: the MCP
and notifier processes import it without pulling in the admin web stack.
"""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType

# secrets.token_urlsafe(32) -> 43 base64url chars = 256 bits. Anything
# shorter is refused, so a truncated or hand-typed token can't be used.
MIN_TOKEN_CHARS = 43
# A generated token has ~30 distinct chars; very few means a placeholder
# ("xxxx...") or a hand-made pattern, not 256 random bits.
MIN_DISTINCT_TOKEN_CHARS = 16
_MAX_TOKEN_FILE_BYTES = 4096
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
# Group-write or any "other" bit makes the token readable/replaceable by others.
_FORBIDDEN_TOKEN_BITS = stat.S_IWGRP | stat.S_IRWXO
_FORBIDDEN_DIR_BITS = stat.S_IWGRP | stat.S_IWOTH
DEFAULT_WHAT = "admin token"
# A POSIX ACL can grant a group/user read access invisible in `st_mode`
# (S-C, F-C item 3): its presence shows up as this xattr name.
_ACL_XATTR = "system.posix_acl_access"


class TokenFileError(RuntimeError):
    """A token file is unsafe or unusable; the process must not start.

    Messages name the file and the rule, never any token content.
    """


def trusted_token_gids(extra: Collection[int] = ()) -> frozenset[int]:
    """Groups that may own the token file: root (0), this process's egid, and `extra`."""
    return frozenset({0, os.getegid(), *extra})


def check_token_value(token: bytes, where: str, *, what: str = DEFAULT_WHAT) -> None:
    """Refuse a token that is too short, not visible ASCII, or low-variety.

    Args:
        token: the token bytes.
        where: the file it came from (named in errors).
        what: which token it is, e.g. "notifier token" (named in errors).

    Raises:
        TokenFileError: naming `what`, `where` and the rule, never the token.
    """
    if len(token) < MIN_TOKEN_CHARS:
        raise TokenFileError(
            f"{what} in {where} is empty or too short "
            f"(need >= {MIN_TOKEN_CHARS} chars, e.g. `preview-dashboard gen-token`)"
        )
    if any(b < 0x21 or b > 0x7E for b in token):
        raise TokenFileError(f"{what} in {where} must be one line of visible ASCII")
    if len(set(token)) < MIN_DISTINCT_TOKEN_CHARS:
        raise TokenFileError(
            f"{what} in {where} has too few distinct characters "
            f"(need >= {MIN_DISTINCT_TOKEN_CHARS}; use `preview-dashboard gen-token`)"
        )


def load_admin_token(
    path: Path,
    *,
    trusted_uids: Collection[int] | None = None,
    trusted_gids: Collection[int] = (),
    what: str = DEFAULT_WHAT,
) -> bytes:
    """Read and validate a token file with the C12 rules. Call once at startup.

    Used for a single token file (e.g. the MCP client's admin token); a
    process that loads several token files uses `TokenLoader` instead, so
    each file gets its own trusted groups.

    Rules (fail closed): not a symlink (`O_NOFOLLOW`), a regular file, owned
    by root or this process's euid (or `trusted_uids`), group root, this
    process's egid or one of `trusted_gids` (the group can read a 0640
    file), no group-write and no access for others (0640 or stricter), no
    POSIX ACL (would grant access invisible in the mode bits), parent
    directory not group/world writable, content one line of >= 43 visible
    ASCII characters with >= 16 distinct ones.

    Args:
        path: the token file.
        trusted_uids: allowed owners (default: root and this euid).
        trusted_gids: extra allowed groups, e.g. the admin service group
            when a root-run process reads a `root:pdash` file.
        what: the token's name in error messages (default "admin token").

    Returns:
        The token bytes (surrounding whitespace stripped).

    Raises:
        TokenFileError: any rule above fails, or the file can't be read.
    """
    owners = frozenset(trusted_uids) if trusted_uids is not None else _default_owners()
    token, _gid = _read_token_file(path, owners, trusted_token_gids(trusted_gids), what)
    return token


def _default_owners() -> frozenset[int]:
    return frozenset({0, os.geteuid()})


def _refuse_posix_acl(fd: int, path: Path, what: str) -> None:
    """Refuse a token file carrying a POSIX ACL: it can grant read access to a
    group or user invisible in `st_mode` (S-C, F-C item 3), defeating the
    group checks above. `ENOTSUP`/`EOPNOTSUPP` means the filesystem has no
    xattr support at all, i.e. no ACL -- not an error.
    """
    try:
        names = os.listxattr(fd)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return
        raise TokenFileError(f"cannot check ACLs on {what} file {path}: {exc.strerror}") from None
    if _ACL_XATTR in names:
        raise TokenFileError(
            f"{what} file {path} carries a POSIX ACL, which can grant access "
            "invisible in its mode bits (remove it with `setfacl -b`)"
        )


def _read_token_file(
    path: Path, owners: Collection[int], groups: Collection[int], what: str
) -> tuple[bytes, int]:
    """The C12 checks with exact owner/group sets; returns (token, the file's gid)."""
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        # ELOOP: final component is a symlink (O_NOFOLLOW).
        raise TokenFileError(f"cannot open {what} file {path}: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise TokenFileError(f"{what} file {path} is not a regular file")
        if st.st_uid not in owners:
            raise TokenFileError(f"{what} file {path} has an untrusted owner")
        if st.st_gid not in groups:
            # Checked even for 0600: a later g+r must not expose the token
            # to a group nobody vetted.
            raise TokenFileError(f"{what} file {path} has an untrusted group (gid {st.st_gid})")
        if st.st_mode & _FORBIDDEN_TOKEN_BITS:
            raise TokenFileError(
                f"{what} file {path} must not be group-writable or accessible by others "
                "(use mode 0640 or 0600)"
            )
        _refuse_posix_acl(fd, path, what)
        raw = os.read(fd, _MAX_TOKEN_FILE_BYTES + 1)
    finally:
        os.close(fd)
    parent = os.stat(Path(path).parent)
    if parent.st_uid not in owners or parent.st_mode & _FORBIDDEN_DIR_BITS:
        raise TokenFileError(f"directory of {what} file {path} is not trusted")
    if len(raw) > _MAX_TOKEN_FILE_BYTES:
        raise TokenFileError(f"{what} file {path} is too large")
    token = raw.strip()
    check_token_value(token, str(path), what=what)
    return token, st.st_gid


class TokenKind(StrEnum):
    """The token files; the value is the `--token-group KIND=GROUP` prefix."""

    ADMIN = "admin"
    NOTIFIER = "notifier"
    TELEGRAM = "telegram"
    # Claudia host's admin-API token (ADR 0031, C45).
    CLAUDIA = "claudia"
    # The viewer's token for the dashboard-decision route (F-CL6, ADR 0043).
    VIEWER = "viewer"

    @property
    def label(self) -> str:
        """The token's name in error messages."""
        return _LABELS[self]


_LABELS: Mapping[TokenKind, str] = MappingProxyType(
    {
        TokenKind.ADMIN: DEFAULT_WHAT,
        TokenKind.NOTIFIER: "notifier token",
        TokenKind.TELEGRAM: "telegram bot token",
        TokenKind.CLAUDIA: "claudia token",
        TokenKind.VIEWER: "viewer token",
    }
)


def _no_scopes() -> Mapping[TokenKind, frozenset[int]]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class TokenGroupPolicy:
    """Which groups may own each token file one process loads (C12/C36, ADR 0024).

    Every file trusts root, plus:
    - the `own` file only: this process's egid (admin.token for the admin
      side, telegram.token for the notifier). The egid never owns another
      file, so the shared notifier.token can't be either service's group.
    - groups scoped to that file (`--token-group KIND=GROUP`); a group
      scoped to one file is never trusted for another.
    - `shared` groups (plain `--token-group GROUP`, backward compatible),
      minus groups scoped to other files. `TokenLoader` also refuses two
      files of one process in the same non-root group, so a plain group
      still ends up owning at most one of them.

    Args:
        own: the process's own token file.
        scoped: groups named for exactly one file.
        shared: unscoped groups.
        egid: this process's effective gid (default `os.getegid()`).

    Raises (constructor):
        TokenFileError: one non-root group is scoped to two different files.
    """

    own: TokenKind
    scoped: Mapping[TokenKind, frozenset[int]] = field(default_factory=_no_scopes)
    shared: frozenset[int] = frozenset()
    egid: int = field(default_factory=os.getegid)

    def __post_init__(self) -> None:
        seen: dict[int, TokenKind] = {}
        for kind, gids in self.scoped.items():
            for gid in gids:
                other = seen.setdefault(gid, kind)
                if other is not kind and gid != 0:
                    raise TokenFileError(
                        f"group gid {gid} is named for both the {other.label} and the "
                        f"{kind.label} file; each token needs its own group"
                    )

    def gids_for(self, kind: TokenKind) -> frozenset[int]:
        """Groups allowed to own the `kind` token file (always includes root)."""
        elsewhere: set[int] = set()
        for other, gids in self.scoped.items():
            if other is not kind:
                elsewhere |= gids
        allowed = {0, *self.scoped.get(kind, frozenset()), *(self.shared - elsewhere)}
        if kind is self.own:
            allowed.add(self.egid)
        elif self.egid != 0:
            allowed.discard(self.egid)  # our own group reads our own token only
        return frozenset(allowed)


class TokenLoader:
    """Loads one process's token files, each with its own trusted groups (C12/C36).

    No non-root group may own two of the files it loads: a group that can
    read this process's token must not also read the other process's one.

    Args:
        policy: the per-file groups (see `TokenGroupPolicy`).
        trusted_uids: allowed owners (default: root and this euid).
    """

    def __init__(
        self, policy: TokenGroupPolicy, *, trusted_uids: Collection[int] | None = None
    ) -> None:
        self.policy = policy
        self._owners = frozenset(trusted_uids) if trusted_uids is not None else _default_owners()
        self._group_of: dict[int, TokenKind] = {}

    def load(self, kind: TokenKind, path: Path) -> bytes:
        """Read and validate the `kind` token file (the rules of `load_admin_token`).

        Raises:
            TokenFileError: a C12 rule fails, the file's group isn't trusted
                for `kind`, or another file loaded here has the same group.
        """
        token, gid = _read_token_file(path, self._owners, self.policy.gids_for(kind), kind.label)
        if gid != 0:
            other = self._group_of.setdefault(gid, kind)
            if other is not kind:
                raise TokenFileError(
                    f"{kind.label} file {path} has the same group (gid {gid}) as the "
                    f"{other.label} file; each token needs its own group"
                )
        return token
