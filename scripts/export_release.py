"""scripts/export_release.py: copy this repo into a clean, shareable release tree.

Exports the git-listed files minus owner-only material (agent/orchestrator
files, handoff, memory, outbox, secrets, databases), scans every exported byte
with the repo's secret scanner (C15) and a personal-data denylist (config
values, git identity, installed token/secret file contents, owner-only agent
paths), and adds a release README.md + generic CLAUDE.md from
`scripts/release_templates/`. Fails closed: any hit, symlink or unsafe output
dir aborts before a single file is written.

Usage: uv run python scripts/export_release.py --out <new or empty dir>
"""

from __future__ import annotations

import argparse
import errno
import fnmatch
import os
import re
import shutil
import stat
import subprocess  # nosec B404 - fixed git argv, no shell
import sys
import tomllib
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final
from urllib.parse import urlsplit

from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.domain.errors import SecretDetectedError

REPO_ROOT: Final = Path(__file__).resolve().parents[1]
TEMPLATES_DIR: Final = PurePosixPath("scripts/release_templates")
DEFAULT_CONFIG: Final = Path("/etc/preview-dashboard/config.toml")
DEFAULT_SECRETS_DIR: Final = Path("/etc/preview-dashboard")

# Release file -> template (repo-relative). The repo's own README.md and
# CLAUDE.md are owner-facing and replaced by these.
TEMPLATES: Final[dict[str, str]] = {
    "README.md": f"{TEMPLATES_DIR}/README.release.md",
    "CLAUDE.md": f"{TEMPLATES_DIR}/CLAUDE.release.md",
}

# Any path with one of these components is owner-only (agent rules,
# orchestrator backlog + spikes, memory, published-content staging).
EXCLUDED_COMPONENTS: Final = frozenset({".claude", "memory", "outbox"})
# File-name globs, matched at any depth: owner rules/handoff, secrets, and
# everything `.gitignore` treats as secret or runtime data (an untracked copy
# that slipped past the ignore rules must still never ship).
EXCLUDED_NAMES: Final = (
    "CLAUDE.md",
    "HANDOFF.md",
    "*.secret",
    "*.token",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    ".env",
    ".env.*",
    "*.env",
    "*.db",
    "*.db-*",
    "*.sqlite*",
    "config.toml",
    "id_rsa*",
    "id_ed25519*",
)
# JSONL is transcript/sample data: only the curated test fixtures may ship.
JSONL_ALLOWED_DIR: Final = PurePosixPath("tests/fixtures")

# Installed secret files whose literal contents are denied (secrets-1).
SECRET_FILE_GLOBS: Final = ("*.token", "*.secret")

# Real tailnet names carry a hex tailnet id (docs use `tailXXXX`, not hex).
_TAILNET_HOST: Final = re.compile(rb"\.tail[0-9a-f]{4,12}\.ts\.net", re.IGNORECASE)
# Pointers into the owner-only agent tree mean a doc still leans on files
# the release doesn't have (and names the owner's working layout).
_AGENT_PATHS: Final = re.compile(rb"\.claude/(?:orchestrator|agents)\b", re.IGNORECASE)
# Shorter numbers are too common in code to deny (a placeholder id like 1).
_MIN_CHAT_ID_DIGITS: Final = 5
_MIN_TERM_LEN: Final = 4
# Real tokens/secrets are long; a shorter "secret" would deny common words.
_MIN_SECRET_LEN: Final = 8
_MAX_SECRET_FILE_BYTES: Final = 64 * 1024


class ExportError(Exception):
    """The export was refused; nothing (more) was written."""


@dataclass(frozen=True)
class DenyTerm:
    """One personal-data pattern; `label` names its source, never its value."""

    label: str
    pattern: re.Pattern[bytes]


@dataclass(frozen=True)
class ExportResult:
    """Outcome of a successful export.

    `deny_labels` lists each denylist source that was loaded (labels only).
    """

    out: Path
    files: tuple[str, ...]
    deny_labels: tuple[str, ...]


# --- git -------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise ExportError("git not found on PATH")
    result = subprocess.run(  # noqa: S603  # nosec B603 - resolved git, fixed argv
        [git, "-C", str(repo), *args], capture_output=True, text=True, check=False, timeout=60
    )
    if result.returncode != 0:
        raise ExportError(f"git {args[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def _git_optional(repo: Path, *args: str) -> str:
    """Like `_git`, but "unset" (non-zero exit) is an empty answer."""
    try:
        return _git(repo, *args).strip()
    except ExportError:
        return ""


def list_files(repo: Path) -> list[str]:
    """Tracked plus untracked-but-not-ignored files, repo-relative, sorted."""
    raw = _git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({p for p in raw.split("\0") if p})


def is_dirty(repo: Path) -> bool:
    """True if the work tree differs from HEAD (incl. untracked files)."""
    return bool(_git(repo, "status", "--porcelain").strip())


# --- exclusions --------------------------------------------------------------------


def is_excluded(relpath: str) -> bool:
    """True if `relpath` must never leave the working repo."""
    path = PurePosixPath(relpath)
    if relpath in TEMPLATES:  # owner-facing originals, replaced by the templates
        return True
    # Case-insensitive: `.Claude/`, `claude.md` or `X.TOKEN` must not slip through.
    if any(part.lower() in EXCLUDED_COMPONENTS for part in path.parts):
        return True
    name = path.name.lower()
    if fnmatch.fnmatchcase(name, "*.jsonl"):
        return path.parent != JSONL_ALLOWED_DIR
    return any(fnmatch.fnmatchcase(name, glob.lower()) for glob in EXCLUDED_NAMES)


# --- denylist ------------------------------------------------------------------------


def _literal(label: str, value: str) -> DenyTerm | None:
    value = value.strip()
    if len(value) < _MIN_TERM_LEN:
        return None
    return DenyTerm(label, re.compile(re.escape(value.encode()), re.IGNORECASE))


def _config_terms(config: Path | None) -> list[DenyTerm]:
    if config is None:
        return []
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except FileNotFoundError:
        # A typo'd path would silently drop every owner value: refuse instead
        # (`--no-config` is the explicit opt-out).
        raise ExportError(f"config {config} not found (pass --no-config to skip)") from None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        # An existing but unreadable config could hold exactly the values to
        # deny: fail closed instead of exporting without them.
        raise ExportError(f"cannot read {config}: {type(exc).__name__}") from exc
    terms: list[DenyTerm | None] = []
    owner = data.get("owner_login")
    if isinstance(owner, str):
        terms.append(_literal("config owner_login", owner))
    hosts = data.get("allowed_hosts")
    if isinstance(hosts, list):
        terms.extend(_literal("config allowed_hosts", h) for h in hosts if isinstance(h, str))
    origin = data.get("preview_origin")
    if isinstance(origin, str) and origin:
        terms.append(_literal("config preview_origin host", urlsplit(origin).hostname or ""))
    chat = data.get("notify_owner_chat_id")
    if isinstance(chat, int) and not isinstance(chat, bool) and chat > 0:
        digits = str(chat)
        if len(digits) >= _MIN_CHAT_ID_DIGITS:
            pattern = re.compile(rb"(?<![0-9])" + digits.encode() + rb"(?![0-9])")
            terms.append(DenyTerm("config notify_owner_chat_id", pattern))
    return [t for t in terms if t is not None]


def _read_secret_file(path: Path) -> bytes:
    """Bytes of one secret file; never follows a symlink, caps the size."""
    try:
        # O_NONBLOCK: a FIFO planted under a secret name must not hang the export.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ExportError(f"cannot read secret file {path.name}: {type(exc).__name__}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ExportError(f"secret file {path.name} is not a regular file")
        data = os.read(fd, _MAX_SECRET_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _MAX_SECRET_FILE_BYTES:
        raise ExportError(f"secret file {path.name} is too large to check")
    return data


def _secret_values(data: bytes) -> set[bytes]:
    whole = data.strip()
    values = {whole} if whole else set()
    values.update(line.strip() for line in data.splitlines() if line.strip())
    return {v for v in values if len(v) >= _MIN_SECRET_LEN}


def _secret_file_terms(secrets_dir: Path | None) -> list[DenyTerm]:
    """Literal contents of installed `*.token` / `*.secret` files (labels name the file only).

    Raises:
        ExportError: the dir exists but can't be listed, or a matching file
            can't be read (its contents might be in the tree).
    """
    if secrets_dir is None:
        return []
    try:
        names = sorted(os.listdir(secrets_dir))
    except FileNotFoundError:
        return []  # nothing installed on this host: nothing to deny
    except OSError as exc:
        raise ExportError(f"cannot list {secrets_dir}: {type(exc).__name__}") from exc
    terms: list[DenyTerm] = []
    for name in names:
        if not any(fnmatch.fnmatchcase(name.lower(), g) for g in SECRET_FILE_GLOBS):
            continue
        for value in sorted(_secret_values(_read_secret_file(secrets_dir / name))):
            # Bytes compiled straight into the pattern; the value is never printed.
            terms.append(DenyTerm(f"secret file {name}", re.compile(re.escape(value))))
    return terms


def _remote_owner(url: str) -> tuple[str, str]:
    """(owner, owner/repo) of a GitHub-style remote URL, or empty strings."""
    match = re.search(r"[:/]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$", url.strip())
    if match is None:
        return "", ""
    return match.group(1), f"{match.group(1)}/{match.group(2)}"


def _checkout_paths(repo: Path) -> list[Path]:
    paths = {repo.resolve()}
    common = _git_optional(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if common:
        paths.add(Path(common).resolve().parent)
    # A bare top-level dir (e.g. /srv) is too generic to deny.
    return sorted(p for p in paths if len(p.parts) >= 3)


def build_denylist(
    repo: Path,
    config: Path | None,
    extra: Sequence[str] = (),
    *,
    secrets_dir: Path | None = None,
) -> list[DenyTerm]:
    """Personal-data patterns: config values, secret files, git identity, paths, tailnet ids.

    Raises:
        ExportError: `config` is missing or unreadable, or `secrets_dir` holds a
            token/secret file that can't be read.
    """
    terms: list[DenyTerm | None] = [
        DenyTerm("tailnet host name", _TAILNET_HOST),
        DenyTerm("owner-only agent path", _AGENT_PATHS),
    ]
    terms.extend(_config_terms(config))
    terms.extend(_secret_file_terms(secrets_dir))
    terms.append(_literal("git user.email", _git_optional(repo, "config", "user.email")))
    terms.append(_literal("git user.name", _git_optional(repo, "config", "user.name")))
    owner, slug = _remote_owner(_git_optional(repo, "remote", "get-url", "origin"))
    terms.append(_literal("git remote owner", owner))
    terms.append(_literal("git remote repo", slug))
    for path in _checkout_paths(repo):
        terms.append(_literal("checkout path", f"{path}/"))
    terms.extend(_literal(f"--deny #{i + 1}", value) for i, value in enumerate(extra))
    return [t for t in terms if t is not None]


# --- scanning ------------------------------------------------------------------------


def scan(
    relpath: str, data: bytes, scanner: RegexSecretScanner, deny: Sequence[DenyTerm]
) -> list[str]:
    """Every problem in one file, as `"<relpath>: <label>"` (never the matched bytes)."""
    problems: list[str] = []
    session = scanner.new_session()
    try:
        session.feed(data)
        session.finish()
    except SecretDetectedError as exc:
        problems.append(f"{relpath}: secret rule {exc.rule!r}")
    problems.extend(f"{relpath}: personal data ({t.label})" for t in deny if t.pattern.search(data))
    return problems


# --- output dir ------------------------------------------------------------------------


def _check_existing_out(out: Path, st: os.stat_result) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise ExportError(f"{out} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise ExportError(f"{out} is not a directory")
    # Someone else who can write into it could plant files or swap subdirs
    # for symlinks between our checks and our writes.
    if st.st_uid != os.geteuid():
        raise ExportError(f"{out} is not owned by the current user")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ExportError(f"{out} is group/other-writable")
    if any(out.iterdir()):
        raise ExportError(f"{out} is not empty")


def _check_out(out: Path, repo: Path) -> None:
    try:
        st = os.lstat(out)
    except FileNotFoundError:
        if not out.parent.is_dir():
            raise ExportError(f"parent of {out} does not exist") from None
    else:
        _check_existing_out(out, st)
    resolved = out.resolve()
    repo = repo.resolve()
    if resolved.is_relative_to(repo) or repo.is_relative_to(resolved):
        raise ExportError("--out must be outside the repository")


def _read_regular(repo: Path, relpath: str) -> bytes:
    path = repo / relpath
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ExportError(f"{relpath} is a symlink (refused: could point outside the tree)")
    if not stat.S_ISREG(st.st_mode):
        raise ExportError(f"{relpath} is not a regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        return fh.read()


_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


@contextmanager
def _open_out(out: Path) -> Iterator[int]:
    """Create (or re-verify) `out` and yield an fd on it; never follows a symlink."""
    try:
        os.mkdir(out, 0o755)  # exist_ok=False: a racing creator makes this fail
    except FileExistsError:
        _check_existing_out(out, os.lstat(out))  # the pre-checked empty dir
    try:
        fd = os.open(out, _DIR_FLAGS)
    except OSError as exc:
        raise ExportError(f"cannot open {out}: {type(exc).__name__}") from exc
    try:
        yield fd
    finally:
        os.close(fd)


def _subdir(parent_fd: int, name: str, relpath: str) -> int:
    """Open (creating if needed) one real subdirectory, relative to `parent_fd`."""
    # Exists already: created for an earlier file, verified by the open below.
    with suppress(FileExistsError):
        os.mkdir(name, 0o755, dir_fd=parent_fd)
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ExportError(f"{relpath}: a parent became a symlink or file") from exc
        raise


def _write(out_fd: int, relpath: str, data: bytes, executable: bool) -> None:
    *dirs, name = PurePosixPath(relpath).parts
    fd = os.dup(out_fd)
    try:
        for part in dirs:
            child = _subdir(fd, part, relpath)
            os.close(fd)
            fd = child
        mode = 0o755 if executable else 0o644
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        file_fd = os.open(name, flags, mode, dir_fd=fd)
    finally:
        os.close(fd)
    with os.fdopen(file_fd, "wb") as fh:
        fh.write(data)
        os.fchmod(fh.fileno(), mode)  # umask must not change the shipped mode


# --- export ------------------------------------------------------------------------------


def export_release(
    repo: Path,
    out: Path,
    *,
    config: Path | None = DEFAULT_CONFIG,
    secrets_dir: Path | None = DEFAULT_SECRETS_DIR,
    extra_deny: Sequence[str] = (),
    allow_dirty: bool = False,
) -> ExportResult:
    """Export `repo` into `out` (created if missing; must be empty and ours).

    Every file is read and scanned before anything is written, so a refusal
    leaves `out` untouched. `config=None` skips the config denylist;
    `secrets_dir=None` skips the installed token/secret contents.

    Raises:
        ExportError: unsafe `out`, dirty tree (without `allow_dirty`), a
            symlink or special file, a missing template, a missing or
            unreadable config/secret file, or any scan hit.
    """
    _check_out(out, repo)
    if not allow_dirty and is_dirty(repo):
        raise ExportError("work tree has uncommitted changes (commit, or pass --allow-dirty)")

    contents: dict[str, tuple[bytes, bool]] = {}
    for relpath in list_files(repo):
        if is_excluded(relpath):
            continue
        if not os.path.lexists(repo / relpath):
            continue  # deleted in the work tree, not yet committed
        data = _read_regular(repo, relpath)
        executable = bool(os.lstat(repo / relpath).st_mode & stat.S_IXUSR)
        contents[relpath] = (data, executable)
    for release_name, template in TEMPLATES.items():
        try:
            contents[release_name] = (_read_regular(repo, template), False)
        except FileNotFoundError as exc:
            raise ExportError(f"template {template} is missing") from exc

    scanner = RegexSecretScanner()
    deny = build_denylist(repo, config, extra_deny, secrets_dir=secrets_dir)
    problems = [p for rel, (data, _) in contents.items() for p in scan(rel, data, scanner, deny)]
    if problems:
        raise ExportError("refused, nothing written:\n  " + "\n  ".join(problems))

    with _open_out(out) as out_fd:
        for relpath, (data, executable) in sorted(contents.items()):
            _write(out_fd, relpath, data, executable)
    labels = tuple(dict.fromkeys(t.label for t in deny))
    return ExportResult(out=out, files=tuple(sorted(contents)), deny_labels=labels)


def build_parser() -> argparse.ArgumentParser:
    """CLI for `export_release.py`."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--out", type=Path, required=True, help="new or empty output directory")
    parser.add_argument("--repo", type=Path, default=REPO_ROOT, help="source checkout")
    config = parser.add_mutually_exclusive_group()
    config.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="dashboard config whose owner values are denied (must exist)",
    )
    config.add_argument(
        "--no-config", action="store_true", help="host has no dashboard config: skip it"
    )
    parser.add_argument(
        "--secrets-dir",
        type=Path,
        default=DEFAULT_SECRETS_DIR,
        help="dir whose *.token / *.secret contents are denied (missing dir = none installed)",
    )
    parser.add_argument(
        "--deny", action="append", default=[], metavar="TEXT", help="extra text to deny"
    )
    parser.add_argument(
        "--allow-dirty", action="store_true", help="export uncommitted work-tree state"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the export; 0 ok, 1 refused (reason on stderr)."""
    args = build_parser().parse_args(argv)
    try:
        result = export_release(
            args.repo,
            args.out,
            config=None if args.no_config else args.config,
            secrets_dir=args.secrets_dir,
            extra_deny=args.deny,
            allow_dirty=args.allow_dirty,
        )
    except ExportError as exc:
        print(f"export_release: {exc}", file=sys.stderr)
        return 1
    print(f"exported {len(result.files)} files to {result.out}")
    print("denylist sources: " + ", ".join(result.deny_labels))
    return 0


if __name__ == "__main__":
    sys.exit(main())
