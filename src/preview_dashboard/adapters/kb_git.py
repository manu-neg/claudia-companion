"""GitKbHistory: `KbGit` over the KB's git repo for the gardener (docs/security.md C54).

Reads what a run changed and reverts it with one commit; restores and checks
the notes' work tree (callers hold the KB locks, C53). Same hardening as
`FsKbStore` git calls: absolute git path, argv lists, scrubbed environment,
no hooks, no system/global config, no remote.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # nosec B404 - git only: fixed absolute path, argv list, no shell
from pathlib import Path

from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.ports.claudia_gardener import ChangedFile

logger = logging.getLogger(__name__)
_GIT_TIMEOUT_S = 30


class GitKbHistory:
    """`KbGit` for the repo at `root`.

    Args:
        root: KB directory (already a git repo, created by `FsKbStore.commit`).
        git_bin: git executable (resolved once).
        git_name / git_email: identity of the revert commit.

    Raises (constructor):
        StorageUnavailableError: git is not installed.
    """

    def __init__(
        self,
        root: Path,
        *,
        git_bin: str = "git",
        git_name: str = "Claudia host",
        git_email: str = "claudia@localhost",
    ) -> None:
        resolved = shutil.which(git_bin)
        if resolved is None or not os.path.isabs(resolved):
            raise StorageUnavailableError("git executable not found")
        self._git = resolved
        self._root = root
        self._ident = (git_name, git_email)

    def head(self) -> str | None:
        """Full id of HEAD, None for a repo without commits."""
        proc = self._run("rev-parse", "--verify", "-q", "HEAD", check=False)
        return proc.stdout.strip() or None if proc.returncode == 0 else None

    def tracked_files(self) -> list[str]:
        """`git ls-files`, NUL-separated so odd names cannot split."""
        out = self._run("ls-files", "-z").stdout
        return [p for p in out.split("\0") if p]

    def changed_since(self, base: str) -> list[ChangedFile]:
        """`git diff --name-status -z --no-renames <base> HEAD`."""
        out = self._run("diff", "--name-status", "-z", "--no-renames", base, "HEAD").stdout
        parts = out.split("\0")
        # Pairs of (status, path); a trailing empty element is normal.
        return [ChangedFile(parts[i], parts[i + 1]) for i in range(0, len(parts) - 1, 2)]

    def revert_since(self, base: str) -> str | None:
        """Revert `base..HEAD` into the index, then commit once; None if that changes nothing."""
        if self.head() == base:
            return None
        self._run("revert", "--no-commit", f"{base}..HEAD")
        if self._run("diff", "--cached", "--quiet", check=False).returncode == 0:
            return None
        self._run("commit", "-q", "--no-verify", "-m", "gardener: revert run")
        return self._run("rev-parse", "--short", "HEAD").stdout.strip()

    def restore_worktree(self) -> None:
        """Put every note back to HEAD and delete untracked notes (F-C2a-2 leftover).

        After a failed post-run commit the model's files are still in the work
        tree; left there, the next commit would take them in unverified.
        Pathspec `*.md` only and no `-x`: `.git`, lock files and ignored files stay.
        """
        if self.head() is None:
            return  # no commit: nothing to restore to
        # `*.md` matches at any depth (pathspec `*` crosses `/`). Unstage first, so
        # staged-but-uncommitted new notes become untracked and `clean` drops them.
        self._run("reset", "-q", "--", "*.md")
        if self._run("ls-files", "-z", "--", "*.md").stdout:
            self._run("checkout", "-q", "HEAD", "--", "*.md")
        self._run("clean", "-f", "-q", "--", "*.md")

    def worktree_clean(self) -> bool:
        """True if no note differs from HEAD (`git status --porcelain -- *.md` is empty).

        A repo without commits counts as clean only when it holds no notes.

        Raises:
            StorageUnavailableError: git failed.
        """
        out = self._run("status", "--porcelain", "--untracked-files=all", "--", "*.md").stdout
        return out.strip() == ""

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        name, email = self._ident
        env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
        }
        argv = [
            self._git,
            "-C",
            str(self._root),
            "-c",
            f"safe.directory={self._root}",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            *args,
        ]
        try:
            proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, scrubbed env
                argv, env=env, capture_output=True, text=True, timeout=_GIT_TIMEOUT_S, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise StorageUnavailableError("git could not run") from exc
        if check and proc.returncode != 0:
            logger.error("git %s failed (exit %d)", args[0], proc.returncode)
            raise StorageUnavailableError(f"git {args[0]} failed")
        return proc
