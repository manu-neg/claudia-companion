"""FsKbStore: filesystem + git adapter of the `KbStore` port (docs/security.md C53).

Every path component is opened fd-relative with `O_NOFOLLOW`, so a symlink,
FIFO or hardlink planted inside the KB can neither redirect a write nor hang
or leak a read. Writes go to a temp file in the target directory and replace
the note atomically. Run commits use `git` through argv lists with a fixed
host identity, a scrubbed environment and no remote. Every mutation, cap
check and work-tree restore holds the cross-process KB locks (`.run.lock`
shared, `.lock` exclusive; fixcheck-a-2/3).
"""

from __future__ import annotations

import contextlib
import fcntl
import logging
import os
import secrets
import shutil
import stat
import subprocess  # nosec B404 - git only: fixed absolute path, argv list, no shell
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.ports.claudia_kb import KbAdmit, KbBusyError, KbStats

logger = logging.getLogger(__name__)

DIR_MODE = 0o750  # root rwx, viewer group r-x (C57), others none
FILE_MODE = 0o640
MAX_READ_BYTES = 1024 * 1024  # notes are capped far lower; this bounds a planted giant file
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK: a FIFO planted at a note path must not hang the reader.
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
_TMP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_GIT_TIMEOUT_S = 30
_TMP_PREFIX = ".tmp-"  # never ends in .md, so never counted, committed or served
_LOCK = ".lock"  # short mutex per write/delete/commit
_RUN_LOCK = ".run.lock"  # shared by writers, exclusive for a gardener run
LOCK_WAIT_S = 30.0


class FsKbStore:
    """`KbStore` over a directory (default `/var/lib/claudia-kb`).

    Args:
        root: KB directory; must exist and be a real directory (not a symlink).
        group_id: optional gid (the viewer group) given to every dir/file created.
        git_bin: git executable.
        git_name / git_email: host identity for run commits.
        exempt_run_lock: True only for the gardener and its MCP child, which
            may mutate while `exclusive_run` is held (kb-map-2).
        lock_wait_s: how long a mutation waits for the KB locks before failing.
    """

    def __init__(
        self,
        root: Path,
        *,
        group_id: int | None = None,
        git_bin: str = "git",
        git_name: str = "Claudia host",
        git_email: str = "claudia@localhost",
        exempt_run_lock: bool = False,
        lock_wait_s: float = LOCK_WAIT_S,
    ) -> None:
        self._root = root
        self._exempt = exempt_run_lock
        self._exclusive = False  # True inside this store's own `exclusive_run`
        self._lock_wait = lock_wait_s
        self._gid = group_id
        # Resolved once to an absolute path so later calls never search PATH again.
        resolved = shutil.which(git_bin)
        if resolved is None or not os.path.isabs(resolved):
            raise StorageUnavailableError("git executable not found")
        self._git = resolved
        self._ident = (git_name, git_email)
        with self._root_fd():  # fail fast on a missing or symlinked root
            pass

    # -- port -----------------------------------------------------------

    def read(self, relpath: str) -> bytes | None:
        """Read one note via a no-follow fd; see `KbStore.read`."""
        with self._parent(relpath, create=False) as (dfd, name):
            if dfd is None:
                return None
            fd = self._open_file(dfd, name)
            if fd is None:
                return None
            try:
                st = os.fstat(fd)
                self._require_plain(st)
                if st.st_size > MAX_READ_BYTES:
                    raise StorageUnavailableError("note too large to read")
                return os.read(fd, st.st_size) if st.st_size else b""
            except OSError as exc:
                raise StorageUnavailableError("could not read note") from exc
            finally:
                os.close(fd)

    def size(self, relpath: str) -> int | None:
        """Size of one note, None if absent; see `KbStore.size`."""
        with self._parent(relpath, create=False) as (dfd, name):
            if dfd is None:
                return None
            st = self._lstat(dfd, name)
            if st is None:
                return None
            self._require_plain(st)
            return st.st_size

    def write(self, relpath: str, data: bytes) -> None:
        """Atomic write under the KB lock; see `KbStore.write`."""
        with self._locked():
            self._write(relpath, data)

    def delete(self, relpath: str) -> bool:
        """Unlink one plain note under the KB lock; see `KbStore.delete`."""
        with self._locked():
            return self._delete(relpath)

    def commit(self, message: str) -> str | None:
        """Commit under the KB lock (never overlaps another process's git/write)."""
        with self._locked():
            return self._commit(message)

    def write_admitted(self, relpath: str, data: bytes, admit: KbAdmit) -> None:
        """Cap check + write under one lock hold; see `KbStore.write_admitted`."""
        with self._locked():
            # Same hold as the write: no other process can add a note in between.
            admit(self.size(relpath), self.stats())
            self._write(relpath, data)

    def update(self, relpath: str, fn: Callable[[bytes | None], bytes | None]) -> bool:
        """Read-modify-write under one lock hold; see `KbStore.update`."""
        with self._locked():
            new = fn(self.read(relpath))
            if new is None:
                return False
            self._write(relpath, new)
            return True

    def run_locked[T](self, fn: Callable[[], T], *, wait_s: float | None = None) -> T:
        """Run `fn` under the write locks; see `KbStore.run_locked`."""
        with self._locked(wait_s):
            return fn()

    @contextmanager
    def exclusive_run(self) -> Iterator[None]:
        """Hold the KB for a whole gardener run (kb-map-2).

        Other processes' writes, deletes and commits wait up to `LOCK_WAIT_S`
        then fail, so none of Claudia's notes can land inside the run and be
        reverted with it. Only the gardener's own store (`exempt_run_lock`) and
        its MCP child may write meanwhile. While it is held, this store's
        locked steps also remove a stale `.git/index.lock` (fixcheck-a-1).

        Raises:
            KbBusyError: another writer holds the KB for too long.
        """
        with self._lock_file(_RUN_LOCK, fcntl.LOCK_EX):
            self._exclusive = True
            try:
                yield
            finally:
                self._exclusive = False

    @contextmanager
    def _locked(self, wait_s: float | None = None) -> Iterator[None]:
        """Cross-process mutex for one mutation: shared run lock, then the short `.lock`."""
        with contextlib.ExitStack() as stack:
            if not self._exempt:
                stack.enter_context(self._lock_file(_RUN_LOCK, fcntl.LOCK_SH, wait_s))
            stack.enter_context(self._lock_file(_LOCK, fcntl.LOCK_EX, wait_s))
            if self._exclusive:
                self._clear_stale_index_lock()
            yield

    def _clear_stale_index_lock(self) -> None:
        """Remove `.git/index.lock` left by a killed git (fixcheck-a-1).

        Only called holding the exclusive run lock and `.lock`: every git
        process in the KB holds one of them (host, MCP children, restores),
        so no live git can own the file now; left there, every later git call
        fails until someone deletes it by hand.
        """
        try:
            with self._root_fd() as rfd:
                gfd = os.open(".git", _DIR_FLAGS, dir_fd=rfd)
                try:
                    st = self._lstat(gfd, "index.lock")
                    if st is None or not stat.S_ISREG(st.st_mode):
                        return  # absent, or not what git leaves: never touch it
                    os.unlink("index.lock", dir_fd=gfd)
                finally:
                    os.close(gfd)
        except FileNotFoundError:
            return  # no repo yet
        except (OSError, StorageUnavailableError) as exc:
            # The next git call fails closed on the lock anyway.
            logger.error("could not remove a stale git index.lock (%s)", type(exc).__name__)
            return
        logger.warning("knowledge base: removed a stale git index.lock")

    @contextmanager
    def _lock_file(self, name: str, op: int, wait_s: float | None = None) -> Iterator[None]:
        # flock on a root-owned dotfile (walkers skip it); bounded wait so a stuck
        # holder fails the write closed instead of hanging the caller.
        try:
            with self._root_fd() as rfd:
                fd = os.open(
                    name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=rfd
                )
        except OSError as exc:
            raise StorageUnavailableError("could not open the knowledge base lock") from exc
        try:
            deadline = time.monotonic() + (self._lock_wait if wait_s is None else wait_s)
            while True:
                try:
                    fcntl.flock(fd, op | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise KbBusyError("knowledge base is busy") from None
                    time.sleep(0.05)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _write(self, relpath: str, data: bytes) -> None:
        """Atomic temp-file + rename write; see `KbStore.write`."""
        tmp = f"{_TMP_PREFIX}{secrets.token_hex(8)}"
        with self._parent(relpath, create=True) as (dfd, name):
            if dfd is None:  # unreachable with create=True; fail closed
                raise StorageUnavailableError("could not create directory")
            existing = self._lstat(dfd, name)
            if existing is not None:
                self._require_plain(existing)  # refuse to replace a symlink/FIFO/hardlink
            try:
                fd = os.open(tmp, _TMP_FLAGS, FILE_MODE, dir_fd=dfd)
            except OSError as exc:
                raise StorageUnavailableError("could not create note") from exc
            try:
                try:
                    os.fchmod(fd, FILE_MODE)  # not subject to umask
                    self._chown(fd)
                    view = memoryview(data)
                    while view:
                        view = view[os.write(fd, view) :]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            except OSError as exc:
                with suppress(OSError):
                    os.unlink(tmp, dir_fd=dfd)
                raise StorageUnavailableError("could not write note") from exc

    def _delete(self, relpath: str) -> bool:
        """Unlink one plain note; see `KbStore.delete`."""
        with self._parent(relpath, create=False) as (dfd, name):
            if dfd is None:
                return False
            st = self._lstat(dfd, name)
            if st is None:
                return False
            self._require_plain(st)
            try:
                os.unlink(name, dir_fd=dfd)
            except OSError as exc:
                raise StorageUnavailableError("could not delete note") from exc
            return True

    def stats(self) -> KbStats:
        """Count plain `.md` files below the root; everything else is skipped."""
        with self._root_fd() as rfd:
            files, total = self._walk(rfd, depth=0)
        return KbStats(files, total)

    def _commit(self, message: str) -> str | None:
        """Stage every `.md` change and commit it once; None when clean."""
        if not (self._root / ".git").exists():
            self._run_git("init", "-q", "-b", "main")
            with suppress(OSError):
                os.chmod(self._root / ".git", DIR_MODE)
        # Pathspec `*.md` (fnmatch, crosses dirs): nothing but notes is ever committed.
        self._run_git("add", "-A", "--", "*.md")
        if self._run_git("diff", "--cached", "--quiet", check=False).returncode == 0:
            return None
        self._run_git("commit", "-q", "--no-verify", "-m", message)
        return self._run_git("rev-parse", "--short", "HEAD").stdout.strip()

    # -- fd-relative helpers ----------------------------------------------

    @contextmanager
    def _root_fd(self) -> Iterator[int]:
        try:
            fd = os.open(self._root, _DIR_FLAGS)
        except OSError as exc:
            raise StorageUnavailableError("knowledge base root is not a real directory") from exc
        try:
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def _parent(self, relpath: str, *, create: bool) -> Iterator[tuple[int | None, str]]:
        """Yield (fd of the note's directory or None if absent, file name)."""
        parts = relpath.split("/")
        if not relpath or any(p in ("", ".", "..") or "\0" in p for p in parts):
            raise StorageUnavailableError("invalid note path")
        opened: list[int] = []
        try:
            with self._root_fd() as rfd:
                cur = rfd
                missing = False
                for comp in parts[:-1]:
                    nxt = self._enter(cur, comp, create)
                    if nxt is None:
                        missing = True
                        break
                    opened.append(nxt)
                    cur = nxt
                yield (None if missing else cur), parts[-1]
        finally:
            for fd in opened:
                os.close(fd)

    def _enter(self, parent: int, name: str, create: bool) -> int | None:
        for attempt in (0, 1):
            try:
                return os.open(name, _DIR_FLAGS, dir_fd=parent)
            except FileNotFoundError:
                if not create or attempt:
                    return None
                try:
                    os.mkdir(name, DIR_MODE, dir_fd=parent)
                except FileExistsError:
                    continue
                except OSError as exc:
                    raise StorageUnavailableError("could not create directory") from exc
                fd = os.open(name, _DIR_FLAGS, dir_fd=parent)
                os.fchmod(fd, DIR_MODE)
                self._chown(fd)
                return fd
            except OSError as exc:  # ELOOP (symlink), ENOTDIR (file in the way) ...
                raise StorageUnavailableError("a path component is not a plain directory") from exc
        return None

    def _open_file(self, dfd: int, name: str) -> int | None:
        try:
            return os.open(name, _READ_FLAGS, dir_fd=dfd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StorageUnavailableError("note is not a plain file") from exc

    @staticmethod
    def _lstat(dfd: int, name: str) -> os.stat_result | None:
        try:
            return os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise StorageUnavailableError("could not stat note") from exc

    @staticmethod
    def _require_plain(st: os.stat_result) -> None:
        # Regular, single link: no symlink/FIFO/device, no hardlink to a file elsewhere.
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise StorageUnavailableError("note is not a plain single-link file")

    def _chown(self, fd: int) -> None:
        if self._gid is None:
            return
        try:
            os.fchown(fd, -1, self._gid)
        except OSError as exc:
            raise StorageUnavailableError("could not set group on knowledge base entry") from exc

    def _walk(self, dfd: int, *, depth: int) -> tuple[int, int]:
        files = total = 0
        if depth > 4:  # layout is at most 3 deep; deeper is not ours
            return 0, 0
        with os.scandir(dfd) as it:
            entries = list(it)
        for entry in entries:
            if entry.name in (".git", _LOCK, _RUN_LOCK) or entry.name.startswith(_TMP_PREFIX):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                try:
                    sub = os.open(entry.name, _DIR_FLAGS, dir_fd=dfd)
                except OSError:
                    continue
                try:
                    f, t = self._walk(sub, depth=depth + 1)
                finally:
                    os.close(sub)
                files += f
                total += t
            elif entry.name.endswith(".md") and stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                files += 1
                total += st.st_size
            else:
                logger.warning("knowledge base: skipping odd entry")  # no name: untrusted
        return files, total

    # -- git ----------------------------------------------------------------

    def _run_git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
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


__all__ = ["DIR_MODE", "FILE_MODE", "FsKbStore"]
