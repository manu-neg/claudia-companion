"""MCP publish intake policy: turn requested host paths into a safe file bundle.

Owns docs/security.md C10/C27 for the MCP server: allowed-root check (also on
the symlink-resolved root), secret denylist, TOCTOU-safe fd-relative walk (no
symlinks, regular single-link files only, no filesystem or mount crossing),
limits, and bundle relpath validation. Bytes are only ever read from the fds
opened and checked here.
"""

from __future__ import annotations

import errno
import os
import stat
import weakref
from collections.abc import Iterable, Iterator, Sequence
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from pathlib import PurePosixPath

from preview_dashboard.config import Settings, check_intake_root, intake_sensitive_paths
from preview_dashboard.domain.paths import MAX_DEPTH
from preview_dashboard.domain.unicode import caseless_key
from preview_dashboard.interfaces.mcp.denylist import DenyList
from preview_dashboard.interfaces.mcp.errors import IntakeError, IntakeErrorCode, safe_display
from preview_dashboard.interfaces.mcp.relpaths import check_relpath

# Directories: never follow a symlink in the opened component (dir_fd walk
# means no earlier component is followed either).
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# Files: O_NONBLOCK so a FIFO swapped in after lstat can't hang the open;
# O_NOCTTY so a swapped-in tty never becomes our controlling terminal.
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY
# Kernel pseudo-filesystems: rejected whatever the config says.
_PSEUDO_FS_ROOTS = tuple(PurePosixPath(p) for p in ("/proc", "/sys", "/dev"))
DEFAULT_CHUNK_BYTES = 64 * 1024
# Requested paths deeper than this are refused before any filesystem call.
MAX_REQUEST_DEPTH = 64
_FDINFO_MAX_BYTES = 64 * 1024
_MNT_ID_PREFIX = b"mnt_id:"


def mount_id(fd: int) -> int | None:
    """Return the mount id of an open fd (from `/proc/self/fdinfo`), or None.

    Why: `st_dev` alone can't see bind mounts of the same filesystem (e.g.
    `/root/.ssh` bind-mounted into the outbox); the mount id can. None means
    it couldn't be determined, and callers must fail closed.
    """
    try:
        info = os.open(f"/proc/self/fdinfo/{fd}", os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        raw = b""
        while len(raw) < _FDINFO_MAX_BYTES:
            chunk = os.read(info, 4096)
            if not chunk:
                break
            raw += chunk
    except OSError:
        return None
    finally:
        os.close(info)
    for line in raw.splitlines():
        if line.startswith(_MNT_ID_PREFIX):
            value = line[len(_MNT_ID_PREFIX) :].strip()
            return int(value) if value.isdigit() else None
    return None


@dataclass(frozen=True, slots=True)
class IntakeLimits:
    """Hard caps applied while collecting a bundle.

    Attributes:
        max_files: files per bundle (also caps directories walked).
        max_file_bytes: bytes per file (from `fstat`, re-checked on read).
        max_item_bytes: total bytes per bundle.
    """

    max_files: int
    max_file_bytes: int
    max_item_bytes: int

    def __post_init__(self) -> None:
        if min(self.max_files, self.max_file_bytes, self.max_item_bytes) <= 0:
            raise ValueError("intake limits must be > 0")


class _FdSlot:
    """One owned file descriptor; `None` once the bundle is closed.

    Kept separate from `IntakeFile` so the bundle's finalizer can close fds
    without holding a reference to the bundle itself.
    """

    __slots__ = ("fd",)

    def __init__(self, fd: int) -> None:
        self.fd: int | None = fd


def _close_slots(slots: list[_FdSlot]) -> None:
    for slot in slots:
        fd, slot.fd = slot.fd, None
        if fd is not None:
            # Nothing useful to do on a close error; the fd is gone either way.
            with suppress(OSError):
                os.close(fd)


class IntakeFile:
    """One file accepted by intake, backed by an already-open, verified fd.

    Attributes:
        relpath: bundle-relative path (passed `validate_relpath`).
        size: byte size from `fstat` at open time; the reader delivers
            exactly this many bytes or raises.
    """

    __slots__ = ("_slot", "relpath", "size")

    def __init__(self, relpath: str, size: int, slot: _FdSlot) -> None:
        self.relpath = relpath
        self.size = size
        self._slot = slot

    def _fd(self) -> int:
        fd = self._slot.fd
        if fd is None:
            raise RuntimeError("intake bundle is closed")
        return fd

    @contextmanager
    def open_reader(self, chunk_size: int = DEFAULT_CHUNK_BYTES) -> Iterator[Iterator[bytes]]:
        """Yield an iterator of byte chunks read from the verified fd.

        Reads use `pread`, so a file may be read more than once. Chunks
        total exactly `size` bytes.

        Raises (from the iterator):
            IntakeError: code `CHANGED` if the file shrank or grew since it
                was opened (never reads past the `fstat` size).
            RuntimeError: the bundle was closed.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        self._fd()
        yield self._chunks(chunk_size)

    def _chunks(self, chunk_size: int) -> Iterator[bytes]:
        offset = 0
        while offset < self.size:
            data = self._pread(min(chunk_size, self.size - offset), offset)
            if not data:
                raise self._changed("shrank")
            offset += len(data)
            yield data
        # Growth past the checked size would bypass the size limits; the extra
        # bytes are never delivered, the publish is refused instead.
        if self._pread(1, offset):
            raise self._changed("grew")

    def _pread(self, size: int, offset: int) -> bytes:
        try:
            return os.pread(self._fd(), size, offset)
        except OSError as exc:
            reason = os.strerror(exc.errno) if exc.errno else "I/O error"
            raise IntakeError(
                IntakeErrorCode.UNREADABLE,
                f"'{safe_display(self.relpath)}' could not be read ({reason}); publish aborted.",
            ) from None

    def _changed(self, how: str) -> IntakeError:
        return IntakeError(
            IntakeErrorCode.CHANGED,
            f"'{safe_display(self.relpath)}' {how} while being read; publish aborted. "
            "Retry once the file is no longer being written.",
        )


class IntakeBundle:
    """The files accepted for one publish. Owns their fds: use as a context manager.

    Attributes:
        files: accepted files in deterministic (walk) order.
        total_bytes: sum of file sizes.
    """

    def __init__(self, files: tuple[IntakeFile, ...], slots: list[_FdSlot]) -> None:
        self.files = files
        self.total_bytes = sum(f.size for f in files)
        # Safety net only: callers should close explicitly or use `with`.
        self._finalizer = weakref.finalize(self, _close_slots, slots)

    @property
    def closed(self) -> bool:
        """True once `close()` ran (or the bundle was garbage collected)."""
        return not self._finalizer.alive

    def close(self) -> None:
        """Close every file descriptor. Idempotent."""
        self._finalizer()

    def __enter__(self) -> IntakeBundle:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class _Root:
    configured: PurePosixPath
    resolved: PurePosixPath
    # Why the resolved root is refused (C10 rules re-applied after realpath).
    problem: str | None = None


@dataclass(frozen=True, slots=True)
class _OpenRoot:
    fd: int
    dev: int
    mnt: int


@dataclass(frozen=True, slots=True)
class _Target:
    """A requested path mapped onto an allowed root."""

    root: _Root
    rel_parts: tuple[str, ...]  # components below the resolved root
    name_prefix: tuple[str, ...]  # relpath prefix for this target's files


def _parse_absolute(raw: object, what: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw:
        raise IntakeError(IntakeErrorCode.INVALID_REQUEST, f"{what} must be a non-empty string")
    if "\x00" in raw:
        raise IntakeError(IntakeErrorCode.INVALID_REQUEST, f"{what} contains NUL")
    # Lone surrogates (e.g. JSON "\ud800") are no real file name; the OS
    # layer would re-encode them via surrogateescape into arbitrary bytes.
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in raw):
        raise IntakeError(
            IntakeErrorCode.INVALID_REQUEST, f"{what} contains an unpaired surrogate character"
        )
    path = PurePosixPath(raw)
    if len(path.parts) > MAX_REQUEST_DEPTH:
        raise IntakeError(
            IntakeErrorCode.INVALID_REQUEST,
            f"{what} is nested too deeply (max {MAX_REQUEST_DEPTH} components)",
        )
    if not path.is_absolute():
        raise IntakeError(
            IntakeErrorCode.INVALID_REQUEST,
            f"{what} '{safe_display(path.name)}' must be an absolute path",
        )
    # '..' can't be resolved lexically without following symlinks; refuse it.
    if ".." in path.parts:
        raise IntakeError(IntakeErrorCode.INVALID_REQUEST, f"{what} must not contain '..'")
    return path


def _under(path: PurePosixPath, root: PurePosixPath) -> bool:
    # is_relative_to compares whole components: /root/outbox-evil is NOT
    # under /root/outbox (a string startswith check would say it is).
    return path.is_relative_to(root)


def _check_not_pseudo_fs(path: PurePosixPath, shown: str) -> None:
    if any(_under(path, pseudo) for pseudo in _PSEUDO_FS_ROOTS):
        raise IntakeError(
            IntakeErrorCode.OUTSIDE_ROOTS,
            f"'{shown}' is inside a kernel pseudo-filesystem (/proc, /sys, /dev); never published",
        )


class IntakePolicy:
    """Validates publish requests and opens the accepted files safely.

    Args:
        allowed_roots: absolute directories intake may read below.
        denylist: secret-path matcher applied to every resolved component.
        limits: bundle caps.
        sensitive_paths: paths no (resolved) root may contain or lie in
            (`config.intake_sensitive_paths`); `/`, `/root`, `/etc`, ...
            and pseudo-filesystems are always refused.
    """

    def __init__(
        self,
        *,
        allowed_roots: Sequence[PurePosixPath | str],
        denylist: DenyList,
        limits: IntakeLimits,
        sensitive_paths: Sequence[PurePosixPath | str] = (),
    ) -> None:
        roots = tuple(PurePosixPath(r) for r in allowed_roots)
        if not roots:
            raise ValueError("at least one allowed root is required")
        if not all(r.is_absolute() for r in roots):
            raise ValueError("allowed roots must be absolute")
        self._roots = roots
        self._sensitive = tuple(PurePosixPath(p) for p in sensitive_paths)
        self._denylist = denylist
        self._limits = limits

    @classmethod
    def from_settings(cls, settings: Settings, *, extra_denied: Iterable[str] = ()) -> IntakePolicy:
        """Build the policy from `Settings` (roots, denied patterns, limits).

        Args:
            settings: the loaded configuration.
            extra_denied: patterns denied on top of the configured list
                (e.g. names only some tools must refuse); never narrows it.
        """
        return cls(
            allowed_roots=tuple(PurePosixPath(r) for r in settings.intake_allowed_roots),
            denylist=DenyList((*settings.intake_denied_patterns, *extra_denied)),
            limits=IntakeLimits(
                max_files=settings.max_files,
                max_file_bytes=settings.max_file_bytes,
                max_item_bytes=settings.max_item_bytes,
            ),
            sensitive_paths=intake_sensitive_paths(
                admin_token_file=settings.admin_token_file, data_dir=settings.data_dir
            ),
        )

    def collect(self, paths: Sequence[str], *, base: str | None = None) -> IntakeBundle:
        """Check and open the requested files/directories as one bundle.

        Naming (relpaths):
        - `base` given: every path must be equal to or under `base`;
          relpaths are relative to `base` (a directory contributes its tree).
        - no `base`: a file is named by its basename; a directory
          contributes its contents relative to itself.

        Every path must lie under an allowed root (compared per component
        against the configured and the symlink-resolved root). A directory
        is walked recursively; any symlink, special file, hardlinked file,
        denylisted name or invalid name anywhere rejects the whole request.

        Returns:
            An open `IntakeBundle`; the caller must close it.

        Raises:
            IntakeError: on any policy violation (see `IntakeErrorCode`).
        """
        if isinstance(paths, str) or not paths:
            raise IntakeError(
                IntakeErrorCode.INVALID_REQUEST, "paths must be a non-empty list of absolute paths"
            )
        if len(paths) > self._limits.max_files:
            raise IntakeError(
                IntakeErrorCode.LIMIT,
                f"too many paths requested (max {self._limits.max_files} files per publish)",
            )
        requested = [_parse_absolute(p, "path") for p in paths]
        base_path = _parse_absolute(base, "base") if base is not None else None
        resolved_roots = self._resolve_roots()
        targets = [self._target(p, base_path, resolved_roots) for p in requested]
        collector = _Collector(self._denylist, self._limits)
        return collector.run(targets)

    def _resolve_roots(self) -> tuple[_Root, ...]:
        # Resolved once per request: the root may legitimately be a symlink
        # (e.g. to a bigger disk), and may not exist yet at server start.
        # Sensitive paths are compared both as configured and resolved, so a
        # symlinked data dir or token dir can't hide an overlap.
        sensitive = sorted(
            {form for p in self._sensitive for form in (p, PurePosixPath(os.path.realpath(p)))}
        )
        roots: list[_Root] = []
        for configured in self._roots:
            resolved = PurePosixPath(os.path.realpath(configured))
            problem: str | None = None
            try:
                # Config load checked the root lexically; a symlink may point
                # anywhere (/, /root, the data dir), so re-apply the same rules.
                check_intake_root(resolved, sensitive)
            except ValueError as exc:
                problem = str(exc)
            roots.append(_Root(configured=configured, resolved=resolved, problem=problem))
        return tuple(roots)

    def _target(
        self, path: PurePosixPath, base: PurePosixPath | None, roots: Sequence[_Root]
    ) -> _Target:
        _check_not_pseudo_fs(path, safe_display(path.name))
        best: tuple[_Root, tuple[str, ...]] | None = None
        for root in roots:
            for anchor_path in (root.resolved, root.configured):
                if _under(path, anchor_path):
                    rel = path.relative_to(anchor_path).parts
                    # Nested roots: the deepest match gives the shortest display path.
                    if best is None or len(rel) < len(best[1]):
                        best = (root, rel)
        if best is None:
            allowed = ", ".join(str(r) for r in self._roots)
            raise IntakeError(
                IntakeErrorCode.OUTSIDE_ROOTS,
                f"'{safe_display(path.name)}' is not under an allowed intake root "
                f"(allowed: {allowed}); copy it into an allowed root first",
            )
        root, rel = best
        if root.problem is not None:
            raise IntakeError(
                IntakeErrorCode.OUTSIDE_ROOTS,
                f"allowed root {safe_display(str(root.configured))} resolves to a forbidden "
                f"location ({safe_display(root.problem)}); fix the intake configuration",
            )
        # Empty prefix: a directory's files are named relative to it, a
        # file by its basename.
        prefix: tuple[str, ...] = ()
        if base is not None:
            if not _under(path, base):
                raise IntakeError(
                    IntakeErrorCode.INVALID_REQUEST,
                    f"'{safe_display(path.name)}' is not under base '{safe_display(str(base))}'",
                )
            prefix = path.relative_to(base).parts
        return _Target(root=root, rel_parts=rel, name_prefix=prefix)


class _Collector:
    """Per-request walk state: opened fds, counters, and seen relpaths."""

    def __init__(self, denylist: DenyList, limits: IntakeLimits) -> None:
        self._deny = denylist
        self._limits = limits
        self._slots: list[_FdSlot] = []
        self._files: list[IntakeFile] = []
        self._seen: dict[str, str] = {}  # caseless key -> relpath
        self._total = 0
        self._dirs = 0
        self._root_fds: dict[PurePosixPath, _OpenRoot] = {}  # keyed by resolved root

    def run(self, targets: Sequence[_Target]) -> IntakeBundle:
        try:
            for target in targets:
                self._collect_target(target)
            if not self._files:
                raise IntakeError(IntakeErrorCode.EMPTY, "nothing to publish: no files found")
            return IntakeBundle(tuple(self._files), self._slots)
        except BaseException:
            _close_slots(self._slots)
            raise
        finally:
            for opened in self._root_fds.values():
                os.close(opened.fd)

    # --- display / checks -------------------------------------------------

    def _shown(self, root: _Root, rel: Sequence[str]) -> str:
        where = "/".join(rel) if rel else "."
        return f"'{safe_display(where)}' (under allowed root {safe_display(str(root.configured))})"

    def _check_denied(self, root: _Root, rel: Sequence[str]) -> None:
        full = (*root.resolved.parts[1:], *rel)
        pattern = self._deny.match_last(full)
        if pattern is not None:
            raise IntakeError(
                IntakeErrorCode.DENIED,
                f"{self._shown(root, rel)} matches intake denylist pattern "
                f"'{safe_display(pattern)}'; secret-looking paths are never published",
            )

    def _classify(self, parent: int, name: str, root: _Root, rel: Sequence[str]) -> os.stat_result:
        try:
            st = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            raise IntakeError(
                IntakeErrorCode.NOT_FOUND, f"{self._shown(root, rel)} does not exist"
            ) from None
        except OSError as exc:
            raise self._unreadable(root, rel, exc) from None
        if stat.S_ISLNK(st.st_mode):
            raise IntakeError(
                IntakeErrorCode.SYMLINK,
                f"{self._shown(root, rel)} is a symlink; symlinks are never followed "
                "(copy the real file into the allowed root instead)",
            )
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise IntakeError(
                IntakeErrorCode.NOT_REGULAR,
                f"{self._shown(root, rel)} is not a regular file or directory "
                "(FIFOs, sockets and devices are never published)",
            )
        return st

    def _unreadable(self, root: _Root, rel: Sequence[str], exc: OSError) -> IntakeError:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            return IntakeError(
                IntakeErrorCode.SYMLINK,
                f"{self._shown(root, rel)} changed into a symlink or non-directory during intake",
            )
        reason = os.strerror(exc.errno) if exc.errno else "I/O error"
        return IntakeError(IntakeErrorCode.UNREADABLE, f"{self._shown(root, rel)}: {reason}")

    def _verify_same(
        self, fd: int, before: os.stat_result, anchor: _OpenRoot, root: _Root, rel: Sequence[str]
    ) -> os.stat_result:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise self._unreadable(root, rel, exc) from None
        # The fd must be the very object lstat saw: catches a swap in between.
        if (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino) or stat.S_IFMT(
            st.st_mode
        ) != stat.S_IFMT(before.st_mode):
            raise IntakeError(
                IntakeErrorCode.CHANGED, f"{self._shown(root, rel)} changed during intake"
            )
        # Crossing into another mount (e.g. a bind-mounted /proc or home dir)
        # would sidestep the allowlist; stay on the root's filesystem.
        if st.st_dev != anchor.dev:
            raise IntakeError(
                IntakeErrorCode.FILESYSTEM_BOUNDARY,
                f"{self._shown(root, rel)} is on a different filesystem than its allowed root",
            )
        # Same filesystem but another mount = a bind mount (st_dev can't tell).
        if mount_id(fd) != anchor.mnt:
            raise IntakeError(
                IntakeErrorCode.FILESYSTEM_BOUNDARY,
                f"{self._shown(root, rel)} is on a different mount than its allowed root "
                "(or its mount could not be verified)",
            )
        return st

    # --- opening ------------------------------------------------------------

    def _open_root(self, root: _Root) -> _OpenRoot:
        cached = self._root_fds.get(root.resolved)
        if cached is not None:
            return cached
        _check_not_pseudo_fs(root.resolved, safe_display(str(root.configured)))
        # Walk from '/' with O_NOFOLLOW: the realpath must contain no symlink
        # now, so a root swapped after resolution fails instead of redirecting.
        fd = os.open("/", _DIR_FLAGS)
        try:
            for part in root.resolved.parts[1:]:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        except OSError as exc:
            os.close(fd)
            if exc.errno == errno.ENOENT:
                raise IntakeError(
                    IntakeErrorCode.NOT_FOUND,
                    f"allowed root {safe_display(str(root.configured))} does not exist",
                ) from None
            raise IntakeError(
                IntakeErrorCode.UNREADABLE,
                f"allowed root {safe_display(str(root.configured))} could not be opened safely",
            ) from None
        try:
            dev = os.fstat(fd).st_dev
        except OSError:
            os.close(fd)
            raise IntakeError(
                IntakeErrorCode.UNREADABLE,
                f"allowed root {safe_display(str(root.configured))} could not be opened safely",
            ) from None
        mnt = mount_id(fd)
        if mnt is None:
            os.close(fd)
            # Fail closed: without the root's mount id no bind mount is detectable.
            raise IntakeError(
                IntakeErrorCode.FILESYSTEM_BOUNDARY,
                f"the mount of allowed root {safe_display(str(root.configured))} could not "
                "be verified (/proc/self/fdinfo unreadable)",
            )
        entry = _OpenRoot(fd=fd, dev=dev, mnt=mnt)
        self._root_fds[root.resolved] = entry
        return entry

    def _open_dir(
        self,
        parent: int,
        name: str,
        st: os.stat_result,
        anchor: _OpenRoot,
        root: _Root,
        rel: Sequence[str],
    ) -> int:
        try:
            fd = os.open(name, _DIR_FLAGS, dir_fd=parent)
        except OSError as exc:
            raise self._unreadable(root, rel, exc) from None
        try:
            self._verify_same(fd, st, anchor, root, rel)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _collect_target(self, target: _Target) -> None:
        root = target.root
        # Denylist on the resolved root itself (e.g. a root symlinked into a
        # .git dir): every component of the resolved path counts.
        pattern = self._deny.match(root.resolved.parts[1:])
        if pattern is not None:
            raise IntakeError(
                IntakeErrorCode.DENIED,
                f"allowed root {safe_display(str(root.configured))} matches intake "
                f"denylist pattern '{safe_display(pattern)}'",
            )
        anchor = self._open_root(root)
        parent = anchor.fd
        rel = target.rel_parts
        with ExitStack() as walk:
            for i, name in enumerate(rel):
                sub = rel[: i + 1]
                self._check_denied(root, sub)
                st = self._classify(parent, name, root, sub)
                if i < len(rel) - 1:
                    if not stat.S_ISDIR(st.st_mode):
                        raise IntakeError(
                            IntakeErrorCode.NOT_FOUND,
                            f"{self._shown(root, sub)} is not a directory",
                        )
                    parent = self._open_dir(parent, name, st, anchor, root, sub)
                    walk.callback(os.close, parent)
                    continue
                if stat.S_ISREG(st.st_mode):
                    naming = target.name_prefix or (name,)
                    self._add_file(parent, name, st, anchor, root, sub, naming)
                    return
                dir_fd = self._open_dir(parent, name, st, anchor, root, sub)
                walk.callback(os.close, dir_fd)
                self._walk_dir(dir_fd, anchor, root, sub, target.name_prefix)
                return
            # rel empty: the target is the allowed root itself.
            self._walk_dir(anchor.fd, anchor, root, (), target.name_prefix)

    def _walk_dir(
        self, fd: int, anchor: _OpenRoot, root: _Root, rel: tuple[str, ...], prefix: tuple[str, ...]
    ) -> None:
        self._dirs += 1
        if self._dirs > self._limits.max_files:
            raise IntakeError(
                IntakeErrorCode.LIMIT,
                f"too many directories (max {self._limits.max_files} per publish)",
            )
        names: list[str] = []
        # Bounded listing: a huge directory aborts early instead of being
        # fully read into memory.
        budget = 2 * self._limits.max_files
        try:
            with os.scandir(fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > budget:
                        raise IntakeError(
                            IntakeErrorCode.LIMIT,
                            f"{self._shown(root, rel)} has too many entries "
                            f"(max {self._limits.max_files} files per publish)",
                        )
        except OSError as exc:
            raise self._unreadable(root, rel, exc) from None
        for name in sorted(names):
            sub = (*rel, name)
            naming = (*prefix, name)
            self._check_denied(root, sub)
            st = self._classify(fd, name, root, sub)
            if stat.S_ISDIR(st.st_mode):
                # Files below would exceed the relpath depth: refuse before
                # opening more fds.
                if len(naming) >= MAX_DEPTH:
                    raise IntakeError(
                        IntakeErrorCode.RELPATH,
                        f"{self._shown(root, sub)} is nested too deeply: bundle paths may "
                        f"have at most {MAX_DEPTH} segments; flatten the directory tree",
                    )
                child = self._open_dir(fd, name, st, anchor, root, sub)
                try:
                    self._walk_dir(child, anchor, root, sub, naming)
                finally:
                    os.close(child)
            else:
                self._add_file(fd, name, st, anchor, root, sub, naming)

    def _add_file(
        self,
        parent: int,
        name: str,
        st: os.stat_result,
        anchor: _OpenRoot,
        root: _Root,
        rel: Sequence[str],
        naming: Sequence[str],
    ) -> None:
        relpath = check_relpath("/".join(naming))
        key = caseless_key(relpath)
        if key in self._seen:
            raise IntakeError(
                IntakeErrorCode.DUPLICATE,
                f"two files would both be named '{safe_display(relpath)}' "
                f"(or differ only by case: '{safe_display(self._seen[key])}'); "
                "rename one or pass a common base",
            )
        if len(self._files) >= self._limits.max_files:
            raise IntakeError(
                IntakeErrorCode.LIMIT, f"too many files (max {self._limits.max_files} per publish)"
            )
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
        except OSError as exc:
            raise self._unreadable(root, rel, exc) from None
        slot = _FdSlot(fd)
        self._slots.append(slot)  # closed by run() on any later failure
        verified = self._verify_same(fd, st, anchor, root, rel)
        if not stat.S_ISREG(verified.st_mode):
            raise IntakeError(
                IntakeErrorCode.NOT_REGULAR, f"{self._shown(root, rel)} is not a regular file"
            )
        # A second link could make an outside (e.g. secret) file appear
        # inside the root under an innocent name.
        if verified.st_nlink != 1:
            raise IntakeError(
                IntakeErrorCode.HARDLINK,
                f"{self._shown(root, rel)} has {verified.st_nlink} hard links; only "
                "single-link files are published (copy the file instead of linking it)",
            )
        size = verified.st_size
        if size > self._limits.max_file_bytes:
            raise IntakeError(
                IntakeErrorCode.LIMIT,
                f"{self._shown(root, rel)} is {size} bytes; max per file is "
                f"{self._limits.max_file_bytes}",
            )
        self._total += size
        if self._total > self._limits.max_item_bytes:
            raise IntakeError(
                IntakeErrorCode.LIMIT,
                f"bundle exceeds {self._limits.max_item_bytes} bytes in total",
            )
        self._seen[key] = relpath
        self._files.append(IntakeFile(relpath, size, slot))
