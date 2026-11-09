"""Step-up state file adapter: the TOTP replay mark and lockout counters, persisted (C47).

`FileStepUpState` keeps one small JSON file (`stepup-state.json`, mode 0600,
format version 2: replay mark, wrong-code counters, handled code messages)
in the admin-only `<data_dir>/claudia/` directory (`open_stepup_state`
migrates a file from the old `<data_dir>` location once). Every access is
`dir_fd`-relative with `O_NOFOLLOW`; saves are write-temp + fsync + atomic
rename. A present but unreadable, foreign-owned, loose-mode or malformed
file raises `StorageUnavailableError`: every code is refused instead of
silently resetting the lockout (fail closed). `exclusive()` holds an
`flock` on `stepup-state.lock` (0600, same checks) so the admin and root's
`claudia totp setup` never interleave a load-modify-save (storage-totp-3).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Final

from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.totp import SeenCode, StepUpState, TotpError

STATE_FILE_NAME: Final = "stepup-state.json"
LOCK_FILE_NAME: Final = "stepup-state.lock"
# The admin-only dir (0700) the Claudia DB lives in; the viewer can't reach it.
STATE_SUBDIR: Final = "claudia"
_TEMP_SUFFIX: Final = ".tmp"
_FILE_MODE: Final = 0o600
_MAX_BYTES: Final = 4096
_VERSION: Final = 2
_KEYS: Final = frozenset({"version", "last_step", "failures", "locked_until", "seen"})
# Version 1 (M3, unreleased) kept an update-id high-water mark instead of
# `seen`; it is read once more with that mark dropped (S-C1 S0): the replay
# mark and the lockout counters carry over unchanged.
_V1_KEYS: Final = frozenset({"version", "last_step", "failures", "locked_until", "last_update_id"})
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_WRITE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
# flock needs no write access; O_EXCL tells "we created it" (chown it) from "found it" (check it).
_LOCK_CREATE_FLAGS: Final = os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class StepUpStateError(StorageUnavailableError):
    """The step-up state can't be read, trusted or written (every code is refused)."""


def state_to_json(state: StepUpState) -> dict[str, object]:
    """The file's JSON object for `state`."""
    return {
        "version": _VERSION,
        "last_step": state.last_step,
        "failures": list(state.failures),
        "locked_until": state.locked_until,
        "seen": [[s.update_id, s.message_id, s.seen_at] for s in state.seen],
    }


def _seen_from_json(raw: object) -> tuple[SeenCode, ...]:
    if not isinstance(raw, list):
        raise StepUpStateError("step-up state has an unexpected shape")
    seen: list[SeenCode] = []
    for entry in raw:
        if not isinstance(entry, list) or len(entry) != 3:
            raise StepUpStateError("step-up state has an unexpected shape")
        update_id, message_id, seen_at = entry
        seen.append(SeenCode(update_id, message_id, seen_at))
    return tuple(seen)


def state_from_json(raw: object) -> StepUpState:
    """Parse the file's JSON object strictly (exact keys; version 2, or 1 upgraded).

    Raises:
        StepUpStateError: any other shape or value.
    """
    if not isinstance(raw, dict):
        raise StepUpStateError("step-up state has an unexpected shape")
    keys = set(raw)
    if not (
        (keys == _KEYS and raw.get("version") == _VERSION)
        or (keys == _V1_KEYS and raw.get("version") == 1)
    ):
        raise StepUpStateError("step-up state has an unexpected shape")
    failures = raw["failures"]
    if not isinstance(failures, list):
        raise StepUpStateError("step-up state has an unexpected shape")
    try:
        return StepUpState(
            last_step=raw["last_step"],
            failures=tuple(failures),
            locked_until=raw["locked_until"],
            seen=_seen_from_json(raw.get("seen", [])),
        )
    except TotpError:
        raise StepUpStateError("step-up state has invalid values") from None


def _lstat_or_none(name: str, dir_fd: int) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise StepUpStateError("step-up state migration could not inspect a file") from None


def _open_trusted_dir(path: Path, owner_uid: int, *, allow_group_read: bool) -> int:
    try:
        fd = os.open(path, _DIR_FLAGS)
    except OSError:
        raise StepUpStateError("step-up state directory is not usable") from None
    st = os.fstat(fd)
    loose = stat.S_IWGRP | stat.S_IWOTH | (0 if allow_group_read else stat.S_IRWXG | stat.S_IRWXO)
    if st.st_uid != owner_uid or st.st_mode & loose:
        os.close(fd)
        raise StepUpStateError("step-up state directory is not trusted")
    return fd


def migrate_legacy_state(data_dir: Path, subdir: str, *, owner_uid: int) -> None:
    """One-time move of `stepup-state.json` (+ `.lock`) from `data_dir` into `data_dir/subdir`.

    The old location sits in the viewer-readable data dir; the admin-only
    `claudia/` dir is where it belongs (F-C2b-3). Safe by construction:
    both directories are opened without following symlinks and must be
    owned by `owner_uid`; a symlink, non-regular, foreign-owned, hard-linked
    or loose-mode old file is refused (never moved); if the old AND the new
    path exist for either name nothing is touched and it raises (which one
    is current is the admin's call). The rename keeps owner and 0600 mode.

    Raises:
        StepUpStateError: a refusal above, or the rename failed.
    """
    src_fd = _open_trusted_dir(data_dir, owner_uid, allow_group_read=True)
    try:
        dst_fd = _open_trusted_dir(data_dir / subdir, owner_uid, allow_group_read=False)
        try:
            moves: list[str] = []
            for name in (STATE_FILE_NAME, LOCK_FILE_NAME):
                old = _lstat_or_none(name, src_fd)
                if old is None:
                    continue
                if _lstat_or_none(name, dst_fd) is not None:
                    raise StepUpStateError(
                        f"step-up state exists at both the old and the new path ({name}); "
                        "remove the stale one as the admin user"
                    )
                if (
                    not stat.S_ISREG(old.st_mode)
                    or old.st_uid != owner_uid
                    or old.st_nlink != 1
                    or stat.S_IMODE(old.st_mode) & 0o077
                ):
                    raise StepUpStateError(f"old step-up file {name} failed its checks")
                moves.append(name)
            for name in moves:
                try:
                    os.rename(name, name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)
                except OSError:
                    raise StepUpStateError("step-up state could not be migrated") from None
            if moves:
                os.fsync(dst_fd)
                os.fsync(src_fd)
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)


def open_stepup_state(data_dir: Path, *, owner_uid: int | None = None) -> FileStepUpState:
    """The store in `data_dir/claudia/` (admin-only), migrating an old-path file first.

    Raises:
        StepUpStateError: the migration was refused (see `migrate_legacy_state`).
    """
    uid = os.geteuid() if owner_uid is None else owner_uid
    migrate_legacy_state(Path(data_dir), STATE_SUBDIR, owner_uid=uid)
    return FileStepUpState(Path(data_dir) / STATE_SUBDIR, owner_uid=owner_uid)


class FileStepUpState:
    """`StepUpStateStore` over `<directory>/stepup-state.json`.

    Writers: the admin (every code) and, once per setup, root's `claudia
    totp setup` (burns the confirmation step), which passes the admin's uid
    as `owner_uid` so the file stays owned by the admin. Both wrap their
    load-modify-save in `exclusive()`.

    Args:
        directory: the admin's data directory (must exist, owned by the owner uid).
        owner_uid: who must own the directory and file (default: this
            process's euid). A different uid needs root (the file is chowned).
    """

    def __init__(self, directory: Path, *, owner_uid: int | None = None) -> None:
        self._directory = Path(directory)
        self._owner_uid = owner_uid

    def _owner(self) -> int:
        return os.geteuid() if self._owner_uid is None else self._owner_uid

    def _open_dir(self) -> int:
        try:
            fd = os.open(self._directory, _DIR_FLAGS)
        except OSError:
            raise StepUpStateError("step-up state directory is not usable") from None
        st = os.fstat(fd)
        if st.st_uid != self._owner() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            os.close(fd)
            raise StepUpStateError("step-up state directory is not trusted")
        return fd

    def load(self) -> StepUpState:
        """Return the stored state, or a fresh one if the file was never written.

        Raises:
            StepUpStateError: the file exists but fails a check or doesn't parse.
        """
        dir_fd = self._open_dir()
        try:
            try:
                fd = os.open(STATE_FILE_NAME, _READ_FLAGS, dir_fd=dir_fd)
            except FileNotFoundError:
                return StepUpState()
            except OSError:
                raise StepUpStateError("step-up state file is not readable") from None
            try:
                st = os.fstat(fd)
                if (
                    not stat.S_ISREG(st.st_mode)
                    or st.st_uid != self._owner()
                    or st.st_nlink != 1
                    or stat.S_IMODE(st.st_mode) & 0o077
                ):
                    raise StepUpStateError("step-up state file failed its ownership/mode checks")
                data = os.read(fd, _MAX_BYTES + 1)
            finally:
                os.close(fd)
        finally:
            os.close(dir_fd)
        if len(data) > _MAX_BYTES:
            raise StepUpStateError("step-up state file is too large")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise StepUpStateError("step-up state file is not valid JSON") from None
        return state_from_json(parsed)

    def save(self, state: StepUpState) -> None:
        """Write `state` atomically (temp file + fsync + rename + directory fsync).

        Raises:
            StepUpStateError: the file could not be written.
        """
        data = json.dumps(state_to_json(state), sort_keys=True).encode("ascii")
        temp = STATE_FILE_NAME + _TEMP_SUFFIX
        dir_fd = self._open_dir()
        try:
            # A temp file left by a crash is ours to replace (never followed: unlink).
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp, dir_fd=dir_fd)
            fd = os.open(temp, _WRITE_FLAGS, _FILE_MODE, dir_fd=dir_fd)
            try:
                if self._owner() != os.geteuid():
                    # Root (setup) writing for the admin: the admin must own it to load it.
                    os.fchown(fd, self._owner(), -1)
                os.fchmod(fd, _FILE_MODE)
                written = 0
                while written < len(data):
                    written += os.write(fd, data[written:])
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(temp, STATE_FILE_NAME, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            os.fsync(dir_fd)
        except OSError:
            raise StepUpStateError("step-up state could not be saved") from None
        finally:
            os.close(dir_fd)

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[None]:
        """Hold an exclusive `flock` on `stepup-state.lock` for the `with` body.

        Blocks until the other writer is done (its holds last one load and
        one save). Closing the fd releases the lock, also on a crash.

        Raises:
            StepUpStateError: the lock file is unsafe (symlink, not regular,
                foreign owner, extra link, loose mode) or can't be locked.
        """
        fd = self._open_lock()
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                raise StepUpStateError("step-up state lock could not be taken") from None
            yield
        finally:
            os.close(fd)

    def _open_lock(self) -> int:
        dir_fd = self._open_dir()
        try:
            try:
                fd = os.open(LOCK_FILE_NAME, _LOCK_CREATE_FLAGS, _FILE_MODE, dir_fd=dir_fd)
                created = True
            except FileExistsError:
                try:
                    fd = os.open(LOCK_FILE_NAME, _READ_FLAGS, dir_fd=dir_fd)
                except OSError:
                    raise StepUpStateError("step-up state lock is not usable") from None
                created = False
            except OSError:
                raise StepUpStateError("step-up state lock is not usable") from None
        finally:
            os.close(dir_fd)
        try:
            if created:
                if self._owner() != os.geteuid():
                    # Root (setup) creating it: the admin must be able to open it later.
                    os.fchown(fd, self._owner(), -1)
                os.fchmod(fd, _FILE_MODE)
            st = os.fstat(fd)
            if (
                not stat.S_ISREG(st.st_mode)
                or st.st_uid != self._owner()
                or st.st_nlink != 1
                or stat.S_IMODE(st.st_mode) & 0o077
            ):
                # Never "fixed": a lock others can open would let them stall every code.
                raise StepUpStateError("step-up state lock failed its ownership/mode checks")
        except OSError:
            os.close(fd)
            raise StepUpStateError("step-up state lock is not usable") from None
        except StepUpStateError:
            os.close(fd)
            raise
        return fd
