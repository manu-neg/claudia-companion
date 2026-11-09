"""MCP tools for live work trackers: `dashboard_progress_set` / `_update` (ADR 0029).

One call per tracker update: the status is validated against the `progress`
kind's schema (`kinds/progress.py`), staged as `progress.json` in a private
state dir under the intake root, and published through the normal intake
(C10/C27) and admin publish/revision path (secret scan C15 included). No
path ever comes from the caller; item ids are checked as ULIDs before they
name a directory.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import secrets
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Annotated, Final, Protocol

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.interfaces.mcp.client import (
    AdminClientError,
    AdminConflictError,
    UploadFile,
)
from preview_dashboard.interfaces.mcp.errors import IntakeError
from preview_dashboard.interfaces.mcp.tools.folders import FolderIdArg
from preview_dashboard.kinds.progress import (
    MAX_PROGRESS_BYTES,
    NOTE_MAX,
    PROGRESS_FILE,
    STATES,
    UNIT_DETAIL_MAX,
    UNIT_ID_PATTERN,
    ProgressDoc,
    clean_text,
    encode_progress,
    normalize_progress,
    parse_progress,
    progress_json_schema,
    unit_id,
    unit_state,
)

logger = logging.getLogger("preview_dashboard.mcp")

KIND: Final = "progress"
STATE_DIR: Final = "progress-state"
STATE_FILE: Final = "state.json"
_STAGE_PREFIX: Final = "stage-"
# state.json = {"revision", "status"}: the status plus a little envelope.
_MAX_STATE_BYTES: Final = MAX_PROGRESS_BYTES + 1024
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_EXCL: never write through a pre-planted file; O_NONBLOCK: a FIFO can't hang a read.
_NEW_FILE_FLAGS: Final = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
# Only names this module creates are ever swept; strict patterns, never a glob.
_STAGE_NAME: Final = re.compile(r"^stage-[0-9a-f]{16}$")
_TMP_NAME: Final = re.compile(r"^state\.json\.[0-9a-f]{16}\.tmp$")
STALE_AFTER_S: Final = 3600.0
_MAX_REVISION: Final = 2**31 - 1
_ULID: Final = r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_SET_HINT: Final = "call dashboard_progress_set with the full status"


class ProgressStateError(Exception):
    """The private state dir is unusable (unsafe, unreadable, corrupt). `str()` is caller-safe."""


class ProgressApi(Protocol):
    """The admin operations the progress tools need (`AdminClient` implements this)."""

    def publish(
        self,
        files: Sequence[UploadFile],
        *,
        title: str,
        description: str = ...,
        kind_hint: str | None = ...,
        pinned: bool = ...,
        folder_id: str | None = ...,
    ) -> dict[str, object]: ...

    def publish_revision(
        self,
        item_id: str,
        files: Sequence[UploadFile],
        *,
        kind_hint: str | None = ...,
        expected_revision: int | None = ...,
    ) -> dict[str, object]: ...

    def update_item(
        self,
        item_id: str,
        *,
        title: str | None = ...,
        description: str | None = ...,
        pinned: bool | None = ...,
    ) -> dict[str, object]: ...

    def move_item(self, item_id: str, folder_id: str | None) -> dict[str, object]: ...

    def get_item(self, item_id: str) -> dict[str, object]: ...


class Bundle(Protocol):
    """What the tools use of an intake bundle (`IntakeBundle`)."""

    @property
    def files(self) -> Sequence[UploadFile]: ...

    def __enter__(self) -> Bundle: ...

    def __exit__(self, *exc_info: object) -> None: ...


class Intake(Protocol):
    """The intake operation the tools use (`IntakePolicy` implements this)."""

    def collect(self, paths: Sequence[str], *, base: str | None = ...) -> Bundle: ...


def _check_private_dir(fd: int, shown: str) -> None:
    st = os.fstat(fd)
    # Fail closed: someone else's or a shared dir could feed us content.
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise ProgressStateError(
            f"progress state dir {shown} must be a directory owned by this user with mode 0700"
        )


def _open_private_dir(parent_fd: int, name: str, shown: str, *, create: bool) -> int | None:
    """Open (and optionally create, 0700) directory `name` under `parent_fd`; None if absent."""
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError:
            raise _io_error() from None
    try:
        fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError:
        # ELOOP (symlink), ENOTDIR, EACCES: never follow or guess.
        raise ProgressStateError(f"progress state dir {shown} is not a plain directory") from None
    try:
        _check_private_dir(fd, shown)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _write_new(dir_fd: int, name: str, data: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=dir_fd,
    )
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)


class ProgressStateStore:
    """The private per-item state under `<intake root>/progress-state/` (ADR 0029).

    Layout: `<ITEM ULID>/state.json` (`{"revision", "status"}`, replaced
    atomically) and short-lived `stage-<hex>/progress.json` publish stages.
    Every directory is opened fd-relative with `O_NOFOLLOW` and must be
    owned by this user with mode 0700.

    Args:
        intake_root: an allowed intake root (the state must pass intake).
    """

    def __init__(self, intake_root: PurePosixPath | str) -> None:
        root = PurePosixPath(intake_root)
        if not root.is_absolute():
            raise ValueError("intake_root must be absolute")
        self._root = root

    @property
    def state_dir(self) -> PurePosixPath:
        """Absolute path of the state directory."""
        return self._root / STATE_DIR

    @contextmanager
    def _base(self, *, create: bool) -> Iterator[int | None]:
        try:
            # The root itself may be a symlink (as intake allows); below it, never.
            root_fd = os.open(str(self._root), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            raise ProgressStateError("the intake root is not available") from None
        try:
            fd = _open_private_dir(root_fd, STATE_DIR, STATE_DIR, create=create)
        finally:
            os.close(root_fd)
        try:
            yield fd
        finally:
            if fd is not None:
                os.close(fd)

    @contextmanager
    def stage(self, data: bytes) -> Iterator[str]:
        """Write `data` as a fresh `stage-<hex>/progress.json`; yield its absolute path.

        The stage is removed when the block exits.
        """
        name = _STAGE_PREFIX + secrets.token_hex(8)
        with self._base(create=True) as base:
            if base is None:  # just created; only a racing delete gets here
                raise ProgressStateError("progress state dir vanished")
            # Only setup is wrapped: OSErrors from the publish body are not state errors.
            try:
                os.mkdir(name, 0o700, dir_fd=base)
            except OSError:
                raise _io_error() from None
            try:
                stage_fd = _open_private_dir(base, name, name, create=False)
                if stage_fd is None:
                    raise ProgressStateError("progress stage dir vanished")
                try:
                    try:
                        _write_new(stage_fd, PROGRESS_FILE, data)
                    except OSError:
                        raise _io_error() from None
                    yield str(self.state_dir / name / PROGRESS_FILE)
                finally:
                    with suppress(OSError):
                        os.unlink(PROGRESS_FILE, dir_fd=stage_fd)
                    os.close(stage_fd)
            finally:
                with suppress(OSError):
                    os.rmdir(name, dir_fd=base)

    def sweep(
        self, *, max_age_s: float = STALE_AFTER_S, now: Callable[[], float] = time.time
    ) -> int:
        """Remove stale leftovers of crashed runs; return how many entries went.

        Only `stage-<hex>/` dirs and `state.json.<hex>.tmp` files older than
        `max_age_s` are touched (everything fd-relative, no symlink followed,
        owned by this user); item `state.json` files are never removed here.
        """
        cutoff = now() - max_age_s
        removed = 0
        with self._base(create=False) as base:
            if base is None:
                return 0
            for name in os.listdir(base):
                if _STAGE_NAME.match(name):
                    removed += _sweep_stage(base, name, cutoff)
                elif is_ulid(name):
                    removed += _sweep_item(base, name, cutoff)
        return removed

    def load(self, item_id: str) -> tuple[int, ProgressDoc] | None:
        """Return `(revision, status)` last saved for `item_id`, or None if there is none.

        Raises:
            ValueError: `item_id` is not a canonical ULID.
            ProgressStateError: the state exists but is unsafe or corrupt.
        """
        _require_ulid(item_id)
        with self._base(create=False) as base:
            if base is None:
                return None
            item_fd = _open_private_dir(base, item_id, item_id, create=False)
            if item_fd is None:
                return None
            try:
                raw = _read_small(item_fd, STATE_FILE)
            finally:
                os.close(item_fd)
        if raw is None:
            return None
        return _decode_state(raw)

    def save(self, item_id: str, revision: int, doc: ProgressDoc) -> None:
        """Atomically replace `item_id`'s state with `(revision, doc)`.

        Raises:
            ValueError: `item_id` is not a canonical ULID.
            ProgressStateError: the state dir is unsafe.
        """
        _require_ulid(item_id)
        data = json.dumps(
            {"revision": revision, "status": doc}, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        with self._base(create=True) as base:
            if base is None:
                raise ProgressStateError("progress state dir vanished")
            item_fd = _open_private_dir(base, item_id, item_id, create=True)
            if item_fd is None:
                raise ProgressStateError("progress state dir vanished")
            try:
                tmp = f"{STATE_FILE}.{secrets.token_hex(8)}.tmp"
                try:
                    _write_new(item_fd, tmp, data)
                    os.replace(tmp, STATE_FILE, src_dir_fd=item_fd, dst_dir_fd=item_fd)
                except OSError:
                    with suppress(OSError):
                        os.unlink(tmp, dir_fd=item_fd)
                    raise _io_error() from None
            finally:
                os.close(item_fd)


def _io_error() -> ProgressStateError:
    # Raw OSError text can carry paths; callers get a fixed message.
    return ProgressStateError("progress state could not be written (I/O error)")


def _is_stale_own(dir_fd: int, name: str, cutoff: float, *, want_dir: bool) -> bool:
    """True for a plain (non-symlink) entry of the wanted type, ours, and older than cutoff."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return False
    is_type = stat.S_ISDIR(st.st_mode) if want_dir else stat.S_ISREG(st.st_mode)
    return is_type and st.st_uid == os.geteuid() and st.st_mtime < cutoff


def _sweep_stage(base: int, name: str, cutoff: float) -> int:
    if not _is_stale_own(base, name, cutoff, want_dir=True):
        return 0
    try:
        fd = _open_private_dir(base, name, name, create=False)
    except ProgressStateError:
        return 0
    if fd is None:
        return 0
    try:
        with suppress(OSError):
            os.unlink(PROGRESS_FILE, dir_fd=fd)
    finally:
        os.close(fd)
    try:
        os.rmdir(name, dir_fd=base)  # fails (kept) if anything unexpected is inside
    except OSError:
        return 0
    return 1


def _sweep_item(base: int, name: str, cutoff: float) -> int:
    try:
        fd = _open_private_dir(base, name, name, create=False)
    except ProgressStateError:
        return 0
    if fd is None:
        return 0
    removed = 0
    try:
        for entry in os.listdir(fd):
            if _TMP_NAME.match(entry) and _is_stale_own(fd, entry, cutoff, want_dir=False):
                try:
                    os.unlink(entry, dir_fd=fd)
                    removed += 1
                except OSError:
                    continue
    finally:
        os.close(fd)
    return removed


def _require_ulid(item_id: str) -> None:
    # Ids become directory names: only canonical ULIDs, never caller paths.
    if not is_ulid(item_id):
        raise ValueError("invalid item id")


def _read_small(dir_fd: int, name: str) -> bytes | None:
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd
        )
    except FileNotFoundError:
        return None
    except OSError:
        raise ProgressStateError("progress state file is not a plain file") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_STATE_BYTES:
            raise ProgressStateError("progress state file is not a plain file or too large")
        return os.read(fd, _MAX_STATE_BYTES + 1)[:_MAX_STATE_BYTES]
    finally:
        os.close(fd)


def _decode_state(raw: bytes) -> tuple[int, ProgressDoc]:
    try:
        value: object = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) != {"revision", "status"}:
            raise ValueError("bad envelope")
        revision = value["revision"]
        if type(revision) is not int or not 1 <= revision <= _MAX_REVISION:
            raise ValueError("bad revision")
        return revision, parse_progress(value["status"])
    except (ValueError, ValidationError):  # UnicodeDecodeError/JSON errors are ValueErrors
        raise ProgressStateError(f"the local progress state is corrupt; {_SET_HINT}") from None


def _compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _summary(item: Mapping[str, object], doc: ProgressDoc) -> dict[str, object]:
    """Server-controlled fields at the top; titles (untrusted text) nested apart."""
    folder = item.get("folder")
    done = sum(1 for u in doc["units"] if u["state"] == "done")
    return {
        "id": item.get("id"),
        "kind": item.get("kind"),
        "revision": item.get("revision"),
        "pinned": item.get("pinned"),
        "folder_id": folder.get("id") if isinstance(folder, dict) else None,
        "viewer_url": item.get("viewer_url"),
        "updated_at": doc["updated_at"],
        "units_done": f"{done}/{len(doc['units'])}",
        "untrusted_item_data": {"title": item.get("title"), "status_title": doc["title"]},
    }


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ProgressTools:
    """Tool implementations: validate, stage, publish via intake, remember the state.

    Calls are serialized in-process (one lock); across processes the admin
    API's `expected_revision` check decides.

    Args:
        intake: the publish intake policy (re-checks the staged file).
        admin: the admin API client.
        store: the private state store under the intake root.
        clock: source of `updated_at` (tz-aware).
    """

    def __init__(
        self,
        *,
        intake: Intake,
        admin: ProgressApi,
        store: ProgressStateStore,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._intake = intake
        self._admin = admin
        self._store = store
        self._clock = clock
        self._lock = threading.Lock()
        # Best effort at startup: leftovers of crashed runs; never blocks the server.
        try:
            store.sweep()
        except (ProgressStateError, OSError) as exc:
            logger.info("progress state sweep skipped: %s", type(exc).__name__)

    def set(
        self,
        status: Mapping[str, object],
        item_id: str | None = None,
        title: str | None = None,
        folder_id: str | None = None,
        pinned: bool | None = None,
        expected_revision: int | None = None,
    ) -> str:
        """Publish `status` as a new progress item, or as a new revision of `item_id`."""
        if item_id is None and expected_revision is not None:
            raise ToolError("expected_revision needs item_id (it guards an existing item)")
        if item_id is not None and not is_ulid(item_id):
            raise ToolError("invalid item id")
        with self._lock:
            doc = self._normalize(dict(status))
            data = self._encode(doc)
            if item_id is None:
                item = self._publish_new(doc, data, title=title, folder_id=folder_id, pinned=pinned)
            else:
                guard = self._require_progress_item(item_id, expected_revision)
                item = self._publish_revision(item_id, doc, data, guard)
                item = self._apply_meta(
                    item_id, item, title=title, folder_id=folder_id, pinned=pinned
                )
        logger.info("progress_set ok: item %s revision %s", item.get("id"), item.get("revision"))
        return _compact(_summary(item, doc))

    def update(
        self,
        item_id: str,
        unit_id_arg: str | None = None,
        state: str | None = None,
        detail: str | None = None,
        note: str | None = None,
    ) -> str:
        """Patch one unit's state/detail and/or the note of a tracker this host published."""
        if not is_ulid(item_id):
            raise ToolError("invalid item id")
        if (state is not None or detail is not None) and unit_id_arg is None:
            raise ToolError("state/detail need unit_id (the unit to change)")
        if unit_id_arg is not None and state is None and detail is None:
            raise ToolError("unit_id needs state and/or detail to change")
        if unit_id_arg is None and note is None:
            raise ToolError("nothing to change: give unit_id with state/detail, and/or note")
        with self._lock:
            loaded = self._guard(lambda: self._store.load(item_id))
            if loaded is None:
                raise ToolError(
                    "no local progress state for this item (not published by "
                    f"dashboard_progress_set on this host); {_SET_HINT}"
                )
            revision, current = loaded
            patched = self._patch(current, unit_id_arg, state, detail, note)
            doc = self._normalize(patched)
            data = self._encode(doc)
            item = self._publish_revision(item_id, doc, data, revision)
        logger.info("progress_update ok: item %s revision %s", item_id, item.get("revision"))
        return _compact(_summary(item, doc))

    # --- steps ------------------------------------------------------------------------

    def _normalize(self, status: dict[str, object]) -> ProgressDoc:
        try:
            return normalize_progress(status, updated_at=self._clock())
        except ValidationError as exc:
            raise ToolError(f"invalid progress status: {exc}") from None

    @staticmethod
    def _encode(doc: ProgressDoc) -> bytes:
        try:
            return encode_progress(doc)
        except ValidationError as exc:
            raise ToolError(f"invalid progress status: {exc}") from None

    @staticmethod
    def _patch(
        current: ProgressDoc,
        uid: str | None,
        state: str | None,
        detail: str | None,
        note: str | None,
    ) -> dict[str, object]:
        doc = copy.deepcopy(current)
        try:
            if note is not None:
                doc["note"] = clean_text(note, "note", NOTE_MAX, required=False)
            if uid is not None:
                wanted = unit_id(uid)
                unit = next((u for u in doc["units"] if u["id"] == wanted), None)
                if unit is None:
                    raise ToolError(f"unit {wanted!r} is not in this tracker; {_SET_HINT}")
                if state is not None:
                    unit["state"] = unit_state(state)
                if detail is not None:
                    unit["detail"] = clean_text(detail, "detail", UNIT_DETAIL_MAX, required=False)
        except ValidationError as exc:
            raise ToolError(f"invalid progress update: {exc}") from None
        return dict(doc)

    def _require_progress_item(self, item_id: str, expected_revision: int | None) -> int:
        """Refuse to turn a non-progress item into a tracker; return the revision to guard.

        The kind check and the publish are tied together by the revision just
        checked (which the caller's `expected_revision`, if given, must equal):
        if the item changes in between, the admin API refuses the publish
        instead of racing it.
        """
        current = self._call("dashboard_progress_set", lambda: self._admin.get_item(item_id))
        if current.get("kind") != KIND:
            raise ToolError(
                f"item {item_id} is not a progress tracker; dashboard_progress_set only "
                "updates progress items -- use dashboard_update_content for other items"
            )
        revision = current.get("revision")
        if type(revision) is not int or not 1 <= revision <= _MAX_REVISION:
            raise ToolError("admin API returned an unexpected item; the tracker may be stale")
        if expected_revision is not None and expected_revision != revision:
            # Guarding with any other revision would let a later non-progress
            # revision (e.g. the caller's expected one) slip past the kind check.
            def refuse() -> dict[str, object]:
                raise AdminConflictError(
                    f"conflict (409): item is at revision {revision}, not expected_revision "
                    f"{expected_revision}",
                    status=409,
                    code="conflict",
                )

            self._call("dashboard_progress_set", refuse)
        return revision

    def _publish_new(
        self,
        doc: ProgressDoc,
        data: bytes,
        *,
        title: str | None,
        folder_id: str | None,
        pinned: bool | None,
    ) -> dict[str, object]:
        def publish(files: Sequence[UploadFile]) -> dict[str, object]:
            return self._admin.publish(
                files,
                title=title if title is not None else doc["title"],
                kind_hint=KIND,
                pinned=bool(pinned),
                folder_id=folder_id,
            )

        item = self._send("dashboard_progress_set", data, publish)
        self._remember(item, doc)
        return item

    def _publish_revision(
        self, item_id: str, doc: ProgressDoc, data: bytes, expected_revision: int | None
    ) -> dict[str, object]:
        def publish(files: Sequence[UploadFile]) -> dict[str, object]:
            return self._admin.publish_revision(
                item_id, files, kind_hint=KIND, expected_revision=expected_revision
            )

        item = self._send("dashboard_progress", data, publish)
        self._remember(item, doc)
        return item

    def _apply_meta(
        self,
        item_id: str,
        item: dict[str, object],
        *,
        title: str | None,
        folder_id: str | None,
        pinned: bool | None,
    ) -> dict[str, object]:
        if title is not None or pinned is not None:
            item = self._call(
                "dashboard_progress_set",
                lambda: self._admin.update_item(item_id, title=title, pinned=pinned),
            )
        if folder_id is not None:
            item = self._call(
                "dashboard_progress_set", lambda: self._admin.move_item(item_id, folder_id)
            )
        return item

    def _send(
        self,
        tool: str,
        data: bytes,
        publish: Callable[[Sequence[UploadFile]], dict[str, object]],
    ) -> dict[str, object]:
        def run() -> dict[str, object]:
            with self._store.stage(data) as path, self._intake.collect([path]) as bundle:
                return publish(bundle.files)

        return self._call(tool, run)

    def _remember(self, item: Mapping[str, object], doc: ProgressDoc) -> None:
        item_id, revision = item.get("id"), item.get("revision")
        if not isinstance(item_id, str) or not is_ulid(item_id) or type(revision) is not int:
            raise ToolError("admin API returned an unexpected item; the tracker may be stale")
        try:
            self._store.save(item_id, revision, doc)
        except ProgressStateError as exc:
            logger.info("progress state not saved after publish: %s", exc)
            # The publish went through: say so, or the caller would create a duplicate.
            raise ToolError(
                f"published as item {item_id} revision {revision}, but the local state could "
                f"not be saved ({exc}); do NOT publish a new item: call dashboard_progress_set "
                f"with item_id={item_id} to continue"
            ) from None

    @staticmethod
    def _guard[T](action: Callable[[], T]) -> T:
        try:
            return action()
        except ProgressStateError as exc:
            logger.info("progress state refused: %s", exc)
            raise ToolError(str(exc)) from None

    def _call(self, tool: str, action: Callable[[], dict[str, object]]) -> dict[str, object]:
        """Run one admin call, turning known failures into caller-safe `ToolError`s."""
        try:
            return self._guard(action)
        except IntakeError as exc:
            logger.info("%s refused by intake: %s", tool, exc.code.value)
            raise ToolError(f"intake refused ({exc.code.value}): {exc}") from None
        except AdminConflictError as exc:
            logger.info("%s conflict: %s", tool, exc.code)
            raise ToolError(
                f"{exc} -- the item changed since this tracker's last write (or is trashed); "
                f"check it with dashboard_get, then {_SET_HINT}"
            ) from None
        except AdminClientError as exc:
            logger.info("%s failed: %s (status %s)", tool, exc.code, exc.status)
            raise ToolError(str(exc)) from None


_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=False)

ItemIdArg = Annotated[
    str,
    Field(pattern=_ULID, description="Progress item id (26 chars) from dashboard_progress_set."),
]


def register(server: MCPServer, tools: ProgressTools) -> ProgressTools:
    """Register `dashboard_progress_set` and `dashboard_progress_update` on `server`."""

    @server.tool(
        name="dashboard_progress_set",
        annotations=_WRITE,
        structured_output=False,
        description=(
            "Create or fully replace a LIVE WORK TRACKER (progress page) on the owner's "
            "dashboard in ONE call -- no files to write. status = the whole tracker: title, "
            "note, units (id, name, who, state done|running|waiting|blocked, detail), phases "
            "(timeline columns) and timeline lanes of bars (unit, from, to = phase indexes, to "
            "exclusive). Plain text only, one line per field. Without item_id a new item is "
            "published (title defaults to status.title; folder_id/pinned optional); with "
            "item_id (an existing progress item; others are refused) it becomes that "
            "tracker's next revision (same viewer_url), and "
            "title/pinned/folder_id, if given, are applied too. Pass expected_revision to "
            "refuse overwriting a revision you haven't seen. For small changes (one unit's "
            "state/detail, the note) use dashboard_progress_update. Returns id, revision, "
            "viewer_url."
        ),
    )
    def dashboard_progress_set(
        status: Annotated[
            dict[str, object],
            Field(
                description="The whole tracker (schema v1, see ADR 0029).",
                json_schema_extra=progress_json_schema(),
            ),
        ],
        item_id: ItemIdArg | None = None,
        title: Annotated[
            str | None,
            Field(min_length=1, max_length=1000, description="Item title (<= 200 chars)."),
        ] = None,
        folder_id: FolderIdArg | None = None,
        pinned: Annotated[bool | None, Field(description="Pin to the top of the feed.")] = None,
        expected_revision: Annotated[
            int | None,
            Field(ge=1, le=_MAX_REVISION, description="Refuse if the item's revision differs."),
        ] = None,
    ) -> str:
        return tools.set(status, item_id, title, folder_id, pinned, expected_revision)

    @server.tool(
        name="dashboard_progress_update",
        annotations=_WRITE,
        structured_output=False,
        description=(
            "Update a live work tracker made with dashboard_progress_set in ONE call: set one "
            "unit's state (done|running|waiting|blocked) and/or detail, and/or the tracker's "
            "note; everything else stays. Publishes a new revision (same viewer_url) and "
            "refuses if the item changed elsewhere since (then use dashboard_progress_set). "
            "To add/remove units, phases or lanes use dashboard_progress_set."
        ),
    )
    def dashboard_progress_update(
        item_id: ItemIdArg,
        unit_id: Annotated[
            str | None, Field(pattern=UNIT_ID_PATTERN, description="Unit to change.")
        ] = None,
        state: Annotated[
            str | None,
            Field(pattern="^(" + "|".join(STATES) + ")$", description="New unit state."),
        ] = None,
        detail: Annotated[
            str | None,
            Field(max_length=4 * UNIT_DETAIL_MAX, description="New unit detail ('' clears)."),
        ] = None,
        note: Annotated[
            str | None,
            Field(max_length=4 * NOTE_MAX, description="New tracker note ('' clears)."),
        ] = None,
    ) -> str:
        return tools.update(item_id, unit_id, state, detail, note)

    return tools
