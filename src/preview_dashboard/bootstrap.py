"""Composition root: the ONLY module that wires concrete adapters into services.

`build_core(settings, role=...)` maps `Settings` to adapters (SQLite repo,
filesystem blob store, clock, ULIDs, secret scanner, rate limiters, the
question/outbox store and in-process wake-ups) and returns a small frozen
container holding only the services that process role needs (least
privilege: the viewer core has no publish capability, a read-only blob
store, read-only folders and a keep=1-only revision pruner; only the admin
core can ask or answer questions
or change folders). The container owns
the adapters' resources and closes them on `close()` / context-manager exit.
"""

from __future__ import annotations

import functools
import os
import sqlite3
from collections.abc import Callable, Collection, Iterable
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, Literal, Self, overload

from preview_dashboard.adapters.approvals_snapshot import FileSnapshotSink, default_snapshot_path
from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.adapters.sqlite import (
    CURRENT_VERSION,
    SqliteApprovalStore,
    SqliteFolderRepository,
    SqliteItemRepository,
    SqliteNotificationOutbox,
    SqliteOwnerMessageStore,
    SqliteQuestionRepository,
    connect,
    connect_claudia,
    default_claudia_db_path,
    default_db_path,
)
from preview_dashboard.adapters.sqlite.claudia_db import compact_claudia
from preview_dashboard.adapters.stepup_state import open_stepup_state
from preview_dashboard.adapters.telegram.answers import SOURCE_NAME as TELEGRAM_SOURCE
from preview_dashboard.adapters.telegram.channel import CHANNEL_NAME as TELEGRAM_CHANNEL
from preview_dashboard.adapters.totp_secret import FileTotpSecret
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.adapters.voice_store import VOICE_DIR_NAME, FsVoiceStore
from preview_dashboard.adapters.wakeups import AsyncioOutboxEvents, AsyncioQuestionEvents
from preview_dashboard.application import (
    ArchiveService,
    FolderListing,
    FolderService,
    HistoryService,
    LifecycleService,
    NotifyService,
    OutboxService,
    PruneResult,
    PublishLimits,
    PublishService,
    PurgeReport,
    PurgeService,
    QueryService,
    QuestionHousekeeping,
    QuestionService,
    SlidingWindowRateLimiter,
)
from preview_dashboard.application.approval_prompts import OutboxApprovalPrompts
from preview_dashboard.application.approvals import ApprovalService
from preview_dashboard.application.approvals_snapshot import (
    ApprovalsSnapshotWriter,
    SnapshotOnChange,
)
from preview_dashboard.application.claudia.voice import VoiceService
from preview_dashboard.application.inbox import InboxService, ScreenHealthBoard
from preview_dashboard.application.purge import InboxHousekeeping, MaintenanceHook
from preview_dashboard.application.replies import OutboxReplyQueue, ReplyService
from preview_dashboard.application.stepup import WRONG_CODE_TITLE, StepUpService
from preview_dashboard.config import (
    ConfigError,
    Settings,
    config_file_explicit,
    config_file_path,
    verify_config_file_secure,
)
from preview_dashboard.domain.approvals import ApprovalRequest
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.domain.folders import Folder
from preview_dashboard.domain.models import BlobRef, Item, ItemState
from preview_dashboard.domain.notifications import DashboardLinks, dashboard_origin
from preview_dashboard.kinds import default_registry
from preview_dashboard.kinds.base import KindRegistry
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.claudia import ApprovalPrompts
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.notify import OutboxEvents
from preview_dashboard.ports.questions import QuestionEvents
from preview_dashboard.ports.scanner import ContentScanner

Role = Literal["admin", "viewer", "purge"]
ROLES: tuple[Role, ...] = ("admin", "viewer", "purge")

_RATE_WINDOW = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class StorageTrust:
    """Who may own the on-disk layout (docs/security.md C24, C25, C28).

    Attributes:
        uids: uids allowed to own `data_dir`, `blobs/`, `staging/`, `db/` and
            the DB files. None = only this process's effective uid (right for
            admin/purge, which create everything). The viewer must add the
            admin service's uid, since it reads what the admin wrote.
        gid: the shared service group (`pdash`) that may hold group-write on
            `db/` and the DB files. None = this process's effective gid.
        sidecar_uids: extra uids that may own the DB's `-wal`/`-shm` only
            (never dirs, blobs or the DB file). Admin/purge/migrate pass the
            viewer's uid: it writes the DB too and recreates the sidecars
            whenever it opens the DB first (ADR 0025).
    """

    uids: frozenset[int] | None = None
    gid: int | None = None
    sidecar_uids: frozenset[int] = frozenset()


class ReadOnlyBlobStore:
    """A `BlobStore` view that can read but never write or delete.

    The viewer only serves bytes; handing it a store whose `put`/`delete`
    fail closed keeps a viewer bug from ever modifying blobs (defense in
    depth next to systemd `ReadOnlyPaths`, C28).
    """

    def __init__(self, inner: BlobStore) -> None:
        self._inner = inner

    def put(self, chunks: Iterable[bytes], max_bytes: int) -> BlobRef:
        """Always refused."""
        raise PermissionError("this process has a read-only blob store")

    def open(self, blob_id: str) -> BinaryIO:
        """Delegate to the wrapped store."""
        return self._inner.open(blob_id)

    def delete(self, blob_id: str) -> None:
        """Always refused."""
        raise PermissionError("this process has a read-only blob store")

    def list_ids(self, created_before: datetime | None = None) -> set[str]:
        """Delegate to the wrapped store."""
        return self._inner.list_ids(created_before)

    def free_bytes(self) -> int:
        """Delegate to the wrapped store."""
        return self._inner.free_bytes()


class TrashControl:
    """Viewer write capability #1: trash and restore (no edits).

    Narrows `LifecycleService` so the owner-facing process cannot change
    titles/descriptions even if a route were added by mistake.
    """

    def __init__(self, lifecycle: LifecycleService) -> None:
        self._lifecycle = lifecycle

    def trash(self, item_id: str) -> Item:
        """Move an item to the trash (idempotent). See `LifecycleService.trash`."""
        return self._lifecycle.trash(item_id)

    def restore(self, item_id: str) -> Item:
        """Restore an item from the trash (idempotent). See `LifecycleService.restore`."""
        return self._lifecycle.restore(item_id)


class PinControl:
    """Viewer write capability #2: pin and unpin (ADR 0020).

    A separate narrowing of `LifecycleService` exposing only the pin flag,
    never title/description edits (which would need the secret scan, C15).
    """

    def __init__(self, lifecycle: LifecycleService) -> None:
        self._lifecycle = lifecycle

    def set_pinned(self, item_id: str, *, pinned: bool) -> Item:
        """Pin/unpin an active item (idempotent). See `LifecycleService.set_pinned`."""
        return self._lifecycle.set_pinned(item_id, pinned=pinned)


class RevisionPruner:
    """Viewer write capability #3: delete an item's old versions (ADR 0030, C43).

    Narrows `HistoryService` to "keep only the current version" (keep=1):
    the owner-facing process cannot choose another `keep`. Wired with
    `delete_blobs=False` over the read-only store: the DB prune commits and
    the hourly orphan sweep frees the space.
    """

    def __init__(self, history: HistoryService) -> None:
        self._history = history

    def prune_old(self, item_id: str, *, expected_revision: int | None = None) -> PruneResult:
        """Drop every revision but the head. See `HistoryService.prune_revisions`."""
        return self._history.prune_revisions(item_id, keep=1, expected_revision=expected_revision)


class TrashBin:
    """Admin capability: empty the trash now (ADR 0030).

    Narrows `PurgeService` to `empty_trash`, so the admin process can't run
    the timed purge, orphan sweep or question housekeeping (the purge job's).
    """

    def __init__(self, purge: PurgeService) -> None:
        self._purge = purge

    def empty(self) -> PurgeReport:
        """Permanently delete every trashed item now. See `PurgeService.empty_trash`."""
        return self._purge.empty_trash()


class FolderReader:
    """Viewer folder capability: read only (ADR 0027, C40).

    Narrows `FolderService` to `list`/`get`, so the owner-facing process
    can show folders but never create, rename, delete or move anything,
    even if a route were added by mistake.
    """

    def __init__(self, folders: FolderService) -> None:
        self._folders = folders

    def list(self, *, state: ItemState = ItemState.ACTIVE) -> FolderListing:
        """Folders with item counts in `state`, plus unfiled. See `FolderService.list`."""
        return self._folders.list(state=state)

    def get(self, folder_id: str) -> Folder:
        """One folder. See `FolderService.get`."""
        return self._folders.get(folder_id)

    def names(self) -> tuple[Folder, ...]:
        """Every folder, without item counts. See `FolderService.names`."""
        return self._folders.names()


@dataclass(frozen=True, slots=True, kw_only=True)
class _CoreBase:
    """Resource ownership shared by every core: close once, in reverse order."""

    settings: Settings
    _resources: ExitStack = field(repr=False)

    def close(self) -> None:
        """Release adapter resources (blob-store directory fds). Idempotent."""
        self._resources.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


@dataclass(frozen=True, slots=True, kw_only=True)
class ClaudiaCore:
    """The admin's Claudia companion services (ADR 0031, C44-C47, C56).

    `inbox` + `approvals.tap` + `stepup` back notifier-token routes;
    `inbox` (read/handled), `replies`, `approvals` (create/get/consume) and
    `health` back `claudia`-token routes. Only `stepup` approves (C46/C47).
    """

    inbox: InboxService
    approvals: ApprovalService
    stepup: StepUpService
    replies: ReplyService
    voice: VoiceService
    health: ScreenHealthBoard
    inbox_events: AsyncioOutboxEvents
    approval_events: AsyncioOutboxEvents


@dataclass(frozen=True, slots=True, kw_only=True)
class AdminCore(_CoreBase):
    """Admin services: publish, read, edit, trash/restore, folders, questions, alerts.

    `questions.answer` must only be reachable with the notifier token (C34);
    `outbox` backs `/v1/notifier/*`. `answer_sources` are the answer-source
    names the notifier may report (empty when notifications are disabled).
    `history` (prune old revisions) and `trash_bin` (empty the trash) are the
    permanent deletes of ADR 0030, admin token only (C43). `claudia` is None
    unless `claudia_enabled` (ADR 0031).
    """

    kinds: KindRegistry
    publish: PublishService
    queries: QueryService
    lifecycle: LifecycleService
    folders: FolderService
    history: HistoryService
    trash_bin: TrashBin
    questions: QuestionService
    notify: NotifyService
    outbox: OutboxService
    question_events: QuestionEvents
    outbox_events: OutboxEvents
    answer_sources: tuple[str, ...]
    claudia: ClaudiaCore | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ViewerCore(_CoreBase):
    """Services for the viewer process: read, download, trash/restore, pin, read folders.

    Plus `history`: delete an item's old versions (keep=1 only; ADR 0030).
    No publish, no text edits, no folder changes.
    """

    kinds: KindRegistry
    queries: QueryService
    trash: TrashControl
    pins: PinControl
    archive: ArchiveService
    folders: FolderReader
    history: RevisionPruner


@dataclass(frozen=True, slots=True, kw_only=True)
class PurgeCore(_CoreBase):
    """Services for the purge job and host CLI: permanent deletion + sweeps only.

    `history` backs `preview-dashboard prune-revisions` (ADR 0030).
    """

    purge: PurgeService
    history: HistoryService


Core = AdminCore | ViewerCore | PurgeCore


def dashboard_base_url(settings: Settings) -> str | None:
    """The dashboard origin used in `viewer_url`s and alert links, or None if unset.

    With several `allowed_hosts`, the lexicographically first one is used
    (deterministic across restarts).
    """
    # One derivation shared with the notifier, which pins links to it (C35).
    return dashboard_origin(settings.allowed_hosts)


def notify_channels(settings: Settings) -> tuple[str, ...]:
    """Enabled delivery channels: Telegram when notifications are on, else none."""
    return (TELEGRAM_CHANNEL,) if settings.notify_enabled else ()


def answer_sources(settings: Settings) -> tuple[str, ...]:
    """Answer sources the notifier may report taps from (none when notifications are off)."""
    return (TELEGRAM_SOURCE,) if settings.notify_enabled else ()


def alert_rate_limiter(settings: Settings) -> SlidingWindowRateLimiter:
    """The one alert budget shared by `ask` and `notify` (C37)."""
    return SlidingWindowRateLimiter(limit=settings.notify_rate_per_hour, window=_RATE_WINDOW)


@dataclass(frozen=True, slots=True, kw_only=True)
class _NotifyParts:
    """The question/notification services of one process, over one shared store."""

    questions: QuestionService
    notify: NotifyService
    outbox: OutboxService
    question_repo: SqliteQuestionRepository
    outbox_repo: SqliteNotificationOutbox
    question_events: AsyncioQuestionEvents
    outbox_events: AsyncioOutboxEvents


def _notify_parts(
    settings: Settings,
    conn_factory: Callable[[], sqlite3.Connection],
    *,
    clock: Clock,
    ids: IdGenerator,
    scanner: ContentScanner,
    approvals: SqliteApprovalStore | None = None,
) -> _NotifyParts:
    """Wire QuestionService / NotifyService / OutboxService on the SQLite store (ADR 0021).

    One store (both repos on the same connection factory), one alert rate
    limiter shared by ask + notify, links only from `DashboardLinks`.
    `approvals` (admin with Claudia on) tells the outbox which approval
    prompts are still live; None settles every prompt unsent (fail closed).
    """
    question_repo = SqliteQuestionRepository(conn_factory)
    outbox_repo = SqliteNotificationOutbox(conn_factory, approvals=approvals)
    question_events = AsyncioQuestionEvents()
    outbox_events = AsyncioOutboxEvents()
    limiter = alert_rate_limiter(settings)
    links = DashboardLinks(dashboard_base_url(settings))
    channels = notify_channels(settings)
    questions = QuestionService(
        repo=question_repo,
        outbox=outbox_repo,
        events=question_events,
        clock=clock,
        ids=ids,
        scanner=scanner,
        rate_limiter=limiter,
        channels=channels,
        ttl=timedelta(seconds=settings.question_ttl_seconds),
        links=links,
        outbox_events=outbox_events,
    )
    notify = NotifyService(
        outbox=outbox_repo,
        clock=clock,
        ids=ids,
        scanner=scanner,
        rate_limiter=limiter,
        channels=channels,
        links=links,
        outbox_events=outbox_events,
    )
    return _NotifyParts(
        questions=questions,
        notify=notify,
        outbox=OutboxService(outbox=outbox_repo, clock=clock),
        question_repo=question_repo,
        outbox_repo=outbox_repo,
        question_events=question_events,
        outbox_events=outbox_events,
    )


def _claudia_core(
    settings: Settings,
    conn_factory: Callable[[], sqlite3.Connection],
    parts: _NotifyParts,
    *,
    clock: Clock,
    ids: IdGenerator,
    scanner: ContentScanner,
    prompts: ApprovalPrompts | None,
    totp_gids: Collection[int] = (),
) -> ClaudiaCore:
    """Wire the Claudia services; `conn_factory` opens the admin-only Claudia DB (ADR 0031).

    Approval prompts go through the same outbox as alerts (ADR 0033); the
    TOTP secret is re-read per code with the C12 rules (group root or one
    of `totp_gids`, never the shared primary group: S-C1 S2); the step-up
    counters live in the admin-only data dir.
    """
    messages = SqliteOwnerMessageStore(conn_factory)
    inbox_events = AsyncioOutboxEvents()
    approval_events = AsyncioOutboxEvents()
    # M5b: every approval change also rewrites the viewer's read-only snapshot (C46 view, S1).
    snapshot = ApprovalsSnapshotWriter(
        store=SqliteApprovalStore(conn_factory),
        sink=FileSnapshotSink(default_snapshot_path(Path(settings.data_dir))),
        clock=clock,
    )
    snapshot.refresh()  # drop whatever a previous run left behind
    approvals = ApprovalService(
        store=SqliteApprovalStore(conn_factory),
        messages=messages,
        clock=clock,
        ids=ids,
        scanner=scanner,
        prompts=prompts
        or OutboxApprovalPrompts(
            outbox=parts.outbox_repo,
            clock=clock,
            ids=ids,
            channels=notify_channels(settings),
            outbox_events=parts.outbox_events,
        ),
        events=SnapshotOnChange(approval_events, snapshot),
    )
    notify = parts.notify
    replies = ReplyService(
        outbox=OutboxReplyQueue(
            outbox=parts.outbox_repo,
            clock=clock,
            ids=ids,
            channels=notify_channels(settings),
            links=DashboardLinks(dashboard_base_url(settings)),
            outbox_events=parts.outbox_events,
        ),
        messages=messages,
        scanner=scanner,
    )

    def wrong_code_alert() -> object:
        return notify.notify("failed", WRONG_CODE_TITLE)

    return ClaudiaCore(
        inbox=InboxService(
            messages=messages,
            clock=clock,
            ids=ids,
            owner_chat_id=settings.notify_owner_chat_id,
            events=inbox_events,
        ),
        approvals=approvals,
        stepup=StepUpService(
            secret=FileTotpSecret(settings.totp_secret_file, trusted_gids=totp_gids),
            state=open_stepup_state(Path(settings.data_dir)),
            approvals=approvals,
            clock=clock,
            owner_chat_id=settings.notify_owner_chat_id,
            alert=wrong_code_alert,
        ),
        replies=replies,
        # Voice shares the reply service, so it shares its budget (C56, M10).
        voice=VoiceService(
            replies=replies, store=FsVoiceStore(Path(settings.data_dir) / VOICE_DIR_NAME)
        ),
        health=ScreenHealthBoard(clock),
        inbox_events=inbox_events,
        approval_events=approval_events,
    )


def publish_limits(settings: Settings) -> PublishLimits:
    """Map `Settings` to the application's `PublishLimits` (C18)."""
    return PublishLimits(
        max_files=settings.max_files,
        max_file_bytes=settings.max_file_bytes,
        max_item_bytes=settings.max_item_bytes,
        max_total_bytes=settings.max_total_bytes,
        max_items=settings.max_items,
        min_free_disk_bytes=settings.min_free_disk_bytes,
        timeout=timedelta(seconds=settings.publish_timeout_seconds),
    )


def connection_factory(
    settings: Settings, trust: StorageTrust | None = None, *, migrate: bool = True
) -> Callable[[], sqlite3.Connection]:
    """Return the zero-argument SQLite connection factory for `settings.data_dir`.

    `migrate=False` (viewer, purge): connections never create the database
    or change its schema; they require it at the current version.
    """
    trust = trust or StorageTrust()
    return functools.partial(
        connect,
        default_db_path(settings.data_dir),
        trusted_uids=trust.uids,
        trusted_gid=trust.gid,
        trusted_sidecar_uids=trust.sidecar_uids,
        migrate=migrate,
    )


def claudia_connection_factory(
    settings: Settings, *, create: bool
) -> Callable[[], sqlite3.Connection]:
    """Return the connection factory for the admin-only Claudia database (S-C1 S1).

    `create=True` (admin only): create `data_dir/claudia/` (0700) and the
    file (0600) if missing and migrate them; False (purge): open only.
    """
    return functools.partial(
        connect_claudia, default_claudia_db_path(settings.data_dir), create=create
    )


class _PurgeNoPrompts:
    """`ApprovalPrompts` for the purge job, which only expires requests and never creates one."""

    def prompt(self, request: ApprovalRequest) -> None:
        """Always refused (fail closed): purge has no business queueing a prompt."""
        raise StorageUnavailableError("the purge job never queues approval prompts")


def _purge_inbox(settings: Settings, *, clock: Clock, ids: IdGenerator) -> InboxHousekeeping | None:
    """The purge job's Claudia housekeeping, or None while Claudia is off (no DB to open).

    Expiry goes through `ApprovalService.expire_due` (same CAS path as the
    admin's, S-C1 S12); the database is opened, never created, here.
    """
    if not settings.claudia_enabled:
        return None
    factory = claudia_connection_factory(settings, create=False)
    messages = SqliteOwnerMessageStore(factory)
    approvals = SqliteApprovalStore(factory)
    service = ApprovalService(
        store=approvals,
        messages=messages,
        clock=clock,
        ids=ids,
        scanner=RegexSecretScanner(),
        prompts=_PurgeNoPrompts(),
    )
    return InboxHousekeeping(
        messages=messages,
        approvals=approvals,
        expire_due=service.expire_due,
        # Checkpoint the WAL after deletes, like the item DB (C24).
        compact=functools.partial(compact_claudia, factory),
    )


# Voice audio is collected within minutes; a day covers every retry window and
# anything older belongs to a delivery the notifier gave up on (C56).
_VOICE_MAX_AGE_SECONDS = 24 * 3600


def _purge_maintenance(
    settings: Settings, store: FsBlobStore, grace: timedelta
) -> dict[str, MaintenanceHook]:
    """The purge job's maintenance hooks: staging sweep, plus stale voice audio with Claudia on."""
    hooks: dict[str, MaintenanceHook] = {
        "staging": functools.partial(store.sweep_staging, older_than=grace)
    }
    if settings.claudia_enabled:
        voice = FsVoiceStore(Path(settings.data_dir) / VOICE_DIR_NAME)
        hooks["voice"] = functools.partial(voice.purge_older_than, _VOICE_MAX_AGE_SECONDS)
    return hooks


def migrate_database(settings: Settings, trust: StorageTrust | None = None) -> int:
    """Validate the DB location, create/migrate the schema; return its version.

    Raises:
        UnsafeDatabasePathError: the layout fails the trust checks (C24).
        FileNotFoundError: `data_dir` does not exist.
    """
    connection_factory(settings, trust)().close()
    return CURRENT_VERSION


def verify_config() -> None:
    """Refuse to run on an insecure or missing-but-named TOML config file (C16, I6).

    Raises:
        ConfigError: the file is a symlink, not regular, not root-owned, or
            it or its directory is group/world-writable; or `PDASH_CONFIG`
            names a file that does not exist.
    """
    path = config_file_path()
    explicit = config_file_explicit()
    # Fail closed (I6): a named-but-missing file would otherwise mean "all defaults".
    if explicit and not os.path.lexists(path):
        raise ConfigError(
            f"PDASH_CONFIG names {path}, which does not exist; refusing to start with "
            "defaults (unset PDASH_CONFIG to use the default path)"
        )
    verify_config_file_secure(path, missing_ok=not explicit)


@overload
def build_core(
    settings: Settings,
    *,
    role: Literal["admin"],
    trust: StorageTrust | None = ...,
    clock: Clock | None = ...,
    approval_prompts: ApprovalPrompts | None = ...,
    totp_gids: Collection[int] = ...,
) -> AdminCore: ...
@overload
def build_core(
    settings: Settings,
    *,
    role: Literal["viewer"],
    trust: StorageTrust | None = ...,
    clock: Clock | None = ...,
    approval_prompts: ApprovalPrompts | None = ...,
    totp_gids: Collection[int] = ...,
) -> ViewerCore: ...
@overload
def build_core(
    settings: Settings,
    *,
    role: Literal["purge"],
    trust: StorageTrust | None = ...,
    clock: Clock | None = ...,
    approval_prompts: ApprovalPrompts | None = ...,
    totp_gids: Collection[int] = ...,
) -> PurgeCore: ...
@overload
def build_core(
    settings: Settings,
    *,
    role: Role,
    trust: StorageTrust | None = ...,
    clock: Clock | None = ...,
    approval_prompts: ApprovalPrompts | None = ...,
    totp_gids: Collection[int] = ...,
) -> Core: ...
def build_core(
    settings: Settings,
    *,
    role: Role,
    trust: StorageTrust | None = None,
    clock: Clock | None = None,
    approval_prompts: ApprovalPrompts | None = None,
    totp_gids: Collection[int] = (),
) -> Core:
    """Wire the adapters and services one process role needs.

    Verifies the config file (C16) and opens the database once (so a bad
    storage layout refuses to start instead of failing on first request).
    Only the admin role creates/migrates the schema; viewer and purge
    require it to exist at the current version (least privilege: no DDL).

    Args:
        settings: validated configuration.
        role: `admin` (publish/read/edit/trash, questions, alerts, outbox),
            `viewer` (read/download/trash/restore/pin; read-only blobs) or
            `purge` (purge + sweeps + question expiry/housekeeping).
        trust: storage ownership policy; see `StorageTrust`.
        clock: time source (default: the real UTC clock); tests inject one.
        approval_prompts: (admin, `claudia_enabled`) queues Approve/Deny
            messages; default `OutboxApprovalPrompts` on the shared outbox
            (refuses, so create fails closed, when no channel is enabled).
        totp_gids: (admin, `claudia_enabled`) groups trusted on the TOTP
            secret besides root (`serve-admin --token-group totp=…`).

    Returns:
        The role's core; close it (or use `with`) to release resources.

    Raises:
        ValueError: unknown role.
        ConfigError: insecure config file.
        UnsafeDatabasePathError / UnsafeStorageLayoutError: untrusted layout.
        DatabaseSetupError: (viewer/purge) the database is missing or not
            migrated yet.
        FileNotFoundError: `data_dir` does not exist.
    """
    if role not in ROLES:
        raise ValueError("unknown role")
    verify_config()
    trust = trust or StorageTrust()
    clock = clock or SystemClock()
    ids = UlidGenerator()
    kinds = default_registry()
    resources = ExitStack()
    try:
        conn_factory = connection_factory(settings, trust, migrate=role == "admin")
        conn_factory().close()  # fail fast: validate layout (+ migrate) at startup
        repo = SqliteItemRepository(conn_factory)
        folder_repo = SqliteFolderRepository(conn_factory)
        store = FsBlobStore(
            Path(settings.data_dir),
            ids=ids,
            clock=clock,
            reserve_bytes=settings.min_free_disk_bytes,
            trusted_owner_uids=trust.uids,
        )
        resources.callback(store.close)
        if role == "admin":
            scanner = RegexSecretScanner()
            # S-C1 S1: approvals + inbox live in the admin-only Claudia DB,
            # created only here; the outbox asks it whether a prompt is live.
            claudia_factory = claudia_connection_factory(settings, create=True)
            if settings.claudia_enabled:
                claudia_factory().close()  # fail fast: validate layout + migrate
            parts = _notify_parts(
                settings,
                conn_factory,
                clock=clock,
                ids=ids,
                scanner=scanner,
                approvals=(
                    SqliteApprovalStore(claudia_factory) if settings.claudia_enabled else None
                ),
            )
            return AdminCore(
                settings=settings,
                _resources=resources,
                kinds=kinds,
                questions=parts.questions,
                notify=parts.notify,
                outbox=parts.outbox,
                question_events=parts.question_events,
                outbox_events=parts.outbox_events,
                answer_sources=answer_sources(settings),
                claudia=(
                    _claudia_core(
                        settings,
                        claudia_factory,
                        parts,
                        clock=clock,
                        ids=ids,
                        scanner=scanner,
                        prompts=approval_prompts,
                        totp_gids=totp_gids,
                    )
                    if settings.claudia_enabled
                    else None
                ),
                publish=PublishService(
                    repo=repo,
                    folders=folder_repo,
                    blobs=store,
                    ids=ids,
                    clock=clock,
                    kinds=kinds,
                    scanner=scanner,
                    rate_limiter=SlidingWindowRateLimiter(
                        limit=settings.publish_rate_per_hour, window=_RATE_WINDOW
                    ),
                    limits=publish_limits(settings),
                ),
                queries=QueryService(repo=repo, blobs=store, kinds=kinds),
                lifecycle=LifecycleService(repo=repo, clock=clock, scanner=scanner),
                folders=FolderService(
                    folders=folder_repo, items=repo, clock=clock, ids=ids, scanner=scanner
                ),
                history=HistoryService(
                    repo=repo, blobs=store, clock=clock, post_commit=_post_purge_hooks(repo)
                ),
                trash_bin=TrashBin(
                    PurgeService(
                        repo=repo,
                        blobs=store,
                        clock=clock,
                        retention=timedelta(days=settings.trash_retention_days),
                        orphan_grace=timedelta(seconds=settings.orphan_grace_seconds),
                        post_purge=_post_purge_hooks(repo),
                    )
                ),
            )
        if role == "viewer":
            readonly = ReadOnlyBlobStore(store)
            lifecycle = LifecycleService(repo=repo, clock=clock, scanner=RegexSecretScanner())
            return ViewerCore(
                settings=settings,
                _resources=resources,
                kinds=kinds,
                queries=QueryService(repo=repo, blobs=readonly, kinds=kinds),
                # Trash/restore/pin edit no text, so the scanner is never consulted.
                trash=TrashControl(lifecycle),
                pins=PinControl(lifecycle),
                archive=ArchiveService(repo=repo, blobs=readonly),
                # Read-only: the viewer never writes folders (C40).
                folders=FolderReader(
                    FolderService(
                        folders=folder_repo,
                        items=repo,
                        clock=clock,
                        ids=ids,
                        scanner=RegexSecretScanner(),
                    )
                ),
                # Read-only store: the prune commits, the orphan sweep frees the blobs.
                history=RevisionPruner(
                    HistoryService(
                        repo=repo,
                        blobs=readonly,
                        clock=clock,
                        delete_blobs=False,
                        post_commit=_post_purge_hooks(repo),
                    )
                ),
            )
        grace = timedelta(seconds=settings.orphan_grace_seconds)
        # Purge only expires (enqueuing RESOLVEs) and deletes; its wake-ups
        # reach no waiter (other process): the admin's long-polls re-read.
        parts = _notify_parts(
            settings, conn_factory, clock=clock, ids=ids, scanner=RegexSecretScanner()
        )
        return PurgeCore(
            settings=settings,
            _resources=resources,
            history=HistoryService(
                repo=repo, blobs=store, clock=clock, post_commit=_post_purge_hooks(repo)
            ),
            purge=PurgeService(
                repo=repo,
                blobs=store,
                clock=clock,
                retention=timedelta(days=settings.trash_retention_days),
                orphan_grace=grace,
                maintenance=_purge_maintenance(settings, store, grace),
                post_purge=_post_purge_hooks(repo),
                questions=QuestionHousekeeping(
                    expire_due=parts.questions.expire_due,
                    questions=parts.question_repo,
                    outbox=parts.outbox_repo,
                ),
                # C44: 30-day inbox (and finished approval) retention + expiry.
                inbox=_purge_inbox(settings, clock=clock, ids=ids),
            ),
        )
    except BaseException:
        resources.close()
        raise


def _post_purge_hooks(repo: SqliteItemRepository) -> tuple[Callable[[], None], ...]:
    """SQLite maintenance after rows were purged: WAL checkpoint + truncate (C24)."""

    def compact() -> None:
        # Best effort: a busy reader just defers the truncate to the next run.
        repo.compact()

    return (compact,)


def effective_trust(
    extra_uids: Collection[int] = (),
    gid: int | None = None,
    sidecar_uids: Collection[int] = (),
) -> StorageTrust:
    """Trust this process's euid plus `extra_uids` (e.g. the admin uid for the viewer).

    `sidecar_uids` may additionally own `-wal`/`-shm` only (ADR 0025).
    """
    sidecars = frozenset(sidecar_uids)
    if not extra_uids and gid is None:
        return StorageTrust(sidecar_uids=sidecars)
    return StorageTrust(uids=frozenset({os.geteuid(), *extra_uids}), gid=gid, sidecar_uids=sidecars)
