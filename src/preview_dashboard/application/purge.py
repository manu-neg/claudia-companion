"""PurgeService: permanent deletion of expired trash plus the orphan-blob sweep.

Crash-safe ordering (docs/security.md C11, docs/architecture.md): purge
deletes the DB row **first**, then the blobs; the orphan sweep snapshots
old blob ids **before** reading referenced ids. Afterwards it expires due
questions and deletes resolved questions/notifications after 30 days (ADR
0021), then expires overdue approval requests and deletes Claudia's inbox
messages and finished approval requests after 30 days (ADR 0031, C44);
those steps are isolated, so they can never block the trash purge.
Run hourly by the purge timer; every step is idempotent, so a crashed run
is simply repeated. `empty_trash` is the on-demand variant (ADR 0030):
every trashed item now, through the same atomic per-item delete.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import Item, ItemState, ensure_utc
from preview_dashboard.domain.query import MAX_PAGE_LIMIT, ItemQuery
from preview_dashboard.ports.approvals import ApprovalStore
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.notify import NotificationOutbox
from preview_dashboard.ports.owner_messages import OwnerMessageStore
from preview_dashboard.ports.questions import QuestionRepository
from preview_dashboard.ports.repository import ItemRepository

MaintenanceHook = Callable[[], int]
"""Extra adapter-specific cleanup run after purge (e.g. the FS staging sweep).

Returns how many things it removed. Injected by the composition root, so
the core never knows about staging files or any other adapter detail.
"""

PostPurgeHook = Callable[[], object]
"""Run only when a purge removed at least one item, e.g. the SQLite
`compact()` (WAL checkpoint) so deleted metadata doesn't linger on disk.
The return value is ignored (`compact()` returns a bool; an unfinished
checkpoint is simply retried by the next run)."""

NOTIFICATION_RETENTION = timedelta(days=30)
# C44: owner messages (and the approval requests around them) are kept 30 days.
INBOX_RETENTION = timedelta(days=30)

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True, kw_only=True)
class QuestionHousekeeping:
    """What purge needs to maintain questions and notifications (ADR 0021).

    Attributes:
        expire_due: `QuestionService.expire_due` (expires and enqueues RESOLVEs).
        questions: repository of resolved questions to delete.
        outbox: notifications (and their tasks) to delete.
        retention: how long resolved questions / notifications are kept (> 0).
    """

    expire_due: Callable[[datetime], int]
    questions: QuestionRepository
    outbox: NotificationOutbox
    retention: timedelta = NOTIFICATION_RETENTION

    def __post_init__(self) -> None:
        if self.retention <= timedelta(0):
            raise ValueError("retention must be > 0")


@dataclass(frozen=True, slots=True, kw_only=True)
class InboxHousekeeping:
    """What purge needs to trim Claudia's inbox and approvals (ADR 0031, C44).

    Attributes:
        messages: owner messages; any older than the retention are deleted.
        approvals: approval requests; any that expired before the cutoff
            are deleted (each expires at most 24 h after creation, so all
            are done).
        expire_due: `ApprovalService.expire_due` (marks overdue open requests
            EXPIRED, S-C1 S12), run first; None = skip that step.
        compact: WAL checkpoint (TRUNCATE) of the Claudia database, run when
            this step changed any row, so deleted message text and action
            texts don't linger in `-wal` (C24 for the Claudia DB); None = skip.
        retention: how long both are kept (> 0).
    """

    messages: OwnerMessageStore
    approvals: ApprovalStore
    expire_due: Callable[[], int] | None = None
    compact: PostPurgeHook | None = None
    retention: timedelta = INBOX_RETENTION

    def __post_init__(self) -> None:
        if self.retention <= timedelta(0):
            raise ValueError("retention must be > 0")


@dataclass(frozen=True, slots=True, kw_only=True)
class PurgeReport:
    """What one purge run removed.

    Attributes:
        items_purged: item rows permanently deleted.
        blobs_deleted: blobs of those items deleted right after.
        orphans_deleted: unreferenced blobs removed by the sweep.
        maintenance: per-hook removal counts, by hook name.
        questions_expired: OPEN questions expired by this run.
        questions_deleted: resolved questions older than the retention.
        notifications_deleted: notifications (with their tasks) older than it.
        questions_failed: the question housekeeping step raised (its counts
            are then 0; items were purged regardless).
        inbox_deleted: owner messages older than the inbox retention.
        approvals_expired: overdue open approval requests marked EXPIRED.
        approvals_deleted: approval requests expired before that cutoff.
        inbox_failed: the inbox housekeeping step raised (counts then 0).
    """

    items_purged: int
    blobs_deleted: int
    orphans_deleted: int
    maintenance: Mapping[str, int] = field(default_factory=dict)
    questions_expired: int = 0
    questions_deleted: int = 0
    notifications_deleted: int = 0
    questions_failed: bool = False
    inbox_deleted: int = 0
    approvals_expired: int = 0
    approvals_deleted: int = 0
    inbox_failed: bool = False


class PurgeService:
    """Permanently deletes expired trash and sweeps orphaned blobs.

    Args:
        retention: how long trashed items are kept (> 0).
        orphan_grace: minimum blob age before the sweep may delete it; must
            exceed the publish timeout (enforced in `config.Settings`).
        maintenance: named hooks run after purge and sweep, every run.
        post_purge: hooks run last, only if rows were removed (items,
            questions or notifications) or question housekeeping failed.
        questions: question/notification housekeeping (run after the item
            purge, sweep and maintenance, errors contained); None = skip it.
        inbox: owner-message / approval housekeeping (run last, errors
            contained); None = skip it.

    Raises:
        ValueError: non-positive `retention` or `orphan_grace`.
    """

    def __init__(
        self,
        *,
        repo: ItemRepository,
        blobs: BlobStore,
        clock: Clock,
        retention: timedelta,
        orphan_grace: timedelta,
        maintenance: Mapping[str, MaintenanceHook] | None = None,
        post_purge: Sequence[PostPurgeHook] = (),
        questions: QuestionHousekeeping | None = None,
        inbox: InboxHousekeeping | None = None,
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention must be > 0")
        if orphan_grace <= timedelta(0):
            raise ValueError("orphan_grace must be > 0")
        self._repo = repo
        self._blobs = blobs
        self._clock = clock
        self._retention = retention
        self._grace = orphan_grace
        self._maintenance = dict(maintenance or {})
        self._post_purge = tuple(post_purge)
        self._questions = questions
        self._inbox = inbox

    def run(self, now: datetime | None = None) -> PurgeReport:
        """Purge expired trash, sweep orphans, run maintenance, then question housekeeping.

        Question housekeeping runs last and its errors are contained (logged
        by exception type, flagged in the report), so a bad question row can
        never stop trash from being purged.

        Args:
            now: reference time (tz-aware); defaults to the clock. Only
                tests should pass it: a future `now` also shortens the
                orphan-sweep grace for blobs of in-flight publishes.

        Returns:
            Counts of what was removed.

        Raises:
            ValidationError: `now` is naive, or `now - retention` /
                `now - orphan_grace` falls outside the datetime range.
        """
        at = self._clock.now() if now is None else ensure_utc(now, "now")
        purge_cutoff = _minus(at, self._retention)
        sweep_cutoff = _minus(at, self._grace)
        items_purged, blobs_deleted = self._purge_expired(at, purge_cutoff)
        orphans_deleted = self._sweep_orphans(sweep_cutoff)
        maintenance = self._run_maintenance()
        failed = False
        try:
            expired, questions_deleted, notifications_deleted = self._housekeep_questions(at)
        except Exception as exc:  # contained on purpose: the trash purge above must win
            # Type only: exception text may quote stored question content.
            _log.error("question housekeeping failed: %s", type(exc).__name__)
            failed = True
            expired = questions_deleted = notifications_deleted = 0
        inbox_failed = False
        try:
            approvals_expired, inbox_deleted, approvals_deleted = self._housekeep_inbox(at)
        except Exception as exc:  # contained on purpose, like the question step
            # Type only: exception text could quote stored message content (C29).
            _log.error("inbox housekeeping failed: %s", type(exc).__name__)
            inbox_failed = True
            approvals_expired = inbox_deleted = approvals_deleted = 0
        if (
            self._inbox is not None
            and self._inbox.compact is not None
            and (inbox_deleted or approvals_deleted or approvals_expired or inbox_failed)
        ):
            self._compact_claudia(self._inbox.compact)
        # A failed step may still have deleted some rows: compact then too.
        if (
            items_purged
            or questions_deleted
            or notifications_deleted
            or failed
            or inbox_deleted
            or approvals_deleted
            or inbox_failed
        ):
            self._run_post_purge()
        return PurgeReport(
            items_purged=items_purged,
            blobs_deleted=blobs_deleted,
            orphans_deleted=orphans_deleted,
            maintenance=maintenance,
            questions_expired=expired,
            questions_deleted=questions_deleted,
            notifications_deleted=notifications_deleted,
            questions_failed=failed,
            inbox_deleted=inbox_deleted,
            approvals_expired=approvals_expired,
            approvals_deleted=approvals_deleted,
            inbox_failed=inbox_failed,
        )

    def empty_trash(self) -> PurgeReport:
        """Permanently delete every trashed item now, regardless of retention (ADR 0030).

        Same safe path as the timed purge: each row is deleted by the atomic
        `delete_if_purgeable` with the item's own listed `trashed_at` as the
        cutoff, so an item the owner restored after the listing (or restored
        and trashed again) is left alone; blobs go only after their row, and
        only if no row still references them. A blob that can't be deleted
        is logged and left to the orphan sweep. No orphan sweep, maintenance
        or question housekeeping here: that stays the hourly job's.

        Returns:
            A report with `items_purged` and `blobs_deleted` (other counts 0).
        """
        listed = self._all_trashed()
        purged = 0
        candidates: set[str] = set()
        for item in listed:
            if item.trashed_at is None:  # pragma: no cover - TRASHED always has it
                continue
            deleted = self._repo.delete_if_purgeable(item.id, item.trashed_at)
            if deleted is not None:
                purged += 1
                candidates.update(f.blob_id for f in deleted.all_files)
        blobs_deleted = 0
        if candidates:
            for blob_id in candidates - self._repo.all_blob_ids():
                try:
                    self._blobs.delete(blob_id)
                    blobs_deleted += 1
                except Exception:  # rows are gone already; the orphan sweep is the backstop
                    _log.warning("empty trash: could not delete blob %s", blob_id)
        if purged:
            self._run_post_purge()
        _log.info("trash emptied: %d item(s), %d blob(s)", purged, blobs_deleted)
        return PurgeReport(items_purged=purged, blobs_deleted=blobs_deleted, orphans_deleted=0)

    def _run_maintenance(self) -> dict[str, int]:
        """Run each maintenance hook alone: one failing hook must not skip the rest (voice-2)."""
        counts: dict[str, int] = {}
        for name, hook in self._maintenance.items():
            try:
                counts[name] = hook()
            except Exception as exc:  # contained: retention steps after it must still run
                # Type only: exception text could quote stored content.
                _log.error("maintenance hook %s failed: %s", name, type(exc).__name__)
                counts[name] = 0
        return counts

    def _run_post_purge(self) -> None:
        """Run each post-purge hook; a failing one is logged and never undoes the purge."""
        for hook in self._post_purge:
            try:
                hook()
            except Exception as exc:  # rows are already gone; compaction is best effort
                # Type only: exception text could quote stored content.
                _log.warning("post-purge hook failed: %s", type(exc).__name__)

    @staticmethod
    def _compact_claudia(compact: PostPurgeHook) -> None:
        """Checkpoint the Claudia DB; best effort, like the item DB's post-purge hooks."""
        try:
            compact()
        except Exception as exc:  # rows are already gone; compaction is retried next run
            _log.warning("claudia db compaction failed: %s", type(exc).__name__)

    def _all_trashed(self) -> list[Item]:
        """Every TRASHED item, read page by page before anything is deleted."""
        out: list[Item] = []
        cursor: str | None = None
        while True:
            page = self._repo.list(
                ItemQuery(state=ItemState.TRASHED, limit=MAX_PAGE_LIMIT, cursor=cursor)
            )
            out.extend(page.items)
            if page.next_cursor is None:
                return out
            cursor = page.next_cursor

    def _housekeep_questions(self, now: datetime) -> tuple[int, int, int]:
        """Expire due questions, then drop old notifications, then old resolved questions.

        Notifications go first: a question's notification is never younger
        than its resolution, so no notification outlives its question.
        """
        if self._questions is None:
            return 0, 0, 0
        housekeeping = self._questions
        expired = housekeeping.expire_due(now)
        cutoff = _minus(now, housekeeping.retention)
        notifications = housekeeping.outbox.delete_before(cutoff)
        questions = housekeeping.questions.delete_resolved_before(cutoff)
        return expired, questions, notifications

    def _housekeep_inbox(self, now: datetime) -> tuple[int, int, int]:
        """Expire overdue approvals, then delete messages and approvals past the retention.

        Expiry first (S-C1 S12): an open request nobody touched again is
        marked EXPIRED (audit-visible) instead of staying "open" forever.
        """
        if self._inbox is None:
            return 0, 0, 0
        expired = self._inbox.expire_due() if self._inbox.expire_due is not None else 0
        cutoff = _minus(now, self._inbox.retention)
        messages = self._inbox.messages.delete_received_before(cutoff)
        approvals = self._inbox.approvals.delete_expired_before(cutoff)
        return expired, messages, approvals

    def _purge_expired(self, now: datetime, cutoff: datetime) -> tuple[int, int]:
        purged = 0
        candidates: set[str] = set()
        for listed in self._repo.list_purgeable(now, self._retention):
            # Conditional, atomic delete: the owner may have restored the
            # item (viewer process) since the listing. Row first (C11): a
            # crash after this leaves orphans, never a dangling row.
            deleted = self._repo.delete_if_purgeable(listed.id, cutoff)
            if deleted is not None:
                purged += 1
                # Every kept revision's blobs, not just the head's.
                candidates.update(f.blob_id for f in deleted.all_files)
        if not candidates:
            return purged, 0
        # Never delete a blob some other row still references.
        doomed = candidates - self._repo.all_blob_ids()
        for blob_id in doomed:
            self._blobs.delete(blob_id)
        return purged, len(doomed)

    def _sweep_orphans(self, created_before: datetime) -> int:
        # Order matters: snapshot old blobs FIRST, read references SECOND.
        # Reversed, a publish committing in between would lose its blobs.
        old_blobs = self._blobs.list_ids(created_before=created_before)
        orphans = old_blobs - self._repo.all_blob_ids()
        for blob_id in orphans:
            self._blobs.delete(blob_id)
        return len(orphans)


def _minus(at: datetime, delta: timedelta) -> datetime:
    """`at - delta` as a domain error: a huge retention must not crash with OverflowError."""
    try:
        return at - delta
    except OverflowError:
        raise ValidationError("purge cutoff is out of range") from None
