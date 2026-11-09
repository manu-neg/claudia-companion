"""HistoryService: permanently delete an item's old revisions on request (ADR 0030).

Commits the shorter item by compare-and-swap first, then deletes the dropped
blobs; failed deletes are left to the orphan sweep (C11, C43). A process with
a read-only blob store (the viewer) skips the deletes and leaves every dropped
blob to that sweep.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from preview_dashboard.domain.errors import ConflictError, InvalidStateError
from preview_dashboard.domain.models import (
    Item,
    ItemState,
    Revision,
    parse_item_id,
    validate_keep_revisions,
    validate_revision_number,
)
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.repository import ItemRepository

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True, kw_only=True)
class PruneResult:
    """Outcome of `HistoryService.prune_revisions`.

    Attributes:
        item: the item as committed (unchanged if nothing was pruned).
        revisions_removed: how many old revisions were dropped.
        bytes_freed: their total file size (what they counted against the
            quota), whether or not every blob was already gone from disk.
    """

    item: Item
    revisions_removed: int
    bytes_freed: int


class HistoryService:
    """Prune an ACTIVE item's old revisions, keeping the newest `keep` (head included).

    Idempotent: with nothing to prune, nothing is written and the counts are
    zero. Concurrency: the save is a compare-and-swap on `updated_at`; on a
    conflict the item is re-read, re-checked (ACTIVE, `expected_revision`)
    and the prune recomputed once, so a revision published meanwhile is
    never dropped unseen.

    `delete_blobs=False` (the viewer, whose blob store is read-only): commit
    only; the dropped blobs are unreferenced from then on and the hourly
    orphan sweep frees them (ADR 0030), with no per-blob warning.

    `post_commit` hooks (e.g. SQLite WAL truncate, C24) run best effort after
    a successful prune; a failing hook is logged by exception type only.
    """

    def __init__(
        self,
        *,
        repo: ItemRepository,
        blobs: BlobStore,
        clock: Clock,
        delete_blobs: bool = True,
        post_commit: Sequence[Callable[[], object]] = (),
    ) -> None:
        self._repo = repo
        self._blobs = blobs
        self._clock = clock
        self._delete_blobs_now = delete_blobs
        self._post_commit = tuple(post_commit)

    def prune_revisions(
        self, item_id: str, *, keep: int = 1, expected_revision: int | None = None
    ) -> PruneResult:
        """Permanently delete all but the newest `keep` revisions of an active item.

        Args:
            item_id: the item (canonical ULID).
            keep: revisions kept including the head, 1..MAX_REVISIONS (default 1:
                only the current version stays).
            expected_revision: if set, refuse unless this is still the head.

        Returns:
            The committed item plus how many revisions / bytes were removed.

        Raises:
            ValidationError: malformed id, `keep` or `expected_revision`.
            NotFoundError: no such item.
            InvalidStateError: the item is trashed.
            ConflictError: `expected_revision` is not the head, or the item
                changed concurrently twice in a row.
        """
        parsed = parse_item_id(item_id)
        validate_keep_revisions(keep)
        if expected_revision is not None:
            validate_revision_number(expected_revision)
        for attempt in range(2):
            current = self._repo.get(parsed)
            _check_prunable(current, expected_revision)
            updated, dropped = current.without_history(
                keep, at=current.next_change_at(self._clock.now())
            )
            if not dropped:
                return PruneResult(item=current, revisions_removed=0, bytes_freed=0)
            try:
                self._repo.save(updated, expected_updated_at=current.updated_at)
            except ConflictError:
                if attempt:
                    raise
                continue  # re-read: a revision/trash may have landed meanwhile
            # Blobs only after the commit (C11): a crash here leaves orphans, never
            # a kept revision pointing at deleted bytes.
            self._delete_blobs(updated, dropped)
            self._run_post_commit()
            _log.info("revisions pruned: item %s, %d revision(s) removed", updated.id, len(dropped))
            return PruneResult(
                item=updated,
                revisions_removed=len(dropped),
                bytes_freed=sum(r.total_size for r in dropped),
            )
        raise AssertionError("unreachable")  # pragma: no cover

    def _run_post_commit(self) -> None:
        for hook in self._post_commit:
            try:
                hook()
            # Log the type only: the exception text could quote stored content.
            except Exception as exc:  # committed already; compaction is best effort
                _log.warning("revision prune: post-commit hook failed: %s", type(exc).__name__)

    def _delete_blobs(self, item: Item, dropped: Sequence[Revision]) -> None:
        if not self._delete_blobs_now:
            # Expected, not a failure: this process may not delete (read-only store).
            _log.info("revision prune: %d revision(s) left to the orphan sweep", len(dropped))
            return
        keep = {f.blob_id for f in item.all_files}
        for revision in dropped:
            for f in revision.files:
                if f.blob_id in keep:  # pragma: no cover - the domain forbids shared blobs
                    continue
                try:
                    self._blobs.delete(f.blob_id)
                except Exception:  # committed already; the orphan sweep is the backstop
                    _log.warning("revision prune: could not delete blob %s", f.blob_id)


def _check_prunable(item: Item, expected_revision: int | None) -> None:
    """Raise unless `item` may be pruned now (state first, like `publish_revision`).

    Raises:
        InvalidStateError: the item is trashed.
        ConflictError: `expected_revision` is set and is not the head.
    """
    if item.state is not ItemState.ACTIVE:
        raise InvalidStateError("trashed items cannot be changed")
    if expected_revision is not None and item.revision != expected_revision:
        raise ConflictError(
            f"item is at revision {item.revision}, not {expected_revision}; re-read and retry"
        )
