"""LifecycleService: metadata edits, pin/unpin and the trash/restore state transitions.

Transitions are the domain's (`Item.trashed/restored/with_metadata`); this
service adds the clock, optimistic-concurrency persistence, idempotency and
the secret scan on edited text (docs/security.md C11, C15).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from preview_dashboard.domain.errors import ConflictError, InvalidStateError
from preview_dashboard.domain.models import Item, ItemId, ItemState, parse_item_id
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.repository import ItemRepository
from preview_dashboard.ports.scanner import ContentScanner


class LifecycleService:
    """Update, pin/unpin, trash and restore items.

    Idempotency: `trash` on a trashed item and `restore` on an active item
    are **no-ops** that return the item unchanged — the caller's intent
    ("this should be in the trash") already holds, so double clicks and
    retries from the viewer never surface an error. `set_pinned` with the
    current pin state is a no-op too. `update` and `set_pinned` on a trashed
    item raise `InvalidStateError` (trashed items are read-only).

    Concurrency: every save is a compare-and-swap on `updated_at`
    (`ItemRepository.save(expected_updated_at=...)`), and every transition
    stamps `updated_at` strictly later than the stored one, so it works as a
    version even when the wall clock steps backwards (NTP) or two writers
    share a microsecond. `trash`/`restore`/`set_pinned` re-read and retry **once** on a
    conflict (their intent is absolute, and the retry keeps the no-op
    semantics); `update` never retries and raises `ConflictError`.
    """

    def __init__(self, *, repo: ItemRepository, clock: Clock, scanner: ContentScanner) -> None:
        self._repo = repo
        self._clock = clock
        self._scanner = scanner

    def update(
        self,
        item_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        pinned: bool | None = None,
    ) -> Item:
        """Change title/description/pinned (None = keep). All None is a no-op.

        Raises:
            ValidationError: malformed id or invalid new value.
            NotFoundError: no such item.
            InvalidStateError: the item is trashed.
            SecretDetectedError: new text (raw or sanitized) matches a secret rule.
            ConflictError: the item changed concurrently; re-read and retry.
        """
        item = self._repo.get(parse_item_id(item_id))
        if title is None and description is None and pinned is None:
            return item
        # Build (= sanitize) first, then scan what will actually be stored.
        updated = item.with_metadata(
            now=self._next_stamp(item),
            title=title,
            description=description,
            pinned=pinned,
        )
        if title is not None or description is not None:
            self._scan_text(title, description, updated.title, updated.description)
        self._repo.save(updated, expected_updated_at=item.updated_at)
        return updated

    def set_pinned(self, item_id: str, *, pinned: bool) -> Item:
        """Pin or unpin an active item (no-op if it already has that pin state).

        Unlike `update(pinned=...)` this is idempotent and conflict-tolerant
        like `trash`/`restore`: the owner's intent is absolute, so a repeated
        click writes nothing (no `updated_at` bump) and a concurrent change is
        re-read and retried once.

        Raises:
            ValidationError: malformed id.
            NotFoundError: no such item.
            InvalidStateError: the item is trashed (even if the pin state matches).
            ConflictError: the item changed concurrently twice in a row.
        """

        def step(item: Item) -> Item:
            # State check first: a trashed item answers the same way whatever
            # its stored pin flag, so the reply never depends on it.
            if item.state is not ItemState.ACTIVE:
                raise InvalidStateError("trashed items cannot be pinned")
            if item.pinned is pinned:
                return item
            changed = item.with_metadata(now=self._next_stamp(item), pinned=pinned)
            self._repo.save(changed, expected_updated_at=item.updated_at)
            return changed

        return self._transition(parse_item_id(item_id), step)

    def trash(self, item_id: str) -> Item:
        """Move an item to the trash (no-op if already trashed).

        Raises:
            ValidationError: malformed id.
            NotFoundError: no such item (including one purged meanwhile).
            ConflictError: the item changed concurrently twice in a row.
        """
        return self._transition(parse_item_id(item_id), self._trash_once)

    def restore(self, item_id: str) -> Item:
        """Restore an item from the trash (no-op if already active).

        Raises:
            ValidationError: malformed id.
            NotFoundError: no such item (including one already purged).
            ConflictError: the item changed concurrently twice in a row.
        """
        return self._transition(parse_item_id(item_id), self._restore_once)

    # --- internals -----------------------------------------------------------

    def _transition(self, item_id: ItemId, step: Callable[[Item], Item]) -> Item:
        try:
            return step(self._repo.get(item_id))
        except ConflictError:
            # Re-read: the other writer may already have done what we want
            # (then `step` is a no-op). A second conflict propagates (409).
            return step(self._repo.get(item_id))

    def _trash_once(self, item: Item) -> Item:
        if item.state is ItemState.TRASHED:
            return item
        trashed = item.trashed(self._next_stamp(item))
        self._repo.save(trashed, expected_updated_at=item.updated_at)
        return trashed

    def _restore_once(self, item: Item) -> Item:
        if item.state is ItemState.ACTIVE or item.trashed_at is None:
            return item
        # updated_at >= trashed_at always, so this also satisfies `restored`.
        restored = item.restored(self._next_stamp(item))
        self._repo.save(restored, expected_updated_at=item.updated_at)
        return restored

    def _next_stamp(self, item: Item) -> datetime:
        """Now, but strictly after the item's last change (it doubles as the version)."""
        return item.next_change_at(self._clock.now())

    def _scan_text(self, *texts: str | None) -> None:
        # Edited text is published content too (ADR 0008).
        session = self._scanner.new_session()
        for text in texts:
            if text is not None:
                session.feed(text.encode("utf-8", "surrogatepass") + b"\n")
        session.finish()
