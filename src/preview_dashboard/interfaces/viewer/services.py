"""What the viewer apps need from the core: narrow Protocols + per-app options.

`ViewerServices` is satisfied by `bootstrap.ViewerCore` (queries, trash
and pin control, archive, read-only folders, kinds, keep=1 revision prune);
the viewer never sees publish, text edit or folder write capabilities (C40).
`ViewerOptions`
carries the few `Settings` values routes need, so routes never touch
`Settings` directly.
"""

from __future__ import annotations

from collections.abc import Generator
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from starlette.requests import Request

from preview_dashboard.application.history import PruneResult
from preview_dashboard.application.queries import OpenedFile
from preview_dashboard.config import Settings
from preview_dashboard.domain.models import Item, Revision
from preview_dashboard.domain.query import ItemQuery, Page
from preview_dashboard.interfaces.folder_refs import FolderLookup
from preview_dashboard.kinds.base import KindRegistry


class ItemQueries(Protocol):
    """Read-side use cases (`application.QueryService`)."""

    def list(self, query: ItemQuery) -> Page[Item]:
        """One page of items, pinned first, newest first."""
        ...

    def get(self, item_id: str) -> Item:
        """An item in any state (ValidationError / NotFoundError)."""
        ...

    def revision(
        self, item_id: str, number: int | None, *, allow_trashed: bool
    ) -> tuple[Item, Revision]:
        """An item and one kept revision (None = head); NotFoundError if pruned/hidden."""
        ...

    def open_file(
        self,
        item_id: str,
        relpath: str,
        *,
        allow_trashed: bool,
        revision: int | None = None,
    ) -> OpenedFile:
        """Open one manifest file of an item revision (NotFoundError if trashed and not allowed)."""
        ...


class TrashActions(Protocol):
    """Viewer write capability: trash/restore (`bootstrap.TrashControl`); both idempotent."""

    def trash(self, item_id: str) -> Item:
        """Move an item to the trash."""
        ...

    def restore(self, item_id: str) -> Item:
        """Restore an item from the trash."""
        ...


class PinActions(Protocol):
    """Viewer write capability: the pin flag only (`bootstrap.PinControl`); idempotent."""

    def set_pinned(self, item_id: str, *, pinned: bool) -> Item:
        """Pin/unpin an active item (InvalidStateError if trashed)."""
        ...


class HistoryActions(Protocol):
    """Viewer write capability: delete old versions (`bootstrap.RevisionPruner`, keep=1)."""

    def prune_old(self, item_id: str, *, expected_revision: int | None = None) -> PruneResult:
        """Drop every revision but the head.

        Raises InvalidStateError if trashed, ConflictError if
        `expected_revision` is no longer the head.
        """
        ...


class ItemArchiver(Protocol):
    """Streamed ZIP downloads (`application.ArchiveService`)."""

    def stream_zip(
        self, item_id: str, *, allow_trashed: bool = False, revision: int | None = None
    ) -> Generator[bytes, None, None]:
        """Eagerly look up the item, then lazily yield ZIP bytes."""
        ...


class ViewerServices(Protocol):
    """Everything the two viewer apps call into (read-only attributes)."""

    @property
    def kinds(self) -> KindRegistry:
        """The content-kind registry (`GET /api/kinds`, media-type checks)."""
        ...

    @property
    def queries(self) -> ItemQueries:
        """Listing, detail and manifest-only file access."""
        ...

    @property
    def trash(self) -> TrashActions:
        """Trash/restore."""
        ...

    @property
    def pins(self) -> PinActions:
        """Pin/unpin."""
        ...

    @property
    def archive(self) -> ItemArchiver:
        """ZIP downloads of multi-file items."""
        ...

    @property
    def history(self) -> HistoryActions:
        """Delete an item's old versions (keep the current one only; C43)."""
        ...

    @property
    def folders(self) -> FolderLookup:
        """Folders, read only (`bootstrap.FolderReader`: `list`/`get`/`names`, C40)."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class ViewerOptions:
    """Route-level settings, derived once from `Settings`.

    Attributes:
        render_cap_bytes: most bytes `/t/...` returns for a TEXT kind.
        trash_retention: how long a trashed item lives before purge (for
            the `purge_at` hint in JSON).
        preview_origin: `https://<host>:<port>` used to build item URLs.
    """

    render_cap_bytes: int
    trash_retention: timedelta
    preview_origin: str

    @classmethod
    def from_settings(cls, settings: Settings, preview_origin: str) -> ViewerOptions:
        """Build options; `preview_origin` comes from the validated `ViewerOrigins`.

        Raises:
            ValueError: a non-positive render cap or retention (fail closed).
        """
        if settings.render_cap_bytes <= 0 or settings.trash_retention_days <= 0:
            raise ValueError("render_cap_bytes and trash_retention_days must be > 0")
        return cls(
            render_cap_bytes=settings.render_cap_bytes,
            trash_retention=timedelta(days=settings.trash_retention_days),
            preview_origin=preview_origin,
        )


def services_of(request: Request) -> ViewerServices:
    """The services the app factory attached to this app."""
    services: ViewerServices = request.app.state.services
    return services


def options_of(request: Request) -> ViewerOptions:
    """The options the app factory attached to this app."""
    options: ViewerOptions = request.app.state.options
    return options
