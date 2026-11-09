"""Item -> JSON presentation for the dashboard API, including preview-origin URLs.

Every URL that points at item bytes is absolute on the **preview** origin
(docs/security.md C5) and built with `encode_relpath_url`, the exact
inverse of the preview app's one-time decode (C7, C20). URLs name a
concrete revision number (never the `latest` alias), so a page and its
bundle sub-resources always come from one revision (ADR 0019). Trashed
items get the explicit `?t=1` flag, the only way their bytes are served.
Every item carries `folder: {"id", "name"} | null` (ADR 0027).
"""

from __future__ import annotations

from datetime import datetime

from preview_dashboard.domain.errors import UnsupportedContentError
from preview_dashboard.domain.models import Item, ItemFile, ItemState, Revision
from preview_dashboard.interfaces.folder_refs import FolderNames, folder_ref
from preview_dashboard.interfaces.viewer.relpath_url import encode_relpath_url
from preview_dashboard.interfaces.viewer.services import ViewerOptions
from preview_dashboard.kinds.base import ContentKind, KindRegistry

JsonObject = dict[str, object]

TRASH_FLAG = "t"
REVISION_PARAM = "rev"


def iso(value: datetime | None) -> str | None:
    """UTC timestamp as ISO 8601 with a `Z` suffix (None stays None)."""
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


class ItemPresenter:
    """Builds the JSON shapes of `/api/items` and `/api/items/{id}`.

    Args:
        kinds / options: the registry and route settings.
        folders: id -> name of the folders the presented items are filed
            in (`folder_refs.folder_names`); an item whose folder is
            missing from it is shown unfiled (`null`), never an error.
    """

    def __init__(self, kinds: KindRegistry, options: ViewerOptions, folders: FolderNames) -> None:
        self._kinds = kinds
        self._options = options
        self._folders = folders

    def _kind(self, kind_name: str) -> ContentKind | None:
        try:
            return self._kinds.get(kind_name)
        except UnsupportedContentError:
            return None  # kind removed from the registry: download only

    def _suffix(self, item: Item) -> str:
        return f"?{TRASH_FLAG}=1" if item.state is ItemState.TRASHED else ""

    def _file_url(self, letter: str, item: Item, rev: Revision, relpath: str) -> str:
        return (
            f"{self._options.preview_origin}/{letter}/{item.id}/{rev.number}/"
            f"{encode_relpath_url(relpath)}{self._suffix(item)}"
        )

    def preview_url(self, item: Item, rev: Revision, relpath: str) -> str:
        """Inline bytes URL of one file (`/i/<id>/<rev>/...`) on the preview origin."""
        return self._file_url("i", item, rev, relpath)

    def render_url(self, item: Item, rev: Revision, relpath: str) -> str:
        """Capped text URL of one file (`/t/...`), for render-capped kinds."""
        return self._file_url("t", item, rev, relpath)

    def render_page_url(self, item: Item, rev: Revision, relpath: str) -> str:
        """Rendered text page URL of one file (`/r/...`), for render-capped kinds."""
        return self._file_url("r", item, rev, relpath)

    def download_url(self, item: Item, rev: Revision, relpath: str | None = None) -> str:
        """Attachment URL: a whole revision (`/d/<id>/<rev>`) or one file of it."""
        if relpath is not None:
            return self._file_url("d", item, rev, relpath)
        return f"{self._options.preview_origin}/d/{item.id}/{rev.number}{self._suffix(item)}"

    def _revision_entry(self, rev: Revision) -> JsonObject:
        return {
            "number": rev.number,
            "created_at": iso(rev.created_at),
            "kind": rev.kind,
            "entry_file": rev.entry_file,
            "file_count": len(rev.files),
            "total_size": rev.total_size,
        }

    def summary(self, item: Item, rev: Revision | None = None) -> JsonObject:
        """Feed/trash entry: metadata plus URLs of the entry file of `rev` (default: head).

        `revision` is the number the URLs point at; `latest_revision` the
        head's; `revisions` lists every kept revision, newest first.
        """
        rev = item.head if rev is None else rev
        kind = self._kind(rev.kind)
        capped = kind is not None and kind.render_capped
        entry = rev.entry_file
        purge_at = (
            None if item.trashed_at is None else item.trashed_at + self._options.trash_retention
        )
        return {
            "id": item.id,
            "title": item.title,
            "description": item.description,
            "kind": rev.kind,
            "preview_mode": str(kind.preview_mode) if kind is not None else "download",
            "pinned": item.pinned,
            "state": str(item.state),
            "created_at": iso(item.created_at),
            "updated_at": iso(item.updated_at),
            "trashed_at": iso(item.trashed_at),
            "purge_at": iso(purge_at),
            "file_count": len(rev.files),
            "total_size": rev.total_size,
            "entry_file": entry,
            "preview_url": self.preview_url(item, rev, entry),
            "render_url": self.render_url(item, rev, entry) if capped else None,
            "render_page_url": self.render_page_url(item, rev, entry) if capped else None,
            "download_url": self.download_url(item, rev),
            "revision": rev.number,
            "revision_created_at": iso(rev.created_at),
            "latest_revision": item.revision,
            "revisions": [self._revision_entry(r) for r in reversed(item.revisions)],
            "folder": folder_ref(item, self._folders),
        }

    def file(self, item: Item, rev: Revision, item_file: ItemFile, capped: bool) -> JsonObject:
        """One manifest entry of `rev` with its URLs."""
        relpath = item_file.relpath
        return {
            "relpath": relpath,
            "media_type": item_file.media_type,
            "size": item_file.size,
            "sha256": item_file.sha256,
            "preview_url": self.preview_url(item, rev, relpath),
            "render_url": self.render_url(item, rev, relpath) if capped else None,
            "render_page_url": self.render_page_url(item, rev, relpath) if capped else None,
            "download_url": self.download_url(item, rev, relpath),
        }

    def detail(self, item: Item, rev: Revision | None = None) -> JsonObject:
        """Item detail for `rev` (default: head): the summary plus every file of it."""
        rev = item.head if rev is None else rev
        kind = self._kind(rev.kind)
        capped = kind is not None and kind.render_capped
        body = self.summary(item, rev)
        body["files"] = [self.file(item, rev, f, capped) for f in rev.files]
        return body
