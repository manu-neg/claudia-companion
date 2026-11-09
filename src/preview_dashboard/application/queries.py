"""QueryService: read-only use cases (feed/trash listing, item detail, file bytes, kinds).

File access goes item id -> DB manifest -> generated blob id -> BlobStore;
a request's relpath is only ever a manifest lookup key, never a path
(docs/security.md I2, C7, C20).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import BinaryIO

from preview_dashboard.domain.errors import NotFoundError
from preview_dashboard.domain.models import (
    Item,
    ItemFile,
    ItemState,
    Revision,
    parse_item_id,
    validate_revision_number,
)
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.domain.query import ItemQuery, Page
from preview_dashboard.kinds.base import KindRegistry
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.repository import ItemRepository


@dataclass(frozen=True, slots=True)
class OpenedFile:
    """An open item file. Use as a context manager (or call `close`).

    Attributes:
        item: the owning item.
        item_file: the manifest entry (media type, size, sha256).
        stream: seekable binary stream of the blob's bytes.
        revision: the revision the file belongs to (its kind decides
            preview mode/headers, its entry file the bundle page).
    """

    item: Item
    item_file: ItemFile
    stream: BinaryIO
    revision: Revision

    def close(self) -> None:
        """Close the underlying stream."""
        self.stream.close()

    def __enter__(self) -> OpenedFile:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class QueryService:
    """Read-side use cases over the repository, blob store and kind registry."""

    def __init__(self, *, repo: ItemRepository, blobs: BlobStore, kinds: KindRegistry) -> None:
        self._repo = repo
        self._blobs = blobs
        self._kinds = kinds

    def list(self, query: ItemQuery) -> Page[Item]:
        """Return one page of items (pinned first, newest first; see `domain.query`)."""
        return self._repo.list(query)

    def get(self, item_id: str) -> Item:
        """Return an item in any state.

        Raises:
            ValidationError: `item_id` is not a canonical ULID.
            NotFoundError: no such item.
        """
        return self._repo.get(parse_item_id(item_id))

    def revision(
        self, item_id: str, number: int | None, *, allow_trashed: bool
    ) -> tuple[Item, Revision]:
        """Return an item and one of its kept revisions (None = head).

        Args:
            allow_trashed: if False, a trashed item is reported as not found.

        Raises:
            ValidationError: malformed `item_id` or revision number.
            NotFoundError: unknown item, trashed item (unless allowed), or a
                revision that never existed or was pruned.
        """
        parsed_id = parse_item_id(item_id)
        if number is not None:
            validate_revision_number(number)
        item = self._repo.get(parsed_id)
        if item.state is ItemState.TRASHED and not allow_trashed:
            raise NotFoundError("item not found")
        revision = item.revision_by_number(number)
        if revision is None:
            raise NotFoundError("revision not found")
        return item, revision

    def open_file(
        self,
        item_id: str,
        relpath: str,
        *,
        allow_trashed: bool,
        revision: int | None = None,
    ) -> OpenedFile:
        """Open one file of an item revision by its manifest relpath.

        `relpath` is validated, then matched exactly against the revision's
        manifest; it never reaches the storage layer (I2).

        Args:
            allow_trashed: if False, a trashed item is reported as not found
                (same error as a missing one, so existence isn't revealed).
            revision: revision number; None = the head (the "latest" alias).

        Raises:
            ValidationError: malformed `item_id` or revision number.
            InvalidPathError: unsafe/non-canonical `relpath`.
            NotFoundError: unknown item, trashed item (unless allowed),
                unknown/pruned revision, no such file in its manifest, or
                the blob is missing.
        """
        validate_relpath(relpath)
        item, rev = self.revision(item_id, revision, allow_trashed=allow_trashed)
        item_file = rev.file(relpath)
        if item_file is None:
            raise NotFoundError("file not found")
        return OpenedFile(
            item=item,
            item_file=item_file,
            stream=self._blobs.open(item_file.blob_id),
            revision=rev,
        )

    def kinds(self) -> tuple[dict[str, object], ...]:
        """Describe every registered kind (served as `GET /api/kinds`)."""
        return self._kinds.describe()
