"""ArchiveService: streams an item's files as a ZIP, plus a safe download name.

Arcnames come only from validated manifest relpaths; entries are regular
files (no directories, symlinks or exec bits), DEFLATE-compressed, with a
fixed timestamp from the item (docs/security.md C7, C9). Bytes are checked
against the manifest's size and SHA-256 while streaming.
"""

from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import zipfile
from collections.abc import Buffer, Generator
from datetime import datetime

from preview_dashboard.domain.errors import InvalidPathError, NotFoundError, ValidationError
from preview_dashboard.domain.models import (
    Item,
    ItemState,
    Revision,
    parse_item_id,
    validate_revision_number,
)
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.repository import ItemRepository

# Regular file, rw-r--r--: never a symlink (0o120000) or executable.
REGULAR_FILE_ATTR = 0o100644 << 16
_UNIX = 3  # ZIP "version made by" host: makes extractors honour external_attr
_ZIP_MIN = (1980, 1, 1, 0, 0, 0)  # DOS timestamps can't go outside 1980..2107
_ZIP_MAX = (2107, 12, 31, 23, 59, 58)
_READ_CHUNK = 64 * 1024
_MAX_SLUG = 80
_FALLBACK_NAME = "download.zip"


class _ChunkSink(io.RawIOBase):
    """Write-only, unseekable sink; zipfile then streams with data descriptors."""

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[bytes] = []

    def writable(self) -> bool:
        return True

    def write(self, b: Buffer, /) -> int:
        data = bytes(b)
        self._parts.append(data)
        return len(data)

    def drain(self) -> bytes:
        """Return and forget everything written so far."""
        data = b"".join(self._parts)
        self._parts.clear()
        return data


def _zip_time(at: datetime) -> tuple[int, int, int, int, int, int]:
    stamp = (at.year, at.month, at.day, at.hour, at.minute, at.second)
    return min(max(stamp, _ZIP_MIN), _ZIP_MAX)


def download_filename(item: Item, revision: int | None = None) -> str:
    """Return a safe ASCII `<slug>.zip` (or `<slug>-v<N>.zip`) name for an archive.

    The slug keeps `[A-Za-z0-9._-]` from the NFKD-folded title (other runs
    become `-`), trimmed to 80 chars. Anything unusable (empty, Windows
    device names such as `CON`) falls back to `download.zip`. With
    `revision`, `-v<N>` is appended so two versions don't overwrite each
    other in the owner's downloads. The RFC 6266 header (with the UTF-8
    `filename*` form) is built by the viewer.
    """
    ascii_title = unicodedata.normalize("NFKD", item.title).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", ascii_title).strip("-._")
    slug = slug[:_MAX_SLUG].strip("-._")
    if not slug:
        return _FALLBACK_NAME
    suffix = "" if revision is None else f"-v{validate_revision_number(revision)}"
    name = f"{slug}{suffix}.zip"
    try:
        return validate_relpath(name)
    except InvalidPathError:
        return _FALLBACK_NAME


class ArchiveService:
    """Builds streamed ZIP archives of items."""

    def __init__(self, *, repo: ItemRepository, blobs: BlobStore) -> None:
        self._repo = repo
        self._blobs = blobs

    def stream_zip(
        self, item_id: str, *, allow_trashed: bool = False, revision: int | None = None
    ) -> Generator[bytes, None, None]:
        """Return a generator of ZIP bytes for all files of one item revision (None = head).

        The item is looked up eagerly (so callers can answer 404 before
        starting a response); bytes are produced lazily. Aborting iteration
        early (or calling `.close()`) closes any open blob stream.

        Raises (eagerly):
            ValidationError: malformed `item_id` or revision number.
            NotFoundError: unknown item or revision (pruned), or trashed and
                not `allow_trashed`.
        Raises (while iterating):
            NotFoundError: a blob is missing.
            ValidationError: a blob does not match its manifest size/digest.
        """
        if revision is not None:
            validate_revision_number(revision)
        item = self._repo.get(parse_item_id(item_id))
        if item.state is ItemState.TRASHED and not allow_trashed:
            raise NotFoundError("item not found")
        rev = item.revision_by_number(revision)
        if rev is None:
            raise NotFoundError("revision not found")
        return self._generate(rev)

    def _generate(self, revision: Revision) -> Generator[bytes, None, None]:
        sink = _ChunkSink()
        date_time = _zip_time(revision.created_at)
        with zipfile.ZipFile(sink, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item_file in revision.files:
                # Re-validated although the Item already did: arcnames are the
                # one place a bad path would become a file on the owner's disk.
                info = zipfile.ZipInfo(validate_relpath(item_file.relpath), date_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = _UNIX
                info.external_attr = REGULAR_FILE_ATTR
                info.file_size = item_file.size  # lets zipfile pick zip64 up front
                digest = hashlib.sha256()
                seen = 0
                with (
                    self._blobs.open(item_file.blob_id) as source,
                    archive.open(info, mode="w") as dest,
                ):
                    while chunk := source.read(_READ_CHUNK):
                        seen += len(chunk)
                        if seen > item_file.size:
                            raise ValidationError("stored file does not match its manifest")
                        digest.update(chunk)
                        dest.write(chunk)
                        if data := sink.drain():
                            yield data
                if seen != item_file.size or digest.hexdigest() != item_file.sha256:
                    raise ValidationError("stored file does not match its manifest")
                if data := sink.drain():
                    yield data
        if data := sink.drain():
            yield data
