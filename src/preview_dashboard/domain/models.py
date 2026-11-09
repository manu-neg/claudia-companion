"""Domain entities and value objects: ItemId, ItemState, BlobRef, ItemFile, Revision, Item.

All are frozen, slotted dataclasses that validate their invariants on
construction (including via `dataclasses.replace`). State changes are
methods returning new instances; illegal transitions raise InvalidStateError.
An item is its head revision (kind, files, entry file) plus up to
`MAX_REVISIONS - 1` older revisions kept in `history` (ADR 0019), and sits
in at most one folder (`folder_id`, ADR 0027).
"""

from __future__ import annotations

import dataclasses
import itertools
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, NewType

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.domain.text import sanitize_description, sanitize_title
from preview_dashboard.domain.unicode import caseless_key

if TYPE_CHECKING:
    # Type only: `domain.folders` imports this module (is_ulid, ensure_utc).
    from preview_dashboard.domain.folders import FolderId

ItemId = NewType("ItemId", str)
"""Canonical ULID string (26 chars, Crockford base32, uppercase)."""

# Canonical ULID: first char <= '7' keeps the value within 128 bits.
# Uppercase only: ids are compared as strings, so one spelling per id.
_ULID_RE = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_KIND_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
# type/subtype, lowercase, no parameters: charset etc. are added at serve
# time from the kind registry (docs/security.md C8), never stored.
_MEDIA_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")
# Sizes must fit a signed 64-bit integer (SQLite INTEGER, off_t, HTTP
# Content-Length parsers); larger values would overflow in adapters.
MAX_BLOB_SIZE = 2**63 - 1
# Owner decision (ADR 0019): an item keeps its last 20 revisions, head included.
MAX_REVISIONS = 20
# Revision numbers only grow; the bound keeps them far inside 64-bit ranges
# and short in URLs (10 digits max).
MAX_REVISION_NUMBER = 2**31 - 1
_ONE_US = timedelta(microseconds=1)


def is_ulid(value: object) -> bool:
    """Return True if `value` is a canonical (uppercase) ULID string."""
    return isinstance(value, str) and _ULID_RE.fullmatch(value) is not None


def parse_item_id(raw: str) -> ItemId:
    """Validate an untrusted string as an ItemId.

    Raises:
        ValidationError: if `raw` is not a canonical ULID.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid item id")
    return ItemId(raw)


def validate_blob_id(raw: str) -> str:
    """Validate a blob id (canonical ULID); it is used as a storage key/filename.

    Raises:
        ValidationError: if `raw` is not a canonical ULID.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid blob id")
    return raw


def validate_kind(raw: str) -> str:
    """Validate a kind name's syntax (registry membership is checked elsewhere).

    Raises:
        ValidationError: if `raw` does not match `[a-z][a-z0-9-]{0,31}`.
    """
    if not isinstance(raw, str) or not _KIND_RE.fullmatch(raw):
        raise ValidationError("invalid kind")
    return raw


def ensure_utc(value: datetime, name: str = "datetime") -> datetime:
    """Return `value` converted to UTC.

    Raises:
        ValidationError: if `value` is not a timezone-aware datetime.
    """
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValidationError(f"{name} must be a timezone-aware datetime")
    try:
        return value.astimezone(UTC)
    except OverflowError:  # e.g. datetime.min at +05:00 has no UTC equivalent
        raise ValidationError(f"{name} is out of range") from None


class ItemState(StrEnum):
    """Lifecycle state of an item.

    ACTIVE --trashed()--> TRASHED --restored()--> ACTIVE;
    TRASHED --(retention elapsed)--> purged (row deleted, not a state).
    """

    ACTIVE = "active"
    TRASHED = "trashed"


@dataclass(frozen=True, slots=True, kw_only=True)
class BlobRef:
    """Result of storing bytes in a BlobStore: id, byte size and SHA-256 hex digest."""

    blob_id: str
    size: int
    sha256: str

    def __post_init__(self) -> None:
        validate_blob_id(self.blob_id)
        if (
            not isinstance(self.size, int)
            or isinstance(self.size, bool)
            or not 0 <= self.size <= MAX_BLOB_SIZE
        ):
            raise ValidationError("blob size must be an int in 0..2**63-1")
        if not isinstance(self.sha256, str) or not _SHA256_RE.fullmatch(self.sha256):
            raise ValidationError("sha256 must be 64 lowercase hex chars")


@dataclass(frozen=True, slots=True, kw_only=True)
class ItemFile:
    """One file of an item: its bundle-relative path plus the blob holding its bytes.

    Raises (on construction):
        InvalidPathError: unsafe `relpath` (see `validate_relpath`).
        ValidationError: bad blob id, size, digest or media type.
    """

    relpath: str
    blob_id: str
    size: int
    sha256: str
    media_type: str

    def __post_init__(self) -> None:
        validate_relpath(self.relpath)
        # Reuse BlobRef's checks so blob invariants live in one place.
        BlobRef(blob_id=self.blob_id, size=self.size, sha256=self.sha256)
        if not isinstance(self.media_type, str) or not _MEDIA_TYPE_RE.fullmatch(self.media_type):
            raise ValidationError("media_type must be a lowercase 'type/subtype'")

    @classmethod
    def from_blob(cls, relpath: str, blob: BlobRef, media_type: str) -> ItemFile:
        """Build an ItemFile for bytes already stored as `blob`."""
        return cls(
            relpath=relpath,
            blob_id=blob.blob_id,
            size=blob.size,
            sha256=blob.sha256,
            media_type=media_type,
        )


def validate_revision_number(value: object) -> int:
    """Validate a revision number (an int in 1..MAX_REVISION_NUMBER, not a bool).

    Raises:
        ValidationError: anything else.
    """
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= MAX_REVISION_NUMBER
    ):
        raise ValidationError("revision number must be an int in 1..2**31-1")
    return value


def validate_keep_revisions(value: object) -> int:
    """Validate how many revisions a prune keeps, head included (1..MAX_REVISIONS, ADR 0030).

    Raises:
        ValidationError: not an int (bools refused) or out of range.
    """
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_REVISIONS:
        raise ValidationError(f"keep must be an int in 1..{MAX_REVISIONS}")
    return value


def _check_manifest(files: Iterable[ItemFile], entry_file: str) -> tuple[ItemFile, ...]:
    """Validate one revision's file manifest; return it as a tuple.

    Raises:
        ValidationError: no files, non-ItemFile entries, caseless duplicate
            paths, a file path also used as a directory, or `entry_file`
            not among the files.
    """
    files = tuple(files)
    if not files:
        raise ValidationError("an item needs at least one file")
    if not all(isinstance(f, ItemFile) for f in files):
        raise ValidationError("files must be ItemFile instances")
    # 'A.txt' and 'a.txt' (or 'İ' and 'i̇', 'ß' and 'SS') collide on
    # macOS/Windows when the owner extracts the zip, silently overwriting
    # one another; plain casefold() misses the canonical-equivalent cases.
    folded = [caseless_key(f.relpath) for f in files]
    if len(set(folded)) != len(folded):
        raise ValidationError("file paths must be unique (case-insensitive)")
    split = [p.split("/") for p in folded]
    parents = {"/".join(parts[:i]) for parts in split for i in range(1, len(parts))}
    if parents.intersection(folded):
        raise ValidationError("a file path is also used as a directory")
    if entry_file not in {f.relpath for f in files}:
        raise ValidationError("entry_file must be one of the item's files")
    return files


@dataclass(frozen=True, slots=True, kw_only=True)
class Revision:
    """One published version of an item's content (immutable once published).

    Invariants (`ValidationError`): `number` in 1..2**31-1; `kind` syntax;
    the manifest rules of `Item` (>= 1 file, caseless-unique paths, no
    file/dir clash, `entry_file` among the files); `created_at` tz-aware (UTC).
    """

    number: int
    kind: str
    files: tuple[ItemFile, ...]
    entry_file: str
    created_at: datetime

    def __post_init__(self) -> None:
        validate_revision_number(self.number)
        validate_kind(self.kind)
        object.__setattr__(self, "files", _check_manifest(self.files, self.entry_file))
        object.__setattr__(self, "created_at", ensure_utc(self.created_at, "created_at"))

    @property
    def total_size(self) -> int:
        """Sum of this revision's file sizes in bytes."""
        return sum(f.size for f in self.files)

    def file(self, relpath: str) -> ItemFile | None:
        """Return the file with exactly this relpath, or None (manifest lookup)."""
        return next((f for f in self.files if f.relpath == relpath), None)


@dataclass(frozen=True, slots=True, kw_only=True)
class Item:
    """A published preview item (single file or multi-file bundle) with its revisions.

    `kind`, `files` and `entry_file` describe the **head** revision (number
    `revision`, published at `revision_at`); `history` holds the older
    revisions still kept, oldest first. The id never changes across
    revisions (stable URLs, ADR 0019).

    Invariants (checked on construction, `ValidationError` unless noted):
    - `id` is a canonical ULID; `kind` matches `[a-z][a-z0-9-]{0,31}`;
    - `title` / `description` are sanitized display text (see `domain.text`:
      control, bidi and invisible chars removed, trimmed), title 1..200
      chars, description <= 5000 chars;
    - at least one file; relpaths unique under compatibility caseless
      matching (`domain.unicode.caseless_key`), and no file path is also a
      directory of another (both would break zip extraction);
    - `entry_file` is one of the files' relpaths;
    - datetimes are tz-aware (stored as UTC), `updated_at >= created_at`;
    - `trashed_at` is set iff `state` is TRASHED, and `trashed_at >= created_at`;
    - revisions: `history` numbers strictly increase and are below
      `revision`; at most `MAX_REVISIONS` revisions in total; revision
      times never precede `created_at`, never decrease, and the head's
      `revision_at` (default: `created_at`) is <= `updated_at`; no blob id
      is used twice across all kept revisions;
    - `folder_id` is None (unfiled) or a canonical ULID. Every transition
      keeps it (trash, restore, edits, revisions); only `moved_to` changes it.
    """

    id: ItemId
    title: str
    kind: str
    files: tuple[ItemFile, ...]
    entry_file: str
    created_at: datetime
    updated_at: datetime
    description: str = ""
    pinned: bool = False
    state: ItemState = ItemState.ACTIVE
    trashed_at: datetime | None = None
    revision: int = 1
    revision_at: datetime | None = None
    history: tuple[Revision, ...] = ()
    folder_id: FolderId | None = None

    def __post_init__(self) -> None:
        parse_item_id(self.id)
        if self.folder_id is not None and not is_ulid(self.folder_id):
            raise ValidationError("invalid folder id")
        self._set("title", sanitize_title(self.title))
        self._set("description", sanitize_description(self.description))
        validate_kind(self.kind)
        if not isinstance(self.pinned, bool):
            raise ValidationError("pinned must be a bool")
        try:
            self._set("state", ItemState(self.state))
        except ValueError:
            raise ValidationError("invalid state") from None
        self._set("files", _check_manifest(self.files, self.entry_file))
        self._check_times()
        self._check_revisions()

    def _set(self, name: str, value: object) -> None:
        # Frozen dataclass: normalization during __post_init__ must bypass
        # the frozen __setattr__. Only ever called from __post_init__.
        object.__setattr__(self, name, value)

    def _check_times(self) -> None:
        self._set("created_at", ensure_utc(self.created_at, "created_at"))
        self._set("updated_at", ensure_utc(self.updated_at, "updated_at"))
        if self.updated_at < self.created_at:
            raise ValidationError("updated_at must not precede created_at")
        if self.state is ItemState.TRASHED:
            if self.trashed_at is None:
                raise ValidationError("a trashed item needs trashed_at")
            self._set("trashed_at", ensure_utc(self.trashed_at, "trashed_at"))
            if self.trashed_at < self.created_at:
                raise ValidationError("trashed_at must not precede created_at")
        elif self.trashed_at is not None:
            raise ValidationError("an active item must not have trashed_at")

    def _check_revisions(self) -> None:
        validate_revision_number(self.revision)
        head_at = ensure_utc(
            self.created_at if self.revision_at is None else self.revision_at, "revision_at"
        )
        self._set("revision_at", head_at)
        history = tuple(self.history)
        self._set("history", history)
        if not all(isinstance(r, Revision) for r in history):
            raise ValidationError("history must hold Revision instances")
        if len(history) + 1 > MAX_REVISIONS:
            raise ValidationError(f"an item keeps at most {MAX_REVISIONS} revisions")
        numbers = [r.number for r in history] + [self.revision]
        if any(a >= b for a, b in itertools.pairwise(numbers)):
            raise ValidationError("revision numbers must strictly increase")
        times = [r.created_at for r in history] + [head_at]
        if times[0] < self.created_at or any(a > b for a, b in itertools.pairwise(times)):
            raise ValidationError("revision times must not run backwards")
        if head_at > self.updated_at:
            raise ValidationError("revision_at must not follow updated_at")
        blob_ids = [f.blob_id for f in self.all_files]
        if len(set(blob_ids)) != len(blob_ids):
            raise ValidationError("a blob is referenced twice by one item")

    # --- construction --------------------------------------------------------

    @classmethod
    def new(
        cls,
        *,
        id: ItemId,  # shadows the builtin on purpose: mirrors the field name
        title: str,
        kind: str,
        files: Iterable[ItemFile],
        entry_file: str,
        now: datetime,
        description: str = "",
        pinned: bool = False,
        folder_id: FolderId | None = None,
    ) -> Item:
        """Create a fresh ACTIVE item with `created_at == updated_at == now`."""
        return cls(
            id=id,
            title=title,
            description=description,
            kind=kind,
            files=tuple(files),
            entry_file=entry_file,
            created_at=now,
            updated_at=now,
            pinned=pinned,
            folder_id=folder_id,
        )

    # --- derived -------------------------------------------------------------

    @property
    def total_size(self) -> int:
        """Sum of the head revision's file sizes in bytes."""
        return sum(f.size for f in self.files)

    @property
    def stored_size(self) -> int:
        """Bytes stored for every kept revision (what counts against the quota)."""
        return sum(f.size for f in self.all_files)

    @property
    def all_files(self) -> tuple[ItemFile, ...]:
        """Every file of every kept revision (oldest revision first, head last)."""
        return tuple(f for r in self.history for f in r.files) + self.files

    @property
    def head(self) -> Revision:
        """The current revision as a `Revision` value."""
        return Revision(
            number=self.revision,
            kind=self.kind,
            files=self.files,
            entry_file=self.entry_file,
            created_at=self.revision_at if self.revision_at is not None else self.created_at,
        )

    @property
    def revisions(self) -> tuple[Revision, ...]:
        """Every kept revision, oldest first, head last."""
        return (*self.history, self.head)

    def revision_by_number(self, number: int | None) -> Revision | None:
        """Return kept revision `number` (None = head), or None if unknown or pruned."""
        if number is None or number == self.revision:
            return self.head
        return next((r for r in self.history if r.number == number), None)

    def file(self, relpath: str) -> ItemFile | None:
        """Return the head file with exactly this relpath, or None (manifest lookup)."""
        return next((f for f in self.files if f.relpath == relpath), None)

    def next_change_at(self, now: datetime) -> datetime:
        """`now`, but strictly after `updated_at` (which doubles as the item's version).

        Every change must move `updated_at` forward for the repository's
        compare-and-swap to work, even if the wall clock stepped back (NTP)
        or two writers share a microsecond.

        Raises:
            ValidationError: `now` is naive, or `updated_at` is at `datetime.max`
                (only a tampered row can be).
        """
        try:
            return max(ensure_utc(now, "now"), self.updated_at + _ONE_US)
        except OverflowError:
            raise ValidationError("item timestamp is out of range") from None

    # --- transitions ---------------------------------------------------------

    def trashed(self, at: datetime) -> Item:
        """Return this item moved to the trash at `at`.

        Raises:
            InvalidStateError: if the item is already trashed.
            ValidationError: if `at` precedes `updated_at` (time must not run
                backwards through a transition).
        """
        if self.state is not ItemState.ACTIVE:
            raise InvalidStateError("item is already in the trash")
        if ensure_utc(at, "at") < self.updated_at:
            raise ValidationError("trash time must not precede updated_at")
        return dataclasses.replace(self, state=ItemState.TRASHED, trashed_at=at, updated_at=at)

    def restored(self, at: datetime) -> Item:
        """Return this item restored from the trash at `at`.

        Raises:
            InvalidStateError: if the item is not in the trash.
            ValidationError: if `at` precedes `trashed_at`.
        """
        if self.state is not ItemState.TRASHED:
            raise InvalidStateError("item is not in the trash")
        # trashed_at is always set while TRASHED (construction invariant).
        if self.trashed_at is not None and ensure_utc(at, "at") < self.trashed_at:
            raise ValidationError("restore time must not precede trashed_at")
        return dataclasses.replace(self, state=ItemState.ACTIVE, trashed_at=None, updated_at=at)

    def with_metadata(
        self,
        *,
        now: datetime,
        title: str | None = None,
        description: str | None = None,
        pinned: bool | None = None,
    ) -> Item:
        """Return a copy with the given metadata changed (None = keep).

        Only ACTIVE items are editable: the trash is a holding area, not a
        workspace, and this keeps trashed items from being pinned.

        Raises:
            InvalidStateError: if the item is trashed.
            ValidationError: if a new value violates an invariant.
        """
        if self.state is not ItemState.ACTIVE:
            raise InvalidStateError("trashed items cannot be edited")
        return dataclasses.replace(
            self,
            title=self.title if title is None else title,
            description=self.description if description is None else description,
            pinned=self.pinned if pinned is None else pinned,
            updated_at=now,
        )

    def moved_to(self, folder_id: FolderId | None, *, at: datetime) -> Item:
        """Return this item filed in `folder_id` (None = unfiled), changed at `at`.

        Allowed in every state: a folder is organisation, not content, and a
        folder can only be deleted once no item (trashed ones included)
        references it (ADR 0027). Whether the folder exists is the
        repository's check, atomically with the save.

        Raises:
            ValidationError: `folder_id` is not a canonical ULID, or `at`
                precedes `updated_at`.
        """
        if ensure_utc(at, "at") < self.updated_at:
            raise ValidationError("move time must not precede updated_at")
        return dataclasses.replace(self, folder_id=folder_id, updated_at=at)

    def with_revision(
        self,
        *,
        kind: str,
        files: Iterable[ItemFile],
        entry_file: str,
        at: datetime,
    ) -> tuple[Item, tuple[Revision, ...]]:
        """Return this item with new head content, plus the revisions pruned to make room.

        The old head moves into `history`; the oldest revisions beyond
        `MAX_REVISIONS` are dropped (their blobs are the caller's to delete
        once the new item is committed). Title, description, pin and id stay.

        Raises:
            InvalidStateError: the item is trashed (trashed items are read-only).
            ValidationError: `at` precedes `updated_at`, the revision number
                would overflow, or the new content breaks an invariant.
        """
        if self.state is not ItemState.ACTIVE:
            raise InvalidStateError("trashed items cannot be updated")
        if ensure_utc(at, "at") < self.updated_at:
            raise ValidationError("revision time must not precede updated_at")
        kept = (*self.history, self.head)
        pruned = kept[: max(0, len(kept) - (MAX_REVISIONS - 1))]
        updated = dataclasses.replace(
            self,
            kind=kind,
            files=tuple(files),
            entry_file=entry_file,
            revision=validate_revision_number(self.revision + 1),
            revision_at=at,
            updated_at=at,
            history=kept[len(pruned) :],
        )
        return updated, pruned

    def without_history(self, keep: int, *, at: datetime) -> tuple[Item, tuple[Revision, ...]]:
        """Return this item keeping only its newest `keep` revisions, plus the dropped ones.

        `keep` counts the head, which is never dropped (ADR 0030). Dropped
        revisions are returned oldest first; their blobs are the caller's to
        delete once the new item is committed. With nothing to drop, the
        item is returned unchanged (no new `updated_at`, so no write needed).

        Raises:
            InvalidStateError: the item is trashed (trashed items are read-only).
            ValidationError: `keep` is not an int in 1..MAX_REVISIONS, or `at`
                precedes `updated_at`.
        """
        validate_keep_revisions(keep)
        if self.state is not ItemState.ACTIVE:
            raise InvalidStateError("trashed items cannot be changed")
        if ensure_utc(at, "at") < self.updated_at:
            raise ValidationError("prune time must not precede updated_at")
        # keep - 1 older revisions stay next to the head.
        dropped = self.history[: max(0, len(self.history) - (keep - 1))]
        if not dropped:
            return self, ()
        kept = self.history[len(dropped) :]
        return dataclasses.replace(self, history=kept, updated_at=at), dropped

    def is_purgeable(self, now: datetime, retention: timedelta) -> bool:
        """True if trashed and `now - trashed_at >= retention` (boundary inclusive)."""
        if self.state is not ItemState.TRASHED or self.trashed_at is None:
            return False
        return ensure_utc(now, "now") - self.trashed_at >= retention

    def ensure_purgeable(self, now: datetime, retention: timedelta) -> None:
        """Raise unless the item may be permanently deleted now.

        Raises:
            InvalidStateError: if not trashed, or the retention has not elapsed.
        """
        if not self.is_purgeable(now, retention):
            raise InvalidStateError("item is not purgeable yet")
