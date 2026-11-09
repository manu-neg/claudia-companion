"""PublishService: publish a new item, or a new revision of an existing one.

Both paths enforce, in order: rate limit, file count, path/metadata
validity, kind detection, global quotas and free-disk floor, per-file/per-
item byte limits on streamed bytes, the secret scan and a hard deadline
(docs/security.md C8, C11, C15, C18). Any failure before the commit is
attempted deletes every blob this call stored; after it, only if the change
provably did not commit (the orphan sweep is the backstop). A revision is
committed with a compare-and-swap; the blobs of revisions pruned by it are
deleted after the commit (ADR 0019).
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import timedelta

from preview_dashboard.application.ratelimit import RateLimiter
from preview_dashboard.domain.errors import (
    ConflictError,
    InvalidStateError,
    LimitExceededError,
    NotFoundError,
    SecretDetectedError,
)
from preview_dashboard.domain.folders import FolderId, parse_folder_id
from preview_dashboard.domain.models import (
    Item,
    ItemFile,
    ItemId,
    ItemState,
    Revision,
    parse_item_id,
    validate_kind,
    validate_revision_number,
)
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.kinds.base import ContentKind, KindRegistry
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.folders import FolderRepository
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.repository import ItemRepository
from preview_dashboard.ports.scanner import ContentScanner, ScanSession

_log = logging.getLogger(__name__)

# Placeholders for the up-front manifest check: valid values that let the
# real domain constructors vet paths/title/entry file before any byte moves.
# (Placeholder blob ids are distinct per file: an item never reuses a blob.)
_PLACEHOLDER_ID = "0" * 26
_PLACEHOLDER_SHA = "0" * 64
_PLACEHOLDER_TYPE = "application/octet-stream"


class _DeadlineExceededError(LimitExceededError):
    """The hard publish deadline passed (kept distinct so it isn't relabeled)."""


@dataclass(frozen=True, slots=True)
class IncomingFile:
    """One file to publish: its bundle-relative path and its bytes (consumed once)."""

    relpath: str
    chunks: Iterable[bytes]


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishCommand:
    """Everything a publisher supplies. No media types: those come from the kind.

    Attributes:
        title / description: untrusted display text (sanitized by the domain).
        files: at least one file; relpaths must pass `validate_relpath`.
        kind_hint: requested kind name, or None to autodetect.
        pinned: pin the item to the top of the feed.
        folder_id: file the new item in this folder (untrusted; validated
            as a ULID, must exist), or None for unfiled (ADR 0027).
    """

    title: str
    files: Sequence[IncomingFile]
    description: str = ""
    kind_hint: str | None = None
    pinned: bool = False
    folder_id: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class RevisionCommand:
    """New content for an existing item (a new head revision; id and metadata stay).

    Attributes:
        item_id: the item to update (untrusted; validated as a ULID).
        files: at least one file; the complete new content (no merging with
            the previous revision).
        kind_hint: requested kind name, or None to autodetect.
        expected_revision: if set, the update only applies while this is
            still the head revision number (else `ConflictError`), so a
            client can't overwrite a revision it has not seen.
    """

    item_id: str
    files: Sequence[IncomingFile]
    kind_hint: str | None = None
    expected_revision: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishLimits:
    """Publish limits (mapped from `Settings` by the composition root).

    Raises (on construction):
        ValueError: a non-positive limit, or file > item > total ordering broken.
    """

    max_files: int
    max_file_bytes: int
    max_item_bytes: int
    max_total_bytes: int
    max_items: int
    min_free_disk_bytes: int
    timeout: timedelta

    def __post_init__(self) -> None:
        for name in (
            "max_files",
            "max_file_bytes",
            "max_item_bytes",
            "max_total_bytes",
            "max_items",
            "min_free_disk_bytes",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be > 0")
        if self.timeout <= timedelta(0):
            raise ValueError("timeout must be > 0")
        if not self.max_file_bytes <= self.max_item_bytes <= self.max_total_bytes:
            raise ValueError("need max_file_bytes <= max_item_bytes <= max_total_bytes")


@dataclass(frozen=True, slots=True)
class _Reservation:
    """What one in-flight publish holds: item slots (0 or 1) and a byte budget."""

    items: int
    budget: int


class _QuotaGate:
    """Global quotas, counting publishes still in flight in this process.

    Without the in-flight reservation, N concurrent publishes could each
    pass the check against the same committed usage and overshoot the quota
    N-fold. Single admin process, so an in-process lock is sufficient.
    Bytes of every kept revision count (`RepositoryUsage.total_bytes`).
    """

    def __init__(self, repo: ItemRepository, limits: PublishLimits) -> None:
        self._repo = repo
        self._limits = limits
        self._lock = threading.Lock()
        self._items = 0
        self._bytes = 0

    def reserve(self, *, new_item: bool) -> _Reservation:
        """Reserve a byte budget (and an item slot if `new_item`).

        A new revision needs no item slot but the full byte budget: bytes of
        a revision it prunes are only freed after it commits.

        Raises:
            LimitExceededError: `max_items` (new items only) or
                `max_total_bytes` is reached.
        """
        with self._lock:
            usage = self._repo.usage()
            if new_item and usage.item_count + self._items >= self._limits.max_items:
                raise LimitExceededError("item quota reached; purge or trash items first")
            left = self._limits.max_total_bytes - usage.total_bytes - self._bytes
            budget = min(self._limits.max_item_bytes, left)
            if budget <= 0:
                raise LimitExceededError("storage quota reached; purge or trash items first")
            reservation = _Reservation(items=1 if new_item else 0, budget=budget)
            self._items += reservation.items
            self._bytes += budget
            return reservation

    def release(self, reservation: _Reservation) -> None:
        """Return a reservation made by `reserve` (after commit or failure)."""
        with self._lock:
            self._items -= reservation.items
            self._bytes -= reservation.budget


class PublishService:
    """Publishes items and revisions: validates, streams + scans bytes into blobs, commits.

    Collaborators are ports (item and folder repositories, blob store, ids,
    clock, scanner, rate limiter) plus the kind registry; `monotonic` is injectable so tests
    can drive the deadline deterministically.
    """

    def __init__(
        self,
        *,
        repo: ItemRepository,
        folders: FolderRepository,
        blobs: BlobStore,
        ids: IdGenerator,
        clock: Clock,
        kinds: KindRegistry,
        scanner: ContentScanner,
        rate_limiter: RateLimiter,
        limits: PublishLimits,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._repo = repo
        self._folders = folders
        self._blobs = blobs
        self._ids = ids
        self._clock = clock
        self._kinds = kinds
        self._scanner = scanner
        self._rate_limiter = rate_limiter
        self._limits = limits
        self._monotonic = monotonic
        self._quota = _QuotaGate(repo, limits)

    def publish(self, cmd: PublishCommand) -> Item:
        """Store the command's files and commit a new ACTIVE item.

        Returns:
            The committed item. Each file's media type is the detected
            kind's `media_type(relpath)` (never client input, C8).

        Raises:
            LimitExceededError: rate limit, file count, per-file/per-item
                bytes, item or byte quota, free-disk floor, or deadline.
            InvalidPathError / ValidationError: bad relpath, title,
                description, kind hint, or manifest (duplicates, ...).
            UnsupportedContentError: kind hint unknown or incompatible.
            SecretDetectedError: content or metadata matched a secret rule.
            NotFoundError: `folder_id` names no folder (checked before any
                byte moves, and again atomically by `repo.add`).
            Any error from the ports. On every failure, blobs already
            stored for this publish are deleted before re-raising.
        """
        deadline = self._monotonic() + self._limits.timeout.total_seconds()
        # Every attempt counts, so failing publishes (probes) are rate limited too.
        self._rate_limiter.acquire()
        folder_id = self._check_folder(cmd.folder_id)
        relpaths = self._validate_files(cmd.files)
        kind = self._detect_kind(relpaths, cmd.kind_hint)
        entry_file = kind.entry_file(relpaths)
        placeholder = self._precheck_manifest(cmd, kind, relpaths, entry_file)
        self._scan_metadata(cmd, placeholder)
        self._check_free_disk()
        reservation = self._quota.reserve(new_item=True)
        stored: list[str] = []
        item: Item | None = None  # set once `repo.add` may have committed
        try:
            files = self._store_files(cmd.files, kind, reservation.budget, deadline, stored)
            self._check_deadline(deadline)
            new_item = Item.new(
                id=self._ids.new_item_id(),
                title=cmd.title,
                description=cmd.description,
                kind=kind.name,
                files=files,
                entry_file=entry_file,
                now=self._clock.now(),
                pinned=cmd.pinned,
                folder_id=folder_id,
            )
            # Last check right before commit: a publish past its deadline
            # must never commit, or the orphan sweep could race it (C11).
            self._check_deadline(deadline)
            item = new_item
            self._repo.add(item)
            return item
        except BaseException:
            # BaseException too: an interrupted publish must not leak blobs.
            self._rollback(stored, None if item is None else item.id)
            raise
        finally:
            self._quota.release(reservation)

    def publish_revision(self, cmd: RevisionCommand) -> Item:
        """Store new content for an existing ACTIVE item as its new head revision.

        Same checks as `publish` (rate limit, limits, quotas, secret scan on
        relpaths and bytes, deadline, rollback). Title, description, pin and
        id are kept. The oldest revisions beyond `MAX_REVISIONS` are pruned
        and their blobs deleted after the commit (best effort; the orphan
        sweep is the backstop). The commit is a compare-and-swap; if another
        writer changed the item meanwhile it is re-read and retried once.

        Returns:
            The committed item (head = the new revision).

        Raises:
            ValidationError / InvalidPathError: bad id, relpath, manifest,
                kind hint or `expected_revision`.
            NotFoundError: no such item (or it was purged meanwhile).
            InvalidStateError: the item is trashed.
            ConflictError: `expected_revision` is not the head revision, or
                the item changed concurrently twice in a row.
            LimitExceededError, UnsupportedContentError, SecretDetectedError:
                as for `publish`. On every failure, blobs already stored for
                this call are deleted before re-raising.
        """
        deadline = self._monotonic() + self._limits.timeout.total_seconds()
        self._rate_limiter.acquire()
        item_id = parse_item_id(cmd.item_id)
        if cmd.expected_revision is not None:
            validate_revision_number(cmd.expected_revision)
        relpaths = self._validate_files(cmd.files)
        kind = self._detect_kind(relpaths, cmd.kind_hint)
        entry_file = kind.entry_file(relpaths)
        self._precheck_revision(kind, relpaths, entry_file)
        self._scan_texts(relpaths)
        current = self._repo.get(item_id)
        _check_revisable(current, cmd.expected_revision)
        self._check_free_disk()
        reservation = self._quota.reserve(new_item=False)
        stored: list[str] = []
        try:
            files = self._store_files(cmd.files, kind, reservation.budget, deadline, stored)
            updated, pruned = self._commit_revision(
                current, cmd.expected_revision, kind, files, entry_file, deadline
            )
        except BaseException:
            # Unlike `publish`, the item already exists before this call, so
            # there is no "not yet created" state to distinguish: `_rollback`
            # can always re-read it and keep only the blobs it references.
            # This also covers `repo.save` committing and then raising (e.g.
            # the connection drops before COMMIT is acked) — the old
            # `committing`-flag version treated that as "definitely not
            # committed" and deleted the new head's blobs out from under it.
            self._rollback(stored, item_id)
            raise
        finally:
            self._quota.release(reservation)
        self._delete_pruned(updated, pruned)
        return updated

    def _commit_revision(
        self,
        current: Item,
        expected_revision: int | None,
        kind: ContentKind,
        files: Sequence[ItemFile],
        entry_file: str,
        deadline: float,
    ) -> tuple[Item, tuple[Revision, ...]]:
        """Compare-and-swap the new head in; re-read and retry once on a conflict.

        Deadline-checked right before each save (never commit late, C11).
        A save that raised may still have committed; the caller's rollback
        checks the stored item before deleting anything.
        """
        for attempt in range(2):
            updated, pruned = current.with_revision(
                kind=kind.name,
                files=files,
                entry_file=entry_file,
                at=current.next_change_at(self._clock.now()),
            )
            self._check_deadline(deadline)
            try:
                self._repo.save(updated, expected_updated_at=current.updated_at)
            except ConflictError:
                if attempt:
                    raise
                # An edit/pin/trash landed meanwhile: re-check against the new state.
                current = self._repo.get(current.id)
                _check_revisable(current, expected_revision)
                continue
            return updated, pruned
        raise AssertionError("unreachable")  # pragma: no cover

    def _delete_pruned(self, item: Item, pruned: Sequence[Revision]) -> None:
        """Delete the blobs of revisions the committed `item` no longer keeps."""
        keep = {f.blob_id for f in item.all_files}
        for revision in pruned:
            for f in revision.files:
                if f.blob_id in keep:  # pragma: no cover - the domain forbids shared blobs
                    continue
                try:
                    self._blobs.delete(f.blob_id)
                except Exception:  # committed already; the orphan sweep is the backstop
                    _log.warning("revision prune: could not delete blob %s", f.blob_id)

    # --- validation ------------------------------------------------------------

    def _check_folder(self, raw: str | None) -> FolderId | None:
        """Validate the target folder up front, so a typo fails before any byte moves.

        Only a fast path: the folder may still be deleted before the commit,
        which `repo.add` then refuses atomically (C41) and the rollback cleans up.
        """
        if raw is None:
            return None
        folder_id = parse_folder_id(raw)
        self._folders.get(folder_id)
        return folder_id

    def _validate_files(self, files: Sequence[IncomingFile]) -> list[str]:
        if len(files) > self._limits.max_files:
            raise LimitExceededError(f"too many files (max {self._limits.max_files})")
        return [validate_relpath(f.relpath) for f in files]

    def _detect_kind(self, relpaths: Sequence[str], hint: str | None) -> ContentKind:
        if hint is not None:
            # Syntax first: an arbitrary (long) hint is never echoed in errors.
            validate_kind(hint)
        return self._kinds.detect(relpaths, hint)

    def _precheck_manifest(
        self, cmd: PublishCommand, kind: ContentKind, relpaths: Sequence[str], entry_file: str
    ) -> Item:
        """Run the real Item invariants on placeholders before storing any byte.

        Catches bad titles, duplicate (caseless) paths, file/dir clashes and
        an empty file list up front, instead of after streaming everything.

        Returns:
            The placeholder item, whose title/description are the sanitized
            values the real item will store.
        """
        return Item.new(
            id=ItemId(_PLACEHOLDER_ID),
            title=cmd.title,
            description=cmd.description,
            kind=kind.name,
            files=_placeholders(relpaths),
            entry_file=entry_file,
            now=self._clock.now(),
            pinned=cmd.pinned,
        )

    def _precheck_revision(
        self, kind: ContentKind, relpaths: Sequence[str], entry_file: str
    ) -> None:
        """Vet the new manifest (duplicates, file/dir clashes) before storing any byte."""
        Revision(
            number=1,
            kind=kind.name,
            files=tuple(_placeholders(relpaths)),
            entry_file=entry_file,
            created_at=self._clock.now(),
        )

    def _scan_metadata(self, cmd: PublishCommand, placeholder: Item) -> None:
        """Inline fields are published content too (ADR 0008): scan them.

        Both forms are scanned: the raw text (what the publisher sent) and
        the sanitized text (what is stored and shown). Sanitizing removes
        invisible chars and NFC-normalizes, so a token split by a ZWSP or
        spelled with a compatibility char (Kelvin sign) only matches after.
        """
        self._scan_texts(
            (
                cmd.title,
                cmd.description,
                placeholder.title,
                placeholder.description,
                *(f.relpath for f in placeholder.files),
            )
        )

    def _scan_texts(self, texts: Iterable[str]) -> None:
        session = self._scanner.new_session()
        for text in texts:
            # surrogatepass: raw text may hold lone surrogates; the scan must not crash.
            session.feed(text.encode("utf-8", "surrogatepass") + b"\n")
        session.finish()

    def _check_free_disk(self) -> None:
        if self._blobs.free_bytes() <= self._limits.min_free_disk_bytes:
            raise LimitExceededError("not enough free disk space")

    def _check_deadline(self, deadline: float) -> None:
        if self._monotonic() > deadline:
            raise _DeadlineExceededError("publish timed out")

    # --- streaming ---------------------------------------------------------------

    def _store_files(
        self,
        files: Sequence[IncomingFile],
        kind: ContentKind,
        budget: int,
        deadline: float,
        stored: list[str],
    ) -> list[ItemFile]:
        """Stream every file into the blob store; append each blob id to `stored`."""
        result: list[ItemFile] = []
        used = 0
        for incoming in files:
            disk_left = self._blobs.free_bytes() - self._limits.min_free_disk_bytes
            max_bytes = max(0, min(self._limits.max_file_bytes, budget - used, disk_left))
            session = self._scanner.new_session()
            try:
                ref = self._blobs.put(
                    self._guarded(incoming.chunks, session, deadline), max_bytes=max_bytes
                )
                stored.append(ref.blob_id)
                session.finish()
            except SecretDetectedError as exc:
                raise SecretDetectedError(exc.rule, incoming.relpath) from None
            except _DeadlineExceededError:
                raise
            except LimitExceededError:
                raise LimitExceededError(
                    f"file {incoming.relpath!r} is over the {max_bytes}-byte budget left for it "
                    "(per-file limit, per-item limit, storage quota or free-disk floor)"
                ) from None
            used += ref.size
            # Type comes from the item's kind, never per-file lookup (C8).
            result.append(
                ItemFile.from_blob(incoming.relpath, ref, kind.media_type(incoming.relpath))
            )
        return result

    def _guarded(
        self, chunks: Iterable[bytes], session: ScanSession, deadline: float
    ) -> Iterator[bytes]:
        """Yield chunks after the deadline check and the secret scan see them."""
        for chunk in chunks:
            self._check_deadline(deadline)
            if chunk:
                session.feed(chunk)
                yield chunk

    def _rollback(self, blob_ids: Sequence[str], committed_id: ItemId | None) -> None:
        """Best-effort delete of this call's blobs; never masks the original error.

        Once `repo.add`/`repo.save` was entered (`committed_id` set) the row
        may have committed even though the call raised (e.g. commit
        succeeded, then the connection failed), and deleting its blobs would
        leave a dangling row. So only blobs provably unreferenced by the
        stored item are deleted: all of them if `get` says NotFound, those
        not in any kept revision if the item exists, and none if `get`
        itself fails. Anything left behind is unreferenced and removed by
        the orphan sweep (C11).
        """
        if committed_id is not None:
            try:
                stored = self._repo.get(committed_id)
            except NotFoundError:
                pass  # provably not committed: delete everything
            except Exception:  # can't tell; keeping is safe, the sweep is the backstop
                _log.warning("publish rollback: commit state unknown; blobs left to the sweep")
                return
            else:
                referenced = {f.blob_id for f in stored.all_files}
                blob_ids = [b for b in blob_ids if b not in referenced]
        for blob_id in blob_ids:
            try:
                self._blobs.delete(blob_id)
            except Exception:  # rollback must go on; the orphan sweep is the backstop
                _log.warning("publish rollback: could not delete blob %s", blob_id)


def _placeholders(relpaths: Sequence[str]) -> list[ItemFile]:
    """Placeholder files (distinct blob ids) so domain constructors can vet a manifest."""
    return [
        ItemFile(
            relpath=p,
            blob_id=f"{index:026d}",
            size=0,
            sha256=_PLACEHOLDER_SHA,
            media_type=_PLACEHOLDER_TYPE,
        )
        for index, p in enumerate(relpaths)
    ]


def _check_revisable(item: Item, expected_revision: int | None) -> None:
    """Raise unless `item` may get a new revision now.

    Raises:
        InvalidStateError: the item is trashed.
        ConflictError: `expected_revision` is set and is not the head.
    """
    if item.state is not ItemState.ACTIVE:
        # Same error the domain transition raises; checked early to fail fast.
        raise InvalidStateError("trashed items cannot be updated")
    if expected_revision is not None and item.revision != expected_revision:
        raise ConflictError(
            f"item is at revision {item.revision}, not {expected_revision}; re-read and retry"
        )
