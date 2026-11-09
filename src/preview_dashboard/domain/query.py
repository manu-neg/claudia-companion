"""Item listing: query value object, result page, ordering rule and cursors.

Ordering rule (every adapter must match it exactly): pinned first, then
`created_at` descending, then `id` descending. Pagination is keyset-based:
the opaque cursor encodes the sort key of the last item on the page.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.folders import FolderFilter, FolderId, Unfiled
from preview_dashboard.domain.models import Item, ItemState, is_ulid, validate_kind

DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200
MAX_QUERY_KINDS = 8
"""Most kinds one listing may filter by (bounds the SQL `IN (...)` list)."""

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_US = timedelta(microseconds=1)
_CURSOR_RE = re.compile(r"v1:([01]):(-?[0-9]{1,20}):([0-9A-Z]{26})")
_MAX_CURSOR_CHARS = 128

# Range of `created_us` values that map back to a datetime. Cursors are
# untrusted: anything outside would raise OverflowError in an adapter that
# converts it (`EPOCH + timedelta(microseconds=...)`) or overflow SQLite's
# 64-bit INTEGER, so decoding rejects it up front.
MIN_CREATED_US = (datetime.min.replace(tzinfo=UTC) - _EPOCH) // _ONE_US
MAX_CREATED_US = (datetime.max.replace(tzinfo=UTC) - _EPOCH) // _ONE_US

SortKey = tuple[int, int, str]
"""(pinned as 0/1, created_at in epoch microseconds, id); listed in descending order."""


def item_sort_key(item: Item) -> SortKey:
    """Return the key that orders `item` in listings (sort descending)."""
    return (int(item.pinned), (item.created_at - _EPOCH) // _ONE_US, item.id)


def created_us_to_datetime(created_us: int) -> datetime:
    """Convert epoch microseconds (as in `SortKey`) back to a UTC datetime.

    Raises:
        ValidationError: if the value is outside the datetime-representable range.
    """
    if (
        not isinstance(created_us, int)
        or isinstance(created_us, bool)
        or not MIN_CREATED_US <= created_us <= MAX_CREATED_US
    ):
        raise ValidationError("timestamp out of range")
    return _EPOCH + timedelta(microseconds=created_us)


def encode_cursor(key: SortKey) -> str:
    """Encode a sort key as an opaque, URL-safe cursor string."""
    pinned, created_us, item_id = key
    raw = f"v1:{pinned}:{created_us}:{item_id}".encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> SortKey:
    """Decode a cursor produced by `encode_cursor`.

    Cursors come from untrusted clients, so decoding is strict and only the
    canonical encoding is accepted (it must round-trip exactly). The decoded
    `created_us` is always within `MIN_CREATED_US..MAX_CREATED_US`, so
    `created_us_to_datetime` on it cannot overflow.

    Raises:
        ValidationError: if the cursor is malformed.
    """
    if not isinstance(cursor, str) or not 0 < len(cursor) <= _MAX_CURSOR_CHARS:
        raise ValidationError("invalid cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        text = base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii")
    except (binascii.Error, UnicodeError, ValueError):
        raise ValidationError("invalid cursor") from None
    match = _CURSOR_RE.fullmatch(text)
    if match is None or not is_ulid(match.group(3)):
        raise ValidationError("invalid cursor")
    key: SortKey = (int(match.group(1)), int(match.group(2)), match.group(3))
    if not MIN_CREATED_US <= key[1] <= MAX_CREATED_US:
        raise ValidationError("invalid cursor")
    if encode_cursor(key) != cursor:
        raise ValidationError("invalid cursor")
    return key


@dataclass(frozen=True, slots=True, kw_only=True)
class ItemQuery:
    """Filter + page request for listing items.

    Attributes:
        kind: only items of this kind, or None (single-kind shorthand; the
            MCP tool and admin API use it).
        kinds: only items of any of these kinds; empty = all kinds. After
            construction it is the canonical filter (sorted, deduplicated;
            `kind` folded in), so adapters read `kinds` only.
        state: ACTIVE (the feed) or TRASHED (the trash view).
        limit: page size, 1..MAX_PAGE_LIMIT.
        cursor: opaque `Page.next_cursor` from the previous page, or None.
        folder: None = every item; a `FolderId` = only items filed there;
            `UNFILED` = only items in no folder (ADR 0027). Same ordering
            and cursors as an unfiltered listing.

    Raises (on construction):
        ValidationError: bad kind, state, limit, cursor or folder; both
            `kind` and `kinds` given; more than `MAX_QUERY_KINDS` kinds.
    """

    kind: str | None = None
    kinds: tuple[str, ...] = ()
    state: ItemState = ItemState.ACTIVE
    limit: int = DEFAULT_PAGE_LIMIT
    cursor: str | None = None
    folder: FolderFilter | None = None

    def __post_init__(self) -> None:
        self._normalize_kinds()
        if self.folder is not None and not (
            isinstance(self.folder, Unfiled) or is_ulid(self.folder)
        ):
            raise ValidationError("invalid folder filter")
        if not isinstance(self.state, ItemState):
            raise ValidationError("invalid state")
        if (
            not isinstance(self.limit, int)
            or isinstance(self.limit, bool)
            or not 1 <= self.limit <= MAX_PAGE_LIMIT
        ):
            raise ValidationError(f"limit must be 1..{MAX_PAGE_LIMIT}")
        if self.cursor is not None:
            decode_cursor(self.cursor)

    def _normalize_kinds(self) -> None:
        if not isinstance(self.kinds, tuple):
            raise ValidationError("invalid kinds")
        if self.kind is not None:
            if self.kinds:
                raise ValidationError("give kind or kinds, not both")
            raw: tuple[str, ...] = (self.kind,)
        else:
            raw = self.kinds
        # Checked before deduplication: an oversized request fails closed
        # instead of being trimmed.
        if len(raw) > MAX_QUERY_KINDS:
            raise ValidationError(f"at most {MAX_QUERY_KINDS} kinds")
        for kind in raw:
            validate_kind(kind)
        # Canonical form (frozen dataclass: set once, here) so equal filters
        # compare equal and adapters see one spelling.
        object.__setattr__(self, "kinds", tuple(sorted(set(raw))))

    @property
    def after(self) -> SortKey | None:
        """Decoded cursor: only items whose sort key is strictly below this."""
        return None if self.cursor is None else decode_cursor(self.cursor)

    def matches(self, item: Item) -> bool:
        """True if `item` passes the kind/state/folder filter (ignores the cursor)."""
        return (
            item.state is self.state
            and (not self.kinds or item.kind in self.kinds)
            and (self.folder is None or item.folder_id == self.folder_id)
        )

    @property
    def folder_id(self) -> FolderId | None:
        """The folder id items must carry when `folder` is set (None for `UNFILED`)."""
        return None if self.folder is None or isinstance(self.folder, Unfiled) else self.folder


@dataclass(frozen=True, slots=True)
class Page[T]:
    """One page of results; `next_cursor` is None on the last page."""

    items: tuple[T, ...]
    next_cursor: str | None = None


def paginate(items: Iterable[Item], query: ItemQuery) -> Page[Item]:
    """Reference implementation of filtering, ordering and keyset paging.

    Used by in-memory adapters; SQL adapters implement the same rule in SQL
    and are held to it by the shared repository contract tests.
    """
    after = query.after
    selected = sorted(
        (i for i in items if query.matches(i) and (after is None or item_sort_key(i) < after)),
        key=item_sort_key,
        reverse=True,
    )
    page = tuple(selected[: query.limit])
    has_more = len(selected) > query.limit
    next_cursor = encode_cursor(item_sort_key(page[-1])) if has_more else None
    return Page(items=page, next_cursor=next_cursor)
