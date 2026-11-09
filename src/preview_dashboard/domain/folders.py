"""Folders: FolderId, the Folder entity, folder-name rules and the listing filter.

One level of folders (ADR 0027): each item sits in at most one folder, or is
"unfiled". Names are untrusted display text (the title rules, 1..80 chars),
unique under compatibility caseless matching. Pure stdlib, like every domain
module.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Final, NewType

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import ensure_utc, is_ulid
from preview_dashboard.domain.text import sanitize_line
from preview_dashboard.domain.unicode import caseless_key

FolderId = NewType("FolderId", str)
"""Canonical ULID string (26 chars, Crockford base32, uppercase)."""

FOLDER_NAME_MAX_CHARS = 80
# Owner decision (backlog 6): a quota, like C18's item quota, so a
# prompt-injected publisher cannot flood the desktop with folder icons.
MAX_FOLDERS = 200
_ONE_US = timedelta(microseconds=1)


def parse_folder_id(raw: object) -> FolderId:
    """Validate an untrusted value as a FolderId.

    Raises:
        ValidationError: if `raw` is not a canonical ULID string.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid folder id")
    return FolderId(str(raw))


def sanitize_folder_name(raw: str) -> str:
    """Return a clean folder name: the title rules (`sanitize_line`) with an 80-char limit.

    Raises:
        ValidationError: see `domain.text.sanitize_line`.
    """
    return sanitize_line(raw, name="folder name", max_chars=FOLDER_NAME_MAX_CHARS)


def folder_name_key(name: str) -> str:
    """Uniqueness key of a (sanitized) folder name: its compatibility caseless key.

    'Plans', 'PLANS' and a fullwidth-letter 'Plans' share one key, so the
    owner never sees two folders that read the same.
    """
    return caseless_key(name)


class Unfiled(Enum):
    """Type of the `UNFILED` sentinel: "items in no folder" in a listing filter."""

    UNFILED = "unfiled"


UNFILED: Final = Unfiled.UNFILED
"""Filter value for items without a folder (distinct from None = no filter)."""

FolderFilter = FolderId | Unfiled
"""A listing restricted to one folder, or to unfiled items."""


def parse_folder_filter(raw: str) -> FolderFilter:
    """Parse an untrusted filter value: the literal `unfiled` or a folder id.

    Raises:
        ValidationError: anything else (case matters: `Unfiled` is refused).
    """
    if raw == UNFILED.value:
        return UNFILED
    return parse_folder_id(raw)


@dataclass(frozen=True, slots=True, kw_only=True)
class Folder:
    """A named folder items can be filed in (ADR 0027).

    Invariants (checked on construction, `ValidationError`):
    - `id` is a canonical ULID;
    - `name` is sanitized display text (`sanitize_folder_name`), 1..80 chars
      with a visible character;
    - datetimes are tz-aware (stored as UTC), `updated_at >= created_at`.
    """

    id: FolderId
    name: str
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        parse_folder_id(self.id)
        # Frozen dataclass: normalization must bypass the frozen __setattr__.
        object.__setattr__(self, "name", sanitize_folder_name(self.name))
        object.__setattr__(self, "created_at", ensure_utc(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", ensure_utc(self.updated_at, "updated_at"))
        if self.updated_at < self.created_at:
            raise ValidationError("updated_at must not precede created_at")

    @classmethod
    def new(cls, *, id: FolderId, name: str, now: datetime) -> Folder:  # id: mirrors the field
        """Create a folder with `created_at == updated_at == now`."""
        return cls(id=id, name=name, created_at=now, updated_at=now)

    @property
    def name_key(self) -> str:
        """Uniqueness key of the name (see `folder_name_key`)."""
        return folder_name_key(self.name)

    def next_change_at(self, now: datetime) -> datetime:
        """`now`, but strictly after `updated_at` (clock steps back are clamped).

        Raises:
            ValidationError: `now` is naive, or `updated_at` is at `datetime.max`.
        """
        try:
            return max(ensure_utc(now, "now"), self.updated_at + _ONE_US)
        except OverflowError:
            raise ValidationError("folder timestamp is out of range") from None

    def renamed(self, name: str, *, at: datetime) -> Folder:
        """Return this folder with a new name, changed at `at`.

        Raises:
            ValidationError: invalid name, or `at` precedes `updated_at`.
        """
        if ensure_utc(at, "at") < self.updated_at:
            raise ValidationError("rename time must not precede updated_at")
        return dataclasses.replace(self, name=name, updated_at=at)
