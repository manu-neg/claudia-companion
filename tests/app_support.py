"""Test harness for application services: wires every service to in-memory fakes.

Shared by `tests/unit/test_*` and `tests/security/test_*` for the unit-4
services, so each test only spells out the limits/collaborators it cares
about. Also provides a controllable monotonic clock and publish helpers.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from preview_dashboard.application import (
    IncomingFile,
    PublishCommand,
    PublishLimits,
    PublishService,
    SlidingWindowRateLimiter,
)
from preview_dashboard.kinds import default_registry
from preview_dashboard.ports.scanner import ContentScanner
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryBlobStore,
    InMemoryFolderRepository,
    InMemoryItemRepository,
    SequentialIdGenerator,
)

DEFAULT_LIMITS: dict[str, Any] = {
    "max_files": 10,
    "max_file_bytes": 1_000,
    "max_item_bytes": 3_000,
    "max_total_bytes": 10_000,
    "max_items": 5,
    "min_free_disk_bytes": 100,
    "timeout": timedelta(seconds=60),
}


class FakeMonotonic:
    """Monotonic seconds counter that only moves when told to."""

    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass
class PublishHarness:
    """A PublishService plus direct handles on its fakes."""

    service: PublishService
    repo: InMemoryItemRepository
    blobs: InMemoryBlobStore
    clock: FixedClock
    scanner: ContentScanner
    mono: FakeMonotonic
    limits: PublishLimits
    folders: InMemoryFolderRepository = field(default_factory=InMemoryFolderRepository)
    extra: dict[str, Any] = field(default_factory=dict)


def make_publish(
    *,
    rate: int = 1_000,
    capacity: int = 1_000_000,
    scanner: ContentScanner | None = None,
    repo: Any = None,  # Any: tests pass failure-injecting wrappers
    blobs: Any = None,
    **limit_overrides: Any,
) -> PublishHarness:
    """Build a PublishService over fakes; `limit_overrides` patch DEFAULT_LIMITS."""
    clock = FixedClock()
    mono = FakeMonotonic()
    limits = PublishLimits(**{**DEFAULT_LIMITS, **limit_overrides})
    real_repo = repo if repo is not None else InMemoryItemRepository()
    real_blobs = (
        blobs if blobs is not None else InMemoryBlobStore(capacity_bytes=capacity, clock=clock)
    )
    real_scanner = scanner if scanner is not None else FakeContentScanner()
    # Wrapped repos (failure injection) get a folder store of their own.
    folders = InMemoryFolderRepository(
        real_repo if isinstance(real_repo, InMemoryItemRepository) else None
    )
    service = PublishService(
        repo=real_repo,
        folders=folders,
        blobs=real_blobs,
        ids=SequentialIdGenerator(),
        clock=clock,
        kinds=default_registry(),
        scanner=real_scanner,
        rate_limiter=SlidingWindowRateLimiter(
            limit=rate, window=timedelta(hours=1), monotonic=mono
        ),
        limits=limits,
        monotonic=mono,
    )
    return PublishHarness(
        service=service,
        repo=real_repo,
        blobs=real_blobs,
        clock=clock,
        scanner=real_scanner,
        mono=mono,
        limits=limits,
        folders=folders,
    )


def incoming(relpath: str, data: bytes = b"x", *, chunk: int | None = None) -> IncomingFile:
    """An IncomingFile whose bytes arrive in `chunk`-sized pieces (default: one)."""
    return IncomingFile(relpath=relpath, chunks=split(data, chunk))


def split(data: bytes, chunk: int | None) -> list[bytes]:
    """Split `data` into `chunk`-sized pieces (one piece if `chunk` is None)."""
    if chunk is None:
        return [data]
    return [data[i : i + chunk] for i in range(0, len(data), chunk)]


def command(*files: IncomingFile, title: str = "A title", **kwargs: Any) -> PublishCommand:
    """A PublishCommand with sensible defaults."""
    return PublishCommand(title=title, files=list(files), **kwargs)


class TrackingIterable:
    """Iterable of chunks that records whether anyone started consuming it."""

    def __init__(self, chunks: Iterable[bytes]) -> None:
        self._chunks = list(chunks)
        self.consumed = False

    def __iter__(self) -> Iterator[bytes]:
        self.consumed = True
        return iter(self._chunks)
