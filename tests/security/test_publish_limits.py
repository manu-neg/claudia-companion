"""Security tests for publish limits, quotas, rate limit and deadline (docs/security.md C18, C11).

Every limit is enforced on the bytes actually streamed (there is no
declared size to lie about), fails closed, and leaves nothing behind.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest

from preview_dashboard.application import IncomingFile
from preview_dashboard.domain.errors import LimitExceededError
from tests.app_support import PublishHarness, command, incoming, make_publish
from tests.builders import make_file, make_item

pytestmark = pytest.mark.security


def _assert_nothing_left(h: PublishHarness, *, items: int = 0) -> None:
    assert h.repo.count() == items
    # No stored blob may be unreferenced (seeded items may reference none).
    assert h.blobs.list_ids() <= h.repo.all_blob_ids()


# --- per-file / per-item / count --------------------------------------------------


def test_per_file_limit_boundary() -> None:
    h = make_publish()
    h.service.publish(command(incoming("ok.bin", b"a" * 1_000)))
    with pytest.raises(LimitExceededError, match="budget"):
        h.service.publish(command(incoming("big.bin", b"a" * 1_001, chunk=100)))
    _assert_nothing_left(h, items=1)


def test_per_file_limit_counts_streamed_bytes_not_chunk_count() -> None:
    # Many tiny chunks must add up exactly like one big one.
    h = make_publish()
    with pytest.raises(LimitExceededError):
        h.service.publish(command(incoming("big.bin", b"a" * 1_001, chunk=1)))
    _assert_nothing_left(h)


def test_per_item_limit_spans_files() -> None:
    h = make_publish()  # 1000/file, 3000/item
    three = [incoming(f"{n}.bin", b"a" * 1_000) for n in range(3)]
    h.service.publish(command(*three))
    four = [incoming(f"{n}.bin", b"a" * 1_000) for n in range(3)] + [incoming("x.bin", b"a")]
    with pytest.raises(LimitExceededError):
        h.service.publish(command(*four))
    _assert_nothing_left(h, items=1)


def test_file_count_limit_boundary() -> None:
    h = make_publish()  # max_files 10
    h.service.publish(command(*(incoming(f"{n}.txt") for n in range(10))))
    with pytest.raises(LimitExceededError, match="too many files"):
        h.service.publish(command(*(incoming(f"{n}.txt") for n in range(11))))
    _assert_nothing_left(h, items=1)


# --- global quotas ------------------------------------------------------------------


def test_item_quota_counts_trashed_items() -> None:
    h = make_publish(max_items=2)
    h.repo.add(make_item(90))
    h.repo.add(make_item(91).trashed(make_item(91).created_at))
    with pytest.raises(LimitExceededError, match="item quota"):
        h.service.publish(command(incoming("a.txt")))
    _assert_nothing_left(h, items=2)


def test_total_bytes_quota_shrinks_item_budget() -> None:
    h = make_publish(max_total_bytes=5_000)
    h.repo.add(make_item(90, files=(make_file(blob=1, size=4_500),)))
    h.service.publish(command(incoming("a.bin", b"a" * 500)))
    with pytest.raises(LimitExceededError, match="storage quota"):
        h.service.publish(command(incoming("b.bin", b"b")))


def test_total_bytes_quota_rejects_partial_overflow() -> None:
    h = make_publish(max_total_bytes=5_000)
    h.repo.add(make_item(90, files=(make_file(blob=1, size=4_500),)))
    with pytest.raises(LimitExceededError, match="budget"):
        h.service.publish(command(incoming("a.bin", b"a" * 501)))
    _assert_nothing_left(h, items=1)


def test_free_disk_floor_refuses_publish_up_front() -> None:
    h = make_publish(capacity=100)  # free == floor (100)
    with pytest.raises(LimitExceededError, match="free disk"):
        h.service.publish(command(incoming("a.txt")))
    _assert_nothing_left(h)


def test_free_disk_floor_caps_each_file() -> None:
    h = make_publish(capacity=600)  # 500 bytes usable above the 100-byte floor
    h.service.publish(command(incoming("a.bin", b"a" * 300)))
    with pytest.raises(LimitExceededError):
        h.service.publish(command(incoming("b.bin", b"b" * 201)))
    assert h.blobs.free_bytes() >= h.limits.min_free_disk_bytes
    _assert_nothing_left(h, items=1)


# --- rate limit ---------------------------------------------------------------------


def test_publish_rate_limit_sliding_window() -> None:
    h = make_publish(rate=3, max_items=100)
    for n in range(3):
        h.service.publish(command(incoming(f"{n}.txt")))
    with pytest.raises(LimitExceededError, match="rate limit"):
        h.service.publish(command(incoming("x.txt")))
    # The window runs on the monotonic clock; wall-clock jumps don't matter.
    h.clock.advance(timedelta(days=1))
    h.mono.advance(59 * 60)
    with pytest.raises(LimitExceededError, match="rate limit"):
        h.service.publish(command(incoming("x.txt")))
    h.mono.advance(61)
    h.service.publish(command(incoming("x.txt")))


def test_failed_publishes_count_toward_rate_limit() -> None:
    h = make_publish(rate=2)
    for _ in range(2):
        with pytest.raises(LimitExceededError):
            h.service.publish(command(incoming("big.bin", b"a" * 1_001)))
    with pytest.raises(LimitExceededError, match="rate limit"):
        h.service.publish(command(incoming("ok.txt")))


# --- hard deadline (C11: a late publish must never commit) ---------------------------


def test_deadline_between_chunks_aborts_and_rolls_back() -> None:
    h = make_publish()

    def slow() -> Iterator[bytes]:
        yield b"a"
        h.mono.advance(61)
        yield b"b"

    with pytest.raises(LimitExceededError, match="timed out"):
        h.service.publish(command(incoming("first.txt"), IncomingFile("slow.txt", slow())))
    _assert_nothing_left(h)


def test_deadline_passed_after_last_byte_never_commits() -> None:
    h = make_publish()

    def slow_tail() -> Iterator[bytes]:
        yield b"a"
        h.mono.advance(61)  # deadline passes after the final chunk

    with pytest.raises(LimitExceededError, match="timed out"):
        h.service.publish(command(IncomingFile("a.txt", slow_tail())))
    _assert_nothing_left(h)


def test_deadline_boundary_is_inclusive() -> None:
    h = make_publish()

    def exactly() -> Iterator[bytes]:
        h.mono.advance(60)
        yield b"a"

    h.service.publish(command(IncomingFile("a.txt", exactly())))
    assert h.repo.count() == 1
