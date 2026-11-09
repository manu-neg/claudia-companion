"""Unit tests for listing queries: ItemQuery validation, cursors, reference paginate()."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import ItemState
from preview_dashboard.domain.query import (
    DEFAULT_PAGE_LIMIT,
    MAX_CREATED_US,
    MAX_PAGE_LIMIT,
    MAX_QUERY_KINDS,
    MIN_CREATED_US,
    ItemQuery,
    Page,
    created_us_to_datetime,
    decode_cursor,
    encode_cursor,
    item_sort_key,
    paginate,
)
from tests.builders import T0, make_item, ulid

pytestmark = pytest.mark.unit


def test_query_defaults() -> None:
    q = ItemQuery()
    assert (q.kind, q.state, q.limit, q.cursor, q.after) == (
        None,
        ItemState.ACTIVE,
        DEFAULT_PAGE_LIMIT,
        None,
        None,
    )


@pytest.mark.parametrize("limit", [0, -1, MAX_PAGE_LIMIT + 1, True])
def test_query_rejects_bad_limit(limit: int) -> None:
    with pytest.raises(ValidationError):
        ItemQuery(limit=limit)


def test_query_limit_boundaries() -> None:
    assert ItemQuery(limit=1).limit == 1
    assert ItemQuery(limit=MAX_PAGE_LIMIT).limit == MAX_PAGE_LIMIT


def test_query_rejects_bad_kind_and_state() -> None:
    with pytest.raises(ValidationError):
        ItemQuery(kind="Bad Kind")
    with pytest.raises(ValidationError):
        ItemQuery(state="active")  # type: ignore[arg-type]


def test_query_kind_folds_into_kinds() -> None:
    assert ItemQuery().kinds == ()
    q = ItemQuery(kind="image")
    assert (q.kind, q.kinds) == ("image", ("image",))


def test_query_kinds_are_sorted_and_deduplicated() -> None:
    q = ItemQuery(kinds=("progress", "html", "progress"))
    assert q.kinds == ("html", "progress")
    assert q == ItemQuery(kinds=("html", "progress"))


def test_query_kinds_maximum() -> None:
    names = tuple(f"k{n}" for n in range(MAX_QUERY_KINDS))
    assert len(ItemQuery(kinds=names).kinds) == MAX_QUERY_KINDS
    with pytest.raises(ValidationError):
        ItemQuery(kinds=(*names, "one-more"))
    # The count is checked before deduplication: oversized input fails closed.
    with pytest.raises(ValidationError):
        ItemQuery(kinds=("html",) * (MAX_QUERY_KINDS + 1))


@pytest.mark.parametrize(
    "kinds",
    [("html", "Bad Kind"), ("",), ("html", "x" * 33), ["html"], "html", ("html", 1)],
)
def test_query_rejects_bad_kinds(kinds: object) -> None:
    with pytest.raises(ValidationError):
        ItemQuery(kinds=kinds)  # type: ignore[arg-type]


def test_query_rejects_kind_and_kinds_together() -> None:
    with pytest.raises(ValidationError):
        ItemQuery(kind="html", kinds=("progress",))


def test_sort_key() -> None:
    at = T0 + timedelta(microseconds=5)
    item = make_item(1, pinned=True, created_at=at, updated_at=at)
    pinned, created_us, item_id = item_sort_key(item)
    assert pinned == 1
    assert created_us == int(T0.timestamp()) * 1_000_000 + 5
    assert item_id == ulid(1)


def test_cursor_round_trip_and_query_after() -> None:
    key = (1, 1_767_268_800_000_000, ulid(7))
    cursor = encode_cursor(key)
    assert decode_cursor(cursor) == key
    assert ItemQuery(cursor=cursor).after == key
    assert "=" not in cursor


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    "cursor",
    [
        "",
        "!!!",
        "x" * 200,
        _b64("v2:1:5:" + ulid(1)),
        _b64("v1:2:5:" + ulid(1)),
        _b64("v1:1:abc:" + ulid(1)),
        _b64("v1:1:5:01arz3ndektsv4rrffq69g5fav"),  # lowercase id
        _b64("v1:1:5:" + "8" + "0" * 25),
        _b64("v1:1:5:" + ulid(1)) + "==",  # non-canonical padding
        _b64("v1:1:05:" + ulid(1)),  # non-canonical number
        _b64("v1:1:5:" + ulid(1) + "\n"),
    ],
)
def test_malformed_cursors_are_rejected(cursor: str) -> None:
    with pytest.raises(ValidationError):
        decode_cursor(cursor)
    with pytest.raises(ValidationError):
        ItemQuery(cursor=cursor)


@given(st.text(max_size=150))
def test_decode_cursor_only_raises_validation_error(raw: str) -> None:
    try:
        key = decode_cursor(raw)
    except ValidationError:
        return
    assert encode_cursor(key) == raw


def test_paginate_orders_and_pages() -> None:
    h = timedelta(hours=1)
    items = [
        make_item(1, created_at=T0, updated_at=T0),
        make_item(2, created_at=T0 + h, updated_at=T0 + h),
        make_item(3, created_at=T0 + h, updated_at=T0 + h),
        make_item(4, pinned=True, created_at=T0 - h, updated_at=T0 - h),
    ]
    first = paginate(items, ItemQuery(limit=3))
    assert [i.id for i in first.items] == [ulid(4), ulid(3), ulid(2)]
    assert first.next_cursor == encode_cursor(item_sort_key(first.items[-1]))
    second = paginate(items, ItemQuery(limit=3, cursor=first.next_cursor))
    assert second == Page(items=(items[0],), next_cursor=None)


def test_paginate_filters() -> None:
    items = [make_item(1, kind="image"), make_item(2).trashed(T0), make_item(3)]
    assert [i.id for i in paginate(items, ItemQuery()).items] == [ulid(3), ulid(1)]
    assert [i.id for i in paginate(items, ItemQuery(kind="image")).items] == [ulid(1)]
    both = paginate(items, ItemQuery(kinds=("image", "html")))
    assert [i.id for i in both.items] == [ulid(3), ulid(1)]
    trashed = paginate(items, ItemQuery(state=ItemState.TRASHED))
    assert [i.id for i in trashed.items] == [ulid(2)]


def test_paginate_empty() -> None:
    assert paginate([], ItemQuery()) == Page(items=())


# --- created_us bounds: no OverflowError may escape from an untrusted cursor ----


@pytest.mark.parametrize(
    "created_us",
    [MIN_CREATED_US - 1, MAX_CREATED_US + 1, 10**19, -(10**19), 99_999_999_999_999_999_999],
)
def test_cursor_with_unrepresentable_timestamp_is_rejected(created_us: int) -> None:
    cursor = _b64(f"v1:0:{created_us}:{ulid(1)}")
    with pytest.raises(ValidationError):
        decode_cursor(cursor)
    with pytest.raises(ValidationError):
        ItemQuery(cursor=cursor)


@pytest.mark.parametrize("created_us", [MIN_CREATED_US, 0, MAX_CREATED_US])
def test_cursor_timestamp_bounds_are_inclusive(created_us: int) -> None:
    key = (0, created_us, ulid(1))
    assert decode_cursor(encode_cursor(key)) == key
    assert created_us_to_datetime(created_us).tzinfo == UTC


def test_created_us_to_datetime() -> None:
    assert created_us_to_datetime(0) == datetime(1970, 1, 1, tzinfo=UTC)
    assert created_us_to_datetime(MAX_CREATED_US) == datetime.max.replace(tzinfo=UTC)
    at = T0 + timedelta(microseconds=3)
    item = make_item(1, created_at=at, updated_at=at)
    assert created_us_to_datetime(item_sort_key(item)[1]) == item.created_at
    for bad in (MAX_CREATED_US + 1, MIN_CREATED_US - 1, True, 1.0):
        with pytest.raises(ValidationError):
            created_us_to_datetime(bad)  # type: ignore[arg-type]


@given(st.integers(min_value=-(10**20) + 1, max_value=10**20 - 1))
def test_decoded_cursor_timestamp_always_converts(created_us: int) -> None:
    try:
        _, decoded, _ = decode_cursor(_b64(f"v1:1:{created_us}:{ulid(2)}"))
    except ValidationError:
        return
    created_us_to_datetime(decoded)  # must not raise OverflowError
