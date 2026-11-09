"""Unit tests for UlidGenerator (ADR 0007: canonical, stdlib-only ULIDs)."""

from __future__ import annotations

import pytest

from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.domain.models import is_ulid

pytestmark = pytest.mark.unit


def test_new_item_id_and_new_blob_id_are_canonical_ulids() -> None:
    gen = UlidGenerator()
    for _ in range(50):
        assert is_ulid(gen.new_item_id())
        assert is_ulid(gen.new_blob_id())


def test_ids_are_unique() -> None:
    gen = UlidGenerator()
    ids = {gen.new_blob_id() for _ in range(2000)}
    assert len(ids) == 2000


def test_ids_are_monotonically_increasing_within_a_process() -> None:
    # Nice-to-have per ADR 0007: a burst from one process sorts in call order
    # even when several ids land in the same millisecond.
    gen = UlidGenerator()
    ids = [gen.new_blob_id() for _ in range(2000)]
    assert ids == sorted(ids)


def test_item_and_blob_ids_are_independent_but_both_valid() -> None:
    gen = UlidGenerator()
    item_id = gen.new_item_id()
    blob_id = gen.new_blob_id()
    assert is_ulid(item_id)
    assert is_ulid(blob_id)
    assert item_id != blob_id


def test_all_ids_are_uppercase_ascii() -> None:
    gen = UlidGenerator()
    for _ in range(20):
        ulid = gen.new_blob_id()
        assert ulid == ulid.upper()
        assert ulid.isascii()
        assert len(ulid) == 26
