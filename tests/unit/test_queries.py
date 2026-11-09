"""Unit tests for QueryService: listing, get, manifest-only file access, kinds (I2, C7)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from preview_dashboard.application import OpenedFile, QueryService
from preview_dashboard.domain.errors import InvalidPathError, NotFoundError, ValidationError
from preview_dashboard.domain.models import Item, ItemId, ItemState
from preview_dashboard.domain.query import ItemQuery
from preview_dashboard.kinds import default_registry
from tests.builders import T0, make_file, make_item, ulid
from tests.fakes import InMemoryBlobStore, InMemoryItemRepository

pytestmark = pytest.mark.unit


Env = tuple[QueryService, InMemoryItemRepository, InMemoryBlobStore]


@pytest.fixture
def env() -> Env:
    repo = InMemoryItemRepository()
    blobs = InMemoryBlobStore()
    return QueryService(repo=repo, blobs=blobs, kinds=default_registry()), repo, blobs


def _add_with_blob(
    repo: InMemoryItemRepository, blobs: InMemoryBlobStore, n: int, data: bytes
) -> Item:
    ref = blobs.put([data], max_bytes=len(data))
    item = make_item(
        n,
        files=(make_file("index.html", blob_id=ref.blob_id, size=ref.size, sha256=ref.sha256),),
    )
    repo.add(item)
    return item


def test_list_delegates_with_ordering(env: Env) -> None:
    service, repo, _ = env
    repo.add(make_item(1))
    repo.add(make_item(2, pinned=True))
    repo.add(make_item(3).trashed(T0 + timedelta(minutes=1)))
    assert [i.id for i in service.list(ItemQuery()).items] == [ulid(2), ulid(1)]
    trash = service.list(ItemQuery(state=ItemState.TRASHED)).items
    assert [i.id for i in trash] == [ulid(3)]


def test_get_any_state(env: Env) -> None:
    service, repo, _ = env
    item = make_item(1).trashed(T0)
    repo.add(item)
    assert service.get(item.id) == item


@pytest.mark.parametrize("bad", ["", "../x", "0" * 25, "a" * 26, "0" * 26 + "/"])
def test_get_rejects_malformed_ids(env: Env, bad: str) -> None:
    service, _, _ = env
    with pytest.raises(ValidationError):
        service.get(bad)


def test_get_missing(env: Env) -> None:
    service, _, _ = env
    with pytest.raises(NotFoundError):
        service.get(ulid(5))


def test_open_file_streams_blob(env: Env) -> None:
    service, repo, blobs = env
    item = _add_with_blob(repo, blobs, 1, b"<h1>hi</h1>")
    with service.open_file(item.id, "index.html", allow_trashed=False) as opened:
        assert isinstance(opened, OpenedFile)
        assert opened.item == item
        assert opened.item_file.relpath == "index.html"
        assert opened.stream.read() == b"<h1>hi</h1>"
        opened.stream.seek(4)
        assert opened.stream.read(2) == b"hi"
    assert opened.stream.closed


def test_trashed_item_hidden_unless_allowed(env: Env) -> None:
    service, repo, blobs = env
    item = _add_with_blob(repo, blobs, 1, b"x")
    repo.save(item.trashed(T0 + timedelta(seconds=1)), expected_updated_at=item.updated_at)
    with pytest.raises(NotFoundError, match="item not found"):
        service.open_file(item.id, "index.html", allow_trashed=False)
    with service.open_file(item.id, "index.html", allow_trashed=True) as opened:
        assert opened.stream.read() == b"x"


def test_missing_item_and_trashed_item_look_the_same(env: Env) -> None:
    service, repo, blobs = env
    item = _add_with_blob(repo, blobs, 1, b"x")
    repo.save(item.trashed(T0 + timedelta(seconds=1)), expected_updated_at=item.updated_at)
    with pytest.raises(NotFoundError) as trashed:
        service.open_file(item.id, "index.html", allow_trashed=False)
    with pytest.raises(NotFoundError) as missing:
        service.open_file(ulid(99), "index.html", allow_trashed=False)
    assert str(trashed.value) == str(missing.value)


def test_relpath_not_in_manifest(env: Env) -> None:
    service, repo, blobs = env
    item = _add_with_blob(repo, blobs, 1, b"x")
    with pytest.raises(NotFoundError, match="file not found"):
        service.open_file(item.id, "other.html", allow_trashed=False)


def test_manifest_lookup_is_exact_not_caseless(env: Env) -> None:
    service, repo, blobs = env
    item = _add_with_blob(repo, blobs, 1, b"x")
    with pytest.raises(NotFoundError):
        service.open_file(item.id, "INDEX.html", allow_trashed=False)


def test_missing_blob_is_not_found(env: Env) -> None:
    service, repo, _ = env
    repo.add(make_item(1))  # manifest points at a blob the store never had
    with pytest.raises(NotFoundError):
        service.open_file(ItemId(ulid(1)), "index.html", allow_trashed=False)


def test_kinds_is_registry_description(env: Env) -> None:
    service, _, _ = env
    assert service.kinds() == default_registry().describe()


@pytest.mark.parametrize(
    "relpath",
    ["../index.html", "/etc/passwd", "a/../index.html", "a\\b", "%2e%2e/x", "", "a//b"],
)
def test_open_file_rejects_unsafe_relpaths(env: Env, relpath: str) -> None:
    service, repo, blobs = env
    item = _add_with_blob(repo, blobs, 1, b"x")
    with pytest.raises(InvalidPathError):
        service.open_file(item.id, relpath, allow_trashed=True)
