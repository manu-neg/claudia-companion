"""Security tests: the viewer can never read outside its data dir (docs/security.md I2, C7, C20).

Real `FsBlobStore` + SQLite in a tmp dir, with sentinel files planted
outside the data dir and in its `db/`. Every route of both apps gets a
traversal/encoding matrix (raw paths exactly as a server would pass them:
`..`, `%2e%2e`, `%252e`, `%2f`, `%5c`, raw backslash, fullwidth, NUL,
overlong UTF-8, absolute paths) in the relpath and item-id positions.
Nothing may succeed, no sentinel may leak, and the blob store may only
ever be asked for blob ids that are in a manifest.
"""

from __future__ import annotations

import functools
import os
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import unquote

import pytest

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore
from preview_dashboard.adapters.sqlite import SqliteItemRepository, connect, default_db_path
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.domain.models import BlobRef, Item
from preview_dashboard.interfaces.viewer import static_assets as static_assets_module
from preview_dashboard.interfaces.viewer.static_assets import (
    MAX_ASSET_BYTES,
    StaticAssetError,
    StaticAssets,
    read_regular_file,
)
from tests.app_support import make_publish
from tests.viewer_support import (
    DASH_HOST,
    OWNER,
    PREVIEW_HOST,
    StubServices,
    ViewerEnv,
    call_asgi,
    make_env,
)

pytestmark = pytest.mark.security

SENTINEL = b"PDASH-SENTINEL-MUST-NEVER-LEAK"


class SpyBlobStore:
    """Delegating BlobStore that records every id the viewer asks to open."""

    def __init__(self, inner: FsBlobStore) -> None:
        self.inner = inner
        self.opened: list[str] = []

    def put(self, chunks: Iterable[bytes], max_bytes: int) -> BlobRef:
        return self.inner.put(chunks, max_bytes)

    def open(self, blob_id: str) -> BinaryIO:
        self.opened.append(blob_id)
        return self.inner.open(blob_id)

    def delete(self, blob_id: str) -> None:
        self.inner.delete(blob_id)

    def list_ids(self, created_before: datetime | None = None) -> set[str]:
        return self.inner.list_ids(created_before)

    def free_bytes(self) -> int:
        return self.inner.free_bytes()


@pytest.fixture
def world(tmp_path: Path) -> Iterator[tuple[ViewerEnv, SpyBlobStore]]:
    data = tmp_path / "data"
    data.mkdir()
    # Sentinels: next to the data dir, inside db/, and a would-be target name.
    (tmp_path / "secret.txt").write_bytes(SENTINEL)
    (tmp_path / "passwd").write_bytes(SENTINEL)
    factory = functools.partial(connect, default_db_path(data))
    factory().close()  # creates db/ and the schema
    repo = SqliteItemRepository(factory)
    (data / "db" / "notes.txt").write_bytes(SENTINEL)
    with FsBlobStore(data, ids=UlidGenerator(), clock=SystemClock()) as store:
        spy = SpyBlobStore(store)
        harness = make_publish(repo=repo, blobs=spy)
        env = make_env(StubServices(repo, spy, harness.clock), publisher=harness.service)
        env.publish({"index.html": b"<p>ok</p>", "sub/a.css": b"p{}"}, title="Bundle")
        env.publish({"notes.txt": b"plain"}, title="Notes")
        spy.opened.clear()
        yield env, spy


def _manifest_blob_ids(items: list[Item]) -> set[str]:
    return {f.blob_id for item in items for f in item.files}


# Raw relpath tails (never normalised: sent byte-for-byte as the raw path).
TRAVERSAL_TAILS = [
    "../../../../etc/passwd",
    "../../../../../../root/.ssh/id_rsa",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2f..%2fsecret.txt",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2E%2E/%2E%2E/secret.txt",
    "%252e%252e/%252e%252e/etc/passwd",
    "%252e%252e%252f%252e%252e%252fsecret.txt",
    "..%5c..%5c..%5cetc%5cpasswd",
    "..\\..\\..\\etc\\passwd",
    "%EF%BC%8E%EF%BC%8E%EF%BC%8F%EF%BC%8E%EF%BC%8E%EF%BC%8Fsecret.txt",  # U+FF0E U+FF0E U+FF0F
    "%EF%BC%8E%EF%BC%8E/%EF%BC%8E%EF%BC%8E/etc/passwd",
    "..%C0%AF..%C0%AFetc%C0%AFpasswd",  # overlong UTF-8 '/'
    "%C0%AE%C0%AE/%C0%AE%C0%AE/secret.txt",  # overlong UTF-8 '.'
    "/etc/passwd",
    "%2Fetc%2Fpasswd",
    "..",
    ".",
    "./index.html",
    "sub/../index.html",
    "sub/%2e%2e/index.html",
    "index.html%00.png",
    "%00/etc/passwd",
    "../db/items.sqlite3",
    "../../data/db/notes.txt",
    "../blobs",
    "C:%5CWindows%5Cwin.ini",
    "~root/.ssh/authorized_keys",
    "sub",
    "sub/",
    "",
]
# Hostile values in the item-id position (and no valid item at all).
ID_POSITION = [
    "..",
    "%2e%2e",
    "..%2F..%2Fetc",
    "%252e%252e",
    "..%5c..",
    "%EF%BC%8E%EF%BC%8E",
    "etc",
    "00000000000000000000000001%2F..",
]


async def _get(app: object, raw: str, host: str) -> tuple[int | None, bytes]:
    path = unquote(raw, errors="replace")
    headers = [(b"host", host.encode()), (b"tailscale-user-login", OWNER.encode())]
    result = await call_asgi(app, path=path, raw_path=raw.encode("latin-1"), headers=headers)
    return result.status, result.body


def _assert_refused(status: int | None, body: bytes, raw: str) -> None:
    assert status in {400, 404, 405, 421}, (raw, status)
    assert SENTINEL not in body, raw
    assert b"root:" not in body, raw


@pytest.mark.parametrize("tail", TRAVERSAL_TAILS)
@pytest.mark.parametrize("prefix", ["i", "t", "r", "d"])
async def test_preview_relpath_traversal_matrix(
    world: tuple[ViewerEnv, SpyBlobStore], prefix: str, tail: str
) -> None:
    env, spy = world
    for item in env.items:
        for query in ("", "?t=1"):
            raw = f"/{prefix}/{item.id}/1/{tail}"
            status, body = await _get(env.preview, raw + query, PREVIEW_HOST)
            _assert_refused(status, body, raw)
    assert set(spy.opened) <= _manifest_blob_ids(env.items)


@pytest.mark.parametrize("hostile", ID_POSITION)
async def test_item_id_position_matrix(world: tuple[ViewerEnv, SpyBlobStore], hostile: str) -> None:
    env, spy = world
    for raw in (
        f"/i/{hostile}/1/etc/passwd",
        f"/t/{hostile}/1/secret.txt",
        f"/r/{hostile}/1/secret.txt",
        f"/d/{hostile}/1",
        f"/d/{hostile}/1/secret.txt",
    ):
        status, body = await _get(env.preview, raw, PREVIEW_HOST)
        _assert_refused(status, body, raw)
    for raw in (
        f"/api/items/{hostile}",
        f"/api/items/{hostile}?t=1",
    ):
        status, body = await _get(env.dashboard, raw, DASH_HOST)
        _assert_refused(status, body, raw)
    assert spy.opened == []


@pytest.mark.parametrize("tail", TRAVERSAL_TAILS)
async def test_static_route_traversal_matrix(
    world: tuple[ViewerEnv, SpyBlobStore], tail: str
) -> None:
    env, spy = world
    for raw in (f"/static/{tail}", f"/{tail}"):
        if raw == "/":
            continue  # the index itself
        status, body = await _get(env.dashboard, raw, DASH_HOST)
        _assert_refused(status, body, raw)
    assert spy.opened == []


@pytest.mark.parametrize(
    "raw",
    [
        "/static/",
        "/static",
        "/static/renderers",
        "/static/renderers/",
        "/static/vendor/",
        "/static/../pyproject.toml",
        "/static/%2e%2e/config.py",
        "/static/../../preview_dashboard/config.py",
        "/static/index.html/",
    ],
)
async def test_no_directory_listing_or_escape_from_static(
    world: tuple[ViewerEnv, SpyBlobStore], raw: str
) -> None:
    env, _ = world
    status, body = await _get(env.dashboard, raw, DASH_HOST)
    _assert_refused(status, body, raw)


async def test_legitimate_requests_only_open_manifest_blobs(
    world: tuple[ViewerEnv, SpyBlobStore],
) -> None:
    env, spy = world
    bundle = env.items[0]
    for raw in (f"/i/{bundle.id}/1/index.html", f"/i/{bundle.id}/1/sub/a.css", f"/d/{bundle.id}/1"):
        status, _ = await _get(env.preview, raw, PREVIEW_HOST)
        assert status == 200, raw
    assert spy.opened
    assert set(spy.opened) <= _manifest_blob_ids(env.items)


async def test_dashboard_never_serves_item_bytes(world: tuple[ViewerEnv, SpyBlobStore]) -> None:
    """C5: item bytes exist only on the preview origin."""
    env, spy = world
    item = env.items[0]
    for raw in (f"/i/{item.id}/1/index.html", f"/d/{item.id}/1", f"/t/{item.id}/1/index.html"):
        status, body = await _get(env.dashboard, raw, DASH_HOST)
        assert status == 404, raw
        assert b"<p>ok</p>" not in body
    assert spy.opened == []


# --- static manifest: loaded once, never a filesystem path at request time ----------


def test_static_manifest_refuses_symlinked_files(tmp_path: Path) -> None:
    root = tmp_path / "static"
    root.mkdir()
    (tmp_path / "secret.js").write_bytes(SENTINEL)
    os.symlink(tmp_path / "secret.js", root / "app.js")
    with pytest.raises(StaticAssetError):
        StaticAssets.load(root)


def test_static_manifest_refuses_symlinked_dirs(tmp_path: Path) -> None:
    root = tmp_path / "static"
    root.mkdir()
    os.symlink("/etc", root / "etc")
    with pytest.raises(StaticAssetError):
        StaticAssets.load(root)


def test_static_manifest_refuses_special_files(tmp_path: Path) -> None:
    root = tmp_path / "static"
    root.mkdir()
    os.mkfifo(root / "pipe.js")
    with pytest.raises(StaticAssetError):
        StaticAssets.load(root)


def test_static_manifest_skips_unlisted_types_and_dotfiles(tmp_path: Path) -> None:
    root = tmp_path / "static"
    (root / "vendor").mkdir(parents=True)
    (root / "index.html").write_text("<!doctype html>")
    (root / "vendor" / "CHECKSUMS").write_text("x")
    (root / "notes.py").write_text("x")
    (root / ".hidden.js").write_text("x")
    (root / "vendor" / "lib.js").write_text("x")
    (root / "lib").mkdir()
    (root / "lib" / "vendor").mkdir()
    (root / "lib" / "vendor" / "ok.js").write_text("x")
    # vendor/ (and preview-render/) at the top level are for /r/ pages only.
    assert StaticAssets.load(root).names() == {"index.html", "lib/vendor/ok.js"}
    assert StaticAssets.load(root, exclude_dirs=frozenset()).names() == {
        "index.html",
        "vendor/lib.js",
        "lib/vendor/ok.js",
    }


def test_static_assets_are_served_from_memory(tmp_path: Path) -> None:
    root = tmp_path / "static"
    root.mkdir()
    (root / "app.js").write_bytes(b"export {};")
    assets = StaticAssets.load(root)
    (root / "app.js").unlink()
    root.rmdir()
    asset = assets.get("app.js")
    assert asset is not None and asset.body == b"export {};"
    assert assets.get("../app.js") is None


def test_static_file_read_refuses_a_symlink_swapped_in_after_lstat(tmp_path: Path) -> None:
    # The lstat() in the walk saw a regular file; the open itself must not follow.
    (tmp_path / "secret.js").write_bytes(SENTINEL)
    link = tmp_path / "app.js"
    os.symlink(tmp_path / "secret.js", link)
    with pytest.raises(StaticAssetError):
        read_regular_file(link, MAX_ASSET_BYTES)


def test_static_file_read_refuses_a_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.js"
    os.mkfifo(fifo)
    with pytest.raises(StaticAssetError):
        read_regular_file(fifo, MAX_ASSET_BYTES)  # O_NONBLOCK: no writer needed


def test_static_file_read_is_bounded(tmp_path: Path) -> None:
    big = tmp_path / "big.js"
    big.write_bytes(b"x" * 11)
    assert read_regular_file(big, 11) == b"x" * 11
    with pytest.raises(StaticAssetError):
        read_regular_file(big, 10)


def test_static_manifest_refuses_oversized_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "static"
    root.mkdir()
    (root / "app.js").write_bytes(b"x" * 64)
    monkeypatch.setattr(static_assets_module, "MAX_ASSET_BYTES", 32)
    with pytest.raises(StaticAssetError):
        StaticAssets.load(root)
