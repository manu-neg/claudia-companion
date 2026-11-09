"""Unit tests for ArchiveService (streamed ZIP round trip) and download_filename."""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime, timedelta

import pytest

from preview_dashboard.application import ArchiveService, download_filename
from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.domain.models import Item
from tests.builders import T0, make_file, make_item, ulid
from tests.fakes import InMemoryBlobStore, InMemoryItemRepository

pytestmark = pytest.mark.unit


class Env:
    def __init__(self) -> None:
        self.repo = InMemoryItemRepository()
        self.blobs = InMemoryBlobStore()
        self.service = ArchiveService(repo=self.repo, blobs=self.blobs)

    def add(self, files: dict[str, bytes], n: int = 1, **overrides: object) -> Item:
        manifest = []
        for relpath, data in files.items():
            ref = self.blobs.put([data], max_bytes=len(data))
            manifest.append(
                make_file(relpath, blob_id=ref.blob_id, size=ref.size, sha256=ref.sha256)
            )
        fields: dict[str, object] = {"files": tuple(manifest), "entry_file": manifest[0].relpath}
        fields.update(overrides)
        item = make_item(n, **fields)
        self.repo.add(item)
        return item

    def zip_bytes(self, item: Item, **kwargs: bool) -> bytes:
        return b"".join(self.service.stream_zip(item.id, **kwargs))


@pytest.fixture
def env() -> Env:
    return Env()


def test_round_trip(env: Env) -> None:
    files = {
        "index.html": b"<p>hi</p>",
        "assets/app.js": b"console.log(1)" * 10_000,
        "empty.txt": b"",
        "déjà/ünicöde.txt": "café".encode(),
    }
    item = env.add(files)
    with zipfile.ZipFile(io.BytesIO(env.zip_bytes(item))) as zf:
        assert zf.testzip() is None
        assert zf.namelist() == list(files)
        for name, data in files.items():
            assert zf.read(name) == data


def test_large_file_streams_in_many_pieces(env: Env) -> None:
    data = bytes(range(256)) * 4_096  # 1 MiB, poorly compressible pattern
    item = env.add({"big.bin": data})
    pieces = list(env.service.stream_zip(item.id))
    assert len(pieces) > 1
    with zipfile.ZipFile(io.BytesIO(b"".join(pieces))) as zf:
        assert zf.read("big.bin") == data


def test_item_lookup_is_eager(env: Env) -> None:
    with pytest.raises(NotFoundError):
        env.service.stream_zip(ulid(9))  # raises before iteration starts
    with pytest.raises(ValidationError):
        env.service.stream_zip("../../etc/passwd")


def test_trashed_item_needs_allow_trashed(env: Env) -> None:
    item = env.add({"a.txt": b"a"})
    env.repo.save(item.trashed(T0 + timedelta(seconds=1)), expected_updated_at=item.updated_at)
    with pytest.raises(NotFoundError):
        env.service.stream_zip(item.id)
    assert env.zip_bytes(item, allow_trashed=True)


def test_abandoned_stream_closes_blob(env: Env) -> None:
    opened: list[io.BytesIO] = []
    original_open = env.blobs.open

    def tracking_open(blob_id: str) -> io.BytesIO:
        stream = original_open(blob_id)
        opened.append(stream)  # type: ignore[arg-type]
        return stream  # type: ignore[return-value]

    env.blobs.open = tracking_open  # type: ignore[method-assign]
    item = env.add({"big.bin": bytes(range(256)) * 4_096})
    gen = env.service.stream_zip(item.id)
    next(gen)
    gen.close()
    assert opened and all(s.closed for s in opened)


def test_missing_blob_raises_while_streaming(env: Env) -> None:
    item = env.add({"a.txt": b"a"})
    env.blobs.delete(item.files[0].blob_id)
    with pytest.raises(NotFoundError):
        env.zip_bytes(item)


def test_timestamps_come_from_item_and_are_clamped(env: Env) -> None:
    item = env.add({"a.txt": b"a"}, created_at=T0, updated_at=T0)
    with zipfile.ZipFile(io.BytesIO(env.zip_bytes(item))) as zf:
        assert zf.infolist()[0].date_time == (2026, 1, 1, 12, 0, 0)
    old = datetime(1970, 1, 1, tzinfo=UTC)
    item2 = env.add({"b.txt": b"b"}, n=2, created_at=old, updated_at=old)
    with zipfile.ZipFile(io.BytesIO(env.zip_bytes(item2))) as zf:
        assert zf.infolist()[0].date_time == (1980, 1, 1, 0, 0, 0)


def test_output_is_deterministic(env: Env) -> None:
    item = env.add({"a.txt": b"same", "b/c.txt": b"bytes"})
    assert env.zip_bytes(item) == env.zip_bytes(item)


# --- download_filename ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("My Report", "My-Report.zip"),
        ("Café crème", "Cafe-creme.zip"),
        ('a/b\\c:"d"; e%20f', "a-b-c-d-e-20f.zip"),
        ("...hidden...", "hidden.zip"),
        ("日本語", "download.zip"),  # nothing ASCII survives
        ("CON", "download.zip"),  # Windows device name
        ("nul", "download.zip"),
        ("x" * 200, "x" * 80 + ".zip"),
        ("v1.2 release", "v1.2-release.zip"),
    ],
)
def test_download_filename(title: str, expected: str) -> None:
    assert download_filename(make_item(1, title=title)) == expected


def test_download_filename_is_always_safe_ascii() -> None:
    for title in ["\r\nSet-Cookie: x", "../../etc/passwd", "a\tb", "\u202eevil.exe"]:
        name = download_filename(make_item(1, title=title))
        assert name.isascii()
        assert name.endswith(".zip")
        assert all(c.isalnum() or c in "._-" for c in name)
