"""Security tests for streamed ZIP downloads (docs/security.md C9, C7).

Arcnames are exactly the validated manifest relpaths; every entry is a
regular, non-executable file; there are no directory or symlink entries;
extraction cannot escape the target directory; and tampered blobs or
manifests abort the stream instead of shipping unexpected bytes.
"""

from __future__ import annotations

import dataclasses
import io
import stat
import zipfile
from pathlib import Path

import pytest

from preview_dashboard.application import ArchiveService
from preview_dashboard.application.archive import REGULAR_FILE_ATTR
from preview_dashboard.domain.errors import InvalidPathError, ValidationError
from preview_dashboard.domain.models import Item, ItemFile
from tests.builders import make_file, make_item
from tests.fakes import InMemoryBlobStore, InMemoryItemRepository

pytestmark = pytest.mark.security


class Env:
    def __init__(self) -> None:
        self.repo = InMemoryItemRepository()
        self.blobs = InMemoryBlobStore()
        self.service = ArchiveService(repo=self.repo, blobs=self.blobs)

    def add(self, files: dict[str, bytes]) -> Item:
        manifest = []
        for relpath, data in files.items():
            ref = self.blobs.put([data], max_bytes=len(data))
            manifest.append(
                make_file(relpath, blob_id=ref.blob_id, size=ref.size, sha256=ref.sha256)
            )
        item = make_item(1, files=tuple(manifest), entry_file=manifest[0].relpath)
        self.repo.add(item)
        return item

    def archive(self, item: Item) -> zipfile.ZipFile:
        return zipfile.ZipFile(io.BytesIO(b"".join(self.service.stream_zip(item.id))))


FILES = {
    "index.html": b"<html></html>",
    "a/b/c/deep.txt": b"deep",
    "run.sh": b"#!/bin/sh\nrm -rf /\n",
    "it's (1).txt": b"quote",
}


@pytest.fixture
def env() -> Env:
    return Env()


def test_arcnames_are_exactly_the_manifest_relpaths(env: Env) -> None:
    item = env.add(FILES)
    with env.archive(item) as zf:
        assert zf.namelist() == [f.relpath for f in item.files]


def test_entries_are_regular_non_executable_deflated_files(env: Env) -> None:
    with env.archive(env.add(FILES)) as zf:
        for info in zf.infolist():
            mode = info.external_attr >> 16
            assert info.external_attr == REGULAR_FILE_ATTR
            assert stat.S_ISREG(mode)
            assert not stat.S_ISLNK(mode)
            assert not mode & 0o111  # no exec bits, even for run.sh
            assert not info.is_dir()
            assert info.create_system == 3
            assert info.compress_type == zipfile.ZIP_DEFLATED
            assert not info.filename.startswith("/")
            assert ".." not in info.filename.split("/")


def test_no_directory_entries_even_for_nested_paths(env: Env) -> None:
    with env.archive(env.add(FILES)) as zf:
        assert not any(name.endswith("/") for name in zf.namelist())


def test_extraction_stays_inside_target(env: Env, tmp_path: Path) -> None:
    target = tmp_path / "out"
    with env.archive(env.add(FILES)) as zf:
        zf.extractall(target)
    extracted = sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file())
    assert extracted == sorted(FILES)
    for p in target.rglob("*"):
        assert p.resolve().is_relative_to(target.resolve())
        assert not p.is_symlink()


@pytest.mark.parametrize(
    "evil",
    [
        "../escape.txt",
        "/etc/passwd",
        "a/../../x",
        "C:evil.txt",
        "a\\..\\b",
        "dir/",
        "nul.txt",
        "a/\u202etxt.exe",
        "\uff0e\uff0e/x",
    ],
)
def test_adversarial_names_cannot_enter_an_item(evil: str) -> None:
    # The only arcname source is ItemFile.relpath, which refuses these.
    with pytest.raises(InvalidPathError):
        make_file(evil)


def test_tampered_manifest_relpath_is_revalidated(env: Env) -> None:
    item = env.add({"ok.txt": b"x"})
    evil_file = item.files[0]
    object.__setattr__(evil_file, "relpath", "../escape.txt")  # bypass the constructor
    # Keep the manifest self-consistent so only the arcname check can catch it.
    object.__setattr__(item, "entry_file", "../escape.txt")
    with pytest.raises(InvalidPathError):
        b"".join(env.service.stream_zip(item.id))


def _swap_blob(env: Env, item: Item, data: bytes) -> None:
    ref = env.blobs.put([data], max_bytes=len(data))
    tampered: ItemFile = dataclasses.replace(item.files[0], blob_id=ref.blob_id)
    env.repo.save(dataclasses.replace(item, files=(tampered,)), expected_updated_at=item.updated_at)


@pytest.mark.parametrize("data", [b"y", b"xx", b""])
def test_blob_not_matching_manifest_aborts_stream(env: Env, data: bytes) -> None:
    item = env.add({"a.txt": b"x"})
    _swap_blob(env, item, data)  # different digest and/or size
    with pytest.raises(ValidationError, match="manifest"):
        b"".join(env.service.stream_zip(item.id))
