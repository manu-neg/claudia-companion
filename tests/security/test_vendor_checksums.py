"""Security tests: vendored frontend libraries match their checksums (docs/security.md C13).

`static/vendor/CHECKSUMS` (sha256) is the source of truth; `VENDOR.md`
must record the same hashes, every vendored file must be listed, and each
library must ship its LICENSE. A silently modified or added vendor file fails.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

pytestmark = pytest.mark.security

VENDOR = default_static_dir() / "vendor"
_META_FILES = {"CHECKSUMS", "VENDOR.md"}


def _recorded() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in (VENDOR / "CHECKSUMS").read_text("ascii").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        assert name not in entries, f"duplicate entry {name}"
        entries[name.strip()] = digest
    return entries


def _vendored_files() -> set[str]:
    return {
        p.relative_to(VENDOR).as_posix()
        for p in VENDOR.rglob("*")
        if p.is_file() and p.name not in _META_FILES and "__pycache__" not in p.parts
    }


def test_every_vendored_file_matches_its_recorded_sha256() -> None:
    recorded = _recorded()
    assert recorded, "CHECKSUMS must not be empty"
    for name, digest in recorded.items():
        path = VENDOR / name
        assert path.is_file() and not path.is_symlink(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name


def test_no_unrecorded_vendor_files() -> None:
    assert _vendored_files() == set(_recorded())


def test_vendor_md_records_the_same_hashes() -> None:
    doc = (VENDOR / "VENDOR.md").read_text("utf-8")
    for name, digest in _recorded().items():
        assert f"`{name}`" in doc and digest in doc, name


def test_each_library_ships_its_license() -> None:
    libraries = {Path(name).parts[0] for name in _recorded()}
    assert len(libraries) == 3
    for library in libraries:
        assert (VENDOR / library / "LICENSE").is_file(), library
