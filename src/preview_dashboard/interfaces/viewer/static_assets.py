"""In-memory manifest of the dashboard's own UI files (`src/preview_dashboard/static/`).

Loaded once at start-up: every regular file with an allowlisted extension
is read into memory under its URL path. Requests are dict lookups only, so
no request value ever reaches the filesystem and there is no directory
listing (docs/security.md I2, C20). Symlinks, special files or oversized
trees make the dashboard refuse to start (fail closed). Each file is opened
with `O_NOFOLLOW` and checked with `fstat`, so a symlink swapped in during
start-up is refused rather than followed.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

# Closed map: anything else in static/ (CHECKSUMS, READMEs, sources maps
# we did not choose to ship) is never served.
STATIC_MEDIA_TYPES: dict[str, str] = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".json": "application/json",
    ".webmanifest": "application/manifest+json",
}
INDEX_FILE = "index.html"
# Top-level static/ directories the dashboard never serves: they are only
# inlined into preview-origin `/r/` pages (ADR 0018). Serving DOMPurify or
# the renderer from the dashboard origin would only add attack surface.
DASHBOARD_EXCLUDED_DIRS: frozenset[str] = frozenset({"vendor", "preview-render"})
MAX_ASSET_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ASSETS = 512


class StaticAssetError(Exception):
    """The static directory is unsafe or too large; the dashboard must not start."""


@dataclass(frozen=True, slots=True)
class StaticAsset:
    """One UI file held in memory.

    Attributes:
        body: file bytes.
        content_type: full Content-Type header value.
        etag: strong ETag (quoted SHA-256 hex).
    """

    body: bytes
    content_type: str
    etag: str


class StaticAssets:
    """Immutable `relative path -> StaticAsset` manifest."""

    def __init__(self, assets: dict[str, StaticAsset]) -> None:
        self._assets = MappingProxyType(dict(assets))

    def get(self, name: str) -> StaticAsset | None:
        """Return the asset stored under exactly `name` (e.g. `renderers/text.js`)."""
        return self._assets.get(name)

    def names(self) -> frozenset[str]:
        """Every served relative path."""
        return frozenset(self._assets)

    @classmethod
    def load(
        cls, root: Path, *, exclude_dirs: frozenset[str] = DASHBOARD_EXCLUDED_DIRS
    ) -> StaticAssets:
        """Read every allowlisted file under `root` into memory.

        Dotfiles, files with other extensions and the top-level directories
        in `exclude_dirs` are skipped. A missing `root` yields an empty
        manifest (the UI is optional for the API).

        Raises:
            StaticAssetError: a symlink or special file anywhere under `root`,
                a non-UTF-8-safe name, or size/count limits exceeded.
        """
        if not root.exists():
            return cls({})
        if root.is_symlink() or not root.is_dir():
            raise StaticAssetError("static root must be a real directory")
        assets: dict[str, StaticAsset] = {}
        total = 0
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            for name in dirnames:
                if (base / name).is_symlink():
                    raise StaticAssetError("symlinked directory under static/")
            top = base == root
            dirnames[:] = sorted(
                d for d in dirnames if not d.startswith(".") and not (top and d in exclude_dirs)
            )
            for name in sorted(filenames):
                if name.startswith("."):
                    continue
                path = base / name
                mode = os.lstat(path).st_mode
                if not stat.S_ISREG(mode):
                    raise StaticAssetError("non-regular file under static/")
                media_type = STATIC_MEDIA_TYPES.get(path.suffix.lower())
                if media_type is None:
                    continue
                rel = path.relative_to(root).as_posix()
                if not rel.isascii() or any(c in rel for c in "\\%?#"):
                    raise StaticAssetError("static file names must be plain ASCII")
                body = read_regular_file(path, MAX_ASSET_BYTES)
                total += len(body)
                if total > MAX_TOTAL_BYTES:
                    raise StaticAssetError("static assets exceed the size limit")
                assets[rel] = StaticAsset(
                    body=body,
                    content_type=media_type,
                    etag=f'"{hashlib.sha256(body).hexdigest()}"',
                )
                if len(assets) > MAX_ASSETS:
                    raise StaticAssetError("too many static assets")
        return cls(assets)


# O_NOFOLLOW: a file swapped for a symlink after the lstat() above fails
# with ELOOP instead of being read; O_NONBLOCK: a swapped-in FIFO can't
# block start-up in open() (fstat then rejects it).
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def read_regular_file(path: Path, max_bytes: int) -> bytes:
    """Read a regular, non-symlink file of at most `max_bytes` without a TOCTOU gap.

    The type and size are checked with `fstat` on the descriptor actually
    read, not on the path.

    Raises:
        StaticAssetError: `path` is a symlink, not a regular file, can't be
            opened, or is larger than `max_bytes`.
    """
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        raise StaticAssetError("static file is a symlink or unreadable") from exc
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise StaticAssetError("non-regular file under static/")
        if st.st_size > max_bytes:
            raise StaticAssetError("static assets exceed the size limit")
        # Bounded read: the file may grow between fstat() and read().
        body = handle.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise StaticAssetError("static assets exceed the size limit")
    return body


def default_static_dir() -> Path:
    """The packaged `static/` directory (next to this package's top level)."""
    return Path(__file__).resolve().parents[2] / "static"
