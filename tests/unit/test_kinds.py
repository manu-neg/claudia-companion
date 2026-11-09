"""Table-driven unit tests for every built-in content kind.

One table (`KIND_TABLE`) captures each kind's extension -> media-type map,
preview mode, renderer id and render-capped flag; the parametrized tests
below hold every kind to it, plus its detect()/entry_file() behavior. This
also means adding a kind to `KIND_TABLE` here is what proves it is wired
into `default_registry()` correctly.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from preview_dashboard.domain.errors import UnsupportedContentError
from preview_dashboard.kinds import PreviewMode, default_registry
from preview_dashboard.kinds.base import ContentKind

pytestmark = pytest.mark.unit

KIND_TABLE: dict[str, dict[str, object]] = {
    "image": {
        "label": "Image",
        "renderer": "image",
        "preview_mode": PreviewMode.MEDIA,
        "render_capped": False,
        "media_types": {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".avif": "image/avif",
        },
    },
    "svg": {
        "label": "SVG image",
        "renderer": "svg",
        "preview_mode": PreviewMode.MEDIA,
        "render_capped": False,
        "media_types": {".svg": "image/svg+xml"},
    },
    "html": {
        "label": "HTML",
        "renderer": "html",
        "preview_mode": PreviewMode.SANDBOXED,
        "render_capped": False,
        "media_types": {".html": "text/html", ".htm": "text/html"},
    },
    "video": {
        "label": "Video",
        "renderer": "video",
        "preview_mode": PreviewMode.MEDIA,
        "render_capped": False,
        "media_types": {
            ".mp4": "video/mp4",
            ".webm": "video/webm",
            ".mov": "video/quicktime",
        },
    },
    "audio": {
        "label": "Audio",
        "renderer": "audio",
        "preview_mode": PreviewMode.MEDIA,
        "render_capped": False,
        "media_types": {
            ".mp3": "audio/mpeg",
            ".wav": "audio/wav",
            ".ogg": "audio/ogg",
            ".m4a": "audio/mp4",
            ".flac": "audio/flac",
        },
    },
    "pdf": {
        "label": "PDF",
        "renderer": "pdf",
        "preview_mode": PreviewMode.DOCUMENT,
        "render_capped": False,
        "media_types": {".pdf": "application/pdf"},
    },
    "markdown": {
        "label": "Markdown",
        "renderer": "markdown",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {".md": "text/markdown", ".markdown": "text/markdown"},
    },
    "code": {
        "label": "Code",
        "renderer": "code",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {
            ext: "text/plain"
            for ext in (
                ".py",
                ".js",
                ".ts",
                ".tsx",
                ".jsx",
                ".css",
                ".scss",
                ".sh",
                ".bash",
                ".go",
                ".rs",
                ".java",
                ".c",
                ".h",
                ".cpp",
                ".hpp",
                ".rb",
                ".php",
                ".sql",
                ".yaml",
                ".yml",
                ".toml",
                ".ini",
                ".xml",
                ".swift",
                ".kt",
            )
        },
    },
    "json": {
        "label": "JSON",
        "renderer": "json",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {".json": "application/json"},
    },
    "csv": {
        "label": "CSV",
        "renderer": "csv",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {".csv": "text/csv", ".tsv": "text/tab-separated-values"},
    },
    "text": {
        "label": "Text",
        "renderer": "text",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {".txt": "text/plain", ".log": "text/plain"},
    },
    "diff": {
        "label": "Diff",
        "renderer": "diff",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {".diff": "text/x-diff", ".patch": "text/x-diff"},
    },
    "progress": {
        "label": "Progress",
        "renderer": "progress",
        "preview_mode": PreviewMode.TEXT,
        "render_capped": True,
        "media_types": {},  # claims no extension: only an explicit hint selects it
    },
    "file": {
        "label": "File",
        "renderer": "file",
        "preview_mode": PreviewMode.DOWNLOAD,
        "render_capped": False,
        "media_types": {},  # matches nothing by extension; always the fallback
    },
}


@pytest.fixture(scope="module")
def registry_kinds() -> dict[str, ContentKind]:
    return {kind.name: kind for kind in default_registry().all()}


def test_kind_table_covers_every_registered_kind(registry_kinds: dict[str, ContentKind]) -> None:
    assert set(KIND_TABLE) == set(registry_kinds)


@pytest.mark.parametrize("name", sorted(KIND_TABLE))
def test_kind_attributes(name: str, registry_kinds: dict[str, ContentKind]) -> None:
    kind = registry_kinds[name]
    spec = KIND_TABLE[name]
    media_types: Mapping[str, str] = spec["media_types"]  # type: ignore[assignment]
    assert kind.name == name
    assert kind.label == spec["label"]
    assert kind.renderer == spec["renderer"]
    assert kind.preview_mode == spec["preview_mode"]
    assert kind.render_capped == spec["render_capped"]
    assert kind.extensions == frozenset(media_types)


@pytest.mark.parametrize("name", sorted(KIND_TABLE))
def test_kind_media_type_single_file(name: str, registry_kinds: dict[str, ContentKind]) -> None:
    kind = registry_kinds[name]
    media_types: Mapping[str, str] = KIND_TABLE[name]["media_types"]  # type: ignore[assignment]
    for ext, expected in media_types.items():
        relpath = f"file{ext}"
        assert kind.media_type(relpath) == expected
        assert kind.detect([relpath]) == 100
        assert kind.entry_file([relpath]) == relpath


@pytest.mark.parametrize("name", sorted(KIND_TABLE))
def test_kind_rejects_unrelated_extension(
    name: str, registry_kinds: dict[str, ContentKind]
) -> None:
    kind = registry_kinds[name]
    if name == "file":
        pytest.skip("file is the always-matches fallback")
    assert kind.detect(["thing.unknown-ext-zzz"]) == 0


@pytest.mark.parametrize("name", sorted(KIND_TABLE))
def test_kind_detect_empty_is_zero(name: str, registry_kinds: dict[str, ContentKind]) -> None:
    assert registry_kinds[name].detect([]) == 0


# --- kind-specific behavior not covered by the generic table ------------------


def test_html_single_file_need_not_be_named_index(registry_kinds: dict[str, ContentKind]) -> None:
    html = registry_kinds["html"]
    assert html.detect(["about.html"]) == 100
    assert html.entry_file(["about.html"]) == "about.html"


def test_html_bundle_requires_root_index(registry_kinds: dict[str, ContentKind]) -> None:
    html = registry_kinds["html"]
    files = ["index.html", "style.css", "app.js", "img/logo.png"]
    assert html.detect(files) == 100
    assert html.entry_file(files) == "index.html"


def test_html_bundle_without_root_index_is_not_html(registry_kinds: dict[str, ContentKind]) -> None:
    html = registry_kinds["html"]
    # Nested index.html doesn't count -- only a root entry is accepted.
    files = ["pages/index.html", "style.css"]
    assert html.detect(files) == 0


def test_html_entry_file_raises_without_detect(registry_kinds: dict[str, ContentKind]) -> None:
    html = registry_kinds["html"]
    with pytest.raises(UnsupportedContentError):
        html.entry_file(["a.html", "b.html"])  # no root index.html


def test_file_kind_always_detects_with_confidence_one(
    registry_kinds: dict[str, ContentKind],
) -> None:
    file_kind = registry_kinds["file"]
    assert file_kind.detect(["anything.bin"]) == 1
    assert file_kind.detect(["a", "b", "c.zzz"]) == 1
    assert file_kind.detect([]) == 0


def test_file_kind_media_type_is_always_octet_stream(
    registry_kinds: dict[str, ContentKind],
) -> None:
    file_kind = registry_kinds["file"]
    assert file_kind.media_type("thing.bin") == "application/octet-stream"
    assert file_kind.media_type("noext") == "application/octet-stream"


def test_extension_matching_is_case_insensitive_and_last_segment_only(
    registry_kinds: dict[str, ContentKind],
) -> None:
    image = registry_kinds["image"]
    assert image.media_type("a/B/photo.PNG") == "image/png"
    # 'x.html.png' is an image (last extension wins), not html.
    assert image.detect(["x.html.png"]) == 100
    html = registry_kinds["html"]
    assert html.detect(["x.html.png"]) == 0


def test_extensionless_and_dotfile_names_have_no_extension(
    registry_kinds: dict[str, ContentKind],
) -> None:
    for kind in registry_kinds.values():
        if kind.name == "file":
            continue
        assert kind.detect(["README"]) == 0
        assert kind.detect([".env"]) == 0


# --- html bundle asset media types (unit 3 follow-up, docs/adr/0009 amendment) --

# The closed, explicit web-asset map `HtmlKind` uses for every member of its
# own bundle -- distinct from any other kind's own map (see the contrast
# tests below). Duplicated here (not imported from `kinds/html.py`) so a typo
# in the implementation's map is actually caught, not just echoed.
HTML_BUNDLE_MEDIA_TYPES: dict[str, str] = {
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".json": "application/json",
    ".map": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    ".txt": "text/plain",
    ".csv": "text/csv",
}


@pytest.mark.parametrize("ext", sorted(HTML_BUNDLE_MEDIA_TYPES))
def test_html_bundle_member_media_type(ext: str, registry_kinds: dict[str, ContentKind]) -> None:
    html = registry_kinds["html"]
    assert html.media_type(f"asset{ext}") == HTML_BUNDLE_MEDIA_TYPES[ext]


@pytest.mark.parametrize("ext", [".xml", ".wasm", ".flac", ".mov", ".unknown-ext-zzz", ""])
def test_html_bundle_member_outside_the_closed_map_is_octet_stream(
    ext: str, registry_kinds: dict[str, ContentKind]
) -> None:
    # .xml/.wasm are deliberately excluded despite being "web" extensions
    # (see kinds/html.py header); .flac/.mov are extensions other kinds
    # (audio/video) claim but html's own map does not list.
    html = registry_kinds["html"]
    relpath = f"asset{ext}" if ext else "asset"
    assert html.media_type(relpath) == "application/octet-stream"


def test_standalone_js_and_css_items_are_code_kind_and_text_plain(
    registry_kinds: dict[str, ContentKind],
) -> None:
    # A lone .js or .css file (no index.html alongside it) is the `code`
    # kind, not `html`, and stays inert text/plain -- nothing will ever load
    # it as a stylesheet or script (docs/architecture.md, code kind row).
    code = registry_kinds["code"]
    assert code.detect(["app.js"]) == 100
    assert code.media_type("app.js") == "text/plain"
    assert code.detect(["style.css"]) == 100
    assert code.media_type("style.css") == "text/plain"


def test_same_extension_differs_between_standalone_and_bundle_member() -> None:
    # The same .js/.css extension is typed differently depending on which
    # item's kind is asked: standalone -> code -> text/plain (inert);
    # member of an html bundle -> html -> text/css/text/javascript.
    registry = default_registry()
    standalone_kind = registry.detect(["app.js"])
    assert standalone_kind.name == "code"
    assert standalone_kind.media_type("app.js") == "text/plain"

    bundle_files = ["index.html", "app.js", "style.css"]
    bundle_kind = registry.detect(bundle_files)
    assert bundle_kind.name == "html"
    assert bundle_kind.media_type("app.js") == "text/javascript"
    assert bundle_kind.media_type("style.css") == "text/css"
