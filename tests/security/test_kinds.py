"""Security tests for the content-kind registry (docs/security.md C8, I4).

Content-Type comes only from the kind registry, never from client input or
content sniffing, and text-like kinds are served as inert `text/*` /
`application/json` types so the browser never executes them.
"""

from __future__ import annotations

import pytest

from preview_dashboard.kinds import PreviewMode, default_registry

pytestmark = pytest.mark.security

_SCRIPTABLE_MEDIA_TYPES = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "application/javascript",
        "text/javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-javascript",
        "image/svg+xml",  # only ever safe via <img>, checked separately below
    }
)


_EXECUTABLE_MEDIA_TYPES = frozenset({"text/html", "text/javascript"})


def test_executable_types_only_ever_emitted_by_html_kind() -> None:
    """text/html and text/javascript must never come from any kind but html.

    Checked two ways: (1) every kind's own extension set, via its own
    media_type(), and (2) html's own closed bundle-asset map (larger than
    its `extensions` attribute -- it also types .js/.mjs, .css, etc. for
    bundle members), which is where text/javascript can appear at all
    (docs/security.md C8, ADR 0009 amendment).
    """
    registry = default_registry()
    for kind in registry.all():
        for ext in sorted(kind.extensions):
            media_type = kind.media_type(f"sample{ext}")
            if media_type in _EXECUTABLE_MEDIA_TYPES:
                assert kind.name == "html", f"{kind.name} emitted {media_type} for {ext}"
    html = registry.get("html")
    for ext in (".html", ".htm", ".js", ".mjs"):
        assert html.media_type(f"sample{ext}") in _EXECUTABLE_MEDIA_TYPES


def test_code_kind_never_emits_a_scriptable_media_type() -> None:
    registry = default_registry()
    code = registry.get("code")
    for ext in sorted(code.extensions):
        media_type = code.media_type(f"sample{ext}")
        assert media_type == "text/plain", f"{ext} -> {media_type}, expected text/plain"
        assert media_type not in _SCRIPTABLE_MEDIA_TYPES - {"text/html"}


def test_no_kind_emits_a_javascript_or_xml_executable_type() -> None:
    javascript_like = {
        "application/javascript",
        "text/javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-javascript",
        "application/xhtml+xml",
    }
    registry = default_registry()
    for kind in registry.all():
        for ext in sorted(kind.extensions):
            media_type = kind.media_type(f"sample{ext}")
            assert media_type not in javascript_like


def test_html_bundle_asset_map_is_closed_to_a_fixed_safe_set() -> None:
    """html's own bundle-member media types are a fixed, reviewed allowlist.

    Only the media types below may ever be returned for a bundle member;
    anything not in the documented map -- including .xml (avoids an
    XML/XSLT scripting surface) and .wasm (the preview CSP has no
    script-src allowing wasm instantiation anyway), plus any unrecognized
    extension -- must stay the inert `application/octet-stream` default
    (docs/security.md C8, ADR 0009 amendment).
    """
    allowed_media_types = frozenset(
        {
            "text/html",
            "text/css",
            "text/javascript",
            "application/json",
            "image/png",
            "image/jpeg",
            "image/gif",
            "image/webp",
            "image/avif",
            "image/svg+xml",
            "image/x-icon",
            "font/woff",
            "font/woff2",
            "font/ttf",
            "font/otf",
            "video/mp4",
            "video/webm",
            "audio/mpeg",
            "audio/wav",
            "audio/ogg",
            "audio/mp4",
            "text/plain",
            "text/csv",
            "application/octet-stream",
        }
    )
    registry = default_registry()
    html = registry.get("html")
    sample_extensions = (
        ".html",
        ".htm",
        ".css",
        ".js",
        ".mjs",
        ".json",
        ".map",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".avif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".mp4",
        ".webm",
        ".mp3",
        ".wav",
        ".ogg",
        ".m4a",
        ".txt",
        ".csv",
        ".xml",
        ".wasm",
        ".flac",
        ".mov",
        ".unknown-ext-zzz",
    )
    for ext in sample_extensions:
        assert html.media_type(f"sample{ext}") in allowed_media_types
    for opaque_ext in (".xml", ".wasm", ".flac", ".mov", ".unknown-ext-zzz"):
        assert html.media_type(f"sample{opaque_ext}") == "application/octet-stream"


def test_svg_is_only_ever_media_preview_mode() -> None:
    registry = default_registry()
    svg = registry.get("svg")
    # Must be exactly MEDIA: never SANDBOXED/DOCUMENT, which would let the
    # browser navigate to or frame the SVG directly instead of loading it
    # via <img> (the only safe way to display untrusted SVG).
    assert svg.preview_mode is PreviewMode.MEDIA


def test_unknown_extension_is_octet_stream_and_download_only() -> None:
    registry = default_registry()
    relpath = "mystery.some-unknown-ext"
    assert registry.media_type_for(relpath) == "application/octet-stream"
    kind = registry.detect([relpath])
    assert kind.name == "file"
    assert kind.preview_mode is PreviewMode.DOWNLOAD


def test_text_like_kinds_never_use_a_generic_or_html_content_type() -> None:
    # Every TEXT-preview kind must be an inert text/* or application/json
    # family type -- never text/html or a scriptable type.
    registry = default_registry()
    allowed_prefixes = ("text/", "application/json")
    for kind in registry.all():
        if kind.preview_mode is not PreviewMode.TEXT:
            continue
        for ext in sorted(kind.extensions):
            media_type = kind.media_type(f"sample{ext}")
            assert media_type.startswith(allowed_prefixes)
            assert media_type != "text/html"


def test_double_extension_uses_only_the_final_segment_extension() -> None:
    # 'x.html.png' must never be treated (or typed) as HTML: the registry
    # keys off only the last extension of the final path segment.
    registry = default_registry()
    assert registry.media_type_for("x.html.png") == "image/png"
    assert registry.detect(["x.html.png"]).name == "image"
