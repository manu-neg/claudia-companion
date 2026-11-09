"""Image content kind: raster formats, previewed via an <img> element.

Does not include SVG — SVG can embed scripts, so it gets its own kind
(kinds/svg.py) that is still MEDIA but rendered only via <img>, never
navigated to directly (docs/security.md C5).
"""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
}


class ImageKind(SimpleExtensionKind):
    """png/jpg/jpeg/gif/webp/avif, rendered via <img> from the preview origin."""

    name = "image"
    label = "Image"
    renderer = "image"
    preview_mode = PreviewMode.MEDIA
    extensions = frozenset(_MEDIA_TYPES)
    _media_types = _MEDIA_TYPES
