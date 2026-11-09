"""Video content kind: mp4/webm/mov, previewed via a <video> element."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
}


class VideoKind(SimpleExtensionKind):
    """mp4/webm/mov, rendered via <video> from the preview origin (Range support)."""

    name = "video"
    label = "Video"
    renderer = "video"
    preview_mode = PreviewMode.MEDIA
    extensions = frozenset(_MEDIA_TYPES)
    _media_types = _MEDIA_TYPES
