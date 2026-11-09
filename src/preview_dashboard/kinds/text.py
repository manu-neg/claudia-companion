"""Plain-text content kind: txt/log, fetched as text and shown verbatim."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".txt": "text/plain",
    ".log": "text/plain",
}


class TextKind(SimpleExtensionKind):
    """txt/log, fetched as text/plain and shown verbatim."""

    name = "text"
    label = "Text"
    renderer = "text"
    preview_mode = PreviewMode.TEXT
    extensions = frozenset(_MEDIA_TYPES)
    render_capped = True
    _media_types = _MEDIA_TYPES
