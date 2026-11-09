"""JSON content kind: fetched as text and pretty-printed client-side."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {".json": "application/json"}


class JsonKind(SimpleExtensionKind):
    """json, fetched as text and pretty-printed client-side."""

    name = "json"
    label = "JSON"
    renderer = "json"
    preview_mode = PreviewMode.TEXT
    extensions = frozenset(_MEDIA_TYPES)
    render_capped = True
    _media_types = _MEDIA_TYPES
