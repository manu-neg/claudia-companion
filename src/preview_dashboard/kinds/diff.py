"""Diff/patch content kind: fetched as text and rendered with diff highlighting."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".diff": "text/x-diff",
    ".patch": "text/x-diff",
}


class DiffKind(SimpleExtensionKind):
    """diff/patch, fetched as text/x-diff and rendered with diff highlighting."""

    name = "diff"
    label = "Diff"
    renderer = "diff"
    preview_mode = PreviewMode.TEXT
    extensions = frozenset(_MEDIA_TYPES)
    render_capped = True
    _media_types = _MEDIA_TYPES
