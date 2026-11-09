"""Markdown content kind: fetched as text, rendered client-side and sanitized.

Served as `text/markdown`, never `text/html` — the browser never
interprets it directly; the frontend renderer parses it and sanitizes the
result with DOMPurify before insertion (docs/security.md C6).
"""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
}


class MarkdownKind(SimpleExtensionKind):
    """md/markdown, fetched as text and rendered (sanitized) client-side."""

    name = "markdown"
    label = "Markdown"
    renderer = "markdown"
    preview_mode = PreviewMode.TEXT
    extensions = frozenset(_MEDIA_TYPES)
    render_capped = True
    _media_types = _MEDIA_TYPES
