"""PDF content kind: opened natively from the preview origin, no iframe sandbox.

Chrome refuses to render a PDF inside a `sandbox` CSP, so PDFs get their
own DOCUMENT preview mode (no sandbox attribute) but still a strict CSP
and the separate preview origin (docs/security.md C5).
"""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {".pdf": "application/pdf"}


class PdfKind(SimpleExtensionKind):
    """PDF documents, opened natively from the preview origin."""

    name = "pdf"
    label = "PDF"
    renderer = "pdf"
    preview_mode = PreviewMode.DOCUMENT
    extensions = frozenset(_MEDIA_TYPES)
    _media_types = _MEDIA_TYPES
