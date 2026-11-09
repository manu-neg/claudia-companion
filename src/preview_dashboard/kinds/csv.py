"""CSV/TSV content kind: fetched as text and rendered as a table client-side."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
}


class CsvKind(SimpleExtensionKind):
    """csv/tsv, fetched as text and rendered as a table client-side."""

    name = "csv"
    label = "CSV"
    renderer = "csv"
    preview_mode = PreviewMode.TEXT
    extensions = frozenset(_MEDIA_TYPES)
    render_capped = True
    _media_types = _MEDIA_TYPES
