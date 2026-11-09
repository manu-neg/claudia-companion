"""Code content kind: source files, always served as text/plain.

Every extension here maps to `text/plain` — never `text/html` or a
scriptable JavaScript type — so a `.js` or `.html`-adjacent source file can
never be executed by the browser regardless of `nosniff` (docs/security.md
C8, I4). Syntax highlighting happens client-side, against the fetched text.
"""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_EXTENSIONS = frozenset(
    {
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
    }
)


class CodeKind(SimpleExtensionKind):
    """Source code, fetched as text/plain and syntax-highlighted client-side."""

    name = "code"
    label = "Code"
    renderer = "code"
    preview_mode = PreviewMode.TEXT
    extensions = _EXTENSIONS
    render_capped = True
    _default_media_type = "text/plain"
