"""File content kind: the fallback for anything that fits no specific kind.

Always available as a last resort (`detect()` returns 1, the lowest
positive confidence, for any non-empty input) so every publish succeeds
with *some* kind, even for extensions the registry doesn't know — it is
never previewed, only downloaded opaquely as `application/octet-stream`.
"""

from __future__ import annotations

from collections.abc import Sequence

from preview_dashboard.kinds.base import PreviewMode


class FileKind:
    """Opaque fallback: downloaded, never previewed."""

    name = "file"
    label = "File"
    renderer = "file"
    preview_mode = PreviewMode.DOWNLOAD
    extensions: frozenset[str] = frozenset()
    render_capped = False

    def media_type(self, relpath: str) -> str:
        return "application/octet-stream"

    def detect(self, relpaths: Sequence[str]) -> int:
        return 1 if relpaths else 0

    def entry_file(self, relpaths: Sequence[str]) -> str:
        # No preview is ever shown, but Item.entry_file must still name one
        # of the item's files; pick deterministically.
        return min(relpaths)
