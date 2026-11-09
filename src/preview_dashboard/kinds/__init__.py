"""Content-kind registry (Registry + Strategy) and the built-in kinds.

`default_registry()` is the single place that lists every built-in kind;
adding a new one means adding a module here and one line to that function
(see docs/extending.md, "Adding a content kind").
"""

from __future__ import annotations

from preview_dashboard.kinds.audio import AudioKind
from preview_dashboard.kinds.base import ContentKind, KindRegistry, PreviewMode
from preview_dashboard.kinds.code import CodeKind
from preview_dashboard.kinds.csv import CsvKind
from preview_dashboard.kinds.diff import DiffKind
from preview_dashboard.kinds.file import FileKind
from preview_dashboard.kinds.html import HtmlKind
from preview_dashboard.kinds.image import ImageKind
from preview_dashboard.kinds.json import JsonKind
from preview_dashboard.kinds.markdown import MarkdownKind
from preview_dashboard.kinds.pdf import PdfKind
from preview_dashboard.kinds.progress import ProgressKind
from preview_dashboard.kinds.svg import SvgKind
from preview_dashboard.kinds.text import TextKind
from preview_dashboard.kinds.video import VideoKind

__all__ = [
    "ContentKind",
    "KindRegistry",
    "PreviewMode",
    "default_registry",
]


def default_registry() -> KindRegistry:
    """Build a `KindRegistry` with every built-in kind registered.

    Order matters only for tie-breaking in `KindRegistry.detect()` (first
    registered wins a tie) and is otherwise cosmetic; `file` is last so it
    only ever wins as the last resort.
    """
    registry = KindRegistry()
    for kind in (
        ImageKind(),
        SvgKind(),
        HtmlKind(),
        VideoKind(),
        AudioKind(),
        PdfKind(),
        MarkdownKind(),
        CodeKind(),
        JsonKind(),
        CsvKind(),
        TextKind(),
        DiffKind(),
        # Never auto-detected (confidence 1, and `json` claims progress.json
        # first); registered before `file` so the tie on hints can't matter.
        ProgressKind(),
        FileKind(),
    ):
        registry.register(kind)
    return registry
