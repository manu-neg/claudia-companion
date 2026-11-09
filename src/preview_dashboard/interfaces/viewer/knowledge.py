"""The dashboard app's knowledge-map services and their wiring from `Settings` (C57).

`Knowledge` is what `routes/kb.py` reads from `app.state.knowledge`.
`build_knowledge` is the viewer entry point's composition step for these
read-only sources (the core in `bootstrap.py` never sees the KB): no
`kb_root` means the map is off; no snapshot path means the approvals panel
can confirm nothing. Only the dashboard app gets it; the preview app has no
KB routes at all.
"""

from __future__ import annotations

from dataclasses import dataclass

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.kb_reader import FileApprovalsSnapshot, FsKbReader
from preview_dashboard.application.kb_graph import KbGraphService
from preview_dashboard.application.pending_approvals import PendingApprovalsService
from preview_dashboard.config import Settings


@dataclass(frozen=True, slots=True)
class Knowledge:
    """Knowledge-map use cases; `graph` None = the map is off (every KB route is a 404)."""

    graph: KbGraphService | None
    approvals: PendingApprovalsService


def build_knowledge(settings: Settings) -> Knowledge:
    """Wire the KB reader and the approvals snapshot reader from `settings`.

    Nothing is opened here: each request re-checks and re-walks (fail closed at use).
    """
    clock = SystemClock()
    graph = (
        KbGraphService(FsKbReader(settings.kb_root), clock)
        if settings.kb_root is not None
        else None
    )
    snapshot = settings.claudia_approvals_snapshot
    source = FileApprovalsSnapshot(snapshot) if snapshot is not None else None
    return Knowledge(graph=graph, approvals=PendingApprovalsService(source, clock))
