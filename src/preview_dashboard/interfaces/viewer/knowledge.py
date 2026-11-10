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
from preview_dashboard.application.dashboard_decisions import ForwardedDecisions
from preview_dashboard.application.kb_graph import KbGraphService
from preview_dashboard.application.pending_approvals import PendingApprovalsService
from preview_dashboard.config import Settings
from preview_dashboard.ports.approval_decisions import ApprovalDecider


@dataclass(frozen=True, slots=True)
class Knowledge:
    """Knowledge-map use cases; `graph` None = the map is off (every KB route is a 404).

    `decisions` None = the panel is read-only (no Approve/Deny buttons, the
    decision route is a 404); set only when `dashboard_decisions_active`
    and a viewer token is loaded (F-CL6).
    """

    graph: KbGraphService | None
    approvals: PendingApprovalsService
    decisions: ForwardedDecisions | None = None


def build_knowledge(settings: Settings, *, decider: ApprovalDecider | None = None) -> Knowledge:
    """Wire the KB reader, the approvals snapshot reader and (optionally) decisions.

    Nothing is opened here: each request re-checks and re-walks (fail closed at use).
    Decisions need the snapshot too: the owner must see what he decides.
    """
    clock = SystemClock()
    graph = (
        KbGraphService(FsKbReader(settings.kb_root), clock)
        if settings.kb_root is not None
        else None
    )
    snapshot = settings.claudia_approvals_snapshot
    source = FileApprovalsSnapshot(snapshot) if snapshot is not None else None
    decisions = (
        ForwardedDecisions(decider)
        if decider is not None and source is not None and settings.dashboard_decisions_active
        else None
    )
    return Knowledge(
        graph=graph, approvals=PendingApprovalsService(source, clock), decisions=decisions
    )
