"""Port for the viewer's one write to the admin: forward a dashboard decision (F-CL6).

The viewer never decides: it hands the owner's validated click to the
admin, which re-validates everything and answers one fixed verdict.
"""

from __future__ import annotations

from typing import Protocol

from preview_dashboard.domain.approval_decisions import DecisionCommand, DecisionResult


class ApprovalDecider(Protocol):
    """Sends one decision to the admin and returns its verdict."""

    def decide(self, command: DecisionCommand) -> DecisionResult:
        """Forward `command`; return the admin's verdict.

        Raises:
            StorageUnavailableError: the admin could not be reached or
                answered something unexpected (fail closed: nothing decided here).
        """
        ...
