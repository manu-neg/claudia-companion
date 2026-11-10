"""Approve/Deny from the dashboard panel (F-CL6): admin service + viewer-side forwarder.

`DashboardDecisionService` is the admin side; `ForwardedDecisions` is the
viewer side (click budget, then the `ApprovalDecider` port). The viewer
forwards the owner's click as `{request_id, decision, code}`; nothing it
says is trusted. Here every attempt is charged to a small in-process
budget first (a looping or compromised viewer can't flood the admin),
then re-validated: Deny goes through the same CAS as a Telegram Deny
tap, Approve through `StepUpService.submit_dashboard_code` (same
secret, replay mark, wrong-code counters and lockout as Telegram codes).
First decision wins across both surfaces. Codes are never logged. Pure
core: no framework imports.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Final

from preview_dashboard.application.approvals import ApprovalService, SlidingBudget
from preview_dashboard.application.stepup import StepUpService
from preview_dashboard.domain.approval_decisions import (
    Decision,
    DecisionCommand,
    DecisionResult,
)
from preview_dashboard.domain.errors import RateLimitedError
from preview_dashboard.ports.approval_decisions import ApprovalDecider

logger = logging.getLogger("preview_dashboard.approvals")

# A person clicks a handful of times; 20 per 10 min leaves room for typos while
# the TOTP lockout (5 wrong / 15 min) stays the real bound on code guesses.
DASHBOARD_DECISION_BUDGET: Final = 20
DASHBOARD_DECISION_WINDOW: Final = timedelta(minutes=10)


class DashboardDecisionService:
    """Decide one approval request for the owner's dashboard click (C46/C47).

    Args:
        approvals: the approval lifecycle (Deny, lookups).
        stepup: verifies the code and approves (the only path to APPROVED).
        limit / window: the attempt budget (every attempt counts).
        monotonic: time source of the budget (tests inject one).
    """

    def __init__(
        self,
        *,
        approvals: ApprovalService,
        stepup: StepUpService,
        limit: int = DASHBOARD_DECISION_BUDGET,
        window: timedelta = DASHBOARD_DECISION_WINDOW,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._approvals = approvals
        self._stepup = stepup
        self._budget = SlidingBudget(limit=limit, window=window, monotonic=monotonic)

    def decide(self, command: DecisionCommand) -> DecisionResult:
        """Apply one validated decision; returns the verdict (never raises on a bad id)."""
        if not self._budget.has_room():
            logger.warning("dashboard decision refused: attempt budget used up")
            return DecisionResult.RATE_LIMITED
        self._budget.charge()
        if command.decision is Decision.DENY:
            result = self._approvals.deny_from_dashboard(command.approval_id)
        else:
            # parse_decision_command guarantees a code for APPROVE.
            result = self._stepup.submit_dashboard_code(command.approval_id, command.code or "")
        logger.info("dashboard decision: %s -> %s", command.decision, result)
        return result


class ForwardedDecisions:
    """Viewer side: rate-limit the owner's clicks, then forward them to the admin.

    The viewer holds no secret and decides nothing; this only keeps a
    looping page from hammering the admin socket. The admin's own budget
    (`DashboardDecisionService`) is the one that counts.

    Args:
        decider: the admin client (port).
        limit / window: clicks allowed per window (every attempt counts).
        monotonic: time source (tests inject one).
    """

    def __init__(
        self,
        decider: ApprovalDecider,
        *,
        limit: int = DASHBOARD_DECISION_BUDGET,
        window: timedelta = DASHBOARD_DECISION_WINDOW,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._decider = decider
        self._budget = SlidingBudget(limit=limit, window=window, monotonic=monotonic)

    def decide(self, command: DecisionCommand) -> DecisionResult:
        """Forward one decision.

        Raises:
            RateLimitedError: too many clicks in the window (nothing forwarded).
            StorageUnavailableError: the admin could not be reached.
        """
        if not self._budget.has_room():
            raise RateLimitedError("too many decisions; try again later")
        self._budget.charge()
        return self._decider.decide(command)


__all__ = [
    "DASHBOARD_DECISION_BUDGET",
    "DASHBOARD_DECISION_WINDOW",
    "DashboardDecisionService",
    "ForwardedDecisions",
]
