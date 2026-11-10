"""StepUpService: verify the owner's authenticator code and approve the TAPPED request (C47).

The only path to APPROVED (C46). Order per code, under one lock (a thread
lock plus the state store's cross-process `exclusive()`; it can't be taken
-> refused): sender is
the configured owner -> not a re-delivered message (exact `update_id` +
`message_id` seen in the last 24 h; `duplicate`) -> lockout check ->
exactly one TAPPED request (none = a wrong code) -> secret load (fail
closed) -> RFC 6238 match in steps -1..+1, never a step at or before the
last accepted one (no replay) -> persist the new state -> approve.
5 wrong codes in 15 min lock every code out for 15 min (persisted); each
wrong code raises one "Wrong authenticator code" alert (shared C37 budget).
Codes are never logged, stored or returned. A code typed into the
dashboard panel (F-CL6, `submit_dashboard_code`) names its request and
shares the same lock, replay mark, counters, lockout and alert.
Pure core: ports only.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from enum import StrEnum
from typing import Final

from preview_dashboard.application.approvals import ApprovalService
from preview_dashboard.domain.approval_decisions import DecisionResult
from preview_dashboard.domain.errors import DomainError, StorageUnavailableError
from preview_dashboard.domain.totp import StepUpState, matching_step, parse_code, time_step
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.stepup import StepUpStateStore, TotpSecretSource

logger = logging.getLogger("preview_dashboard.stepup")

WRONG_CODE_TITLE: Final = "Wrong authenticator code"


class CodeResult(StrEnum):
    """What the notifier learns about a code (never which part was wrong).

    Values equal `wire.notifier_messages.CodeResult` (a test keeps them equal).
    A server-side failure (secret or state unusable) is `refused` too: fail
    closed, details only in the admin log.
    """

    ACCEPTED = "accepted"
    REFUSED = "refused"
    LOCKED = "locked"
    DUPLICATE = "duplicate"


class StepUpService:
    """Checks TOTP codes in the admin process only (C47).

    Args:
        secret: the TOTP secret source (re-read per code).
        state: persisted replay mark, wrong-code counters, last code update.
        approvals: the approval service (finds and approves the TAPPED request).
        clock: time source (wall clock: TOTP is defined on Unix time).
        owner_chat_id: the configured owner (None: every code refused).
        alert: raises the wrong-code alert; its errors (e.g. the alert
            budget is used up) are logged, never surfaced.
    """

    def __init__(
        self,
        *,
        secret: TotpSecretSource,
        state: StepUpStateStore,
        approvals: ApprovalService,
        clock: Clock,
        owner_chat_id: int | None,
        alert: Callable[[], object] | None = None,
    ) -> None:
        self._secret = secret
        self._state = state
        self._approvals = approvals
        self._clock = clock
        self._owner = owner_chat_id
        self._alert = alert
        # One code at a time: the read-check-write of the state must not interleave.
        self._lock = threading.Lock()

    def submit_code(
        self, code: str, *, update_id: int, message_id: int, sender_id: int
    ) -> CodeResult:
        """Verify one code against the single TAPPED request; approve it on success.

        `update_id` + `message_id` identify the Telegram message: the same
        pair again within 24 h is `DUPLICATE` (a re-delivery, not a try).

        Raises:
            ValidationError: `code` is not exactly six ASCII digits, or an id
                is out of range (a broken client; counts as nothing).
        """
        parse_code(code)
        if self._owner is None or sender_id != self._owner:
            # The notifier already checks this; a mismatch is a bug, not a guess.
            logger.warning("step-up refused: code not from the configured owner")
            return CodeResult.REFUSED
        with self._lock:
            locked = False
            try:
                # Cross-process: root's `claudia totp setup` writes the same state.
                with self._state.exclusive():
                    locked = True
                    return self._submit(code, update_id, message_id)
            except StorageUnavailableError:
                if locked:
                    raise  # not the lock: keep the error as before
                logger.warning("step-up refused: state lock unavailable")
                return CodeResult.REFUSED

    def _submit(self, code: str, update_id: int, message_id: int) -> CodeResult:
        now = int(self._clock.now().timestamp())
        try:
            state = self._state.load()
        except StorageUnavailableError:
            logger.warning("step-up refused: state unavailable")
            return CodeResult.REFUSED
        if state.is_seen_code(update_id, message_id, now):
            logger.info("step-up: re-delivered code message ignored")
            return CodeResult.DUPLICATE
        state = state.with_seen_code(update_id, message_id, now)
        if state.is_locked(now):
            logger.warning("step-up refused: locked out")
            return self._save_only(state, CodeResult.LOCKED)
        tapped = self._approvals.tapped_requests()
        if len(tapped) > 1:
            # Can't tell which action the code is for: refuse, not the owner's fault.
            logger.warning("step-up refused: %d tapped requests", len(tapped))
            return self._save_only(state, CodeResult.REFUSED)
        if not tapped:
            # A code with nothing awaiting it counts as wrong (C46): no free guesses.
            return self._wrong(state, now, reason="no tapped request")
        try:
            secret = self._secret.load()
        except StorageUnavailableError:
            return self._save_only(state, CodeResult.REFUSED)
        step = matching_step(secret, code, time_step(now), after_step=state.last_step)
        del secret
        if step is None:
            return self._wrong(state, now, reason="code mismatch or replay")
        # Burn the step before approving: a crash after this can't allow a replay.
        burned = self._save_only(state.with_success(step), CodeResult.ACCEPTED)
        if burned is not CodeResult.ACCEPTED:
            return CodeResult.REFUSED
        if not self._approvals.approve(tapped[0]):
            logger.info("step-up: code valid but the request expired or changed")
            return CodeResult.REFUSED
        logger.info("step-up: code accepted, request %s approved", tapped[0].id)
        return CodeResult.ACCEPTED

    def submit_dashboard_code(self, approval_id: str, code: str) -> DecisionResult:
        """Verify a code typed into the dashboard panel; approve that one request (F-CL6).

        Same lock, secret, replay mark, wrong-code counters, lockout and alert
        as Telegram codes (one shared attempt budget). Differences: the
        request is named (no "exactly one TAPPED" rule; it may be PENDING or
        TAPPED), and there is no Telegram message to de-duplicate. A request
        that can't be decided is reported without checking the code, so
        nothing about the code is learned and nothing is counted.

        Raises:
            ValidationError: `code` is not exactly six ASCII digits.
        """
        parse_code(code)
        with self._lock:
            locked = False
            try:
                with self._state.exclusive():
                    locked = True
                    return self._submit_named(approval_id, code)
            except StorageUnavailableError:
                if locked:
                    raise
                logger.warning("step-up refused: state lock unavailable")
                return DecisionResult.REFUSED

    def _submit_named(self, approval_id: str, code: str) -> DecisionResult:
        now = int(self._clock.now().timestamp())
        try:
            state = self._state.load()
        except StorageUnavailableError:
            logger.warning("step-up refused: state unavailable")
            return DecisionResult.REFUSED
        if state.is_locked(now):
            logger.warning("step-up refused: locked out (dashboard)")
            return DecisionResult.LOCKED
        verdict, request = self._approvals.open_for_decision(approval_id)
        if verdict is not None or request is None:
            return verdict or DecisionResult.UNKNOWN
        try:
            secret = self._secret.load()
        except StorageUnavailableError:
            return DecisionResult.REFUSED
        step = matching_step(secret, code, time_step(now), after_step=state.last_step)
        del secret
        if step is None:
            wrong = self._wrong(state, now, reason="dashboard code mismatch or replay")
            if wrong is CodeResult.LOCKED:
                return DecisionResult.LOCKED
            return DecisionResult.WRONG_CODE
        # Burn the step before approving: a crash after this can't allow a replay.
        burned = self._save_only(state.with_success(step), CodeResult.ACCEPTED)
        if burned is not CodeResult.ACCEPTED:
            return DecisionResult.REFUSED
        return self._approvals.approve_with_verified_code(request)

    def _save_only(self, state: StepUpState, result: CodeResult) -> CodeResult:
        try:
            self._state.save(state)
        except StorageUnavailableError:
            logger.warning("step-up refused: state could not be saved")
            return CodeResult.REFUSED
        return result

    def _wrong(self, state: StepUpState, now: int, *, reason: str) -> CodeResult:
        updated = state.with_failure(now)
        # Refused either way; a failed save is logged by `_save_only`, the alert still goes.
        self._save_only(updated, CodeResult.REFUSED)
        locked = updated.is_locked(now)
        logger.warning("step-up refused: %s%s", reason, " (lockout started)" if locked else "")
        self._raise_alert()
        return CodeResult.LOCKED if locked else CodeResult.REFUSED

    def _raise_alert(self) -> None:
        if self._alert is None:
            return
        try:
            self._alert()
        except DomainError as exc:
            logger.warning("wrong-code alert not sent: %s", type(exc).__name__)
