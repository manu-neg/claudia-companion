"""Step-up ports: the TOTP secret and the persisted step-up counters (ADR 0031, C47).

Security obligations for every implementation (docs/security.md C12, C47):
- **Secret:** loaded with the token-file rules (private mode, trusted owner
  and group, no symlink, no ACL); missing or bad -> `StorageUnavailableError`
  so every code is refused (fail closed). Never logged, never returned.
- **State:** survives restarts (lockout and replay mark persist); unreadable
  or tampered state -> `StorageUnavailableError` (fail closed), never a
  silent reset to "no failures". Every load-modify-save runs inside
  `exclusive()`, a lock shared by all writer processes (storage-totp-3).
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol

from preview_dashboard.domain.totp import StepUpState


class TotpSecretSource(Protocol):
    """Reads the TOTP secret for one verification."""

    def load(self) -> bytes:
        """Return the raw secret bytes (20..64).

        Raises:
            StorageUnavailableError: the secret file is missing, unsafe or malformed.
        """
        ...


class StepUpStateStore(Protocol):
    """Loads and saves `StepUpState` (the admin per code; `claudia totp setup` once)."""

    def load(self) -> StepUpState:
        """Return the stored state (a fresh state if none was ever saved).

        Raises:
            StorageUnavailableError: the state exists but can't be read or trusted.
        """
        ...

    def save(self, state: StepUpState) -> None:
        """Persist `state` atomically (all or nothing).

        Raises:
            StorageUnavailableError: the state could not be written.
        """
        ...

    def exclusive(self) -> AbstractContextManager[None]:
        """Hold the cross-process writer lock for one load-modify-save (blocks until free).

        Raises:
            StorageUnavailableError: the lock can't be taken safely (on enter).
        """
        ...
