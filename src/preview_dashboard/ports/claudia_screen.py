"""Screen port of the Claudia host: screens one owner message before Claudia sees it (C48).

Defined by unit M4b (the host calls it), implemented by unit M4a
(`application/claudia/screening.py`: parser OR strict Haiku, degraded mode).
The host only reads the verdict: `ok` -> full tool set, `flagged` /
`degraded` -> read-only turn, actions need a code (C48, C51).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from preview_dashboard.domain.owner_messages import OwnerMessage


class ScreenVerdict(StrEnum):
    """Outcome of screening one message (C48)."""

    OK = "ok"
    FLAGGED = "flagged"
    # The screen itself was unavailable (CLI missing, limits): fail closed to read-only.
    DEGRADED = "degraded"


class ScreenHealth(StrEnum):
    """Screen health for `/status` and the admin health report (same values as the wire)."""

    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass(frozen=True, slots=True, kw_only=True)
class ScreenResult:
    """One message's screening result.

    Attributes:
        verdict: ok | flagged | degraded.
        reasons: short fixed reason labels (never message text: they may be logged).
        parser_hits: names of the parser rules that matched (never message text).
    """

    verdict: ScreenVerdict
    reasons: tuple[str, ...] = ()
    parser_hits: tuple[str, ...] = ()

    @property
    def actionable(self) -> bool:
        """True only for `ok`: anything else runs with the read-only tool set (C48, C51)."""
        return self.verdict is ScreenVerdict.OK


class Screen(Protocol):
    """Screens owner messages (parser first, then strict Haiku; C48)."""

    def screen(self, message: OwnerMessage) -> ScreenResult:
        """Screen one message; never raises for screen failures.

        A timeout, invalid output or an unavailable screen yields `flagged`
        or `degraded`, never `ok` (fail closed). A forwarded message is
        always at least `flagged`.
        """
        ...

    def health(self) -> ScreenHealth:
        """Current screen health (for `/status` and `POST /v1/claudia/health`)."""
        ...
