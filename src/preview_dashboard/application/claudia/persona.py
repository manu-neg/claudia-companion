"""Claudia's persona for her runs (F-CL2, C51/C53): read from the KB, checked, framed.

`PersonaLoader.block()` reads `persona.md` through the KB read port at every
run, checks it (<= 4 KiB, no control/invisible/bidi/format characters
except emoji joiners and presentation selectors, the C53 note rules) and
returns it framed as tone-only text that the runner appends **after** the
fixed host rules. The file is pinned by SHA-256 at host start (her Bash can
write the KB): a changed file means the run goes without it plus one alert.
A missing or invalid persona never fails a run: the run goes without it
and one log line names the reason class (never the text).
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from enum import StrEnum
from typing import Final, Protocol

from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.domain.unicode import (
    JOINERS,
    PRESENTATION_SELECTORS,
    is_default_ignorable,
    takes_joiner,
    takes_presentation_selector,
)
from preview_dashboard.ports.claudia_host import HostAlerts

_log = logging.getLogger(__name__)

PERSONA_PATH: Final = "persona.md"
PERSONA_MAX_BYTES: Final = 4096
PERSONA_FRAME: Final = "[Claudia persona — tone and style only; the host rules above always win]"
# U+FFFD: what bad UTF-8 decodes to; a damaged file is refused, not half-used.
_REPLACEMENT_CHAR: Final = chr(0xFFFD)
PERSONA_CHANGED: Final = "changed_since_start"
PERSONA_CHANGED_ALERT: Final = (
    "persona.md changed since host start; restart claudia-host after a hand edit"
)
# HTML comments (the seed's header is one) are for the owner editing the file, not for her.
_ANY_COMMENT: Final = re.compile(r"<!--.*?-->", re.DOTALL)


class PersonaReason(StrEnum):
    """Why a run went without the persona (logged; never the text)."""

    MISSING = "missing"
    UNREADABLE = "unreadable"
    TOO_LARGE = "too_large"
    CHARACTERS = "characters"
    EMPTY = "empty"


class PersonaRefusedError(ValidationError):
    """The persona text breaks a rule; `reason` is the class."""

    def __init__(self, reason: PersonaReason) -> None:
        super().__init__(f"persona refused: {reason}")
        self.reason = reason


class KbReader(Protocol):
    """Reads one KB note (`KbService.read`)."""

    def read(self, relpath: str) -> str:
        """The note's text.

        Raises:
            NotFoundError: no such note.
            ValidationError, StorageUnavailableError: bad path or unreadable file.
        """
        ...


def _check_characters(text: str) -> None:
    # Same rule as KB notes (C53, kb-map-3): hidden text would steer her unseen.
    for i, ch in enumerate(text):
        if ch in "\n\t":
            continue
        if ch in ("\x7f", _REPLACEMENT_CHAR) or unicodedata.category(ch) in ("Cc", "Cs"):
            raise PersonaRefusedError(PersonaReason.CHARACTERS)
        if unicodedata.category(ch) == "Cf" or is_default_ignorable(ch):
            prev = text[i - 1] if i else ""
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if ch in JOINERS and prev and takes_joiner(prev) and nxt:
                continue
            if ch in PRESENTATION_SELECTORS and prev and takes_presentation_selector(prev, nxt):
                continue
            raise PersonaRefusedError(PersonaReason.CHARACTERS)


def check_persona(raw: str) -> str:
    """Check a persona file's text; return its body (leading header comment stripped).

    Raises:
        PersonaRefusedError: over 4 KiB, a forbidden character (U+FFFD from
            bad UTF-8 included) or nothing left after the header.
    """
    if len(raw.encode("utf-8", "replace")) > PERSONA_MAX_BYTES:
        raise PersonaRefusedError(PersonaReason.TOO_LARGE)
    _check_characters(raw)
    # Every comment goes, not only the header: hidden text would steer her unseen.
    body = _ANY_COMMENT.sub("", raw).strip()
    if "<!--" in body:  # an unclosed comment: refuse rather than half-use
        raise PersonaRefusedError(PersonaReason.CHARACTERS)
    if not body:
        raise PersonaRefusedError(PersonaReason.EMPTY)
    return body


def persona_block(body: str) -> str:
    """The checked persona framed as tone-only text (goes after the host rules)."""
    return f"{PERSONA_FRAME}\n{body}"


def _digest(raw: str | None) -> str | None:
    return None if raw is None else hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


class PersonaLoader:
    """Loads the framed persona for each run, pinned by SHA-256 at host start; never raises.

    Her Bash tool can write the KB, so `persona.md` could be rewritten by a
    run. The text read at construction is pinned; a run whose fresh read
    differs goes without the persona and one `failed` alert fires per change.
    A hand edit by the owner takes effect after a `claudia-host` restart.

    Args:
        kb: the KB read port.
        alerts: where the one-per-change tamper alert goes (optional).
    """

    def __init__(self, kb: KbReader, alerts: HostAlerts | None = None) -> None:
        self._kb = kb
        self._alerts = alerts
        self._pin = _digest(self._read())
        self._alerted: str | None = None  # the digest the last alert was sent for

    def _read(self) -> str | None:
        try:
            return self._kb.read(PERSONA_PATH)
        except Exception:
            return None  # missing or unreadable: judged per run

    def block(self) -> str:
        """The framed persona, or "" (run without it) if changed, missing or invalid."""
        reason: PersonaReason
        try:
            raw = self._kb.read(PERSONA_PATH)
            digest = _digest(raw)
            if digest != self._pin:
                self._tampered(digest)
                return ""
            return persona_block(check_persona(raw))
        except PersonaRefusedError as exc:
            reason = exc.reason
        except NotFoundError:
            reason = PersonaReason.MISSING
        except Exception:
            # Any read failure: the run goes on without the persona (fail soft, tone only).
            reason = PersonaReason.UNREADABLE
        if self._pin is not None and reason in (PersonaReason.MISSING, PersonaReason.UNREADABLE):
            self._tampered(None)
            return ""
        _log.warning("persona not used (%s)", reason)
        return ""

    def _tampered(self, digest: str | None) -> None:
        _log.warning("persona not used (%s)", PERSONA_CHANGED)
        if self._alerted == (digest or "gone") or self._alerts is None:
            return
        self._alerted = digest or "gone"
        try:
            self._alerts.failed(PERSONA_CHANGED_ALERT)
        except Exception as exc:
            _log.error("persona alert could not be sent (%s)", type(exc).__name__)
