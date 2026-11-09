"""Choice questions Claude asks the owner: QuestionId, QuestionOption, QuestionState, Question.

A question offers 2..8 fixed options; the owner can only pick one of them
(never free text, ADR 0021). Entities are frozen, slotted dataclasses that
validate on construction; transitions return new instances. Also holds
`AnswerResult`, the outcome of an answer attempt shared by core and notifier.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import NewType

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.models import ItemId, ensure_utc, is_ulid, parse_item_id
from preview_dashboard.domain.text import sanitize_outgoing_line

QuestionId = NewType("QuestionId", str)
"""Canonical ULID string (same syntax as `ItemId`)."""

PROMPT_MAX_CHARS = 200
LABEL_MAX_CHARS = 40
SESSION_LABEL_MAX_CHARS = 40
MIN_OPTIONS = 2
MAX_OPTIONS = 8
# Owner decision D2: 24 h by default; callers may pick 60 s .. 7 d.
DEFAULT_QUESTION_TTL = timedelta(hours=24)
MIN_QUESTION_TTL = timedelta(seconds=60)
MAX_QUESTION_TTL = timedelta(days=7)

# Keys travel inside channel callback data (Telegram: 64 bytes in total),
# so they stay short, lowercase ASCII and free of separators like ':'.
# Public so interface schemas (MCP) reuse it instead of copying it.
OPTION_KEY_PATTERN = r"[a-z0-9_-]{1,16}"
_OPTION_KEY_RE = re.compile(OPTION_KEY_PATTERN)
# Answer sources / channels are plug-in names, same shape as kind names.
_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_ONE_US = timedelta(microseconds=1)


def parse_question_id(raw: object) -> QuestionId:
    """Validate an untrusted value as a QuestionId.

    Raises:
        ValidationError: `raw` is not a canonical ULID string.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid question id")
    return QuestionId(str(raw))


def validate_option_key(raw: object) -> str:
    """Validate an option key (`[a-z0-9_-]{1,16}`).

    Raises:
        ValidationError: anything else.
    """
    if not isinstance(raw, str) or not _OPTION_KEY_RE.fullmatch(raw):
        raise ValidationError("option key must match [a-z0-9_-]{1,16}")
    return raw


def validate_plugin_name(raw: object, what: str) -> str:
    """Validate a channel / answer-source / event-type name (`[a-z][a-z0-9-]{0,31}`).

    Raises:
        ValidationError: anything else.
    """
    if not isinstance(raw, str) or not _NAME_RE.fullmatch(raw):
        raise ValidationError(f"invalid {what} name")
    return raw


def sanitize_option_label(raw: str) -> str:
    """Sanitize an option label: single line, 1..40 chars, >= 1 visible char, no link.

    Raises:
        ValidationError: see `domain.text.sanitize_outgoing_line`.
    """
    return sanitize_outgoing_line(raw, name="option label", max_chars=LABEL_MAX_CHARS)


class QuestionState(StrEnum):
    """Lifecycle state of a question.

    OPEN --answered()--> ANSWERED; OPEN --expired()--> EXPIRED;
    OPEN --cancelled()--> CANCELLED. The three outcomes are terminal.
    """

    OPEN = "open"
    ANSWERED = "answered"
    EXPIRED = "expired"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        """True for ANSWERED, EXPIRED and CANCELLED."""
        return self is not QuestionState.OPEN


class AnswerResult(StrEnum):
    """Outcome of one answer attempt (what the tapping owner is told).

    UNKNOWN covers an unknown question **and** a key the question never
    offered: a forged tap learns nothing about which questions exist.
    """

    RECORDED = "recorded"
    ALREADY_ANSWERED = "already_answered"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class QuestionOption:
    """One choice: a short machine key plus the label the owner sees.

    Raises (on construction):
        ValidationError: bad key syntax, or a label that is not 1..40 chars
            with a visible char after sanitizing.
    """

    key: str
    label: str

    def __post_init__(self) -> None:
        validate_option_key(self.key)
        object.__setattr__(self, "label", sanitize_option_label(self.label))


@dataclass(frozen=True, slots=True, kw_only=True)
class Question:
    """A choice question and, once resolved, its outcome.

    Invariants (`ValidationError` on construction):
    - `id` canonical ULID; `item_id` None or a canonical ULID;
    - `prompt` sanitized single line, 1..200 chars; `session_label` None or
      sanitized 1..40 chars; neither (nor any label) contains a link (C35);
    - 2..8 `QuestionOption`s with unique keys; `default_key` None or one of them;
    - datetimes tz-aware (stored UTC); `created_at < expires_at <=
      created_at + 7 d`; `updated_at >= created_at` (it is the CAS version);
    - OPEN: no answer, no `resolved_at`. ANSWERED: `answer_key` among the
      options, `answer_source` a valid name. EXPIRED/CANCELLED: no answer.
      Terminal states: `created_at <= resolved_at <= updated_at`;
      EXPIRED also `resolved_at >= expires_at`.
    """

    id: QuestionId
    prompt: str
    options: tuple[QuestionOption, ...]
    created_at: datetime
    expires_at: datetime
    updated_at: datetime
    default_key: str | None = None
    item_id: ItemId | None = None
    session_label: str | None = None
    state: QuestionState = QuestionState.OPEN
    answer_key: str | None = None
    answer_source: str | None = None
    resolved_at: datetime | None = None

    def __post_init__(self) -> None:
        parse_question_id(self.id)
        self._set(
            "prompt",
            sanitize_outgoing_line(self.prompt, name="prompt", max_chars=PROMPT_MAX_CHARS),
        )
        self._check_options()
        if self.item_id is not None:
            parse_item_id(self.item_id)
        if self.session_label is not None:
            self._set(
                "session_label",
                sanitize_outgoing_line(
                    self.session_label, name="session label", max_chars=SESSION_LABEL_MAX_CHARS
                ),
            )
        try:
            self._set("state", QuestionState(self.state))
        except ValueError:
            raise ValidationError("invalid question state") from None
        self._check_times()
        self._check_outcome()

    def _set(self, name: str, value: object) -> None:
        # Frozen dataclass: normalization in __post_init__ bypasses __setattr__.
        object.__setattr__(self, name, value)

    def _check_options(self) -> None:
        options = tuple(self.options) if isinstance(self.options, Iterable) else ()
        if not all(isinstance(o, QuestionOption) for o in options):
            raise ValidationError("options must be QuestionOption instances")
        if not MIN_OPTIONS <= len(options) <= MAX_OPTIONS:
            raise ValidationError(f"a question needs {MIN_OPTIONS}..{MAX_OPTIONS} options")
        keys = [o.key for o in options]
        if len(set(keys)) != len(keys):
            raise ValidationError("option keys must be unique")
        self._set("options", options)
        if self.default_key is not None and self.default_key not in keys:
            raise ValidationError("default_key must be one of the option keys")

    def _check_times(self) -> None:
        self._set("created_at", ensure_utc(self.created_at, "created_at"))
        self._set("expires_at", ensure_utc(self.expires_at, "expires_at"))
        self._set("updated_at", ensure_utc(self.updated_at, "updated_at"))
        if self.expires_at <= self.created_at:
            raise ValidationError("expires_at must follow created_at")
        if self.expires_at - self.created_at > MAX_QUESTION_TTL:
            raise ValidationError("a question may stay open for at most 7 days")
        if self.updated_at < self.created_at:
            raise ValidationError("updated_at must not precede created_at")

    def _check_outcome(self) -> None:
        if self.state is QuestionState.OPEN:
            if (self.answer_key, self.answer_source, self.resolved_at) != (None, None, None):
                raise ValidationError("an open question has no outcome")
            return
        if self.resolved_at is None:
            raise ValidationError("a resolved question needs resolved_at")
        self._set("resolved_at", ensure_utc(self.resolved_at, "resolved_at"))
        if not self.created_at <= self.resolved_at <= self.updated_at:
            raise ValidationError("resolved_at must lie between created_at and updated_at")
        if self.state is QuestionState.ANSWERED:
            if self.option(self.answer_key) is None:
                raise ValidationError("answer_key must be one of the option keys")
            validate_plugin_name(self.answer_source, "answer source")
            return
        if self.answer_key is not None or self.answer_source is not None:
            raise ValidationError("only an answered question has an answer")
        if self.state is QuestionState.EXPIRED and self.resolved_at < self.expires_at:
            raise ValidationError("a question cannot expire before expires_at")

    # --- construction --------------------------------------------------------

    @classmethod
    def new(
        cls,
        *,
        id: QuestionId,  # shadows the builtin on purpose: mirrors the field name
        prompt: str,
        options: Iterable[QuestionOption],
        now: datetime,
        expires_at: datetime,
        default_key: str | None = None,
        item_id: ItemId | None = None,
        session_label: str | None = None,
    ) -> Question:
        """Create a fresh OPEN question with `created_at == updated_at == now`."""
        return cls(
            id=id,
            prompt=prompt,
            options=tuple(options),
            created_at=now,
            expires_at=expires_at,
            updated_at=now,
            default_key=default_key,
            item_id=item_id,
            session_label=session_label,
        )

    # --- derived -------------------------------------------------------------

    def option(self, key: object) -> QuestionOption | None:
        """Return the option with exactly this key, or None."""
        return next((o for o in self.options if o.key == key), None)

    @property
    def answer_label(self) -> str | None:
        """Label of the chosen option (ANSWERED only), else None."""
        chosen = self.option(self.answer_key) if self.answer_key is not None else None
        return None if chosen is None else chosen.label

    @property
    def default_label(self) -> str | None:
        """Label of the default option, or None if there is no default."""
        default = self.option(self.default_key) if self.default_key is not None else None
        return None if default is None else default.label

    def is_expired(self, now: datetime) -> bool:
        """True if the question is EXPIRED, or still OPEN with `now >= expires_at`.

        An OPEN question for which this holds is due for `expired()`; it can
        no longer be answered.
        """
        if self.state is QuestionState.EXPIRED:
            return True
        return self.state is QuestionState.OPEN and ensure_utc(now, "now") >= self.expires_at

    def next_change_at(self, now: datetime) -> datetime:
        """`now`, but strictly after `updated_at` (the compare-and-swap version).

        Raises:
            ValidationError: `now` is naive, or `updated_at` is at `datetime.max`.
        """
        try:
            return max(ensure_utc(now, "now"), self.updated_at + _ONE_US)
        except OverflowError:
            raise ValidationError("question timestamp is out of range") from None

    # --- transitions ---------------------------------------------------------

    def answered(self, key: str, source: str, at: datetime) -> Question:
        """Return this question answered with option `key` by `source` at `at`.

        Raises:
            InvalidStateError: not OPEN, or already expired at `at`.
            ValidationError: `key` is not one of the options, `source` is not
                a valid name, or `at` precedes `updated_at`.
        """
        at = self._begin_transition(at)
        if self.option(key) is None:
            raise ValidationError("unknown option key")
        validate_plugin_name(source, "answer source")
        if at >= self.expires_at:
            raise InvalidStateError("question has expired")
        return dataclasses.replace(
            self,
            state=QuestionState.ANSWERED,
            answer_key=key,
            answer_source=source,
            resolved_at=at,
            updated_at=at,
        )

    def expired(self, at: datetime) -> Question:
        """Return this question expired at `at` (never auto-answered, owner decision D2).

        Raises:
            InvalidStateError: not OPEN, or `at < expires_at`.
            ValidationError: `at` precedes `updated_at`.
        """
        at = self._begin_transition(at)
        if at < self.expires_at:
            raise InvalidStateError("question has not expired yet")
        return dataclasses.replace(self, state=QuestionState.EXPIRED, resolved_at=at, updated_at=at)

    def cancelled(self, at: datetime) -> Question:
        """Return this question withdrawn by the asker at `at`.

        Raises:
            InvalidStateError: not OPEN.
            ValidationError: `at` precedes `updated_at`.
        """
        at = self._begin_transition(at)
        return dataclasses.replace(
            self, state=QuestionState.CANCELLED, resolved_at=at, updated_at=at
        )

    def _begin_transition(self, at: datetime) -> datetime:
        if self.state is not QuestionState.OPEN:
            raise InvalidStateError(f"question is already {self.state}")
        at = ensure_utc(at, "at")
        if at < self.updated_at:
            raise ValidationError("transition time must not precede updated_at")
        return at
