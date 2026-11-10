"""Owner free-text messages for Claudia (ADR 0031, docs/security.md C44): the inbox entity.

Holds `OwnerMessageId`, `InboxState`, `OwnerMessage` and the pure rules the
notifier and the admin share: who may send (`is_owner_private_message`),
what is an authenticator code (`is_code_message`) and the redaction of
code-like digit runs inside any other text (`redact_code_runs`). The text
is untrusted and kept verbatim apart from that redaction, so the screen
(C48) still sees invisible and look-alike characters. Voice notes and
photos (C61) are rows of their own `kind` whose text is the caption.
"""

from __future__ import annotations

import dataclasses
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import NewType

from preview_dashboard.domain.errors import InvalidStateError, ValidationError
from preview_dashboard.domain.models import ensure_utc, is_ulid
from preview_dashboard.domain.owner_media import MessageKind, media_max_bytes

OwnerMessageId = NewType("OwnerMessageId", str)
"""Canonical ULID string, assigned by the admin when it stores the message."""

# Telegram's own limit for one text message; longer input is not a message.
MESSAGE_MAX_CHARS = 4096
# Telegram caps a quote at 1024 chars.
QUOTE_MAX_CHARS = 1024
# Marker replacing a code-like digit run (contains no digit: redaction is idempotent).
CODE_REDACTED = "[code redacted]"
# Redaction may lengthen text; the stored bound must allow the worst case.
# One char stands for at most 2 digits after NFKC (e.g. `㉑` -> "21", a test
# proves this for every code point), so 6 digits take >= 3 chars plus one
# separator: 4 chars -> 15 + 1 = 4x. 5x leaves headroom (S-C1 S7).
STORED_EXPANSION_FACTOR = 5
STORED_MESSAGE_MAX_CHARS = STORED_EXPANSION_FACTOR * MESSAGE_MAX_CHARS
STORED_QUOTE_MAX_CHARS = STORED_EXPANSION_FACTOR * QUOTE_MAX_CHARS
CODE_DIGITS = 6
# Telegram ids are positive 64-bit integers (SQLite INTEGER range).
_MAX_TELEGRAM_ID = 2**63 - 1

# A code is exactly six ASCII digits once ASCII spaces are removed (C44):
# full-width / other-script digits are never a code, so they stay in the
# text and are redacted like any other run.
_CODE_RE = re.compile(r"[0-9]{6}")


def parse_owner_message_id(raw: object) -> OwnerMessageId:
    """Validate an untrusted value as an OwnerMessageId.

    Raises:
        ValidationError: `raw` is not a canonical ULID string.
    """
    if not is_ulid(raw):
        raise ValidationError("invalid owner message id")
    return OwnerMessageId(str(raw))


def is_owner_private_message(
    *,
    from_id: object,
    chat_id: object,
    chat_type: object,
    from_is_bot: object,
    owner_chat_id: object,
) -> bool:
    """True only for a private, non-bot message from the configured owner (C44).

    `from.id == chat.id == owner_chat_id`, chat type `private`, `is_bot`
    exactly False. Anything of the wrong type (bools posing as ints, a
    missing owner id) is False: fail closed.
    """
    ids = (from_id, chat_id, owner_chat_id)
    if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in ids):
        return False
    return from_id == chat_id == owner_chat_id and chat_type == "private" and from_is_bot is False


def is_code_message(text: object) -> bool:
    """True if the whole text, ASCII spaces removed, is exactly ASCII `[0-9]{6}` (C44).

    Such a message is an authenticator code: it never enters the inbox.
    """
    return isinstance(text, str) and _CODE_RE.fullmatch(text.replace(" ", "")) is not None


def _digit_count(ch: str) -> int:
    """How many decimal digits `ch` stands for after NFKC (0 = not a digit char).

    Per char, so the original text can be rewritten in place: `①` -> 1,
    `⑽` -> 0 (NFKC gives `(10)`, which is not only digits).
    """
    folded = unicodedata.normalize("NFKC", ch)
    return len(folded) if folded.isdecimal() else 0


# Narrow separators allowed per gap (storage-totp-4): "123-456", "123.456",
# "123\t456", "123\n456", "123<ZWSP>456" are one code typed differently.
MAX_GAP_SEPARATORS = 2
# Across a separator, only groups of <= 3 digits form a code (3+3, 2+2+2):
# ISO dates ("2026-11-08": 4+2+2) are no code anyone types, so they stay.
MAX_SEPARATED_GROUP = 3
_SEPARATOR_CONTROLS = frozenset("\t\n\r\v\f\x85")


def _is_blank(ch: str) -> bool:
    # Blanks may separate digit groups ("123 456", "123  456"), any number of them.
    return ch == " " or unicodedata.category(ch) == "Zs"


def _is_separator(ch: str) -> bool:
    """A narrow separator: whitespace control, dash (Pd), '.', or format char (Cf, e.g. ZWSP)."""
    if ch in _SEPARATOR_CONTROLS or ch == ".":
        return True
    return unicodedata.category(ch) in ("Pd", "Cf")


def _gap_end(text: str, j: int) -> tuple[int, bool]:
    """End of the gap at `j` (blanks plus <= `MAX_GAP_SEPARATORS` separators), and if it had one.

    The end is `j` itself if there is no gap, or if the separator budget
    is exceeded (the run then ends there).
    """
    n = len(text)
    k = j
    separators = 0
    while k < n:
        ch = text[k]
        if _is_blank(ch):
            k += 1
        elif _is_separator(ch):
            separators += 1
            if separators > MAX_GAP_SEPARATORS:
                return j, False
            k += 1
        else:
            break
    return k, separators > 0


def _has_code_window(groups: list[int], separated: list[bool]) -> bool:
    """True if one group, or consecutive groups together, hold exactly 6 digits.

    `separated[i]`: the gap after group `i` holds a narrow separator; a
    window across such a gap counts only if none of its groups has more
    than `MAX_SEPARATED_GROUP` digits. Every group holds >= 1 digit, so
    each inner scan stops within 6 steps.
    """
    n = len(groups)
    for first in range(n):
        total = 0
        last = first
        while last < n and total < CODE_DIGITS:
            total += groups[last]
            last += 1
        if total != CODE_DIGITS:
            continue
        crosses_separator = any(separated[first : last - 1])
        if not crosses_separator or max(groups[first:last]) <= MAX_SEPARATED_GROUP:
            return True
    return False


def _scan_run(text: str, start: int) -> tuple[int, list[int], list[bool]]:
    """From the digit at `start`: the run's end, its digit groups, and which gaps had separators.

    A run continues across a gap (any number of blanks plus at most
    `MAX_GAP_SEPARATORS` narrow separators) that is followed by a digit;
    it ends at the last digit (a trailing gap is not part of it).
    """
    n = len(text)
    groups: list[int] = []
    separated: list[bool] = []
    current = 0
    j = end = start
    while j < n:
        count = _digit_count(text[j])
        if count:
            current += count
            j += 1
            end = j
            continue
        k, had_separator = _gap_end(text, j)
        if k == j or k >= n or not _digit_count(text[k]):
            break
        groups.append(current)
        separated.append(had_separator)
        current = 0
        j = k
    groups.append(current)
    return end, groups, separated


def redact_code_runs(text: str) -> str:
    """Replace every code-like digit run with `[code redacted]` (C44, S-C1 S4).

    A run is a maximal sequence of digit chars (any Unicode digit after
    NFKC) where a gap between digits does not end it: any number of
    blanks plus at most 2 narrow separators (tab/newline and other
    whitespace controls, dashes, `.`, format chars such as ZWSP); the gaps
    split it into groups. The whole run is redacted when any group, or any
    window of consecutive groups, holds exactly 6 digits in total (across
    a separator: only groups of <= 3 digits), so a code next to other
    numbers (`123456 7`, `10 123456`, `123  456`) or typed with separators
    (`123-456`, `12.34.56`, `123\\n456`) never survives. Grouped thousands
    (`1.500.000`, `555-123-4567`) are blanked too: fail closed. Runs with
    no such window (ISO dates `2026-11-08`, phone numbers like
    `12345 6789`, PR numbers) stay. Idempotent; text without digits is
    returned unchanged.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if not _digit_count(text[i]):
            out.append(text[i])
            i += 1
            continue
        end, groups, separated = _scan_run(text, i)
        out.append(CODE_REDACTED if _has_code_window(groups, separated) else text[i:end])
        i = end
    return "".join(out)


def _check_untrusted_text(raw: object, *, name: str, max_chars: int) -> str:
    """Shared checks for stored message/quote text: str, 1..max chars, visible, no NUL.

    No other cleaning: the text stays verbatim for the screen (C48).
    """
    if not isinstance(raw, str):
        raise ValidationError(f"{name} must be a string")
    if not 1 <= len(raw) <= max_chars:
        raise ValidationError(f"{name} must be 1..{max_chars} characters")
    if "\x00" in raw:
        raise ValidationError(f"{name} must not contain NUL")
    # Lone surrogates can't be stored as UTF-8: refuse them up front.
    if any(unicodedata.category(ch) == "Cs" for ch in raw):
        raise ValidationError(f"{name} contains an invalid character")
    if raw.isspace():
        raise ValidationError(f"{name} must not be blank")
    if redact_code_runs(raw) != raw:
        raise ValidationError(f"{name} contains an unredacted code-like digit run")
    return raw


def _check_telegram_id(raw: object, name: str, *, minimum: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= _MAX_TELEGRAM_ID:
        raise ValidationError(f"{name} must be an integer in {minimum}..{_MAX_TELEGRAM_ID}")
    return raw


class InboxState(StrEnum):
    """Lifecycle of an inbox message: RECEIVED --handled()--> HANDLED (terminal)."""

    RECEIVED = "received"
    HANDLED = "handled"


def _check_media(kind: MessageKind, media_id: object, media_bytes: object) -> None:
    """A text row has no media ref; a voice/photo row has a ULID ref and a size within its cap."""
    if not kind.is_media:
        if media_id is not None or media_bytes is not None:
            raise ValidationError("a text message has no media")
        return
    if not is_ulid(media_id):
        raise ValidationError("a media message needs a media id")
    cap = media_max_bytes(kind)
    if isinstance(media_bytes, bool) or not isinstance(media_bytes, int):
        raise ValidationError("media_bytes must be an integer")
    if not 1 <= media_bytes <= cap:
        raise ValidationError(f"media_bytes must be 1..{cap}")


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnerMessage:
    """One owner message in the inbox, as the admin stores it (C44, C61).

    Identity for idempotency is the Telegram pair (`update_id`,
    `telegram_message_id`): a re-delivered update is stored once. `text`
    and `quote_text` are excluded from `repr`, so logging the object never
    logs message content (C29). `kind` is `text`, or `voice` / `photo`
    (C61): then `text` is the caption ("" = none) and `media_id` /
    `media_bytes` name the checked file in the admin's media store.

    Invariants (`ValidationError` on construction):
    - `id` canonical ULID; `update_id >= 0`, `telegram_message_id >= 1`,
      `reply_to_message_id` None or >= 1;
    - `text`: 1..20480 chars (4096 before redaction, 5x), not blank, no NUL
      or lone surrogate, not an authenticator code, no unredacted code-like
      run; `quote_text` None or the same rules with 1..5120 chars; a media
      message may have `text == ""` (no caption);
    - text: no media ref; voice/photo: `media_id` a ULID, `media_bytes`
      1..the kind's cap (2 MiB / 10 MiB);
    - datetimes tz-aware (stored UTC); RECEIVED has no `handled_at`,
      HANDLED has `handled_at >= received_at`.
    """

    id: OwnerMessageId
    update_id: int
    telegram_message_id: int
    text: str = field(repr=False)
    received_at: datetime
    is_forwarded: bool = False
    reply_to_message_id: int | None = None
    quote_text: str | None = field(default=None, repr=False)
    state: InboxState = InboxState.RECEIVED
    handled_at: datetime | None = None
    kind: MessageKind = MessageKind.TEXT
    media_id: str | None = None
    media_bytes: int | None = None

    def __post_init__(self) -> None:
        parse_owner_message_id(self.id)
        _check_telegram_id(self.update_id, "update_id", minimum=0)
        _check_telegram_id(self.telegram_message_id, "telegram_message_id", minimum=1)
        if self.reply_to_message_id is not None:
            _check_telegram_id(self.reply_to_message_id, "reply_to_message_id", minimum=1)
        try:
            object.__setattr__(self, "kind", MessageKind(self.kind))
        except ValueError:
            raise ValidationError("invalid message kind") from None
        _check_media(self.kind, self.media_id, self.media_bytes)
        # Checked first: a code must be refused as a code, not as a redaction miss.
        if is_code_message(self.text):
            raise ValidationError("an authenticator code never enters the inbox")
        if not (self.kind.is_media and self.text == ""):
            _check_untrusted_text(
                self.text, name="message text", max_chars=STORED_MESSAGE_MAX_CHARS
            )
        if self.quote_text is not None:
            _check_untrusted_text(self.quote_text, name="quote", max_chars=STORED_QUOTE_MAX_CHARS)
        if not isinstance(self.is_forwarded, bool):
            raise ValidationError("is_forwarded must be a bool")
        try:
            object.__setattr__(self, "state", InboxState(self.state))
        except ValueError:
            raise ValidationError("invalid inbox state") from None
        object.__setattr__(self, "received_at", ensure_utc(self.received_at, "received_at"))
        if self.state is InboxState.RECEIVED:
            if self.handled_at is not None:
                raise ValidationError("a received message has no handled_at")
            return
        if self.handled_at is None:
            raise ValidationError("a handled message needs handled_at")
        object.__setattr__(self, "handled_at", ensure_utc(self.handled_at, "handled_at"))
        if self.handled_at < self.received_at:
            raise ValidationError("handled_at must not precede received_at")

    @classmethod
    def new(
        cls,
        *,
        id: OwnerMessageId,  # shadows the builtin on purpose: mirrors the field name
        update_id: int,
        telegram_message_id: int,
        text: str,
        received_at: datetime,
        is_forwarded: bool = False,
        reply_to_message_id: int | None = None,
        quote_text: str | None = None,
    ) -> OwnerMessage:
        """Create a RECEIVED message from raw Telegram text, redacting code-like runs.

        The 4096 / 1024-char limits apply to the raw text (Telegram's own),
        before redaction may lengthen it.

        Raises:
            ValidationError: the text is an authenticator code (it must go to
                the code route instead), too long, blank, contains NUL, or any
                other invariant fails.
        """
        if isinstance(text, str):
            if is_code_message(text):
                raise ValidationError("an authenticator code never enters the inbox")
            if len(text) > MESSAGE_MAX_CHARS:
                raise ValidationError(f"message text must be <= {MESSAGE_MAX_CHARS} characters")
            text = redact_code_runs(text)
        if isinstance(quote_text, str):
            if len(quote_text) > QUOTE_MAX_CHARS:
                raise ValidationError(f"quote must be <= {QUOTE_MAX_CHARS} characters")
            quote_text = redact_code_runs(quote_text)
        return cls(
            id=id,
            update_id=update_id,
            telegram_message_id=telegram_message_id,
            text=text,
            received_at=received_at,
            is_forwarded=is_forwarded,
            reply_to_message_id=reply_to_message_id,
            quote_text=quote_text,
        )

    def handled(self, at: datetime) -> OwnerMessage:
        """Return this message marked HANDLED at `at`.

        Raises:
            InvalidStateError: already HANDLED (each message is processed once).
            ValidationError: `at` is naive or precedes `received_at`.
        """
        if self.state is InboxState.HANDLED:
            raise InvalidStateError("message is already handled")
        return dataclasses.replace(self, state=InboxState.HANDLED, handled_at=at)
