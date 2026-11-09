"""Pure RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) and the step-up lockout rules (C47).

Holds the HOTP/TOTP arithmetic, the strict code syntax, base32 secret
encoding, the `otpauth://` URI for authenticator apps and `StepUpState`:
the persisted replay mark (last accepted step), wrong-code counters
(5 per 15 min -> 15 min lockout) and the recently handled code messages
(re-delivery guard). Stdlib only; codes are compared with
`hmac.compare_digest` and every candidate step is always computed.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import quote

from preview_dashboard.domain.errors import ValidationError

TOTP_DIGITS: Final = 6
TOTP_STEP_SECONDS: Final = 30
# Steps -1..+1 around now: tolerates 30 s of clock drift either way (C47).
TOTP_WINDOW: Final = 1
# >= 160 bits (RFC 4226 recommendation, C47).
MIN_SECRET_BYTES: Final = 20
MAX_SECRET_BYTES: Final = 64
SECRET_BYTES: Final = 20

MAX_FAILURES: Final = 5
FAILURE_WINDOW_SECONDS: Final = 15 * 60
LOCKOUT_SECONDS: Final = 15 * 60
# Re-delivery guard (S-C1 S0): exact (update_id, message_id) pairs, not a
# high-water mark. Telegram may restart update ids lower (e.g. after a week
# without updates); a mark would then swallow every fresh code as a
# "duplicate". Replay of a code stays blocked by `last_step`.
SEEN_CODES_MAX: Final = 32
SEEN_CODES_SECONDS: Final = 24 * 60 * 60
_MAX_TELEGRAM_ID = 2**63

_CODE_RE = re.compile(r"[0-9]{6}")
_BASE32_RE = re.compile(r"[A-Z2-7]+")
_LABEL_RE = re.compile(r"[A-Za-z0-9 ._@-]{1,64}")
# Unix seconds well inside int64 and datetime range; anything else is corrupt state.
_MAX_UNIX = 2**40


class TotpError(ValidationError):
    """A malformed secret, code or step-up state (message never holds secret or code)."""


def hotp(secret: bytes, counter: int, *, digits: int = TOTP_DIGITS) -> str:
    """RFC 4226 HOTP value of `counter` as a zero-padded decimal string.

    `digits` other than 6 exists for the RFC test vectors (8 digits).

    Raises:
        TotpError: negative or > 64-bit counter, or `digits` outside 6..8.
    """
    if not 0 <= counter < 2**64:
        raise TotpError("counter out of range")
    if not 6 <= digits <= 8:
        raise TotpError("digits must be 6..8")
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def time_step(unix_seconds: float) -> int:
    """The RFC 6238 time step (T0 = 0, X = 30 s) of a Unix timestamp.

    Raises:
        TotpError: a negative timestamp.
    """
    if unix_seconds < 0:
        raise TotpError("timestamp before the Unix epoch")
    return int(unix_seconds // TOTP_STEP_SECONDS)


def totp_at(secret: bytes, unix_seconds: float, *, digits: int = TOTP_DIGITS) -> str:
    """RFC 6238 TOTP value at `unix_seconds` (HMAC-SHA1).

    Raises:
        TotpError: see `hotp` and `time_step`.
    """
    return hotp(secret, time_step(unix_seconds), digits=digits)


def parse_code(raw: object) -> str:
    """Validate an untrusted code: exactly ASCII `[0-9]{6}` (no spaces, no other digits).

    Raises:
        TotpError: anything else (the message never echoes the input).
    """
    if not isinstance(raw, str) or not _CODE_RE.fullmatch(raw):
        raise TotpError("a code is exactly six ASCII digits")
    return raw


def matching_step(
    secret: bytes,
    code: str,
    now_step: int,
    *,
    after_step: int | None,
    window: int = TOTP_WINDOW,
) -> int | None:
    """Return the step in `now_step ± window` whose code equals `code`, if it is new.

    Every candidate is computed and compared with `hmac.compare_digest`
    (no early exit), so timing doesn't reveal which step matched or how
    many digits were right. A step `<= after_step` (already used, C47) is
    never accepted: a code can't be replayed, nor an older one used after
    a newer one.

    Raises:
        TotpError: `code` is not six ASCII digits, or `now_step < window`.
    """
    parse_code(code)
    if now_step - window < 0:
        raise TotpError("time step out of range")
    found: int | None = None
    expected = code.encode("ascii")
    for step in range(now_step - window, now_step + window + 1):
        candidate = hotp(secret, step).encode("ascii")
        fresh = after_step is None or step > after_step
        if hmac.compare_digest(candidate, expected) and fresh and found is None:
            found = step
    return found


def check_secret(secret: bytes) -> bytes:
    """Validate raw secret bytes: 20..64 bytes (>= 160 bits).

    Raises:
        TotpError: wrong type or length.
    """
    if not isinstance(secret, bytes) or not MIN_SECRET_BYTES <= len(secret) <= MAX_SECRET_BYTES:
        raise TotpError(f"a TOTP secret is {MIN_SECRET_BYTES}..{MAX_SECRET_BYTES} bytes")
    return secret


def encode_secret(secret: bytes) -> str:
    """Base32 (RFC 4648, uppercase, no padding): the form authenticator apps expect.

    Raises:
        TotpError: see `check_secret`.
    """
    return base64.b32encode(check_secret(secret)).decode("ascii").rstrip("=")


def decode_secret(text: str) -> bytes:
    """Inverse of `encode_secret`; strict (uppercase base32, no padding, no spaces).

    Raises:
        TotpError: not canonical base32 or a decoded length out of range.
    """
    if not isinstance(text, str) or not _BASE32_RE.fullmatch(text):
        raise TotpError("the TOTP secret must be one line of uppercase base32")
    padded = text + "=" * (-len(text) % 8)
    try:
        secret = base64.b32decode(padded, casefold=False)
    except (binascii.Error, ValueError):
        raise TotpError("the TOTP secret is not valid base32") from None
    if encode_secret(check_secret(secret)) != text:
        raise TotpError("the TOTP secret is not canonical base32")
    return secret


def otpauth_uri(secret: bytes, *, issuer: str, account: str) -> str:
    """The `otpauth://totp/...` URI an authenticator app imports (shown once at setup).

    Raises:
        TotpError: bad secret, or `issuer`/`account` outside `[A-Za-z0-9 ._@-]{1,64}`.
    """
    for name, value in (("issuer", issuer), ("account", account)):
        if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
            raise TotpError(f"{name} must be 1..64 of [A-Za-z0-9 ._@-]")
    label = quote(f"{issuer}:{account}", safe=":@")
    params = (
        f"secret={encode_secret(secret)}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )
    return f"otpauth://totp/{label}?{params}"


def _unix(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < _MAX_UNIX:
        raise TotpError(f"{name} must be a Unix timestamp")
    return value


def _telegram_id(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < _MAX_TELEGRAM_ID:
        raise TotpError(f"{name} must be a Telegram id")
    return value


@dataclass(frozen=True, slots=True)
class SeenCode:
    """One handled code message: its Telegram `update_id` + `message_id`, and when (Unix s)."""

    update_id: int
    message_id: int
    seen_at: int

    def __post_init__(self) -> None:
        _telegram_id(self.update_id, "update_id")
        _telegram_id(self.message_id, "message_id")
        _unix(self.seen_at, "seen_at")


@dataclass(frozen=True, slots=True, kw_only=True)
class StepUpState:
    """Persisted step-up counters (C47): replay mark, recent wrong codes, lockout.

    Times are whole Unix seconds. `seen` holds the last `SEEN_CODES_MAX`
    code messages handled within `SEEN_CODES_SECONDS`, matched exactly on
    `(update_id, message_id)`: the same message re-delivered is not a
    second try, while any other message (even one with a lower update id)
    is checked. Transitions return new instances.

    Invariants (`TotpError` on construction): `last_step` None or >= 0;
    `failures` ascending timestamps, at most `MAX_FAILURES`;
    `locked_until` None or a timestamp; `seen` at most `SEEN_CODES_MAX`
    `SeenCode`s with distinct id pairs.
    """

    last_step: int | None = None
    failures: tuple[int, ...] = field(default=())
    locked_until: int | None = None
    seen: tuple[SeenCode, ...] = field(default=())

    def __post_init__(self) -> None:
        if self.last_step is not None:
            _unix(self.last_step, "last_step")
        failures = tuple(_unix(v, "failure time") for v in self.failures)
        if len(failures) > MAX_FAILURES or list(failures) != sorted(failures):
            raise TotpError("failures must be at most 5 ascending timestamps")
        object.__setattr__(self, "failures", failures)
        if self.locked_until is not None:
            _unix(self.locked_until, "locked_until")
        seen = tuple(self.seen)
        if len(seen) > SEEN_CODES_MAX or not all(isinstance(s, SeenCode) for s in seen):
            raise TotpError(f"seen must be at most {SEEN_CODES_MAX} handled code messages")
        if len({(s.update_id, s.message_id) for s in seen}) != len(seen):
            raise TotpError("seen code messages must be distinct")
        object.__setattr__(self, "seen", seen)

    def is_locked(self, now: int) -> bool:
        """True while a lockout is running at `now`."""
        return self.locked_until is not None and now < self.locked_until

    def is_seen_code(self, update_id: int, message_id: int, now: int) -> bool:
        """True if this exact code message was handled within the last 24 h."""
        return any(
            s.update_id == update_id
            and s.message_id == message_id
            and now - s.seen_at < SEEN_CODES_SECONDS
            for s in self.seen
        )

    def with_seen_code(self, update_id: int, message_id: int, now: int) -> StepUpState:
        """This state with the code message recorded as handled at `now` (no other change).

        Entries older than 24 h are dropped, then only the newest
        `SEEN_CODES_MAX` are kept (bounded file, bounded work per code).

        Raises:
            TotpError: an id or `now` out of range.
        """
        entry = SeenCode(update_id, message_id, now)
        kept = tuple(
            s
            for s in self.seen
            if now - s.seen_at < SEEN_CODES_SECONDS
            and (s.update_id, s.message_id) != (update_id, message_id)
        )
        return dataclasses.replace(self, seen=(*kept, entry)[-SEEN_CODES_MAX:])

    def with_failure(self, now: int) -> StepUpState:
        """Record one wrong code at `now`; the 5th within 15 min starts a 15 min lockout.

        Failures older than the window are dropped first; a lockout clears
        the counters, so the next 5 wrong codes after it lock again.
        """
        recent = (*tuple(t for t in self.failures if now - t < FAILURE_WINDOW_SECONDS), now)
        if len(recent) >= MAX_FAILURES:
            return dataclasses.replace(self, failures=(), locked_until=now + LOCKOUT_SECONDS)
        return dataclasses.replace(self, failures=recent, locked_until=None)

    def with_success(self, step: int) -> StepUpState:
        """Record an accepted code at `step` (replay mark); wrong-code counters reset.

        Raises:
            TotpError: `step` is not after `last_step` (would allow a replay).
        """
        if self.last_step is not None and step <= self.last_step:
            raise TotpError("an accepted step must be newer than the last one")
        return dataclasses.replace(
            self, last_step=_unix(step, "step"), failures=(), locked_until=None
        )

    def with_burned_step(self, step: int) -> StepUpState:
        """Mark `step` as used without counting a success (the setup's confirmation code).

        The replay mark only moves forward (`max`); failures and a running
        lockout are left as they are, so setup can't be used to reset them.

        Raises:
            TotpError: `step` is not a valid non-negative step.
        """
        step = _unix(step, "step")
        last = step if self.last_step is None else max(step, self.last_step)
        return dataclasses.replace(self, last_step=last)


__all__ = [
    "FAILURE_WINDOW_SECONDS",
    "LOCKOUT_SECONDS",
    "MAX_FAILURES",
    "MIN_SECRET_BYTES",
    "SECRET_BYTES",
    "SEEN_CODES_MAX",
    "SEEN_CODES_SECONDS",
    "TOTP_DIGITS",
    "TOTP_STEP_SECONDS",
    "TOTP_WINDOW",
    "SeenCode",
    "StepUpState",
    "TotpError",
    "check_secret",
    "decode_secret",
    "encode_secret",
    "hotp",
    "matching_step",
    "otpauth_uri",
    "parse_code",
    "time_step",
    "totp_at",
]
