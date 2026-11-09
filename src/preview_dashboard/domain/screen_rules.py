"""Screening rules for owner messages (C48): the no-AI parser and the strict model-output check.

`scan_message` is step 1 of the screen: it flags lines that look like prompt
injection (EN/ES instruction phrases, also in leetspeak / look-alike letters),
role or tool tags, host-built approval turns (resume-turn look-alikes),
commands (incl. prose `rm`/`curl`), code blocks, links, encoded blobs,
invisible or non-Latin characters and forwarded or quoted text. Any hit
flags the message. `parse_screen_output` validates the Haiku verdict
(exact JSON, nothing else). Results carry rule names and line numbers only,
never message text (C29). Stdlib only.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

from preview_dashboard.domain.unicode import (
    BLANK_LOOKALIKES,
    JOINERS,
    PRESENTATION_SELECTORS,
    is_default_ignorable,
    remove_default_ignorables,
    takes_joiner,
    takes_presentation_selector,
)

# Short, typed requests are the normal case (plan section 5): longer text is
# treated as pasted content.
MAX_PLAIN_LINES = 6
MAX_PLAIN_CHARS = 1500
LONG_WORD_CHARS = 40
# Bounds the hint list handed to the model (and any logging of rule names).
MAX_HITS = 50

# --- line rules (matched on the normalized line, see `_normalize`) ----------------------

_PHRASES = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding)\b"
    r"|ignore\s+(?:all\s+|your\s+|the\s+|any\s+)?(?:instructions|rules|guidelines|guard)"
    r"|disregard\s+(?:all\s+|your\s+|the\s+|any\s+)?"
    r"(?:previous|prior|above|rules|instructions|guidelines)"
    r"|forget\s+(?:all\s+|your\s+|the\s+)?(?:previous|prior|above|instructions|rules)"
    r"|you\s+are\s+now\b|from\s+now\s+on\b|new\s+instructions?\b|\bact\s+as\b"
    r"|pretend\s+(?:to\s+be|you)|reveal\s+(?:your|the)\s+(?:system|prompt|token|secret)"
    r"|system\s+prompt|developer\s+mode|jailbreak|pre-?approved"
    r"|do\s+not\s+ask\s+(?:me\s+)?for\s+(?:my\s+|a\s+|the\s+)?(?:code|approval)"
    r"|(?:without|no)\s+(?:any\s+)?restrictions|override\s+(?:your|the)\s+"
    r"|(?:bypass|disable|turn\s+off)\s+(?:the\s+|your\s+)?(?:guard|rules|hook|approval)"
    r"|the\s+owner\s+(?:has\s+)?(?:already\s+)?(?:agreed|approved|authori[sz]ed|allowed)"
    r"|olvida\s+(?:las|todas\s+las|tus|lo\s+anterior)\s*(?:instrucciones|reglas|anteriores)?"
    r"|ignora\s+(?:las|todas\s+las|tus)\s+(?:instrucciones|reglas)"
    r"|ignora\s+(?:lo\s+anterior|todo\s+lo\s+anterior)|ahora\s+eres\b|a\s+partir\s+de\s+ahora\b"
    r"|nuevas\s+instrucciones|act[u\U000000fa]a\s+como\b|haz\s+de\s+cuenta|finge\s+(?:que|ser)"
    r"|sin\s+(?:reglas|restricciones)|prompt\s+del\s+sistema"
    r"|no\s+(?:me\s+)?pidas\s+(?:mi\s+|el\s+|un\s+)?(?:c[o\U000000f3]digo|aprobaci[o\U000000f3]n)"
    r"|es\s+una\s+orden",
    re.IGNORECASE,
)
# Role markers at a line or sentence start, also wrapped in `**`, `[` or `(`.
_ROLE_PREFIX = re.compile(
    r"(?:^|[.!?;]\s+)[\s*_\[(]*"
    r"(?:system|assistant|user|human|developer|tool|sistema|asistente|usuario)[\])*_\s]*:",
    re.IGNORECASE,
)
_TAGS = re.compile(
    r"</?\s*(?:system|assistant|user|human|channel|tool|tool_use|tool_result|instructions?"
    r"|prompt|im_start|im_end|owner_message|function_calls?|invoke|parameter)\b[^>]{0,200}>"
    r"|<\|[a-z_]{1,40}\|>|\[/?(?:INST|SYS)\]|<<\s*/?SYS\s*>>",
    re.IGNORECASE,
)
# Commands, also in prose ("please rm the folder", "curl it"): the owner asks
# for outcomes, a command word in the text is pasted or injected (V4 finding).
_SHELL = re.compile(
    r"^\s*[$#]\s+\S"
    r"|\b(?:sudo|curl|wget|chmod|chown|scp|ssh|rsync|nc|ncat|netcat|eval|rm|rmdir|shred"
    r"|unlink|mkfs|crontab|systemctl|pkill|killall)\b"
    r"|\b(?:ba|z)?sh\s+-c\b|\b(?:python3?|node|perl|ruby)\s+-[ce]\b"
    r"|\bdd\s+if="
    r"|\bgit\s+(?:push|reset|clone|checkout|clean|config|filter-branch|rebase\s+-i)\b"
    r"|\bgh\s+(?:pr|api|repo|release|secret|auth)\b"
    r"|\|\s*(?:ba|z)?sh\b|&&|\|\||\$\("
    r"|~/\.\w|/etc/\w|/root/\.|\bid_rsa\b|\.ssh\b|\.credentials\b|\b[\w-]+\.sh\b"
    r"|(?:^|\s)/(?:bin|usr|var|tmp|dev|proc|opt)/",
    re.IGNORECASE,
)
_FENCE = re.compile(r"```|~~~")
_LINK = re.compile(
    r"[a-z][a-z0-9+.-]{1,20}://|\bmailto:|www\."
    r"|\b[\w-]{1,63}\.(?:com|net|org|io|dev|ru|xyz|me|co|app|ly|gg|info|biz|cn|tk|top|site"
    r"|online|example|link|ai)\b"
    r"|[\w-]{1,63}\.[^\W\d_]{2,63}(?::[0-9]{1,5})?/"
    r"|\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b",
    re.IGNORECASE,
)
_B64 = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")
_EMAIL = re.compile(r"\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.]{1,63}\b")
_FORWARD = re.compile(
    r"^\s*(?:forwarded\s+(?:message|from)|reenviado\s+(?:de|mensaje)|fwd?:|-{2,}\s*forwarded"
    r"|-{2,}\s*original\s+message|begin\s+forwarded)",
    re.IGNORECASE,
)
_QUOTE = re.compile(r"^\s*>+\s")
_SECRET = re.compile(
    r"\b(?:sk[-_][a-z]+[-_]\w{12,}|ghp_\w{20,}|github_pat_\w{20,}|xox[bp]-\S+|AKIA\w{12,})",
    re.IGNORECASE,
)
# Host-built approval turns (C46) must never be typeable: "Approved by the
# owner ...", "Denied by the owner ...", "Treat flagged message ..." and any
# `request <ULID>` shape (26 chars; any alphanumerics, so O/I/L variants count).
_RESUME_TURN = re.compile(
    r"\b(?:approved|denied|aprobad[oa]|denegad[oa]|rechazad[oa])\s+(?:by|por)\s+"
    r"(?:the\s+|el\s+|la\s+)?(?:owner|propietari[oa]|due[n\U000000f1][oa])\b"
    r"|\btreat\s+flagged\s+message\b"
    r"|\br[e3]q[uv][e3][s5$][t7+]\W{0,3}[0-9a-z]{26}\b"
    r"|\bsolicitud\W{0,3}[0-9a-z]{26}\b",
    re.IGNORECASE,
)

_LINE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("phrase", _PHRASES),
    ("role_prefix", _ROLE_PREFIX),
    ("tag", _TAGS),
    ("resume_turn", _RESUME_TURN),
    ("shell", _SHELL),
    ("fence", _FENCE),
    ("link", _LINK),
    ("base64_or_long_token", _B64),
    ("email", _EMAIL),
    ("secret", _SECRET),
    ("forward", _FORWARD),
    ("quote", _QUOTE),
)

# --- look-alike folding -------------------------------------------------------------------

# Cyrillic and Greek letters that render like Latin ones, as code points
# (confusable characters in source are lint errors), and their Latin twins.
# Folded so an all-Cyrillic "system:" matches the rules too; the non-Latin
# letters themselves are flagged separately.
_CONFUSABLE_POINTS: tuple[int, ...] = (
    0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445, 0x0456, 0x0458, 0x0455,
    0x0501, 0x04BB, 0x04CF, 0x051B, 0x051D, 0x0410, 0x0412, 0x0415, 0x041A, 0x041C,
    0x041D, 0x041E, 0x0420, 0x0421, 0x0422, 0x0425, 0x0423, 0x0406, 0x0408, 0x0405,
    0x03BF, 0x03B1, 0x03BD, 0x03C1, 0x03C4, 0x03B9, 0x03BA, 0x0391, 0x0392, 0x0395,
    0x0396, 0x0397, 0x0399, 0x039A, 0x039C, 0x039D, 0x039F, 0x03A1, 0x03A4, 0x03A5,
    0x03A7, 0x0261,
)  # fmt: skip
_CONFUSABLE_LATIN = "aeopcyxijsdhlqwABEKMHOPCTXYIJSoavptikABEZHIKMNOPTYXg"
_CONFUSABLES = str.maketrans(
    {chr(cp): latin for cp, latin in zip(_CONFUSABLE_POINTS, _CONFUSABLE_LATIN, strict=True)}
)

# Leetspeak skeleton: digits/symbols to letters, and `l` and `1` both to `i`
# so "a11", "all" and "aII" share one form. Phrases are compared as skeletons.
_LEET = str.maketrans(
    {
        "0": "o", "1": "i", "l": "i", "!": "i", "|": "i", "3": "e", "4": "a", "@": "a",
        "5": "s", "$": "s", "7": "t", "+": "t", "8": "b", "9": "g",
    }
)  # fmt: skip
_NON_LETTERS = re.compile(r"[^a-z]+")

# Instruction phrases and approval-turn openers matched on the whole message's
# skeleton (catches leetspeak and phrases split over lines or by punctuation).
_SKELETON_PHRASES: tuple[str, ...] = (
    "ignore all previous", "ignore previous", "ignore the previous", "ignore prior",
    "ignore all prior", "ignore the above", "ignore your instructions",
    "ignore all instructions", "ignore the instructions", "ignore your rules",
    "disregard your", "disregard all", "disregard the previous", "disregard previous",
    "forget your instructions", "forget all previous", "forget previous",
    "forget the previous", "you are now", "from now on", "new instructions",
    "system prompt", "developer mode", "jailbreak", "pre approved", "preapproved",
    "act as", "pretend to be", "do not ask for my code", "do not ask for approval",
    "dont ask for my code", "don't ask for my code", "without restrictions", "no restrictions",
    "bypass the guard", "disable the guard", "override your", "override the rules",
    "approved by the owner", "approved by owner", "denied by the owner",
    "denied by owner", "treat flagged message",
    "olvida las instrucciones", "olvida tus instrucciones", "olvida todas las",
    "olvida lo anterior", "ignora las instrucciones", "ignora tus instrucciones",
    "ignora todas las", "ignora lo anterior", "ahora eres", "a partir de ahora",
    "nuevas instrucciones", "actua como", "haz de cuenta", "finge ser", "finge que",
    "sin reglas", "sin restricciones", "prompt del sistema", "no pidas mi codigo",
    "no pidas codigo", "no pidas aprobacion", "aprobado por el propietario",
    "aprobado por el dueno", "denegado por el propietario", "denegado por el dueno",
    "es una orden",
)  # fmt: skip

# Spanish ordinal indicators are letters outside "LATIN ..." names but normal text.
_LATIN_EXTRAS = frozenset({"\xaa", "\xba"})
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"})


def _strip_marks(text: str) -> str:
    """Drop combining marks after NFKD (accented Spanish letters lose their accents)."""
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _normalize(text: str) -> str:
    """NFKC + invisible chars removed + Cyrillic/Greek look-alikes folded to Latin."""
    return unicodedata.normalize("NFKC", remove_default_ignorables(text)).translate(_CONFUSABLES)


def _skeleton(text: str) -> str:
    """Lowercase letters-only form with leetspeak folded, padded with spaces for word matching."""
    folded = _strip_marks(_normalize(text)).casefold().translate(_LEET)
    return f" {_NON_LETTERS.sub(' ', folded).strip()} "


_SKELETON_KEYS: tuple[str, ...] = tuple(_skeleton(p) for p in _SKELETON_PHRASES)


# --- character checks (raw line) ----------------------------------------------------------


def _has_invisible(line: str) -> bool:
    """True for control/format/unassigned/separator/ignorable chars outside emoji sequences.

    ZWJ/ZWNJ and VS15/VS16 are allowed only where they are meaningful (emoji
    and complex scripts, same rule as `domain/text.py`). Characters newer than
    Python's Unicode tables count as unassigned (Cn) and so as hits: strict.
    """
    for i, ch in enumerate(line):
        if ch == "\t":
            continue
        prev = line[i - 1] if i else ""
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if ch in JOINERS:
            prev_ok = bool(prev) and (takes_joiner(prev) or prev in PRESENTATION_SELECTORS)
            if not (prev_ok and nxt and takes_joiner(nxt)):
                return True
            continue
        if ch in PRESENTATION_SELECTORS:
            if not (prev and takes_presentation_selector(prev, nxt)):
                return True
            continue
        if (
            is_default_ignorable(ch)
            or ch in BLANK_LOOKALIKES
            or unicodedata.category(ch) in _INVISIBLE_CATEGORIES
        ):
            return True
    return False


def _has_non_latin_letters(line: str) -> bool:
    """True for any letter outside the Latin script (look-alikes, styled or fullwidth forms).

    The owner writes English or Spanish: Cyrillic/Greek homoglyphs, math
    alphanumerics and fullwidth letters all land here.
    """
    return any(
        ch.isalpha()
        and ch not in _LATIN_EXTRAS
        and not unicodedata.name(ch, "").startswith("LATIN ")
        for ch in line
    )


def _has_non_ascii_digits(line: str) -> bool:
    return any(unicodedata.category(ch) == "Nd" and not ch.isascii() for ch in line)


def _has_stacked_marks(line: str) -> bool:
    """Two or more combining marks in a row (zalgo-style hiding or odd rendering)."""
    run = 0
    for ch in line:
        run = run + 1 if unicodedata.combining(ch) else 0
        if run >= 2:
            return True
    return False


# --- results ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParserHit:
    """One matched rule: `line` is 1-based, 0 for whole-message rules. Never holds text."""

    line: int
    rule: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    """The parser's findings for one message (at most `MAX_HITS`, de-duplicated, ordered)."""

    hits: tuple[ParserHit, ...]

    @property
    def flagged(self) -> bool:
        """Any hit flags the message (C48: parser OR model)."""
        return bool(self.hits)

    @property
    def rules(self) -> tuple[str, ...]:
        """Sorted unique rule names (safe to log and to hand to the host)."""
        return tuple(sorted({hit.rule for hit in self.hits}))


def _split_lines(text: str) -> list[str]:
    """Split on `\\n` only (a trailing `\\r` dropped), so other separators stay visible as hits."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def _line_hits(number: int, line: str) -> list[ParserHit]:
    hits: list[ParserHit] = []
    normalized = _normalize(line)
    for name, rule in _LINE_RULES:
        if rule.search(normalized):
            hits.append(ParserHit(number, name))
    if _has_invisible(line):
        hits.append(ParserHit(number, "invisible"))
    if _has_non_latin_letters(line):
        hits.append(ParserHit(number, "non_latin_letters"))
    if _has_non_ascii_digits(line):
        hits.append(ParserHit(number, "non_ascii_digits"))
    if _has_stacked_marks(line):
        hits.append(ParserHit(number, "stacked_marks"))
    if any(len(word) > LONG_WORD_CHARS for word in normalized.split()) and not _B64.search(
        normalized
    ):
        hits.append(ParserHit(number, "long_token"))
    return hits


def scan_message(text: str, *, forwarded: bool = False, quote: str | None = None) -> ParseResult:
    """Run every parser rule over one owner message (C48 step 1).

    Args:
        text: the message text, verbatim as stored (C44).
        forwarded: Telegram's forwarded flag: always a hit.
        quote: a quoted part of an earlier message the owner replied to: its
            presence is a hit (quoted content), and its lines are scanned too.

    Returns:
        The de-duplicated hits (rule names + line numbers only).
    """
    hits: list[ParserHit] = []
    if forwarded:
        hits.append(ParserHit(0, "forwarded_flag"))
    if quote is not None:
        hits.append(ParserHit(0, "quoted_reply"))
    lines = _split_lines(text)
    if len(lines) > MAX_PLAIN_LINES:
        hits.append(ParserHit(0, "pasted_block_lines"))
    if len(text) > MAX_PLAIN_CHARS:
        hits.append(ParserHit(0, "very_long"))
    whole = text if quote is None else f"{text}\n{quote}"
    skeleton = _skeleton(whole)
    if any(key in skeleton for key in _SKELETON_KEYS):
        hits.append(ParserHit(0, "phrase_folded"))
    for number, line in enumerate(lines, 1):
        hits.extend(_line_hits(number, line))
    if quote is not None:
        # Quote lines are numbered after the message's own lines.
        for offset, line in enumerate(_split_lines(quote), len(lines) + 1):
            hits.extend(_line_hits(offset, line))
    unique = tuple(dict.fromkeys(hits))
    return ParseResult(unique[:MAX_HITS])


# --- strict model output (C48 step 2) -----------------------------------------------------


class ModelVerdict(StrEnum):
    """The only two verdicts the screen model may give."""

    OK = "ok"
    SUSPICIOUS = "suspicious"


# `claude -p --output-format json` prints one small result object; anything
# far larger is not a verdict.
MAX_MODEL_OUTPUT_CHARS = 64 * 1024
MAX_REASON_CHARS = 300
_VERDICT_KEYS = frozenset({"verdict", "reason"})


class _StrictJsonError(ValueError):
    """Duplicate keys or non-standard constants (NaN, Infinity)."""


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise _StrictJsonError("duplicate key")
        out[key] = value
    return out


def _no_constants(name: str) -> object:
    raise _StrictJsonError(f"non-standard constant {name}")


def _strict_json_object(raw: str) -> dict[str, object] | None:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def parse_screen_output(stdout: str) -> ModelVerdict | None:
    """Validate the CLI's JSON envelope and the verdict line inside it.

    The envelope must be one JSON object with `is_error` false and a string
    `result`; the result, stripped, must be exactly
    `{"verdict": "ok"|"suspicious", "reason": "<1..300 chars>"}` - no extra
    keys, duplicates, code fences or prose. The reason is model output
    shaped by hostile text, so it is checked but never returned.

    Returns:
        The verdict, or None for anything else (the caller flags: fail closed).
    """
    if not isinstance(stdout, str) or len(stdout) > MAX_MODEL_OUTPUT_CHARS:
        return None
    envelope = _strict_json_object(stdout.strip())
    if envelope is None or envelope.get("is_error") is not False:
        return None
    result = envelope.get("result")
    if not isinstance(result, str):
        return None
    verdict = _strict_json_object(result.strip())
    if verdict is None or set(verdict) != _VERDICT_KEYS:
        return None
    reason = verdict["reason"]
    if not isinstance(reason, str) or not 1 <= len(reason) <= MAX_REASON_CHARS:
        return None
    value = verdict["verdict"]
    if value == ModelVerdict.OK.value:
        return ModelVerdict.OK
    if value == ModelVerdict.SUSPICIOUS.value:
        return ModelVerdict.SUSPICIOUS
    return None


class ModelRunStatus(StrEnum):
    """How one screen-model process ended (reported by the runner adapter)."""

    COMPLETED = "completed"  # exit 0, stdout captured
    TIMEOUT = "timeout"  # killed after the time limit
    UNAVAILABLE = "unavailable"  # CLI missing or not executable
    FAILED = "failed"  # non-zero exit or signal


@dataclass(frozen=True, slots=True, kw_only=True)
class ModelRun:
    """One screen-model run: status, exit code and stdout (never logged: model output)."""

    status: ModelRunStatus
    stdout: str = ""
    exit_code: int | None = None

    def __repr__(self) -> str:
        return f"ModelRun(status={self.status.value!r}, exit_code={self.exit_code!r})"
