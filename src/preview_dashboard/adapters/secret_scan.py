"""RegexSecretScanner: the `ContentScanner` adapter for the admin secret scan.

Streams bytes through a fixed set of compiled, high-signal secret-format
rules (docs/security.md C15, ADR 0008), keeping an overlap window so a
secret split across chunk boundaries is still caught. Pure stdlib (`re`).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from preview_dashboard.domain.errors import SecretDetectedError

# (label, bytes regex). Labels are shown to the publisher; the matched bytes
# never are. Labels are neutral prose with spaces and mixed case so a label
# can never be (part of) a matched token and leak its prefix. Each rule is
# compiled and run on its own, starting with a literal so `re` can use its
# fast prefix search (a single alternation of all rules scans ~40x slower).
# ReDoS safety: every quantifier is bounded, variable-width runs are
# possessive (`{m,n}+`, no backtracking into them), and each rule checks a
# token boundary right after its literal prefix (`(?<!...)`), so a long run
# of token characters has at most one viable start -> scanning stays linear.
# The one non-possessive run (PEM) is bounded to 64 and anchored on a literal,
# so each start costs at most 64 backtracking steps.
# `\x2d` spells "-" and the SSH2 literal is split so this file does not
# contain a key header that secret scanners (gitleaks, this repo's own
# release export scan) would flag.
_B64URL = rb"A-Za-z0-9_-"
DEFAULT_RULES: Final[tuple[tuple[str, bytes], ...]] = (
    # Commercial SSH (RFC 4716 style) header; listed before the generic PEM
    # rule (which also matches it) so the label is precise. Ends where the
    # PEM match ends, so chunking can never make the PEM label win.
    ("SSH2 private key", rb"\x2d\x2d\x2d\x2d BEGIN SSH2 ENCRYPTED PRIVATE" + rb" KEY"),
    # Any "BEGIN <words> PRIVATE KEY": RSA / EC / DSA / OPENSSH / ENCRYPTED /
    # PGP ("... KEY BLOCK") / plain PKCS#8, and headers whose dashes were
    # dropped or mangled. Not possessive: the run's alphabet includes
    # "PRIVATE KEY" itself, so it must be able to give characters back.
    ("PEM private key", rb"BEGIN(?<![A-Za-z0-9]BEGIN)[ A-Z0-9]{0,64}PRIVATE KEY"),
    ("PuTTY private key", rb"PuTTY-User-Key-File-[0-9]{1,2}: "),
    ("AWS access key id", rb"A(?<![A-Z0-9]A)(?:KIA|SIA)[A-Z2-7]{16}(?![A-Z0-9])"),
    ("GitHub token", rb"gh(?<![A-Za-z0-9_]gh)[pousr]_[A-Za-z0-9]{36}"),
    ("GitHub fine-grained token", rb"github_pat_(?<![A-Za-z0-9_]github_pat_)[A-Za-z0-9_]{22}"),
    ("Anthropic API key", rb"sk-ant-(?<![" + _B64URL + rb"]sk-ant-)[" + _B64URL + rb"]{20}"),
    (
        "OpenAI API key",
        rb"sk-(?<!["
        + _B64URL
        + rb"]sk-)(?:(?:proj|svcacct|admin)-["
        + _B64URL
        + rb"]{20}|[A-Za-z0-9]{32})",
    ),
    ("Slack token", rb"xox(?<![A-Za-z0-9]xox)[baprs]-[A-Za-z0-9-]{10}"),
    ("Slack app token", rb"xapp-(?<![A-Za-z0-9]xapp-)[0-9]{1,2}-[A-Za-z0-9-]{10}"),
    (
        "Slack webhook URL",
        rb"hooks\.slack\.com/services/[A-Za-z0-9_]{6,16}+/[A-Za-z0-9_]{6,16}+/[A-Za-z0-9_]{16}",
    ),
    ("GitLab token", rb"glpat-(?<![" + _B64URL + rb"]glpat-)[" + _B64URL + rb"]{20}"),
    ("Hugging Face token", rb"hf_(?<![A-Za-z0-9_]hf_)[A-Za-z0-9]{34}(?![A-Za-z0-9])"),
    ("npm access token", rb"npm_(?<![A-Za-z0-9_]npm_)[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    # PyPI API tokens are macaroons: "pypi-" + base64 of a fixed header.
    ("PyPI upload token", rb"pypi-(?<![" + _B64URL + rb"]pypi-)AgEI[" + _B64URL + rb"]{16}"),
    (
        "SendGrid API key",
        rb"SG\.(?<![" + _B64URL + rb"]SG\.)[" + _B64URL + rb"]{22}\.[" + _B64URL + rb"]{43}",
    ),
    # dop_ (personal), doo_ (OAuth), dor_ (refresh).
    ("DigitalOcean token", rb"do(?<![A-Za-z0-9_]do)[por]_v1_[a-f0-9]{64}"),
    ("Google API key", rb"AIza(?<![" + _B64URL + rb"]AIza)[" + _B64URL + rb"]{35}"),
    # Starts at "k_live_" (literal prefix); lookbehinds require sk_/rk_ + boundary.
    (
        "Stripe live secret key",
        rb"k_live_(?<=[sr]k_live_)(?<![A-Za-z0-9][sr]k_live_)[A-Za-z0-9]{24}",
    ),
    # "<bot id>:<35 chars>". The digit run must start the number (a longer
    # one never matches), and the secret part is exactly 35 chars; glued
    # letters in front are fine, since tokens often sit in ".../bot<token>/" URLs.
    (
        "Telegram bot token",
        rb"[0-9](?<![0-9][0-9])[0-9]{5,11}+:[" + _B64URL + rb"]{35}(?![" + _B64URL + rb"])",
    ),
    ("JSON private key field", rb'"private_key"[ \t\r\n]{0,16}:'),
    # YAML / TOML / single-quoted keys (also `ssh_private_key`); requires a
    # quoted, block (| >) or 16+ char base64 value so `private_key = 1` or
    # `private_key: ${VAR}` in docs and templates don't block a publish.
    (
        "Private key config field",
        rb"private_key(?<![A-Za-z0-9]private_key)['\"]?[ \t]{0,16}[:=][ \t]{0,16}"
        rb"(?:['\"|>]|[A-Za-z0-9+/=]{16})",
    ),
    # header.payload.signature; both JSON segments base64url-encode "{" -> "eyJ".
    (
        "JSON Web Token",
        rb"eyJ(?<!["
        + _B64URL
        + rb"]eyJ)["
        + _B64URL
        + rb"]{8,4096}+\.eyJ["
        + _B64URL
        + rb"]{8,8192}+\.["
        + _B64URL
        + rb"]{8}",
    ),
)

# Longest possible match of any default rule (the JWT: 3+4096+1+3+8192+1+8).
# The overlap must exceed it so a match cut by a window edge is re-scanned
# whole in the next window; on top of the overlap, the 2 bytes lookbehinds
# may inspect before a match are kept too (searched from, never matched
# from), so a trimmed window can't drop a boundary char and false-positive.
MAX_MATCH_BYTES: Final = 12_304
_LOOKBEHIND_BYTES: Final = 2
DEFAULT_OVERLAP_BYTES: Final = 16 * 1024
# New bytes buffered before a pass: amortizes the overlap re-scan and keeps
# tiny chunks (1 byte each) from making scanning quadratic.
DEFAULT_BLOCK_BYTES: Final = 256 * 1024


_Compiled = tuple[tuple[str, re.Pattern[bytes]], ...]


def _compile(rules: Sequence[tuple[str, bytes]]) -> _Compiled:
    """Compile each rule separately (see the rule-list comment for why)."""
    if not rules:
        raise ValueError("at least one rule is required")
    compiled = []
    for label, pattern in rules:
        if not label or not label.isprintable() or not label.isascii():
            raise ValueError("rule labels must be non-empty printable ASCII")
        compiled.append((label, re.compile(pattern)))
    return tuple(compiled)


class RegexScanSession:
    """One streaming scan (see `ports.scanner.ScanSession`)."""

    def __init__(self, rules: _Compiled, overlap: int, block: int) -> None:
        self._rules = rules
        self._overlap = overlap
        self._block = block
        self._buf = bytearray()
        self._scanned_prefix = 0  # leading bytes of _buf already scanned (the overlap)
        self._search_from = 0  # leading bytes kept only as lookbehind context
        self._closed = False

    def feed(self, chunk: bytes) -> None:
        """Buffer `chunk`; scan once enough new bytes have accumulated.

        Raises:
            SecretDetectedError: a rule matched (rule name only).
            RuntimeError: the session was already finished or failed.
        """
        self._check_open()
        if not chunk:
            return
        self._buf += chunk
        if len(self._buf) - self._scanned_prefix >= self._block:
            self._scan(final=False)
            # Keep the overlap (enough to re-see any match cut at the edge)
            # plus the lookbehind context in front of it.
            keep = self._overlap + _LOOKBEHIND_BYTES
            if len(self._buf) > keep:
                del self._buf[:-keep]
                self._search_from = _LOOKBEHIND_BYTES
            self._scanned_prefix = len(self._buf)

    def finish(self) -> None:
        """Scan whatever is buffered as the end of the stream.

        Raises:
            SecretDetectedError: a rule matched in the buffered tail.
            RuntimeError: the session was already finished or failed.
        """
        self._check_open()
        try:
            self._scan(final=True)
        finally:
            self._closed = True
            self._buf = bytearray()

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("scan session is closed")

    def _scan(self, *, final: bool) -> None:
        end = len(self._buf)
        for name, pattern in self._rules:
            # Lookbehinds still see the bytes before `pos`.
            match = pattern.search(self._buf, self._search_from)
            # A match touching the window end may be a truncated view (its
            # lookahead can't see the next byte); the next window re-scans
            # it whole. Only the final window is authoritative at its end.
            if match is not None and (final or match.end() < end):
                self._closed = True
                self._buf = bytearray()  # drop buffered content promptly
                raise SecretDetectedError(name)


class RegexSecretScanner:
    """`ContentScanner` built from compiled byte-regex rules (ADR 0008).

    Best effort by design: encoded, encrypted, split-by-format or novel
    secrets pass (docs/security.md Known limitations).

    Args:
        rules: `(label, bytes regex)` pairs; defaults to `DEFAULT_RULES`.
            Custom rules must keep matches shorter than `overlap_bytes`,
            and labels must never be a substring of what the rule matches
            (the label is echoed to the publisher).
        overlap_bytes: bytes kept between windows (> `MAX_MATCH_BYTES`).
        block_bytes: new bytes buffered before each scan pass.

    Raises:
        ValueError: invalid rules or window sizes.
    """

    def __init__(
        self,
        rules: Sequence[tuple[str, bytes]] = DEFAULT_RULES,
        *,
        overlap_bytes: int = DEFAULT_OVERLAP_BYTES,
        block_bytes: int = DEFAULT_BLOCK_BYTES,
    ) -> None:
        if overlap_bytes <= MAX_MATCH_BYTES + _LOOKBEHIND_BYTES:
            raise ValueError(f"overlap_bytes must exceed {MAX_MATCH_BYTES + _LOOKBEHIND_BYTES}")
        if block_bytes <= 0:
            raise ValueError("block_bytes must be > 0")
        self._rules = _compile(rules)
        self._rule_names = tuple(name for name, _ in rules)
        self._overlap = overlap_bytes
        self._block = block_bytes

    @property
    def rule_names(self) -> tuple[str, ...]:
        """Labels of the active rules, in priority order."""
        return self._rule_names

    def new_session(self) -> RegexScanSession:
        """Return a fresh streaming session."""
        return RegexScanSession(self._rules, self._overlap, self._block)
