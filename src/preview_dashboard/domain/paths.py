"""Validation of bundle-relative file paths (docs/security.md C7).

`validate_relpath` is the single gate for every path that names a file
inside an item (manifest entries, preview URLs, zip arcnames). It is
canonical-or-reject: it never "fixes" input, so a valid path is returned
unchanged and validation is trivially idempotent.
"""

from __future__ import annotations

import unicodedata

from preview_dashboard.domain.errors import InvalidPathError
from preview_dashboard.domain.unicode import BLANK_LOOKALIKES, is_default_ignorable

MAX_SEGMENT_BYTES = 255
MAX_PATH_BYTES = 1024
MAX_DEPTH = 16

# Unicode categories rejected anywhere in a path: control (Cc: C0 incl.
# CR/LF, DEL, C1), format (Cf: bidi overrides/isolates U+202A-202E and
# U+2066-2069, zero-width chars used for filename spoofing), surrogate (Cs),
# private use (Co), unassigned (Cn), line/paragraph separators.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

# ':' covers Windows drive letters ("C:x") and NTFS alternate data streams
# ("a.txt:evil"); '\\' is a separator on Windows. Both matter because the
# owner may extract downloaded zips on Windows. The rest are reserved in
# Windows file names (`" < > | * ?`) or are URL delimiters/escapes (`% ? # ;`)
# that invite double-decoding and path-parameter confusion in preview URLs.
# `'` stays allowed ("it's.txt") — SQL safety comes from parameterized SQL.
_FORBIDDEN_CHARS = frozenset('\\:%?#;"<>|*')

# NFKC-stable look-alikes of '/', '\\' and ':' that Windows "best fit"
# code-page conversion still folds into the real separator (WorstFit):
# division/fraction slash, set minus, reverse solidus operator, ratio,
# modifier colon, and '¥'/'₩', which *are* 0x5C in cp932/cp949.
_SEPARATOR_LOOKALIKES = frozenset("\u2215\u2044\u2216\u29f5\u29f8\u29f9\u2236\ua789\u00a5\u20a9")

# Windows reserved device names: "NUL", "nul.txt", "Com1.tar.gz" all open
# the device on Windows, whatever the case or extension. Superscript-digit
# variants ("COM¹") are already rejected by the NFKC rule.
_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{dev}{n}" for dev in ("COM", "LPT") for n in range(10)}
)


def validate_relpath(raw: str) -> str:
    """Return `raw` if it is a safe, canonical POSIX relative path.

    Rules (each violation raises `InvalidPathError`):
    - must be a non-empty `str`, at most 1024 UTF-8 bytes;
    - must be NFC-normalized, and every segment NFKC-stable (no fullwidth or
      compatibility look-alikes such as fullwidth dot/solidus/reverse
      solidus/colon (U+FF0E, U+FF0F, U+FF3C, U+FF1A) or superscript digits,
      which tools may fold into `..\\`, `a/b`, `a:b`, `COM1`);
    - no leading `/` (absolute), no leading `~` (home-dir expansion in tools);
    - none of `\\ : % ? # ; " < > | *` (Windows separators/drives/UNC/ADS and
      reserved chars, URL delimiters and escapes), nor separator look-alikes
      that survive NFKC but not Windows best-fit (U+2215, U+2044, U+2216,
      U+2236, YEN SIGN, WON SIGN, ...);
    - no control/format/surrogate/private-use/unassigned characters, no
      Default_Ignorable code points (Hangul fillers, CGJ, variation
      selectors, tags, ...) and no blank look-alikes (U+2800);
    - at most 16 `/`-separated segments; each non-empty (no `a//b`, no
      trailing `/`), at most 255 UTF-8 bytes, not made only of dots (`.`,
      `..`), without leading/trailing whitespace, without a trailing dot and
      not a Windows reserved device name (`CON`, `nul.txt`, `COM1`, `LPT9`, ...).

    Returns:
        The input unchanged (canonical-or-reject; never rewritten).
    """
    if not isinstance(raw, str):
        raise InvalidPathError("path must be a string")
    if not raw:
        raise InvalidPathError("path must not be empty")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates
        raise InvalidPathError("path is not valid UTF-8") from None
    if len(encoded) > MAX_PATH_BYTES:
        raise InvalidPathError(f"path exceeds {MAX_PATH_BYTES} bytes")
    if unicodedata.normalize("NFC", raw) != raw:
        raise InvalidPathError("path must be NFC-normalized")
    if raw.startswith("/"):
        raise InvalidPathError("path must be relative")
    if raw.startswith("~"):
        raise InvalidPathError("path must not start with '~'")
    for ch in raw:
        if ch in _FORBIDDEN_CHARS or ch in _SEPARATOR_LOOKALIKES:
            raise InvalidPathError("path contains a forbidden character")
        if (
            unicodedata.category(ch) in _FORBIDDEN_CATEGORIES
            or is_default_ignorable(ch)
            or ch in BLANK_LOOKALIKES
        ):
            raise InvalidPathError("path contains a control or invisible character")
    segments = raw.split("/")
    if len(segments) > MAX_DEPTH:
        raise InvalidPathError(f"path is deeper than {MAX_DEPTH} segments")
    for segment in segments:
        _validate_segment(segment)
    return raw


def _validate_segment(segment: str) -> None:
    """Check one `/`-separated segment; raise `InvalidPathError` if unsafe."""
    if not segment:
        raise InvalidPathError("path has an empty segment")
    # Compatibility look-alikes (fullwidth '.', '/', '\\', ':', '%') are folded to
    # their ASCII forms by NFKC-normalizing tools and by Windows "best fit"
    # code-page conversion (WorstFit), turning a harmless-looking name into
    # traversal. Requiring NFKC-stable segments rejects the whole class.
    if unicodedata.normalize("NFKC", segment) != segment:
        raise InvalidPathError("path segment must be NFKC-normalized")
    # Dot-only segments: '.'/'..' traverse on POSIX ('...' is caught by the
    # trailing-dot rule below, but is rejected here first).
    if segment.strip(".") == "":
        raise InvalidPathError("path segment must not consist only of dots")
    if segment != segment.strip():
        raise InvalidPathError("path segment has leading or trailing whitespace")
    # Windows silently drops trailing dots/spaces, so 'a.' and 'a' would
    # alias (and collide) when the owner extracts a zip there.
    if segment.endswith("."):
        raise InvalidPathError("path segment must not end with a dot")
    # Windows also ignores spaces before the extension: "NUL .txt" is NUL.
    if segment.split(".", 1)[0].rstrip(" ").upper() in _RESERVED_DEVICE_NAMES:
        raise InvalidPathError("path segment is a reserved device name")
    if len(segment.encode("utf-8")) > MAX_SEGMENT_BYTES:
        raise InvalidPathError(f"path segment exceeds {MAX_SEGMENT_BYTES} bytes")
