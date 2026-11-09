"""Case-insensitive secret-path denylist matcher for MCP intake (docs/security.md C10).

Implements "Intake denylist semantics": NFC + casefold on both sides,
fnmatch globbing per whole path component, and `(full)` patterns (containing
`/`) matched against runs of consecutive components. Pure, stdlib only.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Sequence

from preview_dashboard.config import normalize_pattern


def _compile(pattern: str) -> re.Pattern[str]:
    # translate() anchors the whole string, so matching is whole-component.
    return re.compile(fnmatch.translate(pattern))


class DenyList:
    """Matches resolved path components against denylist patterns.

    Args:
        patterns: glob patterns; normalized here (idempotent), so both raw
            and `Settings`-normalized patterns work.
    """

    def __init__(self, patterns: Iterable[str]) -> None:
        single: list[tuple[str, re.Pattern[str]]] = []
        multi: list[tuple[str, tuple[re.Pattern[str], ...]]] = []
        for raw in sorted({normalize_pattern(p) for p in patterns}):
            if "/" in raw:
                multi.append((raw, tuple(_compile(s) for s in raw.split("/"))))
            else:
                single.append((raw, _compile(raw)))
        self._single = tuple(single)
        self._multi = tuple(multi)

    def match_last(self, components: Sequence[str]) -> str | None:
        """Return the pattern matching the LAST component, or None.

        Checks single-component patterns against `components[-1]` and
        `(full)` patterns against every run of components ending there.
        Calling this for each prefix of a path is equivalent to `match` on
        the whole path; walks use it to check each new component once.
        """
        if not components:
            return None
        norm = [normalize_pattern(c) for c in components]
        last = norm[-1]
        for raw, regex in self._single:
            if regex.match(last):
                return raw
        for raw, segments in self._multi:
            start = len(norm) - len(segments)
            if start >= 0 and all(
                seg.match(comp) for seg, comp in zip(segments, norm[start:], strict=True)
            ):
                return raw
        return None

    def match(self, components: Sequence[str]) -> str | None:
        """Return the first pattern matching anywhere on the path, or None.

        Args:
            components: path components relative to `/` (no separators).
        """
        for end in range(1, len(components) + 1):
            hit = self.match_last(components[:end])
            if hit is not None:
                return hit
        return None
