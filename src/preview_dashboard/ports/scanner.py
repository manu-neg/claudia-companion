"""ContentScanner port: streaming secret detection over published bytes.

The admin publish path feeds every byte of every file (and the inline
metadata) through a scan session before it is committed (docs/security.md
C15, ADR 0008). Implementations: `adapters/secret_scan.py` (regex rules),
`tests/fakes.py` (marker-based fake).
"""

from __future__ import annotations

from typing import Protocol


class ScanSession(Protocol):
    """Scans one logical byte stream (one file) fed in arbitrary chunks.

    Detection must not depend on how the stream is chunked: a secret split
    across two (or more) `feed` calls is still found, at the latest by
    `finish`. A session is single-use and not thread-safe.
    """

    def feed(self, chunk: bytes) -> None:
        """Scan the next chunk of the stream.

        Raises:
            SecretDetectedError: a rule matched. The error names the rule
                only, never the matched bytes.
        """
        ...

    def finish(self) -> None:
        """Signal end of stream and scan anything still buffered.

        Raises:
            SecretDetectedError: a rule matched in the buffered tail.
        """
        ...


class ContentScanner(Protocol):
    """Factory for scan sessions; stateless and safe to share across threads."""

    def new_session(self) -> ScanSession:
        """Return a fresh session for one byte stream."""
        ...
