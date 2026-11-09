"""UlidGenerator: stdlib-only IdGenerator producing canonical ULIDs (ADR 0007).

A ULID is a 48-bit UTC-millisecond timestamp followed by 80 bits of
randomness, encoded as 26 uppercase Crockford-base32 characters. Ids double
as filesystem keys (see `adapters/fs_blobstore.py`), so only the canonical
spelling accepted by `domain.models.is_ulid` is ever produced.
"""

from __future__ import annotations

import os
import threading
import time

from preview_dashboard.domain.models import ItemId, is_ulid

# Crockford base32: 0-9, then A-Z minus the visually-confusable I, L, O, U.
_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_TIME_BITS = 48
_TIME_CHARS = 10  # 50 bits of capacity for a 48-bit value keeps the first
# char's top 2 bits always zero, so it lands in '0'..'7' (matches _ULID_RE).
_RAND_BITS = 80
_RAND_CHARS = 16


def _encode(value: int, chars: int) -> str:
    """Encode `value` as `chars` Crockford-base32 digits, most-significant first."""
    out = [""] * chars
    for i in range(chars - 1, -1, -1):
        out[i] = _CROCKFORD_ALPHABET[value & 0x1F]
        value >>= 5
    return "".join(out)


class UlidGenerator:
    """Generates canonical ULIDs from wall-clock time plus CSPRNG randomness.

    Monotonic within a single process for ids requested in the same
    millisecond: instead of re-randomizing, the random part is incremented,
    so a burst of ids from one process still sorts in call order. This is a
    nice-to-have, not a correctness requirement — 80 bits of fresh
    randomness already make cross-process collisions negligible.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_rand = 0

    def _next(self) -> str:
        with self._lock:
            now_ms = time.time_ns() // 1_000_000
            if now_ms > self._last_ms:
                self._last_ms = now_ms
                self._last_rand = int.from_bytes(os.urandom(_RAND_BITS // 8), "big")
            else:
                # Same millisecond (or the clock moved backwards): keep the
                # timestamp and bump randomness to stay strictly increasing.
                self._last_rand = (self._last_rand + 1) % (1 << _RAND_BITS)
                if self._last_rand == 0:  # 80-bit overflow: vanishingly rare
                    self._last_ms += 1
            ulid = _encode(self._last_ms & ((1 << _TIME_BITS) - 1), _TIME_CHARS) + _encode(
                self._last_rand, _RAND_CHARS
            )
        if not is_ulid(ulid):  # pragma: no cover - defensive, see ADR 0007
            raise RuntimeError("internal error: generated a non-canonical ULID")
        return ulid

    def new_item_id(self) -> ItemId:
        """Return a new, never-before-returned item id."""
        return ItemId(self._next())

    def new_blob_id(self) -> str:
        """Return a new, never-before-returned blob id (canonical ULID)."""
        return self._next()
