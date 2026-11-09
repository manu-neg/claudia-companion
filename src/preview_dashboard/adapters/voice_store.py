"""Filesystem store for voice audio waiting for delivery (C56, unit M10).

Implements `ports.claudia_voice.VoiceStore`: one `<ULID>.ogg` file per reply
in an admin-only directory (0700 dir, 0600 files), written atomically, capped
in count, deleted once delivered or given up and by an age sweep. File names
come only from validated ULIDs, so no path can escape the directory.
"""

from __future__ import annotations

import contextlib
import os
import re
import time
from pathlib import Path
from typing import Final

from preview_dashboard.domain.errors import (
    ConflictError,
    LimitExceededError,
    StorageUnavailableError,
    ValidationError,
)

MAX_WAITING: Final = 50
VOICE_DIR_NAME: Final = "voice"  # under the admin-only data dir
_ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")
_SUFFIX: Final = ".ogg"


def _check_id(voice_id: str) -> str:
    if not isinstance(voice_id, str) or not _ULID_RE.fullmatch(voice_id):
        raise ValidationError("voice id must be a ULID")
    return voice_id


class FsVoiceStore:
    """Voice audio files under `root` (created 0700 on first use)."""

    def __init__(self, root: Path, *, max_waiting: int = MAX_WAITING) -> None:
        self._root = root
        self._max = max_waiting

    def _path(self, voice_id: str) -> Path:
        return self._root / f"{_check_id(voice_id)}{_SUFFIX}"

    def save(self, voice_id: str, audio: bytes) -> None:
        """Write `audio` atomically as a new 0600 file.

        Raises:
            ValidationError: bad id.
            ConflictError: the id already has audio.
            LimitExceededError: `max_waiting` files are already waiting.
            StorageUnavailableError: the directory cannot be written.
        """
        path = self._path(voice_id)
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.exists():
                raise ConflictError("voice audio already stored")
            if sum(1 for _ in self._root.glob(f"*{_SUFFIX}")) >= self._max:
                raise LimitExceededError("too many voice notes are waiting")
            tmp = path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(audio)
            tmp.replace(path)
        except OSError:
            raise StorageUnavailableError("voice store is not writable") from None

    def load(self, voice_id: str) -> bytes | None:
        """The audio, or None if absent or the id is not a ULID."""
        try:
            return self._path(voice_id).read_bytes()
        except (ValidationError, OSError):
            return None

    def discard(self, voice_id: str) -> None:
        """Delete the file (delivered or given up); absent or invalid ids are ignored."""
        with contextlib.suppress(ValidationError, OSError):
            self._path(voice_id).unlink(missing_ok=True)

    def purge_older_than(self, seconds: float) -> int:
        """Delete audio (and stray temp files) older than `seconds`; return the count."""
        try:
            if not self._root.is_dir():
                return 0
            entries = list(self._root.iterdir())  # unreadable dir: nothing to sweep, not a crash
        except OSError:
            return 0
        cutoff, removed = time.time() - seconds, 0
        for path in entries:
            with contextlib.suppress(OSError):
                if path.suffix in (_SUFFIX, ".tmp") and path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
        return removed
