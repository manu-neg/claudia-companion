"""JsonlAuditLog: the host's local audit log (C52), one JSONL file per UTC day.

Entries hold ids, targets, digests and flags only (no message text, C52).
Files live in a 0700 directory the host owns, created `O_NOFOLLOW` 0600
and appended to; publishing the day's log as a dashboard item (one
revision per day) is a later unit's job.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from preview_dashboard.ports.claudia_host import AuditValue
from preview_dashboard.ports.clock import Clock

_FLAGS: Final = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
_log = logging.getLogger(__name__)


class JsonlAuditLog:
    """`AuditLog` appending to `<directory>/YYYY-MM-DD.jsonl`.

    Args:
        directory: private audit directory (created 0700 if missing).
        clock: picks the day file.

    Raises (constructor):
        OSError: the directory can't be created.
        ValueError: it is not a real directory private to this user.
    """

    def __init__(self, directory: Path, clock: Clock) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = os.lstat(directory)
        if (
            not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid()
            or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            raise ValueError(f"audit directory {directory} must be a private 0700 directory")
        self._dir = directory
        self._clock = clock

    def record(self, entry: Mapping[str, AuditValue]) -> None:
        """Append one entry; never raises."""
        line = json.dumps(dict(entry), ensure_ascii=True, sort_keys=True) + "\n"
        path = self._dir / f"{self._clock.now().date().isoformat()}.jsonl"
        try:
            fd = os.open(path, _FLAGS, 0o600)
            try:
                os.write(fd, line.encode("ascii"))
            finally:
                os.close(fd)
        except OSError as exc:
            _log.error("audit entry could not be written (%s)", type(exc).__name__)
