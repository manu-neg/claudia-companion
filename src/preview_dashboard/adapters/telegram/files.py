"""TelegramMediaFiles: fetch one owner voice note / photo by `file_id` (docs/security.md C61).

`getFile` resolves the id to a `file_path`, which is validated (short
relative path, no `..`) before `TelegramBotClient.download` fetches it from
the same Bot API host with a hard byte cap. A size Telegram reports above
the cap is refused before any download. The bot token never leaves the
client; errors carry no URL, path or file id.
"""

from __future__ import annotations

import re

from preview_dashboard.adapters.telegram.answers import as_dict, as_int
from preview_dashboard.adapters.telegram.client import (
    MAX_DOWNLOAD_BYTES,
    TelegramBotClient,
    validate_file_path,
)

# Telegram file ids are url-safe base64-ish tokens.
_FILE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,256}")


class MediaRefusedError(ValueError):
    """The file can never be fetched within the rules (bad id/path, over the cap)."""


def validate_file_id(raw: object) -> str:
    """A Telegram `file_id` (url-safe chars, <= 256).

    Raises:
        MediaRefusedError: anything else.
    """
    if not isinstance(raw, str) or not _FILE_ID_RE.fullmatch(raw):
        raise MediaRefusedError("telegram file id has an unexpected format")
    return raw


class TelegramMediaFiles:
    """Downloads owner media through the notifier's single Bot API client.

    Args:
        client: the Bot API client (holds the token).
    """

    def __init__(self, client: TelegramBotClient) -> None:
        self._client = client

    def download(self, file_id: str, max_bytes: int) -> bytes:
        """The bytes of `file_id`, at most `max_bytes` (<= 10 MiB).

        Raises:
            MediaRefusedError: bad id, bad `file_path`, a cap over 10 MiB or
                a reported size over `max_bytes` (dropped for good).
            TelegramFileTooLargeError: the body went past the cap (dropped).
            TelegramError: `getFile` or the download failed (retried).
        """
        if not 0 < max_bytes <= MAX_DOWNLOAD_BYTES:
            raise MediaRefusedError("download cap out of range")
        result = as_dict(self._client.call("getFile", {"file_id": validate_file_id(file_id)}))
        size = as_int(result.get("file_size"))
        if size is not None and not 0 < size <= max_bytes:
            raise MediaRefusedError("telegram reports a file over the cap")
        try:
            path = validate_file_path(result.get("file_path"))
        except ValueError:
            raise MediaRefusedError("telegram file path has an unexpected format") from None
        return self._client.download(path, max_bytes=max_bytes)
