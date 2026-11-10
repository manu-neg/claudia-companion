"""Ports for the host's voice/photo turns (docs/security.md C62, unit F-CL4 B).

`HostMedia` fetches and releases a voice/photo message's checked bytes at
the admin (C61 routes, `claudia` token). `Transcriber` turns a voice note
into text inside the sandbox; `RunMediaFiles` places a photo in the run's
work dir and removes it after the run.

Security obligations for every implementation (C62):
- **Transcriber:** decode and transcribe only inside the sandbox (no
  network, dynamic user, read-only binds, memory/time caps, no env); the
  host never parses the audio beyond the C61 content check; host-side temp
  files deleted before returning, success or not; never log the audio or
  the transcript.
- **RunMediaFiles:** names only from a validated ULID, files 0600 in 0700
  dirs, no symlink followed; `discard` never raises.
"""

from __future__ import annotations

from typing import Protocol

from preview_dashboard.domain.approvals import WindowId
from preview_dashboard.domain.errors import DomainError
from preview_dashboard.domain.owner_messages import OwnerMessageId


class TranscriptionError(DomainError):
    """A voice note could not be transcribed; the message names a fixed reason, never content."""


class HostMedia(Protocol):
    """The admin's media routes for the host (`GET …/media`, `POST …/media/release`)."""

    def fetch_media(self, message_id: OwnerMessageId) -> bytes:
        """The checked bytes of a voice/photo message.

        Raises:
            NotFoundError: no media (text message, released or purged).
            StorageUnavailableError: the admin could not be reached or answered badly.
        """
        ...

    def release_media(self, message_id: OwnerMessageId) -> None:
        """Delete the admin's copy (idempotent).

        Raises:
            StorageUnavailableError: the admin could not be reached or refused.
        """
        ...


class Transcriber(Protocol):
    """Speech to text for one owner voice note (Ogg/Opus, checked by content first)."""

    def transcribe(self, audio: bytes) -> str:
        """The transcript, non-speech tags stripped; never empty.

        Raises:
            TranscriptionError: refused input, sandbox failure, timeout or no speech.
        """
        ...


class RunMediaFiles(Protocol):
    """Photo files inside a run's work dir (`<workdir>/<window>/media/<ulid>.jpg`)."""

    def put_photo(self, window_id: WindowId, media_id: str, data: bytes) -> str:
        """Write the JPEG 0600 and return its absolute path.

        Raises:
            ValidationError: bad window or media id.
            StorageUnavailableError: the file could not be written safely.
        """
        ...

    def discard(self, path: str) -> None:
        """Delete a file `put_photo` returned (and its empty dirs); never raises."""
        ...

    def sweep(self) -> int:
        """Delete every photo left over in any window's `media` dir (host start); the count."""
        ...
