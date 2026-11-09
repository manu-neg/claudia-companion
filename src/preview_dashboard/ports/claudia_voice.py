"""Ports for Claudia's voice replies: text-to-speech and the temporary audio store (C56, M10).

`TextToSpeech` is implemented by `adapters/piper_tts.py` (local, no network)
and by a fake in tests; `VoiceStore` by `adapters/voice_store.py`. Pure
typing; no framework imports.
"""

from __future__ import annotations

from typing import Protocol


class TextToSpeech(Protocol):
    """Turns already-scanned text into one Ogg/Opus voice note."""

    def synthesize(self, text: str, language: str) -> bytes:
        """Return Ogg/Opus bytes of `text` spoken in `language` (`"es"` or `"en"`).

        Raises:
            StorageUnavailableError: the engine or voice model is missing or failed.
        """
        ...


class VoiceStore(Protocol):
    """Short-lived audio files keyed by delivery id; deleted once delivered or given up."""

    def save(self, voice_id: str, audio: bytes) -> None:
        """Store `audio` under `voice_id` (a ULID), replacing nothing.

        Raises:
            ValidationError: `voice_id` is not a canonical ULID.
            ConflictError: audio for this id already exists.
            LimitExceededError: too many files are waiting.
            StorageUnavailableError: the store cannot be written.
        """
        ...

    def load(self, voice_id: str) -> bytes | None:
        """The stored audio, or None when there is none (never raises for unknown ids)."""
        ...

    def discard(self, voice_id: str) -> None:
        """Delete the audio of `voice_id` (delivered or given up); unknown ids are fine."""
        ...

    def purge_older_than(self, seconds: float) -> int:
        """Delete files older than `seconds`; return how many (housekeeping)."""
        ...
