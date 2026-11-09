"""Claudia voice replies: compose a voice note from scanned text; the admin takes it in (C56, M10).

Host side: `VoiceComposer` speaks **only** text that passed the outgoing
reply policy and the secret scan, picks the voice from the message language,
and falls back to a short spoken summary (the full text is always sent too)
when the audio would exceed the caps. Admin side: `VoiceService` validates
the uploaded audio, queues the text through the reply path (same budget and
scan) and keeps the audio only until delivered or given up. Ports only; the
engine (piper, soundfile) lives in `adapters/piper_tts.py`.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

from preview_dashboard.application.notify import scan_texts
from preview_dashboard.application.replies import validate_reply_text
from preview_dashboard.domain.errors import (
    ConflictError,
    LimitExceededError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.events.voice import VoiceAudio, validate_voice_audio
from preview_dashboard.ports.claudia_voice import TextToSpeech, VoiceStore
from preview_dashboard.ports.scanner import ContentScanner

logger = logging.getLogger("preview_dashboard.voice")

LANG_ES: Final = "es"
LANG_EN: Final = "en"
# ~12-15 spoken characters per second: 700 chars stay well under the 60 s cap;
# the real duration is still checked on the audio itself.
MAX_SPOKEN_CHARS: Final = 700
SUMMARY_MAX_CHARS: Final = 280
# Fixed, owner-language pointer appended to a summary (not model output).
_POINTERS: Final = {
    LANG_ES: " El texto completo está en el mensaje.",
    LANG_EN: " The full text is in the message.",
}
_SENTENCE_END = re.compile(r"(?<=[.!?…])\s+")
_MARKUP = re.compile(r"[*_`#>~|]+")
_WORD = re.compile(r"[a-záéíóúüñ]+")
# Common stop words: enough signal for a chat-length message, no dictionary needed.
_ES_STOP = (
    "el la los las de que y en un una es por con para no se lo como más pero está hola "
    "gracias esto del al su qué sí ya muy tengo puedo estoy tienes hay también cuando donde"
)
_EN_STOP = (
    "the and is are to of in it you that for with this on be have not i my your what but "
    "can will hello thanks was do does there here"
)
_ES_WORDS: Final = frozenset(_ES_STOP.split())
_EN_WORDS: Final = frozenset(_EN_STOP.split())
_ES_CHARS: Final = frozenset("¿¡ñáéíóúü")


def detect_language(text: str) -> str:
    """`"es"` or `"en"`: whichever the message looks like (ties and no signal: English).

    Spanish-only characters weigh more than stop words, so a short
    "¡Hola!" is Spanish while a plain English sentence stays English.
    """
    lowered = text.lower()
    es = 2 * sum(ch in _ES_CHARS for ch in lowered)
    en = 0
    for word in _WORD.findall(lowered):
        es += word in _ES_WORDS
        en += word in _EN_WORDS
    return LANG_ES if es > en else LANG_EN


def spoken_form(text: str, language: str) -> str:
    """The text as spoken: markup characters dropped, newlines as pauses, nothing added.

    Raises:
        ValidationError: no speakable text is left.
    """
    del language  # same rule for both voices; kept for a future per-language tweak
    flat = re.sub(r"\s+", " ", _MARKUP.sub(" ", text)).strip()
    if not flat:
        raise ValidationError("nothing to speak")
    return flat


def spoken_summary(text: str, language: str) -> str:
    """A short spoken summary: the leading sentences of `text` plus a fixed pointer.

    Only words already in the scanned text are spoken, plus the fixed pointer.

    Raises:
        ValidationError: no speakable text (see `spoken_form`).
    """
    flat = spoken_form(text, language)
    summary = ""
    for sentence in _SENTENCE_END.split(flat):
        if summary and len(summary) + 1 + len(sentence) > SUMMARY_MAX_CHARS:
            break
        summary = f"{summary} {sentence}".strip()
    if len(summary) > SUMMARY_MAX_CHARS:
        summary = summary[:SUMMARY_MAX_CHARS].rsplit(" ", 1)[0]
    return summary + _POINTERS[language]


@dataclass(frozen=True, slots=True, kw_only=True)
class VoiceNote:
    """A composed voice reply: the full text (always sent), the checked audio, how it was made."""

    text: str
    audio: VoiceAudio
    language: str
    summarized: bool


class VoiceComposer:
    """Host-side: scanned reply text -> checked Ogg/Opus voice note.

    Args:
        tts: the speech engine (local, no network).
        scanner: the secret scanner; the text is scanned **before** it is spoken.
    """

    def __init__(self, *, tts: TextToSpeech, scanner: ContentScanner) -> None:
        self._tts = tts
        self._scanner = scanner

    def compose(self, text: str) -> VoiceNote:
        """Speak `text` (or a summary when too long) and check the audio against the caps.

        Raises:
            ValidationError: the text breaks the reply policy, or even the
                summary does not fit the audio caps.
            SecretDetectedError: the text matches a secret rule (nothing is spoken).
            StorageUnavailableError: the speech engine is unavailable.
        """
        validate_reply_text(text)
        scan_texts(self._scanner, (text,))
        language = detect_language(text)
        spoken = spoken_form(text, language)
        if len(spoken) <= MAX_SPOKEN_CHARS:
            try:
                return VoiceNote(
                    text=text,
                    audio=self._speak(spoken, language),
                    language=language,
                    summarized=False,
                )
            except ValidationError:
                logger.info("voice: audio over the caps, speaking a summary")
        audio = self._speak(spoken_summary(text, language), language)
        return VoiceNote(text=text, audio=audio, language=language, summarized=True)

    def _speak(self, spoken: str, language: str) -> VoiceAudio:
        return validate_voice_audio(self._tts.synthesize(spoken, language))


class VoiceToggle:
    """The `/voice` on/off state (default off); thread-safe. M4b calls `toggle()`."""

    def __init__(self, *, enabled: bool = False) -> None:
        self._enabled = enabled
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Whether replies are currently also spoken."""
        with self._lock:
            return self._enabled

    def toggle(self) -> bool:
        """Flip the state and return the new one."""
        with self._lock:
            self._enabled = not self._enabled
            return self._enabled


class ReplySender(Protocol):
    """The reply path (`ReplyService.send`): validation, secret scan, budget, queueing."""

    def send(
        self,
        text: str,
        *,
        message_id: str | None,
        item_id: str | None,
        before_visible: Callable[[str], None] | None = None,
    ) -> str:
        """Queue the reply; return its delivery id.

        `before_visible(id)` is called once the id exists, before the reply can be fetched.
        """
        ...


class VoiceService:
    """Admin-side: take a voice reply (text + audio) under the reply budget.

    The audio is checked first (a bad upload uses no budget); the text then
    goes through the reply path, so a voice reply costs exactly one reply and
    the text is always delivered. The audio is kept under the reply's id
    until the notifier has delivered or given up (`release`).
    """

    def __init__(self, *, replies: ReplySender, store: VoiceStore) -> None:
        self._replies = replies
        self._store = store

    def send(self, text: str, audio: bytes, *, message_id: str | None, item_id: str | None) -> str:
        """Queue the reply text and keep its audio; return the delivery id.

        Raises:
            ValidationError: bad audio (not one Ogg/Opus stream, over 1 MiB or
                60 s) or bad text / ids (see `ReplyService.send`).
            SecretDetectedError: the text matches a secret rule.
            RateLimitedError: the reply budget is used up.
        """
        validate_voice_audio(audio)
        saved: list[str] = []

        def save_first(reply_id: str) -> None:
            # Runs before the reply is visible, so the notifier's fetch can never race it.
            try:
                self._store.save(reply_id, audio)
                saved.append(reply_id)
            except (LimitExceededError, ConflictError, StorageUnavailableError):
                # The text is what matters: only the note is dropped.
                logger.warning("voice: audio not kept for %s", reply_id)

        try:
            return self._replies.send(
                text, message_id=message_id, item_id=item_id, before_visible=save_first
            )
        except BaseException:
            for reply_id in saved:  # queueing failed after the save: nothing will fetch it
                self._store.discard(reply_id)
            raise

    def fetch(self, voice_id: str) -> bytes | None:
        """The audio waiting for delivery id `voice_id`, if any (for the notifier)."""
        return self._store.load(voice_id)

    def release(self, voice_id: str) -> None:
        """Delete the audio once it was delivered or given up."""
        self._store.discard(voice_id)


__all__ = [
    "LANG_EN",
    "LANG_ES",
    "MAX_SPOKEN_CHARS",
    "ReplySender",
    "VoiceComposer",
    "VoiceNote",
    "VoiceService",
    "VoiceToggle",
    "detect_language",
    "spoken_form",
    "spoken_summary",
]
