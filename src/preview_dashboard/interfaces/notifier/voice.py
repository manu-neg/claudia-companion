"""Voice-note delivery for the notifier: a `DeliveryQueue` decorator (C56, unit M10b).

A reply's text is delivered like any task. Only after the admin has been told
it was delivered does this wrapper fetch the reply's stored audio (notifier
token route), check it, upload it with `sendVoice` and ask the admin to
delete it. So the text always goes out first and never twice: a voice
failure cannot make the text task retry. A voice that cannot be sent is
logged by exception type and left to the purge job's age sweep.
"""

from __future__ import annotations

import logging
from typing import Protocol

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import PendingTask, TaskId
from preview_dashboard.domain.questions import AnswerResult
from preview_dashboard.events.voice import validate_voice_audio
from preview_dashboard.ports.notify import DeliveryQueue

_log = logging.getLogger(__name__)


class VoiceSource(Protocol):
    """The admin's voice routes (`adapters.admin_queue.AdminDeliveryQueue`)."""

    def fetch_voice(self, voice_id: str) -> bytes | None:
        """The audio waiting for reply `voice_id`, or None."""
        ...

    def release_voice(self, voice_id: str) -> None:
        """Delete the audio of `voice_id` at the admin."""
        ...


class VoiceSender(Protocol):
    """The channel's voice upload (`TelegramChannel.send_voice`)."""

    def send_voice(self, audio: bytes) -> str:
        """Upload `audio` as a voice note; return its message ref."""
        ...


class VoiceDeliveries:
    """A `DeliveryQueue` that also sends the voice note of a delivered reply.

    Args:
        inner: the real queue (delegated to for every call).
        source: where the audio is fetched from and released at.
        sender: the channel that uploads it.
    """

    def __init__(self, inner: DeliveryQueue, source: VoiceSource, sender: VoiceSender) -> None:
        self._inner = inner
        self._source = source
        self._sender = sender
        # Task id -> reply id, for the tasks of the last fetch that may have audio.
        self._voice_ids: dict[str, str] = {}

    def pending(self, wait: float) -> list[PendingTask]:
        """Fetch due tasks; remember which of them may have audio."""
        tasks = self._inner.pending(wait)
        self._voice_ids = {t.id: t.payload.voice_id for t in tasks if t.payload.voice_id}
        return tasks

    def done(self, task_id: TaskId, message_ref: str | None) -> None:
        """Report the text delivered, then send its voice note (best effort)."""
        self._inner.done(task_id, message_ref)
        voice_id = self._voice_ids.pop(task_id, None)
        if voice_id is not None:
            self._send_voice(task_id, voice_id)

    def failed(self, task_id: TaskId) -> None:
        """Report a failed try; no audio is sent for a text that did not go out."""
        self._voice_ids.pop(task_id, None)
        self._inner.failed(task_id)

    def submit_answer(
        self, question_id: str, key: str, source: str, actor_ref: str
    ) -> AnswerResult:
        """Delegated unchanged."""
        return self._inner.submit_answer(question_id, key, source, actor_ref)

    def _send_voice(self, task_id: str, voice_id: str) -> None:
        try:
            raw = self._source.fetch_voice(voice_id)
            if raw is None:
                return  # a plain reply: nothing to speak
            audio = validate_voice_audio(raw)
        except ValidationError:
            # Unusable audio never gets better: delete it instead of retrying.
            _log.warning("task %s: stored voice note is invalid; releasing it", task_id)
            self._release(task_id, voice_id)
            return
        except Exception as exc:
            _log.warning("task %s: voice fetch failed (%s)", task_id, type(exc).__name__)
            return
        try:
            self._sender.send_voice(audio.data)
        except Exception as exc:
            # Text is out; the audio stays for the purge sweep (no second text on retry).
            _log.warning("task %s: voice send failed (%s)", task_id, type(exc).__name__)
            return
        self._release(task_id, voice_id)

    def _release(self, task_id: str, voice_id: str) -> None:
        try:
            self._source.release_voice(voice_id)
        except Exception as exc:
            _log.warning("task %s: voice release failed (%s)", task_id, type(exc).__name__)
