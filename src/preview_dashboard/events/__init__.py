"""Notification event types (Registry + Strategy) and the built-in ones.

`default_event_registry()` is the single place that lists every built-in
event type; adding one means adding a module here plus one line there (see
docs/extending.md, "Adding an event type"). Pure stdlib (ADR 0021, ADR 0031).
"""

from __future__ import annotations

from preview_dashboard.events.approval import APPROVAL_EVENT, ApprovalEventType
from preview_dashboard.events.base import EventRegistry, EventType, RenderContext, compose_text
from preview_dashboard.events.done import DONE_EVENT, DoneEventType
from preview_dashboard.events.failed import FAILED_EVENT, FailedEventType
from preview_dashboard.events.question import QUESTION_EVENT, QuestionEventType
from preview_dashboard.events.reply import REPLY_EVENT, ReplyEventType
from preview_dashboard.events.voice import VOICE_EVENT, VoiceEventType

__all__ = [
    "APPROVAL_EVENT",
    "DONE_EVENT",
    "FAILED_EVENT",
    "QUESTION_EVENT",
    "REPLY_EVENT",
    "VOICE_EVENT",
    "EventRegistry",
    "EventType",
    "RenderContext",
    "compose_text",
    "default_event_registry",
]


def default_event_registry() -> EventRegistry:
    """Build an `EventRegistry` with `question`, `done`, `failed`, `reply`, `voice`, `approval`."""
    registry = EventRegistry()
    for event_type in (
        QuestionEventType(),
        DoneEventType(),
        FailedEventType(),
        ReplyEventType(),
        VoiceEventType(),
        ApprovalEventType(),
    ):
        registry.register(event_type)
    return registry
