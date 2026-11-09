"""Event-type registry (Registry + Strategy, like `kinds/`) for notifications.

`EventType` is the strategy: it turns a `RenderContext` into a
channel-neutral `MessageContent`. `EventRegistry` holds the registered
types; `events/__init__.py`'s `default_event_registry()` is the one place
listing the built-ins (question, done, failed, reply, voice, approval). Pure stdlib
(ADR 0021, ADR 0031).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import MESSAGE_TEXT_MAX_CHARS, MessageContent
from preview_dashboard.domain.questions import QuestionOption, QuestionState, validate_plugin_name
from preview_dashboard.domain.text import trim_cut_end

_ELLIPSIS = "…"


@dataclass(frozen=True, slots=True, kw_only=True)
class RenderContext:
    """Everything an event type may put into a message (already sanitized).

    Attributes:
        title: notification title (a question's prompt), sanitized.
        link: server-built dashboard URL (`DashboardLinks`), or None.
        session_label: the asking session's label (questions), or None.
        options: the question's options (become answer buttons).
        final_state: set when rendering a question's outcome (RESOLVE).
        answer_label: label of the chosen option when ANSWERED.
        body: multi-line message text of a `reply`/`voice` (C56), posted by
            the Claudia host only, or an approval prompt's stored action
            text (C46); None for every alert.
    """

    title: str
    link: str | None = None
    session_label: str | None = None
    options: tuple[QuestionOption, ...] = ()
    final_state: QuestionState | None = None
    answer_label: str | None = None
    body: str | None = None


class EventType(Protocol):
    """A strategy for one notification event type.

    Attributes:
        name: registry key (`[a-z][a-z0-9-]{0,31}`), e.g. `done`.
        emoji: leading symbol of the message text.
        actionable: whether the message carries answer buttons (only
            `question`); `NotifyService` only sends non-actionable types.
    """

    name: str
    emoji: str
    actionable: bool

    def render(self, ctx: RenderContext) -> MessageContent:
        """Return the message for `ctx` (text <= 300 chars; channels only format it)."""
        ...


def compose_text(emoji: str, title: str, extra_lines: Sequence[str] = ()) -> str:
    """`"<emoji> <title>"` plus extra lines, cutting the title (with `…`) to fit 300 chars.

    The title is the only long part (<= 200 chars); status and session
    lines are short and must always survive, so the title yields.

    Raises:
        ValidationError: the extra lines alone leave no room for a title.
    """
    tail = "".join(f"\n{line}" for line in extra_lines)
    head = f"{emoji} "
    budget = MESSAGE_TEXT_MAX_CHARS - len(head) - len(tail)
    if budget < 2:
        raise ValidationError("message lines leave no room for the title")
    if len(title) > budget:
        title = trim_cut_end(title[: budget - 1]) + _ELLIPSIS
    return f"{head}{title}{tail}"


class EventRegistry:
    """Holds every registered `EventType` and looks them up by name."""

    def __init__(self) -> None:
        self._by_name: dict[str, EventType] = {}

    def register(self, event_type: EventType) -> None:
        """Add `event_type`.

        Raises:
            ValidationError: its name has the wrong syntax.
            ValueError: an event type with this name is already registered.
        """
        validate_plugin_name(event_type.name, "event type")
        if event_type.name in self._by_name:
            raise ValueError(f"event type {event_type.name!r} is already registered")
        self._by_name[event_type.name] = event_type

    def get(self, name: str) -> EventType:
        """Return the event type called `name`.

        Raises:
            ValidationError: no such event type (untrusted input, answered as 400).
        """
        try:
            return self._by_name[name]
        except (KeyError, TypeError):
            raise ValidationError("unknown event type") from None

    def names(self) -> tuple[str, ...]:
        """Registered names, in registration order."""
        return tuple(self._by_name)
