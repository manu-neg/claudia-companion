"""The `done` event type: "a task finished", with an optional dashboard link, no buttons."""

from __future__ import annotations

from preview_dashboard.domain.notifications import MessageContent
from preview_dashboard.events.base import RenderContext, compose_text

DONE_EVENT = "done"


class DoneEventType:
    """Work finished; informational only."""

    name = DONE_EVENT
    emoji = "✅"
    actionable = False

    def render(self, ctx: RenderContext) -> MessageContent:
        """`✅ <title>` plus the link."""
        return MessageContent(text=compose_text(self.emoji, ctx.title), link=ctx.link)
