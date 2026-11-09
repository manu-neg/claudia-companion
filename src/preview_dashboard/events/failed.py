"""The `failed` event type: "a task failed", with an optional dashboard link, no buttons."""

from __future__ import annotations

from preview_dashboard.domain.notifications import MessageContent
from preview_dashboard.events.base import RenderContext, compose_text

FAILED_EVENT = "failed"


class FailedEventType:
    """Work failed; informational only."""

    name = FAILED_EVENT
    emoji = "❌"
    actionable = False

    def render(self, ctx: RenderContext) -> MessageContent:
        """`❌ <title>` plus the link."""
        return MessageContent(text=compose_text(self.emoji, ctx.title), link=ctx.link)
