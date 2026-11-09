"""The `question` event type: the prompt, the asking session and one button per option.

Also renders the question's outcome (for RESOLVE deliveries): the same text
plus a status line, with the buttons removed so no late tap is offered.
"""

from __future__ import annotations

from preview_dashboard.domain.notifications import MessageButton, MessageContent
from preview_dashboard.domain.questions import QuestionState
from preview_dashboard.events.base import RenderContext, compose_text

QUESTION_EVENT = "question"

# Status lines shown once a question is resolved (ADR 0021).
_STATUS = {
    QuestionState.EXPIRED: "⌛ Expired",
    QuestionState.CANCELLED: "🚫 Withdrawn",
}


class QuestionEventType:
    """A choice question; actionable (answer buttons)."""

    name = QUESTION_EVENT
    emoji = "❓"
    actionable = True

    def render(self, ctx: RenderContext) -> MessageContent:
        """Open question: prompt + session + buttons; resolved: prompt + session + status."""
        # Every alert names the asking session, so a prompt-injected agent
        # can't pass its question off as another session's (C35).
        lines = [f"Session: {ctx.session_label}"] if ctx.session_label else []
        if ctx.final_state is None:
            buttons = tuple(MessageButton(key=o.key, label=o.label) for o in ctx.options)
            return MessageContent(
                text=compose_text(self.emoji, ctx.title, lines), buttons=buttons, link=ctx.link
            )
        if ctx.final_state is QuestionState.ANSWERED:
            status = f"✅ Answered: {ctx.answer_label or '?'}"
        else:
            status = _STATUS.get(ctx.final_state, "Closed")
        text = compose_text(self.emoji, ctx.title, [*lines, status])
        return MessageContent(text=text, link=ctx.link)
