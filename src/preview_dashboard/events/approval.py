"""The `approval` event type: the Telegram prompt for one approval request (ADR 0031, C46).

The message text is the request's stored action text, verbatim (no prefix,
no link); the channel adds the fixed Approve/Deny buttons for the request
id. Only `OutboxApprovalPrompts` (admin, after `ApprovalService.create`)
renders it: the type is actionable, so `NotifyService` refuses it, and it
has no body unless one is given (fail closed for any alert-style call).
"""

from __future__ import annotations

from typing import Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import MessageContent
from preview_dashboard.events.base import RenderContext

APPROVAL_EVENT: Final = "approval"


class ApprovalEventType:
    """An approval request's prompt; actionable (it gets Approve/Deny buttons)."""

    name = APPROVAL_EVENT
    emoji = "🔐"  # unused in the text: the action text is shown exactly as stored
    actionable = True

    def render(self, ctx: RenderContext) -> MessageContent:
        """`ctx.body` (the stored action text) as the whole message; no link, no buttons.

        Raises:
            ValidationError: no body (an alert-style call), or the body breaks
                the `MessageContent` policy.
        """
        if ctx.body is None:
            raise ValidationError("approval prompts are built from a stored request only")
        return MessageContent(text=ctx.body)
