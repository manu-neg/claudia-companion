"""The `reply` event type: Claudia's chat answer to the owner (ADR 0031, docs/security.md C56).

Plain multi-line text (<= 4096 UTF-16 units) under the same outgoing policy
as every alert (C35: no invisible chars, no web address; the admin also
secret-scans it), plus at most the server-built dashboard link button.
Only the Claudia host posts replies (`claudia` token, M3): `RenderContext.body`
is never set by `NotifyService`, so a `reply` through `dashboard_notify` fails.
"""

from __future__ import annotations

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import REPLY_TEXT_MAX_CHARS, MessageContent
from preview_dashboard.events.base import RenderContext

REPLY_EVENT = "reply"


def render_reply_body(ctx: RenderContext) -> MessageContent:
    """The reply text exactly as given (no prefix) plus the context's link.

    Raises:
        ValidationError: no body (an alert-style call such as `notify`), or
            the body breaks the `MessageContent` policy (too long, invisible
            chars, a web address).
    """
    if ctx.body is None:
        # Fail closed: an alert path (title only) must never produce a reply.
        raise ValidationError("reply events are posted by the Claudia host only")
    # The only place a long-form (<= 4096) message is built; alerts stay <= 300.
    return MessageContent(text=ctx.body, link=ctx.link, long_form=True)


class ReplyEventType:
    """Claudia's text reply; not actionable (no answer buttons).

    `emoji` is unused in the text: a chat answer carries no alert prefix.
    """

    name = REPLY_EVENT
    emoji = "💬"
    actionable = False
    max_chars = REPLY_TEXT_MAX_CHARS  # its own limit; every other type keeps 300

    def render(self, ctx: RenderContext) -> MessageContent:
        """`ctx.body` verbatim plus the link (see `render_reply_body`).

        Raises:
            ValidationError: see `render_reply_body`.
        """
        return render_reply_body(ctx)
