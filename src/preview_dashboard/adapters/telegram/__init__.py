"""Telegram adapters (ADR 0021): the Bot API client, the alert channel and the tap source.

`TelegramBotClient` is the only holder of the bot token; `TelegramChannel`
implements `NotificationChannel`, `TelegramAnswerSource` implements
`AnswerSource`; `pairing` finds the owner's chat id for `notify pair`.
"""

from __future__ import annotations

from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.adapters.telegram.client import (
    BotToken,
    TelegramBotClient,
    TelegramConfigError,
    TelegramError,
)

__all__ = [
    "BotToken",
    "TelegramAnswerSource",
    "TelegramBotClient",
    "TelegramChannel",
    "TelegramConfigError",
    "TelegramError",
]
