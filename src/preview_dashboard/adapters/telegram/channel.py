"""TelegramChannel: the `NotificationChannel` that posts and edits alerts in the owner's chat.

Plain text only (no `parse_mode`, link previews off, C35), with anything
Telegram could auto-link defanged; answer buttons carry `callback_data =
"a:<question_id>:<key>"`; an approval prompt (C46) gets exactly two fixed
buttons, Approve `p:<id>:ok` and Deny `p:<id>:no`, built here from the
payload's `approval_id` (never from stored labels or keys), and after an
Approve tap the owner gets one fixed "send your code" message
(`send_code_prompt`); once the request is decided the prompt is edited
to one fixed outcome text with no buttons (F-CL5); the dashboard link is a separate URL button,
never part of the text, and only if it is on the configured dashboard
origin (C35: a forged task cannot put a phishing button on the owner's
phone). Message refs are `"<chat_id>:<message_id>"` and are only ever
edited in the owner's chat. Also uploads Claudia's checked voice notes
(`sendVoice`, C56) and deletes code messages (`deleteMessage`, C47), both
in the owner's chat only. Replies are up to 4096 chars (the domain caps it).
"""

from __future__ import annotations

import logging
import re
from typing import Final

from preview_dashboard.adapters.telegram.client import (
    TelegramBotClient,
    TelegramConfigError,
    TelegramError,
    validate_chat_id,
)
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.notifications import (
    APPROVAL_OUTCOME_TEXTS,
    DashboardLinks,
    DeliveryPayload,
    MessageContent,
    is_dashboard_link,
)
from preview_dashboard.events.voice import validate_voice_audio
from preview_dashboard.wire.notifier_messages import (
    CODE_PROMPT_TEXT,
    OWNER_NOTICE_TEXTS,
    ApprovalDecision,
    OwnerNotice,
    approval_callback_data,
)

CHANNEL_NAME: Final = "telegram"
CALLBACK_PREFIX: Final = "a"
MAX_CALLBACK_BYTES: Final = 64  # Bot API limit on callback_data
LINK_BUTTON_TEXT: Final = "Open dashboard"
APPROVE_BUTTON_TEXT: Final = "Approve"
DENY_BUTTON_TEXT: Final = "Deny"
_MESSAGE_REF_RE = re.compile(r"(-?[0-9]{1,20}):([0-9]{1,20})")
# Editing to identical content is not an error for us (a retried RESOLVE).
_NOT_MODIFIED = "message is not modified"
# Deleting a message that is already gone is not an error for us.
_NOT_FOUND = "message to delete not found"
VOICE_FILENAME: Final = "voice.ogg"
VOICE_CONTENT_TYPE: Final = "audio/ogg"

_log = logging.getLogger(__name__)

# Defense in depth for C35 (the domain already rejects URLs): Telegram
# auto-links bare hostnames ("evil.example"), IPs, e-mails and @mentions
# even in plain text. A dot between two word chars becomes U+2024 (one dot
# leader: looks the same, never linked), "@" before a word char becomes
# U+FF20 and "://" loses its slashes. File names ("app.js") stay readable.
# Dot-likes: every char that NFKC-folds to "." or U+3002 (the separators
# IDNA/Telegram treat as dots): U+FE52 small, U+FF0E fullwidth, U+3002 /
# U+FF61 / U+FE12 (vertical) ideographic full stops; U+2024 itself is the
# inert replacement. A test re-derives this set from unicodedata.
_DOT_LIKE = "[.\u2024\u3002\ufe12\ufe52\uff0e\uff61]"
_DEFANG_RULES: Final = (
    (re.compile(r"(?<=\w)" + _DOT_LIKE + r"(?=\w)"), "\u2024"),
    (re.compile("[@\uff20](?=\\w)"), "\uff20"),
    (re.compile(":[/\uff0f]{2}"), ":\u2215\u2215"),
)


def defang(text: str) -> str:
    """Return `text` with nothing Telegram could turn into a link (same length, readable)."""
    for pattern, replacement in _DEFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def callback_data(question_id: str, key: str) -> str:
    """`a:<question_id>:<key>` for one answer button.

    Raises:
        ValueError: the result exceeds Telegram's 64-byte limit (cannot
            happen with a ULID and a <= 16-char key; checked anyway).
    """
    data = f"{CALLBACK_PREFIX}:{question_id}:{key}"
    if len(data.encode("utf-8")) > MAX_CALLBACK_BYTES:
        raise ValueError("callback data too long")
    return data


def reply_markup(payload: DeliveryPayload, dashboard_origin: str | None) -> dict[str, object]:
    """Inline keyboard: one row per answer button (label defanged), then the dashboard link.

    An approval prompt instead gets one row of exactly two fixed buttons,
    `Approve` (`p:<id>:ok`) and `Deny` (`p:<id>:no`), and nothing else
    (`DeliveryPayload` already forbids other buttons and a link there);
    a decided one (`approval_outcome` set, F-CL5) gets none at all.
    The link button is added only if the link is on exactly
    `dashboard_origin` (`is_dashboard_link`); otherwise, and always when
    the origin is None, it is left out (fail closed). An empty keyboard
    removes the buttons of an edited message.
    """
    if payload.approval_outcome is not None:
        return {"inline_keyboard": []}
    if payload.approval_id is not None:
        return {
            "inline_keyboard": [
                [
                    {
                        "text": APPROVE_BUTTON_TEXT,
                        "callback_data": approval_callback_data(
                            payload.approval_id, ApprovalDecision.APPROVE
                        ),
                    },
                    {
                        "text": DENY_BUTTON_TEXT,
                        "callback_data": approval_callback_data(
                            payload.approval_id, ApprovalDecision.DENY
                        ),
                    },
                ]
            ]
        }
    rows: list[list[dict[str, str]]] = []
    content: MessageContent = payload.content
    if content.buttons:
        if payload.question_id is None:  # DeliveryPayload forbids this; kept for typing
            raise ValueError("answer buttons need a question id")
        rows.extend(
            [{"text": defang(b.label), "callback_data": callback_data(payload.question_id, b.key)}]
            for b in content.buttons
        )
    if content.link is not None:
        if is_dashboard_link(content.link, dashboard_origin):
            rows.append([{"text": LINK_BUTTON_TEXT, "url": content.link}])
        else:
            # Ids only: the link itself may be attacker-chosen (C35).
            _log.warning(
                "link button dropped: not on the dashboard origin (question %s)",
                payload.question_id or "-",
            )
    return {"inline_keyboard": rows}


class TelegramChannel:
    """Sends alerts to the owner's private chat and edits them once resolved.

    Args:
        client: Bot API client (holds the token).
        owner_chat_id: the owner's chat id from root-owned config (C16, C34).
        dashboard_origin: `https://<host>[:port]` from the notifier's own
            config (`dashboard_origin(allowed_hosts)`): the only origin a
            link button may point to. None: never send link buttons (C35).

    Raises (on construction):
        TelegramConfigError: `owner_chat_id` is not a positive int, or
            `dashboard_origin` is not an `https://<host>[:port]` origin.
    """

    name = CHANNEL_NAME

    def __init__(
        self, client: TelegramBotClient, owner_chat_id: int, *, dashboard_origin: str | None
    ) -> None:
        self._client = client
        self._chat_id = validate_chat_id(owner_chat_id)
        try:
            self._origin = DashboardLinks(dashboard_origin).base
        except ValidationError:
            raise TelegramConfigError("dashboard origin must be https://<host>[:port]") from None

    def send(self, payload: DeliveryPayload) -> str | None:
        """Post `payload`; return `"<chat_id>:<message_id>"`.

        Raises:
            ValueError: `payload` is a decided approval's edit (never a new message).
            TelegramError: the call failed or the reply is not a message in
                the owner's chat.
        """
        if payload.approval_outcome is not None:
            raise ValueError("an approval outcome only ever edits its prompt")
        result = self._client.call(
            "sendMessage",
            {
                "chat_id": self._chat_id,
                "text": defang(payload.content.text),
                "reply_markup": reply_markup(payload, self._origin),
                "link_preview_options": {"is_disabled": True},
            },
        )
        message_id = self._message_id(result)
        return f"{self._chat_id}:{message_id}"

    def resolve(self, message_ref: str, payload: DeliveryPayload) -> None:
        """Replace message `message_ref`'s text with `payload` and drop its answer buttons.

        A decided approval prompt (F-CL5) is edited to the fixed text of its
        `approval_outcome`, taken from `APPROVAL_OUTCOME_TEXTS` here (never
        from the payload's text), with an empty keyboard: Approve/Deny go away.

        Raises:
            ValueError: `message_ref` is malformed or not in the owner's chat,
                or an approval payload has no outcome (never redraw the buttons).
            TelegramError: the edit failed (except "not modified": done already).
        """
        match = _MESSAGE_REF_RE.fullmatch(message_ref)
        if match is None or int(match.group(1)) != self._chat_id:
            raise ValueError("message ref is not a message in the owner's chat")
        text = defang(payload.content.text)
        if payload.approval_id is not None:
            if payload.approval_outcome is None:
                raise ValueError("an approval prompt is only edited to its outcome")
            text = APPROVAL_OUTCOME_TEXTS[payload.approval_outcome]
        try:
            self._client.call(
                "editMessageText",
                {
                    "chat_id": self._chat_id,
                    "message_id": int(match.group(2)),
                    "text": text,
                    "reply_markup": reply_markup(payload, self._origin),
                    "link_preview_options": {"is_disabled": True},
                },
            )
        except TelegramError as exc:
            if exc.status == 400 and _NOT_MODIFIED in exc.description:
                return
            raise

    def send_code_prompt(self) -> None:
        """Post the fixed "send your authenticator code" text after an Approve tap (C46/C47).

        Takes no text on purpose: this path can only ever send the one
        constant (`CODE_PROMPT_TEXT`), no buttons, to the owner's chat.

        Raises:
            TelegramError: the call failed or the reply is not a message in
                the owner's chat.
        """
        result = self._client.call(
            "sendMessage",
            {
                "chat_id": self._chat_id,
                "text": CODE_PROMPT_TEXT,
                "link_preview_options": {"is_disabled": True},
            },
        )
        self._message_id(result)

    def send_notice(self, notice: OwnerNotice) -> None:
        """Post one fixed `OwnerNotice` text to the owner's chat (no buttons, no caller text).

        Raises:
            ValueError: `notice` is not a known notice.
            TelegramError: the call failed or the reply is not a message in
                the owner's chat.
        """
        result = self._client.call(
            "sendMessage",
            {
                "chat_id": self._chat_id,
                "text": OWNER_NOTICE_TEXTS[OwnerNotice(notice)],
                "link_preview_options": {"is_disabled": True},
            },
        )
        self._message_id(result)

    def send_voice(self, audio: bytes) -> str:
        """Upload `audio` as a voice note to the owner's chat; return its message ref (C56).

        The audio must pass `events.voice.validate_voice_audio` (one Ogg/Opus
        stream, <= 1 MiB, <= 60 s); it goes only to `api.telegram.org` as a
        multipart file (never a URL or file id), without a caption: the
        reply text is always sent as its own message.

        Raises:
            ValidationError: the audio breaks the voice caps.
            TelegramError: the upload failed or the reply is not a message
                in the owner's chat.
        """
        checked = validate_voice_audio(audio)
        result = self._client.upload(
            "sendVoice",
            {"chat_id": str(self._chat_id)},
            file_field="voice",
            filename=VOICE_FILENAME,
            data=checked.data,
            content_type=VOICE_CONTENT_TYPE,
        )
        return f"{self._chat_id}:{self._message_id(result)}"

    def delete_message(self, message_id: int) -> None:
        """Delete message `message_id` from the owner's chat (code messages, C44/C47).

        A message that is already gone counts as deleted.

        Raises:
            ValueError: `message_id` is not a positive int.
            TelegramError: the call failed for another reason.
        """
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id < 1:
            raise ValueError("message id must be a positive integer")
        try:
            self._client.call("deleteMessage", {"chat_id": self._chat_id, "message_id": message_id})
        except TelegramError as exc:
            if exc.status == 400 and _NOT_FOUND in exc.description:
                return
            raise

    def _message_id(self, result: object) -> int:
        chat = result.get("chat") if isinstance(result, dict) else None
        message_id = result.get("message_id") if isinstance(result, dict) else None
        chat_id = chat.get("id") if isinstance(chat, dict) else None
        if (
            not isinstance(message_id, int)
            or isinstance(message_id, bool)
            or not 0 < message_id < 10**20
            or chat_id != self._chat_id
        ):
            raise TelegramError("sendMessage", "reply is not a message in the owner's chat")
        return message_id
