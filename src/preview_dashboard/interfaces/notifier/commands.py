"""Command functions behind `serve-notifier`, `notify pair` and `notify test` (wired by the CLI).

`serve_notifier` loads both tokens (C12 file rules, C36; each file with its
own trusted groups, telegram.token being the notifier's own), verifies the
admin socket before sending the notifier token to it (C30), wires the
Telegram adapters (link buttons pinned to the dashboard origin from
`allowed_hosts`, C35) and `AdminDeliveryQueue` into `DeliveryService` and runs
the loops until SIGTERM; with `owner_messages` the single update poller
also reads owner texts, approval taps and codes (C44). `pair` prints a
one-time code and the chat id to configure; `send_test` asks a two-option
test question through a caller-supplied admin-token call. Expected
failures raise `NotifierError` with one safe line (never a token).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, TextIO

import httpx

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
from preview_dashboard.adapters.telegram.answers import TelegramAnswerSource
from preview_dashboard.adapters.telegram.channel import TelegramChannel
from preview_dashboard.adapters.telegram.client import (
    BotToken,
    TelegramBotClient,
    TelegramConfigError,
    TelegramError,
    validate_chat_id,
)
from preview_dashboard.adapters.telegram.pairing import (
    PAIR_TIMEOUT_SECONDS,
    PairingTimeoutError,
    new_pairing_code,
    wait_for_pairing,
)
from preview_dashboard.adapters.telegram.updates import TelegramUpdateSource
from preview_dashboard.application.delivery import DeliveryService
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.domain.notifications import dashboard_origin
from preview_dashboard.interfaces.mcp.admin_socket import AdminSocketTrustError, verify_admin_socket
from preview_dashboard.interfaces.notifier.owner_updates import OwnerUpdateRouter
from preview_dashboard.interfaces.notifier.runner import NotifierRunner
from preview_dashboard.interfaces.notifier.voice import VoiceDeliveries
from preview_dashboard.interfaces.token_file import (
    TokenFileError,
    TokenGroupPolicy,
    TokenKind,
    TokenLoader,
)
from preview_dashboard.ports.notify import AnswerSource, DeliveryQueue

EXIT_OK: Final = 0
EXIT_FAILED: Final = 1
TEST_PROMPT: Final = "Test from preview-dashboard: did this alert reach you?"
TEST_SESSION_LABEL: Final = "notify test"
TEST_EXPIRES_IN_S: Final = 600
PAIRED_TEXT: Final = "Paired with preview-dashboard. Alerts will arrive in this chat."
# The notifier's own secret: its service group may own telegram.token, never
# the notifier.token it shares with the admin (C36, ADR 0024).
NOTIFIER_OWN_TOKEN: Final = TokenKind.TELEGRAM

_log = logging.getLogger(__name__)


class NotifierError(RuntimeError):
    """A notifier command cannot run; `str()` is one safe line (never a token)."""


class NotifierConfig(Protocol):
    """The settings `serve_notifier` reads (a subset of `config.Settings`)."""

    @property
    def admin_socket(self) -> Path: ...

    @property
    def allowed_hosts(self) -> frozenset[str]: ...

    @property
    def notify_enabled(self) -> bool: ...

    @property
    def notify_owner_chat_id(self) -> int | None: ...

    @property
    def notifier_token_file(self) -> Path: ...

    @property
    def telegram_token_file(self) -> Path: ...


@dataclass(frozen=True, slots=True)
class NotifierParts:
    """The wired notifier (see `build_notifier`); `close()` releases both HTTP clients."""

    service: DeliveryService
    queue: AdminDeliveryQueue
    telegram: TelegramBotClient

    def close(self) -> None:
        """Close both connection pools."""
        self.queue.close()
        self.telegram.close()


def default_token_groups() -> TokenGroupPolicy:
    """Root, plus this process's egid for telegram.token only (`NOTIFIER_OWN_TOKEN`)."""
    return TokenGroupPolicy(own=NOTIFIER_OWN_TOKEN)


def load_bot_token(path: Path, *, loader: TokenLoader | None = None) -> BotToken:
    """Read the Telegram bot token file with the C12 rules and check its shape.

    Args:
        path: the bot token file.
        loader: the process's token loader (default: notifier-side policy).

    Raises:
        NotifierError: unsafe/unreadable file or a malformed token.
    """
    loader = loader or TokenLoader(default_token_groups())
    try:
        return BotToken(loader.load(TokenKind.TELEGRAM, path))
    except (TokenFileError, TelegramConfigError) as exc:
        raise NotifierError(f"telegram token: {exc}") from None


def build_notifier(
    config: NotifierConfig,
    *,
    token_groups: TokenGroupPolicy | None = None,
    verify_socket: Callable[[Path], object] = verify_admin_socket,
    admin_transport: httpx.BaseTransport | None = None,
    telegram_transport: httpx.BaseTransport | None = None,
    owner_messages: bool = False,
) -> NotifierParts:
    """Check the configuration (fail closed) and wire the notifier.

    Args:
        config: settings (see `NotifierConfig`).
        token_groups: which groups may own each token file (default:
            `default_token_groups()`: root, plus this egid for telegram.token).
        verify_socket: admin socket trust check (C30), run before the
            notifier token is ever sent; tests may replace it.
        admin_transport / telegram_transport: test transports.
        owner_messages: also read the owner's text messages, approval taps
            and codes (Claudia, C44); off by default, so the bot then
            requests callback queries only.

    Raises:
        NotifierError: notifications disabled, no owner chat id, an unsafe
            token file (incl. both files in one group) or an untrusted
            admin socket.
    """
    if not config.notify_enabled:
        raise NotifierError("notifications are disabled (notify_enabled = false)")
    if config.notify_owner_chat_id is None:
        raise NotifierError("notify_owner_chat_id is not set (run `preview-dashboard notify pair`)")
    try:
        chat_id = validate_chat_id(config.notify_owner_chat_id)
    except TelegramConfigError as exc:
        raise NotifierError(str(exc)) from None
    loader = TokenLoader(token_groups or default_token_groups())
    bot_token = load_bot_token(config.telegram_token_file, loader=loader)
    try:
        notifier_token = loader.load(TokenKind.NOTIFIER, config.notifier_token_file)
    except TokenFileError as exc:
        raise NotifierError(f"notifier token: {exc}") from None
    try:
        verify_socket(config.admin_socket)
    except AdminSocketTrustError as exc:
        raise NotifierError(str(exc)) from None
    queue = AdminDeliveryQueue(config.admin_socket, notifier_token, transport=admin_transport)
    del notifier_token  # only the queue's headers keep it
    telegram = TelegramBotClient(bot_token, transport=telegram_transport)
    # Link buttons are pinned to the origin the admin builds links from,
    # derived here from the notifier's own config (C35); none if unset.
    origin = dashboard_origin(config.allowed_hosts)
    if origin is None:
        _log.warning("allowed_hosts is empty: alerts are sent without dashboard link buttons")
    channel = TelegramChannel(telegram, chat_id, dashboard_origin=origin)
    # One getUpdates poller either way (Telegram allows only one): the
    # router widens it to owner messages only when asked (C44).
    answers: AnswerSource = (
        OwnerUpdateRouter(TelegramUpdateSource(telegram, chat_id), queue, channel)
        if owner_messages
        else TelegramAnswerSource(telegram, chat_id)
    )
    # Voice notes only with Claudia on: the wrapper sends them after the text (C56).
    deliveries: DeliveryQueue = VoiceDeliveries(queue, queue, channel) if owner_messages else queue
    service = DeliveryService(queue=deliveries, channels=[channel], answers=answers)
    return NotifierParts(service=service, queue=queue, telegram=telegram)


def serve_notifier(
    config: NotifierConfig,
    *,
    token_groups: TokenGroupPolicy | None = None,
    build: Callable[..., NotifierParts] = build_notifier,
) -> int:
    """Run the notifier until SIGTERM/SIGINT (`preview-dashboard serve-notifier`).

    Owner-message intake and voice delivery follow `config.claudia_enabled`
    and nothing else (one source of truth, no second flag).

    Returns:
        0 after a requested stop, 1 if a loop died (systemd restarts it).

    Raises:
        NotifierError: see `build_notifier`.
    """
    # Fail closed: only a real `True` switches Claudia on; a missing or odd value is off.
    if getattr(config, "claudia_enabled", False) is True:
        parts = build(config, token_groups=token_groups, owner_messages=True)
    else:
        # Same call as before Claudia: test doubles of `build` need no new keyword.
        parts = build(config, token_groups=token_groups)
    try:
        runner = NotifierRunner(parts.service)
        runner.install_signal_handlers()
        _log.info("notifier started (channel telegram)")
        healthy = runner.run()
    finally:
        parts.close()
    return EXIT_OK if healthy else EXIT_FAILED


def pair(
    telegram_token_file: Path,
    out: TextIO,
    *,
    token_groups: TokenGroupPolicy | None = None,
    timeout: float = PAIR_TIMEOUT_SECONDS,
    transport: httpx.BaseTransport | None = None,
    code: str | None = None,
) -> int:
    """`notify pair`: print a code, wait for `/start <code>`, print the chat id to configure.

    Run as root with the notifier service stopped (else Telegram answers 409).

    Raises:
        NotifierError: bad token file, timeout, or a failed Bot API call.
    """
    loader = TokenLoader(token_groups or default_token_groups())
    bot_token = load_bot_token(telegram_token_file, loader=loader)
    client = TelegramBotClient(bot_token, transport=transport)
    code = code or new_pairing_code()
    minutes = max(1, round(timeout / 60))
    print(f"Send this message to your bot within {minutes} minutes:\n\n  /start {code}\n", file=out)
    out.flush()
    try:
        chat_id = wait_for_pairing(client, code, timeout=timeout)
        try:
            client.call("sendMessage", {"chat_id": chat_id, "text": PAIRED_TEXT})
        except TelegramError as exc:
            _log.warning("pairing confirmation not sent (%s)", type(exc).__name__)
    except PairingTimeoutError:
        raise NotifierError("pairing timed out; run `notify pair` again") from None
    except TelegramError as exc:
        if exc.status == 409:
            raise NotifierError(
                "another process is polling this bot; stop preview-dashboard-notifier first"
            ) from None
        raise NotifierError(str(exc)) from None
    finally:
        client.close()
    print(
        f"Paired: chat id {chat_id}.\n"
        "Put this into /etc/preview-dashboard/config.toml (root-owned) and restart:\n\n"
        f"  notify_enabled = true\n  notify_owner_chat_id = {chat_id}",
        file=out,
    )
    return EXIT_OK


def notify_test_body() -> dict[str, object]:
    """The `POST /questions` body `notify test` sends (two options, 10-minute expiry)."""
    return {
        "prompt": TEST_PROMPT,
        "options": [{"key": "yes", "label": "Yes, it works"}, {"key": "no", "label": "No"}],
        "session_label": TEST_SESSION_LABEL,
        "expires_in_s": TEST_EXPIRES_IN_S,
    }


def send_test(ask: Callable[[dict[str, object]], Mapping[str, object]], out: TextIO) -> int:
    """`notify test`: ask the test question and print `{id, state, wait_command}` as JSON.

    Args:
        ask: posts a body to the admin's `POST /questions` (admin token) and
            returns the decoded reply (`{"question": {...}}` or the question).
        out: where the JSON line goes.

    Raises:
        NotifierError: the reply has no valid question id.
    """
    reply = ask(notify_test_body())
    nested = reply.get("question")
    question = nested if isinstance(nested, Mapping) else reply
    question_id = question.get("id")
    if not is_ulid(question_id):
        raise NotifierError("admin API returned no question id")
    line = {
        "id": question_id,
        "state": question.get("state") if isinstance(question.get("state"), str) else None,
        "wait_command": f"preview-dashboard question wait {question_id}",
    }
    print(json.dumps(line), file=out)
    return EXIT_OK
