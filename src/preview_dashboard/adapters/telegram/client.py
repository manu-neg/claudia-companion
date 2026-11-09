"""Minimal Telegram Bot API client over httpx: the only place that holds the bot token.

`BotToken` wraps the secret (redacted repr); `TelegramBotClient` posts JSON
(or, for `sendVoice` only, one bounded multipart file) to the fixed base
URL `https://api.telegram.org`, with `trust_env=False`,
TLS verification, no redirects, bounded response sizes and timeouts. The
token is never logged: URLs are never logged, the `httpx`/`httpcore`
loggers are kept at WARNING, and errors carry only the method name, the
status and scrubbed, bounded Telegram text (docs/security.md C36).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from typing import Final

import httpx

BASE_URL: Final = "https://api.telegram.org"
# Every Bot API method this project calls; nothing else can be requested.
METHODS: Final = frozenset(
    {
        "getUpdates",
        "sendMessage",
        "editMessageText",
        "answerCallbackQuery",
        "getMe",
        "deleteMessage",  # code messages (C44, C47)
        "sendVoice",  # Claudia's voice replies (C56)
    }
)
# Methods that may carry a file (multipart); everything else is JSON only.
UPLOAD_METHODS: Final = frozenset({"sendVoice"})
MAX_UPLOAD_BYTES: Final = 1024 * 1024
_UPLOAD_READ_TIMEOUT: Final = 60.0
_FIELD_NAME_RE = re.compile(r"[a-z_]{1,32}")
MAX_RESPONSE_BYTES: Final = 1024 * 1024
DEFAULT_READ_TIMEOUT: Final = 20.0
# Headroom on top of a getUpdates long-poll before the read times out.
LONG_POLL_MARGIN: Final = 15.0
_CONNECT_TIMEOUT: Final = 10.0
_MAX_DESCRIPTION_CHARS: Final = 120
_MAX_RETRY_AFTER: Final = 3600
_REDACTED: Final = "<redacted>"
# BotFather tokens: "<bot id>:<secret>"; a stricter shape also keeps any
# path/query characters out of the request URL.
_TOKEN_RE = re.compile(r"[0-9]{1,20}:[A-Za-z0-9_-]{30,100}")
_UNPRINTABLE_RE = re.compile(r"[^\x20-\x7e]")
_HTTP_LOGGERS: Final = ("httpx", "httpcore")


def silence_http_loggers() -> None:
    """Keep `httpx`/`httpcore` below INFO: their request logs include the URL (and token)."""
    for name in _HTTP_LOGGERS:
        logger = logging.getLogger(name)
        if logger.getEffectiveLevel() < logging.WARNING:
            logger.setLevel(logging.WARNING)


class TelegramConfigError(ValueError):
    """The bot token or chat configuration is unusable. Never contains the token."""


class TelegramError(RuntimeError):
    """A Bot API call failed. `str()` never contains the token.

    Attributes:
        method: the Bot API method called.
        status: HTTP status (or Telegram `error_code`), None without a response.
        description: Telegram's error description, scrubbed and bounded ("" if none).
        retry_after: seconds Telegram asked us to wait (429), if any.
    """

    def __init__(
        self,
        method: str,
        message: str,
        *,
        status: int | None = None,
        description: str = "",
        retry_after: int | None = None,
    ) -> None:
        super().__init__(f"telegram {method}: {message}")
        self.method = method
        self.status = status
        self.description = description
        self.retry_after = retry_after


class BotToken:
    """The Telegram bot token; its repr and str never show the secret.

    Raises (on construction):
        TelegramConfigError: not `<digits>:<30..100 url-safe chars>`.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str | bytes) -> None:
        text = value.decode("ascii", "replace") if isinstance(value, bytes) else value
        if not isinstance(text, str) or not _TOKEN_RE.fullmatch(text):
            raise TelegramConfigError("telegram bot token has an unexpected format")
        self._value = text

    def reveal(self) -> str:
        """The raw token, for building a request URL only."""
        return self._value

    def scrub(self, text: str) -> str:
        """`text` with the token (and its secret half) replaced by `<redacted>`."""
        secret = self._value.split(":", 1)[1]
        return text.replace(self._value, _REDACTED).replace(secret, _REDACTED)

    def __repr__(self) -> str:
        return f"BotToken({_REDACTED})"

    __str__ = __repr__


def validate_chat_id(raw: object) -> int:
    """Validate the owner's chat id: a positive int (a private chat is the user's id).

    Raises:
        TelegramConfigError: anything else (bools, groups/channels, huge values).
    """
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 < raw < 2**53:
        raise TelegramConfigError("owner chat id must be a positive integer (a private chat)")
    return raw


class TelegramBotClient:
    """Calls Bot API methods with JSON bodies; returns the `result` field.

    Args:
        token: the bot token (kept private, never logged or repr'd).
        transport: override the httpx transport (tests use `httpx.MockTransport`).
    """

    def __init__(self, token: BotToken, *, transport: httpx.BaseTransport | None = None) -> None:
        silence_http_loggers()
        self._token = token
        self._http = httpx.Client(
            # The transport gets its own trust_env=False: a client-level flag
            # does not reach an explicit transport (SSL_CERT_FILE etc.).
            transport=transport or httpx.HTTPTransport(verify=True, trust_env=False),
            timeout=httpx.Timeout(
                connect=_CONNECT_TIMEOUT,
                read=DEFAULT_READ_TIMEOUT,
                write=_CONNECT_TIMEOUT,
                pool=_CONNECT_TIMEOUT,
            ),
            verify=True,
            follow_redirects=False,
            trust_env=False,  # no HTTP(S)_PROXY / netrc / SSL_CERT_FILE from env (C36)
            headers={"Accept-Encoding": "identity"},
        )

    def __repr__(self) -> str:
        return "TelegramBotClient()"

    def close(self) -> None:
        """Close the connection pool. Idempotent."""
        self._http.close()

    def call(
        self, method: str, params: Mapping[str, object], *, read_timeout: float | None = None
    ) -> object:
        """POST `params` as JSON to `method`; return Telegram's `result`.

        Args:
            method: one of `METHODS`, except `UPLOAD_METHODS`.
            params: the method's JSON parameters.
            read_timeout: override the read timeout (long polls), seconds.

        Raises:
            ValueError: `method` is not in `METHODS` or is an upload method
                (a programming error).
            TelegramError: transport failure, non-JSON or oversized reply,
                or `ok: false` (with status, scrubbed description, retry_after).
        """
        # Upload methods go through `upload` only: as JSON, `sendVoice` would
        # take a URL or file id, letting Telegram fetch audio from anywhere.
        if method not in METHODS or method in UPLOAD_METHODS:
            raise ValueError("unsupported Bot API method")
        timeout = httpx.Timeout(
            connect=_CONNECT_TIMEOUT,
            read=DEFAULT_READ_TIMEOUT if read_timeout is None else read_timeout,
            write=_CONNECT_TIMEOUT,
            pool=_CONNECT_TIMEOUT,
        )
        request = self._http.build_request(
            "POST",
            f"{BASE_URL}/bot{self._token.reveal()}/{method}",
            json=dict(params),
            timeout=timeout,
        )
        return self._send(method, request)

    def upload(
        self,
        method: str,
        params: Mapping[str, str],
        *,
        file_field: str,
        filename: str,
        data: bytes,
        content_type: str,
    ) -> object:
        """POST `params` plus one file as multipart to `method`; return Telegram's `result`.

        Args:
            method: one of `UPLOAD_METHODS` (e.g. `sendVoice`).
            params: plain string form fields (e.g. `chat_id`).
            file_field / filename / content_type: the file part's names
                (fixed by the caller, never from input).
            data: the file, at most `MAX_UPLOAD_BYTES`.

        Raises:
            ValueError: unsupported method, a bad field name or oversized data
                (programming errors; callers validate first).
            TelegramError: as `call`.
        """
        if method not in UPLOAD_METHODS:
            raise ValueError("unsupported Bot API upload method")
        if not _FIELD_NAME_RE.fullmatch(file_field) or not all(
            _FIELD_NAME_RE.fullmatch(k) for k in params
        ):
            raise ValueError("bad multipart field name")
        if not 0 < len(data) <= MAX_UPLOAD_BYTES:
            raise ValueError("upload must be 1..MAX_UPLOAD_BYTES bytes")
        request = self._http.build_request(
            "POST",
            f"{BASE_URL}/bot{self._token.reveal()}/{method}",
            data=dict(params),
            files={file_field: (filename, data, content_type)},
            timeout=httpx.Timeout(
                connect=_CONNECT_TIMEOUT,
                read=_UPLOAD_READ_TIMEOUT,
                write=_UPLOAD_READ_TIMEOUT,
                pool=_CONNECT_TIMEOUT,
            ),
        )
        return self._send(method, request)

    def _send(self, method: str, request: httpx.Request) -> object:
        status, raw, failure = self._exchange(request)
        del request  # holds the token in its URL
        if failure is not None:
            # Raised outside any `except`: no __context__ can carry the URL.
            raise TelegramError(method, f"request failed ({failure})")
        return self._result(method, status, raw)

    def _exchange(self, request: httpx.Request) -> tuple[int, bytes, str | None]:
        """Send and read at most `MAX_RESPONSE_BYTES`; (status, body, failure type name)."""
        try:
            response = self._http.send(request, stream=True)
        except httpx.HTTPError as exc:
            return 0, b"", type(exc).__name__
        try:
            # We asked for identity: a compressed body is refused, never inflated
            # (so iter_bytes below never decompresses).
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                return response.status_code, b"", "UnexpectedEncoding"
            body = bytearray()
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_RESPONSE_BYTES:
                    return response.status_code, b"", "ResponseTooLarge"
            return response.status_code, bytes(body), None
        except httpx.HTTPError as exc:
            return response.status_code, b"", type(exc).__name__
        finally:
            response.close()

    def _result(self, method: str, status: int, raw: bytes) -> object:
        try:
            body = json.loads(raw)
        except (ValueError, RecursionError):
            raise TelegramError(
                method, f"unreadable reply (HTTP {status})", status=status
            ) from None
        if not isinstance(body, dict):
            raise TelegramError(method, f"unexpected reply (HTTP {status})", status=status)
        if body.get("ok") is True and "result" in body:
            return body["result"]
        raw_code = body.get("error_code")
        code = raw_code if isinstance(raw_code, int) and not isinstance(raw_code, bool) else status
        description = self._description(body.get("description"))
        params = body.get("parameters")
        retry = params.get("retry_after") if isinstance(params, dict) else None
        retry_after = (
            min(retry, _MAX_RETRY_AFTER)
            if isinstance(retry, int) and not isinstance(retry, bool) and retry >= 0
            else None
        )
        raise TelegramError(
            method,
            f"error {code}: {description or 'no description'}",
            status=code,
            description=description,
            retry_after=retry_after,
        )

    def _description(self, raw: object) -> str:
        # Telegram's text is untrusted: scrub the token, keep it printable and short.
        if not isinstance(raw, str):
            return ""
        text = _UNPRINTABLE_RE.sub("?", self._token.scrub(raw))
        return text[:_MAX_DESCRIPTION_CHARS]
