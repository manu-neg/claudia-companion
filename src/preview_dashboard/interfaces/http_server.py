"""Shared uvicorn hardening for every HTTP server we run (admin socket, viewer ports).

`HeaderTimeoutH11Protocol` closes connections that don't deliver a complete
request head in time. Uvicorn arms no timer when a connection opens and
none while a request head trickles in, so idle or partial-header
connections would otherwise hold `limit_concurrency` slots forever and turn
every later request into a pre-auth 503 (docs/security.md C26, ADR 0014).
"""

from __future__ import annotations

import asyncio
import logging
from typing import ClassVar, Final

from uvicorn.protocols.http.h11_impl import H11Protocol

logger = logging.getLogger("preview_dashboard.http")

# Budget for a whole request head (request line + headers), from connection
# open or from the end of the previous response. Generous for a local client,
# short enough that a slot-hogging connection is reaped quickly.
HEADER_TIMEOUT_SECONDS: Final = 10.0


class HeaderTimeoutH11Protocol(H11Protocol):
    """uvicorn's h11 protocol plus a deadline on the header phase.

    The timer runs whenever the connection is *waiting for a request head*:
    armed at `connection_made` and again after each response, cancelled as
    soon as a complete head starts a request (the app's own body timeouts
    and uvicorn's keep-alive timer take over from there). Incoming bytes do
    not extend it, so dripping a header byte by byte doesn't help. On expiry
    the transport is closed without a response.

    Subclass (or use `with_header_timeout`) to change `header_timeout`;
    compose other per-connection behavior by subclassing this class.
    """

    header_timeout: ClassVar[float] = HEADER_TIMEOUT_SECONDS
    _header_timer: asyncio.TimerHandle | None = None

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        """Start the header deadline the moment the connection opens."""
        super().connection_made(transport)
        self._sync_header_timer()

    def data_received(self, data: bytes) -> None:
        """Feed h11, then cancel the deadline if a request head completed."""
        super().data_received(data)
        self._sync_header_timer()

    def on_response_complete(self) -> None:
        """After a response the connection waits for the next head: re-arm."""
        super().on_response_complete()
        self._sync_header_timer()

    def connection_lost(self, exc: Exception | None) -> None:
        """Drop the timer with the connection."""
        self._cancel_header_timer()
        super().connection_lost(exc)

    def _awaiting_request_head(self) -> bool:
        # No request running (none yet, or its response is done): any bytes
        # that arrive now belong to the next head (or a discarded body tail).
        cycle = self.cycle
        return cycle is None or cycle.response_complete

    def _sync_header_timer(self) -> None:
        if self.transport is None or self.transport.is_closing():
            self._cancel_header_timer()
        elif self._awaiting_request_head():
            if self._header_timer is None:  # never extended by new bytes
                self._header_timer = self.loop.call_later(
                    self.header_timeout, self._header_timeout_expired
                )
        else:
            self._cancel_header_timer()

    def _cancel_header_timer(self) -> None:
        if self._header_timer is not None:
            self._header_timer.cancel()
            self._header_timer = None

    def _header_timeout_expired(self) -> None:
        self._header_timer = None
        if not self.transport.is_closing():
            # Debug only: an attacker could otherwise flood the journal.
            logger.debug("closing connection: no complete request head in time")
            self.transport.close()


def with_header_timeout[P: HeaderTimeoutH11Protocol](protocol: type[P], seconds: float) -> type[P]:
    """Return a subclass of `protocol` with `header_timeout = seconds` (> 0).

    Raises:
        ValueError: `seconds` is not positive.
    """
    if not seconds > 0:
        raise ValueError("header timeout must be positive")
    name = f"{protocol.__name__}HeaderTimeout"
    return type(name, (protocol,), {"header_timeout": float(seconds)})
