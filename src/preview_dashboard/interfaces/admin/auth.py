"""Admin API authentication: three scoped tokens, peer credentials (token loading re-exported).

Tokens are read once at startup from files that must be private (C12, C36,
C45); every request must carry one as `Authorization: Bearer <token>`,
compared in constant time. Each token is valid on exactly one route family:
the notifier token on `/v1/notifier/*`, the `claudia` token on
`/v1/claudia/*`, the admin token everywhere else; never cross-accepted
(403, C33/C34/C45). The Unix socket peer's uid (`SO_PEERCRED`) is attached
to each request, logged, and optionally restricted to an allowlist per
route family (C26). No token nor the Authorization header is ever logged.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import socket
import struct
from collections.abc import Collection
from dataclasses import dataclass

from starlette.types import ASGIApp, Receive, Scope, Send

from preview_dashboard.interfaces.admin.errors import send_error

# Token-file loading lives in a framework-free module shared with the MCP
# client; re-exported here for existing callers.
from preview_dashboard.interfaces.token_file import (
    MIN_DISTINCT_TOKEN_CHARS,
    MIN_TOKEN_CHARS,
    TokenFileError,
    load_admin_token,
)
from preview_dashboard.wire.claudia import CLAUDIA_PREFIX
from preview_dashboard.wire.notifier import NOTIFIER_PREFIX

__all__ = [
    "ADMIN_ROLE",
    "CLAUDIA_ROLE",
    "MIN_DISTINCT_TOKEN_CHARS",
    "MIN_TOKEN_CHARS",
    "NOTIFIER_ROLE",
    "ROLE_KEY",
    "BearerAuthMiddleware",
    "PeerCredentials",
    "PeerCredentialsApp",
    "PeerPolicyMiddleware",
    "TokenFileError",
    "TokenVerifier",
    "is_claudia_path",
    "is_notifier_path",
    "load_admin_token",
    "peer_of",
    "read_peer_credentials",
    "role_of",
    "route_family",
]

logger = logging.getLogger("preview_dashboard.admin")

_SCHEME = b"bearer "
PEERCRED_SCOPE_KEY = "pdash.peercred"
_UCRED = struct.Struct("3i")  # struct ucred {pid_t pid; uid_t uid; gid_t gid;}
ROLE_KEY = "pdash.token_role"
ADMIN_ROLE = "admin"
NOTIFIER_ROLE = "notifier"
CLAUDIA_ROLE = "claudia"


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def is_notifier_path(path: str) -> bool:
    """True for the notifier route family (`/v1/notifier` and below).

    Classified on the same decoded `scope["path"]` the router matches, so a
    path can't be routed as one family and authorized as the other.
    """
    return _under(path, NOTIFIER_PREFIX)


def is_claudia_path(path: str) -> bool:
    """True for the Claudia route family (`/v1/claudia` and below), like `is_notifier_path`."""
    return _under(path, CLAUDIA_PREFIX)


def route_family(path: str) -> str:
    """The token role a path needs: `notifier`, `claudia` or (everything else) `admin`."""
    if is_notifier_path(path):
        return NOTIFIER_ROLE
    if is_claudia_path(path):
        return CLAUDIA_ROLE
    return ADMIN_ROLE


def role_of(scope: Scope) -> str | None:
    """The token role (`admin` / `notifier` / `claudia`) `BearerAuthMiddleware` attached."""
    state = scope.get("state")
    value = state.get(ROLE_KEY) if isinstance(state, dict) else None
    return value if isinstance(value, str) else None


def _digest(value: bytes) -> bytes:
    # Hash both sides first: compare_digest leaks length differences, a
    # fixed-size digest doesn't.
    return hashlib.sha256(value).digest()


class TokenVerifier:
    """Constant-time check of an `Authorization` header value against the token.

    Raises (constructor):
        ValueError: the token is too short or has too few distinct characters.
    """

    def __init__(self, token: bytes) -> None:
        if len(token) < MIN_TOKEN_CHARS:
            raise ValueError("admin token too short")
        if len(set(token)) < MIN_DISTINCT_TOKEN_CHARS:
            raise ValueError("admin token has too few distinct characters")
        self._expected = _digest(token)

    def same_token(self, other: TokenVerifier) -> bool:
        """True if both verifiers accept the same token (a deployment error, C33)."""
        return hmac.compare_digest(self._expected, other._expected)

    def verify(self, header_values: list[bytes]) -> bool:
        """True iff there is exactly one header, `Bearer <token>`, with the right token.

        Always performs one digest comparison, whatever the input shape, so
        a missing/malformed header costs the same as a wrong token.
        """
        candidate = b""
        well_formed = len(header_values) == 1
        if well_formed:
            value = header_values[0]
            well_formed = value[: len(_SCHEME)].lower() == _SCHEME
            candidate = value[len(_SCHEME) :] if well_formed else b""
        matches = hmac.compare_digest(_digest(candidate), self._expected)
        return well_formed and matches


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Credentials of the process on the other end of the Unix socket."""

    pid: int
    uid: int
    gid: int


def read_peer_credentials(sock: object) -> PeerCredentials | None:
    """Return `SO_PEERCRED` for a connected Unix socket, or None if unavailable.

    `sock` is a `socket.socket` (or asyncio's socket wrapper); anything
    without `getsockopt`, or a platform without `SO_PEERCRED`, yields None.
    """
    getsockopt = getattr(sock, "getsockopt", None)
    peercred = getattr(socket, "SO_PEERCRED", None)
    if getsockopt is None or peercred is None:
        return None
    try:
        raw = getsockopt(socket.SOL_SOCKET, peercred, _UCRED.size)
    except OSError:
        return None
    if not isinstance(raw, bytes) or len(raw) != _UCRED.size:
        return None
    pid, uid, gid = _UCRED.unpack(raw)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def peer_of(scope: Scope) -> PeerCredentials | None:
    """Return the peer credentials the server attached to `scope`, if any."""
    extensions = scope.get("extensions") or {}
    value = extensions.get(PEERCRED_SCOPE_KEY)
    return value if isinstance(value, PeerCredentials) else None


class PeerCredentialsApp:
    """ASGI wrapper that attaches one connection's peer credentials to its scopes."""

    def __init__(self, app: ASGIApp, peer: PeerCredentials | None) -> None:
        self._app = app
        self._peer = peer

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._peer is not None:
            extensions = dict(scope.get("extensions") or {})
            extensions[PEERCRED_SCOPE_KEY] = self._peer
            scope["extensions"] = extensions
        await self._app(scope, receive, send)


class PeerPolicyMiddleware:
    """Refuse (403) peers whose uid isn't allowed, when an allowlist is configured.

    With no allowlist at all, socket file permissions (0660, group-only)
    decide who can connect (C26). Once any list is set, each route family
    has its own: `allowed_uids` for the admin routes, `notifier_uids` for
    `/v1/notifier/*`, `claudia_uids` for `/v1/claudia/*` (an empty list
    there = nobody), so each token only works from its own process's uid
    (C33, C45). A request without known peer credentials is refused too
    (fail closed).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_uids: Collection[int] | None,
        notifier_uids: Collection[int] | None = None,
        claudia_uids: Collection[int] | None = None,
    ) -> None:
        self._app = app
        self._families = {
            ADMIN_ROLE: frozenset(allowed_uids or ()),
            NOTIFIER_ROLE: frozenset(notifier_uids or ()),
            CLAUDIA_ROLE: frozenset(claudia_uids or ()),
        }
        self._active = any(self._families.values())

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._active:
            await self._app(scope, receive, send)
            return
        allowed = self._families[route_family(scope.get("path", ""))]
        peer = peer_of(scope)
        if peer is None or peer.uid not in allowed:
            logger.warning("admin request refused: peer uid not allowed")
            await send_error(scope, send, 403)
            return
        await self._app(scope, receive, send)


class BearerAuthMiddleware:
    """Require a valid bearer token on every request (401), scoped per route family (403).

    Runs before routing, so unauthenticated callers can't even learn which
    paths exist (C12). The admin token is accepted everywhere except
    `/v1/notifier/*` and `/v1/claudia/*`; the notifier token (if configured)
    only on the first, so it can fetch/report deliveries and submit answers,
    taps and codes but never publish or ask, and the admin token can never
    answer (C33, C34); the `claudia` token (if configured) only on the
    second (C45). The accepted role is stored in the scope (`role_of`) for
    the routes' own check. Never logs header values.

    Raises (constructor):
        ValueError: two configured tokens are the same.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: TokenVerifier,
        notifier_verifier: TokenVerifier | None = None,
        claudia_verifier: TokenVerifier | None = None,
    ) -> None:
        if notifier_verifier is not None and verifier.same_token(notifier_verifier):
            raise ValueError("the notifier token must differ from the admin token")
        if claudia_verifier is not None and any(
            other is not None and claudia_verifier.same_token(other)
            for other in (verifier, notifier_verifier)
        ):
            raise ValueError("the claudia token must differ from the admin and notifier tokens")
        self._app = app
        self._verifiers: tuple[tuple[str, TokenVerifier], ...] = tuple(
            (role, v)
            for role, v in (
                (ADMIN_ROLE, verifier),
                (NOTIFIER_ROLE, notifier_verifier),
                (CLAUDIA_ROLE, claudia_verifier),
            )
            if v is not None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        values = [v for k, v in scope["headers"] if k.lower() == b"authorization"]
        # Every configured verifier runs (no short-circuit): equal work per request.
        matches = [role for role, verifier in self._verifiers if verifier.verify(values)]
        if not matches:
            logger.warning("admin request refused: missing or invalid bearer token")
            await send_error(scope, send, 401, [(b"www-authenticate", b"Bearer")])
            return
        role = matches[0]
        wanted = route_family(scope.get("path", ""))
        if role != wanted:
            logger.warning("admin request refused: %s token used on another route family", role)
            await send_error(scope, send, 403)
            return
        scope.setdefault("state", {})[ROLE_KEY] = role
        await self._app(scope, receive, send)
