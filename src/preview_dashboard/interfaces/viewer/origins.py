"""`ViewerOrigins`: the owner identity, origins and Host values the viewer trusts.

Derived once from `Settings` at start-up. Construction is fail-closed
(docs/security.md I6, C2, C3): an unconfigured owner, host list or preview
origin makes the viewer refuse to start instead of serving anyone.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

from preview_dashboard.config import ConfigError, Settings

# Same shape `config.py` enforces; re-checked here because `Settings` can be
# built with `model_construct` (no validation) and this is the last gate.
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(\.{_LABEL})*$")


@dataclass(frozen=True, slots=True)
class ViewerOrigins:
    """Trusted identity and origin values for the two viewer apps.

    Attributes:
        owner_login: the only `Tailscale-User-Login` value accepted.
        dashboard_hosts: exact `Host` values the dashboard app accepts
            (bare hostnames: browsers omit the default 443 port).
        dashboard_origins: `https://<host>` for every dashboard host, sorted;
            used for CSRF `Origin` checks and the preview `frame-ancestors`.
        preview_origin: `https://<host>:<port>` of the preview app.
        preview_host: exact `Host` value the preview app accepts (`host:port`).
    """

    owner_login: str
    dashboard_hosts: frozenset[str]
    dashboard_origins: tuple[str, ...]
    preview_origin: str
    preview_host: str

    @classmethod
    def from_settings(cls, settings: Settings) -> ViewerOrigins:
        """Build the viewer's trust values from `settings`.

        Raises:
            ConfigError: `owner_login`, `allowed_hosts` or `preview_origin` is
                empty or malformed, or the preview origin collides with a
                dashboard origin. The viewer must not start.
        """
        owner = settings.owner_login
        if not owner:
            raise ConfigError("owner_login is empty; the viewer refuses to start (C2)")
        if owner != owner.strip() or any(
            ch.isspace() or unicodedata.category(ch).startswith("C") for ch in owner
        ):
            raise ConfigError("owner_login contains whitespace or control characters")
        if not settings.allowed_hosts:
            raise ConfigError("allowed_hosts is empty; the viewer refuses to start (C3)")
        for host in settings.allowed_hosts:
            if not _HOSTNAME_RE.fullmatch(host):
                raise ConfigError(f"allowed_hosts entry {host!r} is not an exact hostname")
        preview_origin, preview_host = _parse_preview_origin(settings.preview_origin)
        dashboard_origins = tuple(sorted(f"https://{h}" for h in settings.allowed_hosts))
        if preview_origin in dashboard_origins or preview_host in settings.allowed_hosts:
            raise ConfigError("preview_origin must differ from every dashboard origin (C5)")
        return cls(
            owner_login=owner,
            dashboard_hosts=frozenset(settings.allowed_hosts),
            dashboard_origins=dashboard_origins,
            preview_origin=preview_origin,
            preview_host=preview_host,
        )


def _parse_preview_origin(value: str) -> tuple[str, str]:
    """Return `(origin, host:port)` for an exact `https://<host>:<port>` value."""
    if not value:
        raise ConfigError("preview_origin is empty; the viewer refuses to start (C5)")
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        port = None
    host = parts.hostname or ""
    if (
        parts.scheme != "https"
        or port is None
        or port == 443
        or not _HOSTNAME_RE.fullmatch(host)
        or value != f"https://{host}:{port}"
    ):
        raise ConfigError("preview_origin must be exactly https://<host>:<non-443 port>")
    return value, f"{host}:{port}"
