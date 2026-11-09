# ADR 0003: Unix socket for the admin API

**TL;DR:** Publishing goes through a Unix domain socket with filesystem permissions plus a bearer token, never through a TCP port — so "who can publish" is enforced by the OS, not just application logic.

## Context

The admin API is the only write path into the dashboard (publish, update, pin, trash, restore, delete). It's used exclusively by the local MCP server, which is itself spawned locally by Claude Code over stdio. There is no legitimate remote caller. The plan is explicit that publishing must be local-only and that the admin API should "receive bytes, never paths," to keep the trust boundary simple.

## Decision

Bind the admin API to a Unix domain socket (`/run/preview-dashboard/admin.sock`, mode 0660, owned by the `pdash` group) rather than a TCP port, and additionally require a bearer token read from `/etc/preview-dashboard/admin.token` (0640, `root:pdash`) on every request.

## Consequences

- "Reachable" is enforced by two independent mechanisms: filesystem permissions on the socket (who can even connect) and the bearer token (defense in depth, and future-proofing if the socket permissions are ever loosened by mistake).
- There is no TCP port to firewall, scan, or accidentally expose via `tailscale serve` — a whole class of misconfiguration is structurally impossible.
- The MCP server and any future local automation talk to the same socket the same way; no separate network client library is needed (a plain `httpx` client over a Unix socket transport).
- Trade-off: admin API testing needs a real socket (or a socket-aware test client) rather than a plain in-process ASGI test client — accepted, and covered by `tests/integration/`.
