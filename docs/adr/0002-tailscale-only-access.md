# ADR 0002: Tailscale-only access, no public exposure

**TL;DR:** The viewer is never reachable from the public internet — only via the owner's tailnet, with Funnel disabled and a tailnet ACL restricting it to the owner's identity.

## Context

The dashboard holds content the owner considers private enough to control tightly ("Security first" is an explicit requirement). The owner needs access from their phone and multiple computers, without managing their own TLS certificates, public DNS, or an internet-facing attack surface. The host has no existing public ingress and SSH is explicitly left untouched (out of scope).

## Decision

Expose the viewer only through Tailscale:

- `tailscale serve` fronts the viewer (443) and the separate preview origin (8443) with Tailscale-issued TLS, forwarding to loopback-bound local ports.
- Tailscale Funnel (which would make a `serve` config public) stays **off**.
- **Loopback is not a user boundary:** any local user can connect to `127.0.0.1`. An nftables `output` rule on `lo` for dports 8787/8788 accepts only `meta skuid 0` (`tailscaled` runs as root) and rejects every other uid, so a non-root local process can't forge `Tailscale-User-Login` (`docs/security.md` C14, unit 11). If the installed `tailscale serve` supports a `unix:` socket target, prefer that and keep the rule as a backstop.
- A tailnet ACL further restricts the service to the owner's own identity, as defense in depth beyond the app-level identity check (ADR-independent control, `docs/security.md` C2).
- The owner installs Tailscale on their phone and computers and signs in with the same account (owner action, tracked in the project plan), with MFA turned on for that account.

## Consequences

- Zero public attack surface: there is no code path an internet scanner can reach at all.
- Availability is coupled to Tailscale's own availability and the owner's devices being enrolled — accepted, since the alternative (public exposure) is a strictly worse security posture for a private dashboard.
- The app still needs its own identity check (`Tailscale-User-Login` header, ADR-independent, see `docs/security.md` C2) rather than trusting network reachability alone, because any device on the tailnet could otherwise reach the service if the ACL were ever misconfigured — defense in depth.
- An extra deploy artifact (nftables rule) must be installed and checked by `deploy/check.sh`; without it, local non-root users could impersonate the owner.
- Root on the host is a known, documented limitation (`docs/security.md`, Known limitations): a fully privileged local attacker can forge the identity header locally. Tailscale doesn't and can't defend against that; it's out of scope.
