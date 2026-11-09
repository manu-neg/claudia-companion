# ADR 0023: Notifier deployment — group isolation via a socket ACL, host-state artifacts

**TL;DR:** `pdash-notify` gets its own primary group, never `pdash`; it reaches the admin Unix socket via two POSIX ACL entries the admin unit grants itself (so `install.sh` requires `setfacl` and refuses without it). The nftables egress rules and the admin unit's extra flags are generated per host (numeric uid substitution / an optional `EnvironmentFile` expanded unbraced), and whether the notifier is installed is **host state**, so plain re-runs keep it. A host that never had the notifier is functionally unchanged.

## Context

The owner's decision on notifier isolation fixes the group model: `pdash-notify` must **not** be a member of `pdash` (it must never gain read access to `admin.token`, `db/` or `blobs/` — the notifier is the one internet-facing process, C33), and the only group it shares is `pdash-notifytok` (with `pdash-admin`), scoped to `notifier.token` alone.

The admin socket lives in `/run/preview-dashboard` (systemd `RuntimeDirectory`, 0750, `pdash-admin:pdash`). Without `pdash` membership, `pdash-notify` can't even `stat()` the socket, which `verify_admin_socket` does first — a filesystem problem no Python check can work around. The S-B review (FAIL, fail-closed) then found: the braced `${PDASH_NOTIFIER_ADMIN_ARGS}` broke `serve-admin` on every host (H1); `check-config` didn't trust the notifier token's group (H2); `check.sh` put tokens on argv and probed from a uid the peer policy refuses anyway (M1); a re-run without the flag dropped the notifier config (M2); `setfacl` isn't installed on this host (M3); 443 egress also reached tailnet/private addresses (L2).

## Decision

1. **Socket access via two POSIX ACL entries, not group membership.** The admin unit's `ExecStartPost` (as `pdash-admin`, owner of both paths) runs `setfacl -m u:pdash-notify:X` on `/run/preview-dashboard` and, once the socket exists (≤ 30 s poll), `setfacl -m u:pdash-notify:rw` on it. A no-op where `pdash-notify` doesn't exist; logs failures to the journal and always exits 0 (the notifier fails closed instead). Every shell `$` is written `$$`: systemd expands `$NAME`/`${NAME}` in Exec lines itself, even inside quotes.
2. **`setfacl` is a hard prerequisite, never installed by us.** `install.sh` refuses (before any change) to install or keep the notifier without it; `apt install acl` is an explicit owner step. `check.sh` verifies the grant live (`runuser -u pdash-notify -- test -w admin.sock`).
3. **Egress rules come from `deploy/nftables/notifier-egress.nft.in`**, spliced at an inert marker with the **numeric** uid (a username would fail the whole table where the user doesn't exist). Order: loopback DNS → reject tailnet, loopback, RFC1918, link-local, ULA → accept TCP 443 → reject the rest.
4. **Admin flags from an optional `EnvironmentFile=-/etc/preview-dashboard/notifier-admin.env`, expanded unbraced** (`$PDASH_NOTIFIER_ADMIN_ARGS` → zero or more argv words); the unit file stays identical on every host. Token groups use the scoped form (ADR 0024): `serve-admin`/`check-config` get `--token-group admin=pdash` and, on notifier hosts, `notifier=pdash-notifytok`; `serve-notifier` gets `notifier=pdash-notifytok` (its own group trusts `telegram.token`); root's `notify pair` gets `telegram=pdash-notify`.
5. **"Installed" = host state** (notifier unit file or `pdash-notify` present), not this run's flags. The notifier is (re)started only when `config.toml` has `notify_enabled = true` and `telegram.token` exists; with it off, the unit is disabled.
6. **Existing `config.toml`:** `--telegram-chat-id` adds the missing notifier keys in place (flips `notify_enabled = false`), keeping owner/mode, verified by a TOML round-trip (`deploy/lib/notify_config.py`); a different chat id already present is refused, never overwritten.

## Consequences

- No `src/` change is needed for access: `verify_admin_socket` is untouched. If the socket's group model changes later, the ACL layer can be dropped.
- `tmpfs` ACL support is assumed (true on current kernels); `check.sh` catches it if not.
- Pairing after a placeholder chat id means one manual `config.toml` edit (install.sh won't overwrite an id).
- Removing the notifier is `deploy/uninstall.sh`; re-runs never remove it.
