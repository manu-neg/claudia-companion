# ADR 0017: Deployment hardening decisions (unit 11a)

**TL;DR:** `pdash-admin` and `pdash-viewer` share one group, **`pdash-admin`**
(not a separately named `pdash` group), because `interfaces/mcp/server.py`
already hardcodes that exact name to trust the admin token file. `data_dir`
itself stays 0750 (not group-writable — only `db/` is 2770). The admin
token file is `root:pdash-admin`. The admin socket only accepts uid-0
peers. The nftables rule only gates *new* loopback connections. The viewer
unit never uses `StateDirectory=`.

## Context

`docs/operations.md` and the unit-11 task notes sketch this deployment at a
level that leaves several concrete choices open. `ADR 0013` (unit 5)
describes the shared-group model in prose as a group literally named
`pdash`. While implementing this unit, reading the already-shipped code
that actually has to run under these permissions (`interfaces/cli.py`,
`interfaces/token_file.py`, `interfaces/mcp/server.py`,
`interfaces/mcp/client.py`, `adapters/fs_blobstore.py`) turned up several
concrete constraints ADR 0013's prose doesn't mention, one of which
directly contradicts the group name `pdash`:

```python
# src/preview_dashboard/interfaces/mcp/server.py
# The deployed token file is root:pdash-admin 0640 (C12); that group is the
# admin service group ...
ADMIN_SERVICE_GROUP: Final = "pdash-admin"
...
admin = AdminClient.from_settings(settings, token_gids=admin_group_gids())
```

`interfaces/mcp/client.py`'s `AdminClient.from_settings(..., token_gids=)`
feeds that straight into `load_admin_token(..., trusted_gids=token_gids)`.
The MCP server runs as **root** (Claude Code spawns it that way,
`docs/architecture.md` "Processes"), so its own effective gid is 0 — the
*only* reason it can trust a non-root-group token file at all is this
explicit, hardcoded lookup of a group literally named `pdash-admin`. This
unit cannot edit that file (out of scope, Python source belongs to unit
10), so the deployment has to conform to it, not the other way around.

## Decisions

1. **One shared group, named `pdash-admin`.** Both `pdash-admin` and
   `pdash-viewer` get `--gid pdash-admin --no-user-group` at `useradd` time
   (no separate `pdash-viewer` private group), and every systemd unit sets
   `Group=pdash-admin` explicitly (redundant with `pdash-admin`'s own
   primary group, kept explicit for clarity and so it doesn't silently
   depend on `useradd` defaults). A second, differently-named group (e.g.
   the originally-drafted `pdash`) would satisfy ADR 0013's *prose* but not
   `ADMIN_SERVICE_GROUP`'s hardcoded string — the MCP server would refuse
   every token file this deployment could produce. This ADR supersedes
   ADR 0013's group name specifically; its permission *model* (shared
   group, `UMask=0007`, `db/` 2770 setgid) is unchanged.

2. **Why the *viewer* needs the same group, not just the admin.**
   `FsBlobStore` creates new shard directories and blob files under
   `blobs/` without a setgid bit (deliberately: setgid is reserved for
   `db/`, see #3), so a new file's group is whatever the *creating
   process's effective gid* is at that moment (standard POSIX behavior
   absent setgid) — here, always `pdash-admin`, because only the admin/purge
   processes ever write there. For `pdash-viewer` to read those files via
   the kernel's group-permission check, its own effective gid must also be
   `pdash-admin` at the moment it opens them — hence `Group=pdash-admin` on
   the viewer unit too. Static `/etc/group` membership isn't required for
   this: systemd's `Group=` sets the spawned process's real/effective gid
   directly (`setresgid`, running as root), which is what both the
   kernel's DAC check and `os.getegid()`-based application trust
   (`load_admin_token`'s default, `FsBlobStore`'s implicit group
   inheritance) actually consult — not `/etc/group`'s membership list.

3. **The admin token file is `root:pdash-admin`, with `--token-group
   pdash-admin` passed explicitly wherever the CLI reads it.**
   `interfaces/cli.py::cmd_serve_admin`/`cmd_check_config` call
   `load_admin_token(..., trusted_gids=_token_gids(args))`, where
   `_token_gids` comes from a repeatable `--token-group` flag (this CLI
   flag did not exist when this unit started reading the codebase; it
   appeared mid-unit, evidently from a concurrently-running agent's work on
   `interfaces/cli.py` — this unit only reads and uses it, never edits
   `cli.py`). Without any `--token-group`, `load_admin_token`'s default
   (`{0, os.getegid()}`) already accepts a `pdash-admin`-group file from a
   process whose own effective gid is `pdash-admin` (true for
   `serve-admin`, by decision #1) — but `deploy/install.sh`'s `check-config`
   step runs as **root** (egid 0), which does *not* match `pdash-admin`
   without the flag. `deploy/systemd/preview-dashboard-admin.service` also
   passes `--token-group pdash-admin` for symmetry and defense in depth,
   even though it is not load-bearing there today.

4. **`data_dir` (`/var/lib/preview-dashboard`) itself is 0750, not 2770.**
   `FsBlobStore.__init__` opens `root` (== `data_dir`) and refuses it if it
   is group- or world-writable (`_verify_dir_fd`, `_FOREIGN_WRITE_BITS`) —
   the same check it applies to `blobs/` and `staging/`. A 2770 `data_dir`
   would make every role's `FsBlobStore` construction fail at startup with
   `UnsafeStorageLayoutError`. Only `db/`, created and validated
   independently by `adapters/sqlite/connection.py` (via `trusted_gid`,
   ADR 0013), is 2770 setgid — nothing at the SQLite layer imposes the
   "not group-writable" rule `FsBlobStore` imposes on its own root, and
   both writers need `db/` to be group-writable (admin publishes, viewer
   trashes/restores).

5. **`--allowed-peer-uid 0` on the admin socket.** The only legitimate
   caller is the MCP server, which runs as root on this host. The socket's
   own 0660 mode (bound by the app itself, C26) already keeps non-`pdash-
   admin`-group callers out, but root always bypasses Unix-socket DAC
   checks — so without this flag, the trust boundary is "root, or anyone
   ever added to group `pdash-admin`"; with it, it is exactly "root",
   matching the documented threat model precisely (`docs/security.md`
   "Known limitations": root can forge local requests regardless — that is
   accepted, not widened by this choice).

6. **The nftables rule only gates `ct state new` on `oif lo`.** A rule
   without a conntrack-state qualifier would re-evaluate `meta skuid 0` for
   every packet of an already-accepted connection, including the server's
   own outbound data — checked against the *client's* uid, meaningless for
   return traffic. `ct state established,related accept` (the standard
   nftables idiom) lets an accepted flow through without a second check;
   only a fresh connection attempt is gated.

7. **The viewer's systemd unit never declares `StateDirectory=`.**
   `systemd.exec(5)`: if a `StateDirectory=`/`RuntimeDirectory=`-family path
   already exists with a different owning user/group than the unit's own
   `User=`/`Group=`, systemd recursively `chown`s the whole tree to match.
   The admin and purge units share `data_dir`'s actual owner
   (`pdash-admin:pdash-admin`) so declaring it there is a safe no-op; the
   viewer unit's `User=` differs, so it must not, or a restart could turn
   into a mass rechown of `data_dir` to `pdash-viewer`, destroying the
   `trusted_owner_uids` model `FsBlobStore`/SQLite rely on (C25, C28). The
   viewer only ever gets `ReadWritePaths=`/`ReadOnlyPaths=` on paths
   `install.sh` (or the admin unit) already created.

8. **`SystemCallFilter=@system-service` then `SystemCallFilter=~@privileged
   @resources` (two directives, not one).** Per `systemd.exec(5)`, a
   `SystemCallFilter=` value beginning with `~` inverts that *directive*
   into a subtractive merge against the accumulated filter, rather than
   inverting only the first listed name. Two directives — an allowlist
   baseline, then an explicit subtraction — is the documented, composable
   form.

## Consequences

- `docs/operations.md`'s paths table and deployment section, and ADR
  0013's prose group name, are effectively superseded by `pdash-admin` as
  the actual, single shared group. ADR 0013 is not rewritten (its
  permission *model* is still correct and referenced); this ADR is the
  record of the name correction and why.
- A future change to `cli.py`/`interfaces/mcp/server.py` that renamed
  `ADMIN_SERVICE_GROUP` (or made it configurable) would let the group name
  change — decision #1 would need revisiting then, not before.
- `systemd-analyze security` scores and the loopback-firewall / peer-uid
  behavior are unverified by this unit (artifacts only, no service was
  started on this host) — tracked as unit 12 runtime verification
  (`docs/security.md` C1, C14, C20, C28 rows).

## Amendment "G" (unit 10b follow-up, ORCHESTRATOR DECISION): the group is `pdash` again

Decision #1 above predicted its own reversal condition and it landed: unit
10b's `interfaces/mcp/server.py` no longer hardcodes `ADMIN_SERVICE_GROUP`
at all. Instead, `interfaces/mcp/admin_socket.verify_admin_socket` reads the
admin socket's own gid (`os.lstat(admin_socket).st_gid`) *after* verifying
the socket is a real Unix socket, trusted-owned, in a non-group/world-writable
directory, and answered by a trusted `SO_PEERCRED` peer — and that gid, not
a name, is what `AdminClient.from_settings` trusts on the token file (C12,
`docs/adr/0016-mcp-server-stdio-thin-client.md` amendment).

With no hardcoded name left to conform to, the shared group reverts to
`pdash` — ADR 0013's original, and what `docs/architecture.md`/ADR 0013
already say. Every place this ADR's decision #1 pinned to `pdash-admin` as
a *group* changes to `pdash`: `deploy/install.sh`'s `SERVICE_GROUP`,
`gen-token --group`, `serve-admin --token-group`, `check-config
--token-group`, every systemd unit's `Group=`, `deploy/uninstall.sh`, and
`deploy/config.example.toml`'s ownership comments. The service **users**
are unaffected — they stay `pdash-admin` and `pdash-viewer` (decisions #2–#8
above, and the rest of this ADR's reasoning about *why* the viewer needs
the same group, `data_dir`'s mode, the peer-uid/nftables/`SystemCallFilter`
decisions) are unchanged by this amendment; only the group's *name* moves.

`docs/adr/0013-sqlite-shared-group-permissions.md` needs no correction now:
its prose name (`pdash`) was right all along, and this amendment is what
makes ADR 0017 consistent with it again.

## Amendment "F" (orchestrator, at first real install)
- **Context:** the original plan appended an `include` to `/etc/nftables.conf` and enabled `nftables.service`. On Ubuntu that file starts with `flush ruleset`, so enabling the service would wipe tailscaled's rules now and at every boot. Also, `nft -f` *appends* rules, so re-running the installer duplicated them.
- **Decision:** a dedicated oneshot `preview-dashboard-firewall.service` loads and removes only table `inet preview_dashboard`; the rule file declares → deletes → redefines the table in one transaction (atomic, idempotent). The viewer `Requires=` the firewall unit (fail closed). The system nftables config/service are never touched.
- **Consequences:** no interference with tailscaled or other firewall tooling; reinstall is safe; tests assert no `flush ruleset`, no `nftables.conf`/`nftables.service` use, and the declare/delete/define order.

## Amendment "H" (unit 12 audit fix batch)

Five small, independent fixes found by the unit-12 audit, grouped here because they all touch `deploy/`:

1. **H1 — local self-attribution via `tailscale serve`.** `tailscale serve` treats a connection this host makes to *its own* tailnet address (443/8443) the same as one arriving over the tailnet: attributed to the owner's identity. C14's original rule only gated the loopback ports a local process could hit directly (8787/8788); it did nothing about a local non-root process instead connecting to `https://<host>.ts.net`, reaching the exact same effect. `deploy/nftables/preview-dashboard.nft` gets a second rule pair, `fib daddr type local tcp dport { 443, 8443 } ct state new meta skuid 0 accept` / `reject`, ordered right after the loopback pair in the same `output` chain (same `ct state new` reasoning as decision #6 above). `deploy/check.sh` (H below) live-verifies both pairs by refusing `nobody` on all four ports.
2. **H2 — `enable --now` doesn't restart an already-active unit.** `install.sh`'s original last steps were `systemctl enable --now` for the firewall/admin/viewer units, meant to also serve as "restart on update". It doesn't: on a re-run after `git pull` against an already-running deployment, that call is a no-op for any unit already active, silently leaving the *old* code running under a freshly-synced `/opt` and freshly-installed unit file. `install.sh` now `enable`s those three units (no `--now`), then unconditionally `systemctl restart`s them (firewall, then admin, then viewer — the viewer `Requires=` the firewall), then asserts `NeedDaemonReload=no` and `ActiveState=active` on each, failing the install otherwise. This does mean every `install.sh` run interrupts any in-flight publish exactly like a manual restart always could (C11, no graceful drain) — accepted, documented in `docs/operations.md` "Updating".
3. **M1 — `git archive`/`rsync` without `--delete` never removes files.** The original sync step untarred (or, for a non-git source, `rsync -a --delete`'d) straight into `/opt/preview-dashboard`; the git-archive path in particular had no `--delete` equivalent, so a file removed from the repo since the last install would linger under `/opt` forever. Both source types now land in a fresh `mktemp -d` temp dir first, then one shared `rsync -a --delete` (excluding `.venv/`, `.claude/`, `tests/`, `HANDOFF.md`, `.github/`) moves that into `/opt/preview-dashboard`, followed by `chmod -R go-w`.
4. **M2 — no live verification existed.** `tests/unit/test_deploy_artifacts.py` only ever parsed/linted the artifacts in this repo; nothing checked a *running* deployment. `deploy/check.sh` is a new, read-only, root-only script (never writes/restarts/reconfigures) that: confirms the nft table and tailscaled's own `ts-*` chains are intact; confirms a `nobody` process is refused on 127.0.0.1:8787/8788 **and** on `https://<host>{,:8443}` (H1); confirms both apps 403 a request with no `Tailscale-User-Login` header; confirms the firewall/admin/viewer units are active, need no daemon-reload, and were (re)started after their unit file's mtime; `nsenter`s into the live viewer process's own mount namespace to confirm `pdash-viewer` genuinely cannot *read* `/root` or the admin token there (`test -r`, not `test -e` — `InaccessiblePaths=`/`ProtectHome=` replace the target with a 0-mode placeholder that still `stat()`s as present); checks `systemd-analyze security` exposure ≤ 2.0 per unit; and checks Tailscale Funnel is off. Exits non-zero on any failure. `install.sh` runs it as its final step.
5. **L1 — the viewer had no reason to see `/run/preview-dashboard`.** That directory is the *admin* service's own `RuntimeDirectory` (holds `admin.sock`); `ProtectSystem=strict` does not hide `/run` by itself, so the viewer unit's `InaccessiblePaths=` now masks it explicitly too, the same way it already masks the admin token file (decision context above).

**Consequences:** `deploy/check.sh` is the first artifact in this project that is meant to run against a live host rather than only being statically checked — it has no test of its own that *executes* it (that would require root, systemd and nftables), only static coverage tests (`bash -n`, strict mode, and a grep-based check that every required check is present) alongside the rest of `tests/unit/test_deploy_artifacts.py`; it was run for real, read-only, against this project's own live deployment while writing it, printing 17/17 `PASS`.
