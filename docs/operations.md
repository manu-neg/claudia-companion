# Operations

**TL;DR:** Four systemd-managed processes on one host, running as dedicated non-root users (`pdash-admin`, `pdash-viewer`), reachable only over Tailscale, with an nftables rule so only `tailscaled` can reach the viewer's loopback ports (and, separately, the host's own tailnet HTTPS ports — unit 12 audit H1). `deploy/install.sh` installs everything below (units, nftables rule, config template); see "Deployment" for the real step-by-step. Artifacts are written and statically verified (unit 11a); `deploy/check.sh` (unit 12) does the live, read-only verification against a running install — `systemd-analyze security` scores, the loaded nftables rules and Tailscale funnel state are checked there, not just statically.

New host, step by step (wizard, Tailscale, own Telegram bot, MCP, Claudia): [`docs/setup.md`](setup.md). Cutting a shareable release: [`docs/release.md`](release.md).

## Services

| Unit | Type | Runs | Notes |
|---|---|---|---|
| `preview-dashboard-viewer.service` | simple | `preview-dashboard serve-viewer` | Binds `127.0.0.1:8787` + preview origin `127.0.0.1:8788` |
| `preview-dashboard-admin.service` | simple | `preview-dashboard serve-admin` | Listens on `/run/preview-dashboard/admin.sock` (0660, bound by the app; `RuntimeDirectoryMode=0750`) |
| `preview-dashboard-purge.service` | oneshot | `preview-dashboard purge` | Triggered by the timer below |
| `preview-dashboard-purge.timer` | timer | — | Hourly; runs the purge service |
| `preview-dashboard-notifier.service` | simple | `preview-dashboard serve-notifier` | Telegram deliveries + answer taps; **only installed/enabled when `install.sh --telegram-chat-id` was given** (N5) — see "Telegram notifications" below |

Admin and purge run as `pdash-admin` (rw `db/`, `blobs/`); the viewer runs as `pdash-viewer` (rw `db/` for trash/restore, `blobs/` read-only). Both users' **primary** group is `pdash` — one shared group, not a private group each. `interfaces/mcp/server.py` no longer hardcodes any group name: it derives the group it trusts on the token file from the admin socket's own gid at runtime (`interfaces/mcp/admin_socket.py`, ADR 0017 amendment "G"), which is what lets the shared group be named `pdash` (ADR 0013's original name). Both run with `UMask=0007` (ADR 0013). No login shells, no home directory. Full hardening list and rationale: `docs/security.md` C28, `deploy/systemd/*.service`, ADR 0017 (`systemd-analyze security` ≤ 2.0 per unit is a unit-12 runtime check; `systemd-analyze verify` on the shipped unit files passes today, mod the venv binary/service users not existing on a non-deployed host).

The notifier runs as its own user, `pdash-notify`, with its own **private** primary group of the same name — deliberately **not** a member of `pdash` (docs/security.md C33): it must never gain read access to `admin.token`, `db/` or `blobs/` through that group, since it is the one internet-facing process (outbound HTTPS to Telegram). See "Telegram notifications" below for its token access and admin-socket reachability.

## CLI (`preview-dashboard`, unit 7)

Every command vets the TOML config first (C16) and exits non-zero with a one-line reason on any fail-closed check (0 ok, 1 refused/failed check, 2 config/startup error). Logs go to stderr (journald under systemd).

| Command | What it does |
|---|---|
| `serve-admin [--allowed-peer-uid UID]… [--notifier-peer-uid UID]… [--claudia-peer-uid UID]… [--trusted-sidecar-uid UID]… [--token-group [KIND=]GROUP]…` | Admin API on `admin_socket` (binds it 0660 itself; a stale socket is replaced, but one a live instance still answers on — or anything else — is refused). With `--allowed-peer-uid`, only those `SO_PEERCRED` uids are served (`deploy/systemd/preview-dashboard-admin.service` passes `0`: the MCP client runs as root, ADR 0017 #5); `--claudia-peer-uid` does the same for `/v1/claudia/*`. `--token-group KIND=GROUP` (KIND = `admin`/`notifier`/`telegram`/`claudia`) trusts a group for that one token file (ADR 0024; plain `GROUP` still works for any file). `deploy/systemd/preview-dashboard-admin.service` passes `admin=pdash` (not load-bearing there since the process's own effective group already is `pdash`, but explicit for symmetry, ADR 0017 #3) plus, on notifier hosts, `--notifier-peer-uid <uid> --token-group notifier=pdash-notifytok` from `notifier-admin.env`. `--trusted-sidecar-uid`: that uid may own the DB's `-wal`/`-shm` only (the unit passes `${PDASH_VIEWER_UID}` from `viewer-uid.env`, ADR 0025). Creates/migrates the DB schema at startup |
| `serve-viewer [--trusted-owner-uid UID]…` | Viewer apps via `interfaces/viewer/server.serve(core)`. Pass the admin uid as trusted owner (`deploy/systemd/preview-dashboard-viewer.service` resolves it at install time into `/etc/preview-dashboard/admin-uid.env`). Never creates or migrates the DB: refuses to start until the admin (or `migrate`) has created it |
| `purge [--trusted-sidecar-uid UID]…` | One purge + orphan sweep + staging sweep; prints a JSON report (the unit passes the viewer uid as sidecar owner, ADR 0025). No `--now` override, by design. Like the viewer, needs an existing, current schema |
| `prune-revisions ITEM_ID [--keep N] [--trusted-sidecar-uid UID]…` | **Permanently** delete an active item's old revisions, keeping the newest `N` (1–20, default 1, current one included; ADR 0030). Prints `{"item_id", "revision", "revisions_kept", "revisions_removed", "bytes_freed"}` (no title). Trashed/unknown item or stale state → one line, exit 1; bad id or `--keep` → exit 2. Purge role: run it as `pdash-admin` like the purge unit (below) |
| `empty-trash [--trusted-sidecar-uid UID]…` | **Permanently** delete every trashed item now, regardless of retention (an item restored meanwhile is kept). Prints `{"items_purged", "blobs_deleted"}`. Purge role, run as `pdash-admin` |
| `gen-token --out PATH [--group GROUP]` | New admin token (`secrets.token_urlsafe(32)`), file created `O_EXCL\|O_NOFOLLOW`, mode 0640; `GROUP` is a name or existing gid — `deploy/install.sh` passes `pdash` (ADR 0017 amendment "G"). Never overwrites, never prints the token |
| `migrate [--trusted-owner-uid UID]… [--trusted-sidecar-uid UID]…` | Validate the DB location, create/migrate the schema, print the version (`install.sh` passes the viewer uid as sidecar owner: the viewer may be running) |
| `check-config [--skip-token] [--token-group [KIND=]GROUP]…` | Validate config file + settings (+ token files: `notifier.token` too when `notify_enabled`); prints a JSON summary, no secrets. `deploy/install.sh` passes `--token-group admin=pdash` (+ `notifier=pdash-notifytok` on notifier hosts): `check-config` runs as root, whose own effective group (0) does not match the token files' groups without them |

**Token generation / rotation:**
```
preview-dashboard gen-token --out /etc/preview-dashboard/admin.token.new --group pdash
chown root:pdash /etc/preview-dashboard/admin.token.new   # if not run as root with --group
mv -f /etc/preview-dashboard/admin.token.new /etc/preview-dashboard/admin.token
systemctl restart preview-dashboard-admin   # the token is read once at startup
```
`-f`: `gen-token` never overwrites an existing file (by design, so a rotation
can't accidentally clobber the live token before the new one is verified
good) — the old `admin.token` at the destination is expected and must be
replaced, not refused, by this `mv`. The admin refuses to start if the
token file is a symlink, not a regular file, group-writable or accessible
by others, not owned by root/its own user, not in group root, its own
group, or a `--token-group`, in a group/world-writable directory, shorter
than 43 characters or made of fewer than 16 distinct characters. The group
must be `pdash` in this deployment (`deploy/install.sh`'s choice, passed
everywhere via `--group`/`--token-group`) — but nothing in the code
hardcodes that name any more: the MCP client instead verifies the admin
socket itself is trustworthy and then trusts *that socket's own gid* on
the token file (`interfaces/mcp/admin_socket.verify_admin_socket`, C12,
ADR 0017 amendment "G"), so the deployment's group name and the MCP
server's trust always agree by construction.

**The MCP server picks up a rotated token per session, not live:** it reads
`admin_token_file` once at its own startup (`interfaces/mcp/server.py`), and
Claude Code spawns a fresh `preview-dashboard-mcp` process per session (it
is registered as a stdio server, never a long-lived daemon — see
"Registering the MCP server" below). So after rotating the token and
restarting `preview-dashboard-admin`, any MCP session that was already
running keeps using its old, now-invalid in-memory copy until that session
ends; the *next* session started after the rotation reads the new token
file and needs no separate action.

**Deleting old versions / emptying the trash (ADR 0030):** permanent, cannot be undone. Easiest from Claude (`dashboard_prune_revisions`, `dashboard_empty_trash`, which go through the running admin API). On the host, run the CLI as `pdash-admin` (like `migrate` in `install.sh`), never as plain root: the storage trust checks only accept the service's own uid, and a root-owned `-wal`/`-shm` would lock the services out (ADR 0025):
```
. /etc/preview-dashboard/viewer-uid.env
runuser -u pdash-admin -- env PDASH_CONFIG=/etc/preview-dashboard/config.toml \
  /opt/preview-dashboard/.venv/bin/preview-dashboard prune-revisions <item-id> --keep 1 \
  --trusted-sidecar-uid "$PDASH_VIEWER_UID"
runuser -u pdash-admin -- env PDASH_CONFIG=/etc/preview-dashboard/config.toml \
  /opt/preview-dashboard/.venv/bin/preview-dashboard empty-trash --trusted-sidecar-uid "$PDASH_VIEWER_UID"
```

**Startup order:** the admin service (or `preview-dashboard migrate`, run as `pdash-admin`) creates the database; the viewer and purge only open an existing DB at the current schema version and exit with `database does not exist yet` / `schema is at version N` otherwise (systemd restarts the viewer; order it `After=` the admin unit).

## Paths

| Path | Purpose | Owner:group | Mode |
|---|---|---|---|
| `/var/lib/preview-dashboard/` | `data_dir`: `db/`, `blobs/`, `staging/` | `pdash-admin:pdash` | 0750 — **not** group-writable, or `FsBlobStore` refuses to start (ADR 0017 #4) |
| `/var/lib/preview-dashboard/db/` | SQLite DB + `-wal`/`-shm` (admin and viewer both write) | `pdash-admin:pdash` | dir 2770 (setgid), files 0660 — enforced by `connect()` (C24) |
| `/var/lib/preview-dashboard/claudia/` | Claudia DB `claudia.sqlite3` + `-wal`/`-shm`: owner messages + approval requests (ADR 0034). Admin-only: created by the admin when `claudia_enabled`, opened by purge, **never** by the viewer | `pdash-admin` (any group) | dir 0700, files 0600 — anything looser, another owner, a symlink or hardlink is refused (`connect_claudia`), never fixed |
| `/run/preview-dashboard/admin.sock` | Admin API socket (systemd `RuntimeDirectoryMode=0750`) | `pdash-admin:pdash` | 0660, bound by the app itself under `UMask=0007` |
| `/etc/preview-dashboard/` | Config directory | `root:root` | 0755 (never group/world-writable) |
| `/etc/preview-dashboard/admin.token` | Admin bearer token | `root:pdash` | 0640 — group must match what `interfaces/mcp/admin_socket.verify_admin_socket` reads off the admin socket (ADR 0017 amendment "G"); also `InaccessiblePaths=` on `preview-dashboard-viewer.service` — the viewer has no admin API client and must not be able to read it even via a bug |
| `/etc/preview-dashboard/admin-uid.env` | `PDASH_ADMIN_UID=<uid>` for the viewer unit's `--trusted-owner-uid` | `root:root` | 0644, written by `deploy/install.sh` |
| `/etc/preview-dashboard/viewer-uid.env` | `PDASH_VIEWER_UID=<uid>` for the admin/purge units' `--trusted-sidecar-uid` (required: missing → units refuse to start, ADR 0025) | `root:root` | 0644, written by `deploy/install.sh` |
| `/etc/preview-dashboard/config.toml` | TOML config, from `deploy/config.example.toml` | `root:root` | 0644 — **must** be a regular file owned by root, not group/world-writable, or services refuse to start (C16) |
| `/root/outbox/` | Default MCP intake root | `root:root` | 0700 |
| `/root/outbox/progress-state/` | Progress tools' private state (first intake root; `<item id>/state.json` + short-lived `stage-*/`), created by the MCP server (ADR 0029, C42). Deleting an item's dir only makes `dashboard_progress_update` ask for a full `_set`. Stale (> 1 h) `stage-*` dirs and `*.tmp` files are swept at MCP startup; an item's `state.json` is kept after the item is purged (small; remove its dir by hand) | `root:root` | 0700 (anything looser, or a symlink → the tools refuse) |

## SQLite database (`adapters/sqlite/`, unit 5)

**TL;DR:** `data_dir/db/items.sqlite3`, shared-group model (`db/` 2770 setgid, files 0660, group `pdash`), WAL mode; `connect()` creates what's missing with exact modes and refuses anything untrusted — it never "fixes" existing permissions.

| What | Behavior |
|---|---|
| Path | `data_dir/db/items.sqlite3` (`default_db_path`); the data dir must already exist |
| Creation | `db/` (2770) and the DB file (0660) are created on first connect via dir fd, `fchown` to `trusted_gid`, `fchmod` (umask-independent); `-wal`/`-shm` are created by SQLite with the DB file's mode and inherit the group via setgid |
| Refusal (`UnsafeDatabasePathError`, a `StorageUnavailableError`: admin/viewer answer **503** + `Retry-After`, logged WARNING — ADR 0025) | data dir / `db/` / DB file / `-wal` / `-shm` that is a symlink or wrong type, owned by a uid outside `trusted_uids` (sidecars: also `trusted_sidecar_uids`), has any world bit (data dir: world-writable), or is group-writable by a group other than `trusted_gid`; `db/` or the DB file swapped while connecting |
| Wiring | `bootstrap.py` passes `trusted_uids` (admin/purge: their own uid; viewer: admin + viewer uids), `trusted_sidecar_uids` (admin/purge/`migrate`: the viewer uid — SQLite deletes `-wal`/`-shm` on the last close and the viewer recreates them as itself when it opens the DB first) and `trusted_gid` (`pdash`) |
| Pragmas | WAL (asserted, else `DatabaseSetupError`), `busy_timeout=5000`, `foreign_keys=ON`, `secure_delete=ON`, `trusted_schema=OFF`, `synchronous=NORMAL`, `journal_size_limit=1 MiB` (rationale: `connection.connect` docstring) |
| Migrations | Automatic on connect (`PRAGMA user_version`); no separate step |
| WAL residue | Deleted rows' old pages linger in `items.sqlite3-wal` until a TRUNCATE checkpoint; the purge job runs `SqliteItemRepository.compact()` after purging (bounded retry; a busy reader just defers it to the next run) |

Fixing a refused layout (e.g. a backup restored as 0644): `chown pdash-admin:pdash` and `chmod 0660` the file(s), `chmod 2770` the `db/` directory, then restart. Don't `cp` over a live `-wal`/`-shm`.

**Schema version guard:** a database whose `user_version` is newer than the running code (e.g. old code after a rollback that skipped the backup restore) is refused by every role (`database schema is at version N, newer than this code's M`); nothing is written. Restore the matching backup (below).

### Claudia database (`adapters/sqlite/claudia_db.py`, ADR 0034)

**TL;DR:** `data_dir/claudia/claudia.sqlite3`, private to `pdash-admin` (dir 0700, files 0600), own schema version 1. Holds the owner-message inbox and approval requests so the viewer (which writes `db/`) can never forge them.

| What | Behavior |
|---|---|
| Created by | the admin service at startup, only with `claudia_enabled = true` (dir + file with exact modes, umask-independent; schema 1). `migrate` does not create it |
| Opened by | the admin; the purge job (`create=False`: never creates it; a missing file only sets `inbox_failed` in its report). Never the viewer |
| Refused (`UnsafeDatabasePathError` → admin 503; purge `inbox_failed`) | data dir not owned by the admin or group/world-writable; `claudia/` or any file a symlink, wrong type, not owned by the admin uid, any group/other bit (incl. a POSIX ACL mask), file with a second hardlink; dir/file swapped while connecting. Wrong/newer schema → `DatabaseSetupError` |
| Fix a refused layout | as `pdash-admin`: `chmod 0700 claudia/`, `chmod 0600 claudia/claudia.sqlite3*`, `chown pdash-admin` them; check for stray hardlinks (`find / -samefile …`) |
| Housekeeping | purge (Claudia on): overdue open approvals → `expired` (`approvals_expired`), then messages / approvals older than 30 days deleted |
| Viewer confinement | M9 adds `/var/lib/preview-dashboard/claudia` to the viewer unit's `InaccessiblePaths` (defense in depth over the 0700 mode) |

## Blob store layout (`adapters/fs_blobstore.py`, unit 6)

Inside `data_dir` (`/var/lib/preview-dashboard/`), `FsBlobStore` owns two subdirectories:

| Path | Contents | Mode | Safe to delete? |
|---|---|---|---|
| `blobs/<AB>/<ULID>` | Final, immutable blob files, sharded into up to 1024 (32²) subdirectories keyed by the **last** two characters of the blob id (the random part — the first characters are a timestamp and wouldn't spread a burst of publishes across shards) | dirs `0750`, files `0640` (constructor defaults; `install.sh` passes the service's actual `file_mode`/`dir_mode`) | **No** — referenced by the DB manifest; deleting one orphans an item's file |
| `staging/<ULID>.part` | In-flight writes only; a file here for longer than a few seconds means an interrupted `put` | `0750` / `0640` | **Yes** — anything older than an hour or so is a leftover from a crash mid-write, never a live blob; `FsBlobStore.sweep_staging(older_than)` removes these and is intended to run from the purge job |

`root`, `blobs/` and `staging/` must live on the same filesystem (writes are
published via `os.link` + `os.unlink`, which requires that) and must be
real directories, not symlinks, **owned by the service's uid (or an explicitly
trusted one) and not group/world-writable** — the store refuses to start
otherwise (`UnsafeStorageLayoutError`); a shard dir failing the same check
makes `put` fail and `open`/`delete`/`list` treat it as absent. Never point
`blobs/` or `staging/` at a separate mount or a symlink when provisioning
the host.

- **Directory fds:** the store opens `data_dir`, `blobs/` and `staging/` once
  at start-up and works relative to those fds until `close()`. Renaming or
  replacing these directories under a running service has no effect on it
  (it keeps using the originals) — restart the service after any manual
  layout change.
- **Viewer (`pdash-viewer`) vs owner (`pdash-admin`):** the viewer's store must
  be built with `trusted_owner_uids` containing `pdash-admin`'s uid (bootstrap,
  unit 11), since the dirs are owned by the writer, not the viewer. Both
  processes share group `pdash` (ADR 0017 amendment "G"), which is what lets
  the viewer read files the admin/purge processes wrote.
- **Free-disk floor:** `reserve_bytes` (wired to `min_free_disk_bytes`) makes
  `put` refuse any chunk that would leave less free space than the floor.
- **Hardlinks:** a blob file must have exactly one link; never hardlink blob
  files (e.g. `cp -al` backups inside `data_dir`) — such blobs read as "not
  found" until the extra link is removed.

## Network exposure

- `tailscale serve` fronts the viewer on 443 and the preview origin on 8443, both terminating TLS via Tailscale's cert. Funnel (public exposure) stays **off** — `deploy/tailscale/serve.sh` sets both `serve` targets and fails if `tailscale funnel status` doesn't report off.
- A tailnet ACL restricts the service to the owner's identity: `deploy/tailscale/acl-snippet.json` is a grant to merge into the tailnet policy (`tag:pdash:443,8443`, owner login only).
- Local-only admin socket: never bound to a TCP port.
- **Loopback firewall (C14):** any local user can connect to `127.0.0.1`, so only root (`tailscaled`) may reach the viewer ports. `deploy/nftables/preview-dashboard.nft` (installed to `/etc/preview-dashboard/preview-dashboard.nft`, loaded by `preview-dashboard-firewall.service`, which the viewer requires; `/etc/nftables.conf` and `nftables.service` are never touched):

```
table inet preview_dashboard {
  chain output {
    type filter hook output priority filter; policy accept;
    ct state established,related accept
    oif "lo" tcp dport { 8787, 8788 } ct state new meta skuid 0 accept
    oif "lo" tcp dport { 8787, 8788 } ct state new reject with tcp reset
  }
}
```

  `ct state established,related accept` first: an already-accepted connection's own reply/data packets don't need a second per-packet uid check (that check only matters for `ct state new`, i.e. connection attempts). A second rule pair, ordered right after the loopback one, gates *new* connections to `fib daddr type local` dports 443/8443 the same way (unit 12 audit, High 1): `tailscale serve` treats a connection this host makes to its own tailnet address as coming from the owner, so without this rule any local non-root process could reach the same effect as forging the identity header, just by connecting to `https://<host>.ts.net` instead of the loopback port directly. Live-verified by `deploy/check.sh` (root, read-only: confirms the table is loaded, `tailscaled`'s own `ts-*` chains are intact, and a `nobody` process is refused on 127.0.0.1:8787/8788 **and** on `https://<host>{,:8443}`); `tests/unit/test_deploy_artifacts.py` only statically validates the rule file (`nft -c -f`, never loads it). If `tailscale serve` supports a `unix:` target, prefer that and keep this rule as a backstop. Known limitation, unchanged by this rule: root on the host can still forge local requests (`docs/security.md` "Known limitations", ADR 0002).

  **If something else flushes the ruleset:** `preview-dashboard-firewall.service` only ever loads/removes its own `inet preview_dashboard` table (never `nftables.service`, `/etc/nftables.conf`, `ufw`, or `firewalld` — see the unit's own comment). But if *another* tool on the host later runs its own `flush ruleset` (enabling `nftables.service`, `ufw enable`, `firewalld` reload, ...), that removes this table too, even though `preview-dashboard-firewall.service` itself stays "active" (systemd has no way to notice its `ExecStart` effect was undone by someone else). The viewer ports are then unprotected (any local user could reach them) without any failed unit to alert on it. Check by hand with `nft list table inet preview_dashboard` (fails if the table is gone), and recover with:
  ```
  sudo systemctl restart preview-dashboard-firewall preview-dashboard-viewer
  ```
  (the viewer restart isn't strictly required for the rule itself, but keeps `Requires=`/`After=` ordering meaningful and re-confirms the viewer still starts with the rule in place). `ExecStop=` on the firewall unit is prefixed `-` (ignore failure) precisely because `nft delete table` on an already-gone table would otherwise make `stop`/`restart` themselves report failed for what is really a no-op.

## Configuration

- Precedence: TOML file > defaults, with `PDASH_*` env overriding TOML — but env may only **narrow** intake policy and limits (`docs/security.md` "Env narrowing"). Widening requires editing the TOML as root.
- Before trusting the TOML, services call `verify_config_file_secure()`; fix ownership with `chown root:<group> config.toml && chmod 0640 config.toml`.
- Required for the viewer: `owner_login`, `allowed_hosts` (exact hostnames), `preview_origin` (`https://<host>:8443`). Empty values fail closed.

## Deployment

**TL;DR:** `sudo deploy/install.sh --owner-login OWNER --host HOST.ts.net`
does everything except enrolling the host in the tailnet and fronting it
with `tailscale serve` (owner/operator actions, run once, separately). Every
step is idempotent — re-running after a `git pull` updates the code and
dependencies in place and leaves users, data, the token and the config file
untouched.

Artifacts referenced below (`deploy/`) are written and statically checked by
this repo's tests (`tests/unit/test_deploy_artifacts.py`: unit file
structure/hardening directives, `nft -c` syntax, `bash -n` + `systemd-analyze
verify`, `--dry-run` behavior). `deploy/check.sh` (step 10 below, unit 12
audit M2) does the live, read-only verification on an actual installed
host: `systemd-analyze security` scores, the loaded nftables rule (both the
loopback and the local-self-connect gate, H1), the loopback-firewall/
peer-uid behavior, and viewer mount-namespace confinement
(`docs/security.md` C1, C14, C20, C28 rows).

### 1. Prerequisites

- A Linux host with systemd, `nft` (nftables), Python 3.12 and
  [uv](https://docs.astral.sh/uv/) installed.
- Tailscale installed (not installed by `install.sh`; see step 5).
- If you plan to enable the Telegram notifier (`--telegram-chat-id`, see
  "Telegram notifications" below): the `acl` package (`setfacl`), used to
  grant `pdash-notify` access to the admin socket without widening any group.
  `install.sh` refuses the notifier without it and never installs it for
  you (`sudo apt install acl` is an owner step).
- This repo checked out somewhere readable (any path; `install.sh` copies it
  into `/opt/preview-dashboard`, it does not run in place).

### 2. Install services, users, config and the token

```bash
sudo deploy/install.sh --owner-login owner@example.com --host my-host.tailXXXX.ts.net
```

`--host` is the tailnet hostname the dashboard will answer on — if you
don't know it yet, run `tailscale status` after step 5's `tailscale up`, or
run `install.sh` once, then edit `allowed_hosts`/`preview_origin` in
`/etc/preview-dashboard/config.toml` by hand and `systemctl restart
preview-dashboard-viewer`. `--dry-run` (no root required) prints every
action `install.sh` would take without touching the system — useful to
review before running for real, and what `tests/unit/test_deploy_artifacts.py`
exercises.

What it does, in order (see `deploy/install.sh` for the exact commands):

1. Creates group `pdash` and system users `pdash-admin`/`pdash-viewer`
   (`nologin`, no home, shared primary group `pdash` — ADR 0017 amendment "G").
2. Resolves `pdash-admin`'s uid into `/etc/preview-dashboard/admin-uid.env`
   (consumed by the viewer unit's `--trusted-owner-uid`) and `pdash-viewer`'s
   into `/etc/preview-dashboard/viewer-uid.env` (admin/purge units' and
   `migrate`'s `--trusted-sidecar-uid`, ADR 0025).
3. Creates `/opt/preview-dashboard`, `/etc/preview-dashboard`,
   `/var/lib/preview-dashboard` (+ `blobs/`, `staging/`), `/root/outbox`
   with the ownership/modes in "Paths" above.
4. Copies the repo into `/opt/preview-dashboard` (`git archive HEAD` if
   it's a git checkout, else `rsync` excluding `.venv`/`.git`/caches) and
   runs `uv sync --frozen --no-dev` there.
5. Writes `/etc/preview-dashboard/config.toml` from
   `deploy/config.example.toml`, filling in `owner_login`/`allowed_hosts`/
   `preview_origin` from the arguments (only if the file doesn't already
   exist — re-running never overwrites a config you've since edited;
   `--telegram-chat-id` only adds the two notifier keys when absent).
6. Generates the admin token (`gen-token --out ... --group pdash`) if
   absent — never overwrites an existing one.
7. Runs `check-config`, then `migrate` as `pdash-admin` (creates `db/` +
   schema).
8. Installs the five unit files (`deploy/systemd/*`) and the loopback
   firewall rule (`deploy/nftables/preview-dashboard.nft` →
   `/etc/preview-dashboard/`), `systemctl daemon-reload`.
9. Enables `preview-dashboard-firewall.service`,
   `preview-dashboard-admin.service` and `preview-dashboard-viewer.service`
   (`enable`, not `enable --now`), and enables+starts
   `preview-dashboard-purge.timer`.
10. Explicitly `restart`s the firewall, admin and viewer units in that
    order (H2, unit 12 audit): `enable --now` on an already-active unit is
    a no-op that would **not** apply new code/config on a re-run after
    `git pull` — this restart is what makes updates actually take effect.
    Then verifies each of the three has `NeedDaemonReload=no` and is
    active, failing the install otherwise.
11. Prints `systemctl status` and `systemd-analyze security` for review
    (target ≤ 2.0 per unit, C28).
12. Runs `deploy/check.sh` (M2, unit 12 audit): a further, read-only, live
    check of the actual running deployment — the nftables rule is loaded,
    a `nobody` process is refused on the gated ports, the apps refuse
    requests with no identity header, the units are current and active,
    the viewer's own mount namespace cannot read `/root` or the admin
    token, `systemd-analyze security` is ≤ 2.0, and Tailscale Funnel is
    off. Fails (non-zero exit) if any check fails. Some checks are no-ops
    before `tailscale up` + `deploy/tailscale/serve.sh` (step 2 below) have
    run — see the script's own output.

### 3. Verify

```bash
systemctl status preview-dashboard-admin preview-dashboard-viewer preview-dashboard-purge.timer
journalctl -u preview-dashboard-admin -u preview-dashboard-viewer -n 50
systemd-analyze security preview-dashboard-admin.service preview-dashboard-viewer.service
```

### 4. Front it with Tailscale (owner/operator action)

```bash
tailscale up   # enroll this host in the tailnet, if not already
sudo deploy/tailscale/serve.sh   # tailscale serve 443->8787, 8443->8788; verifies Funnel off
```

Merge `deploy/tailscale/acl-snippet.json` into the tailnet's policy file
(Tailscale admin console → Access Controls) to restrict the host to the
owner's identity, and tag the host `tag:pdash` (`tailscale up
--advertise-tags=tag:pdash`, or set it in the console).

### 5. Register the MCP server for Claude Code

Not yet written up here — tracked for unit 13 (`docs/security.md` C30: no
secrets and no `PDASH_INTAKE_*` vars in the MCP registration's env).

### Updating

```bash
git -C /path/to/checkout pull
sudo deploy/install.sh --owner-login owner@example.com --host my-host.tailXXXX.ts.net
```

Re-syncs `/opt/preview-dashboard`, `uv sync`s, and — since the unit 12 audit
(H2) — always explicitly restarts `preview-dashboard-firewall`,
`preview-dashboard-admin` and `preview-dashboard-viewer` at the end so the
new code actually takes effect (`systemctl enable --now` on an
already-active unit does *not* restart it, so without this the old code
would otherwise keep running indefinitely after every `git pull`). This
does interrupt an in-flight publish/edit the same way a manual
`systemctl restart preview-dashboard-admin` always could (C11); there is no
graceful drain. Run updates at a quiet time if that matters.

#### Upgrading to folders (schema 4, ADR 0027)

**TL;DR:** back up the DB first, let `install.sh` migrate and restart everything in one go; rolling back needs that backup.

| Step | Why |
|---|---|
| 1. **Back up the database** (`sqlite3 … ".backup '…'"`, see [Backups](#backups)) before `git pull` | Migration 4 (`folders` table + `items.folder_id`) is **forward-only**: there is no down-migration |
| 2. Run `deploy/install.sh` as usual | It runs `migrate` as `pdash-admin` (schema 3 → 4), then restarts firewall, admin and viewer together |
| 3. Expect the old viewer/purge to refuse the DB until restarted | Only the admin (or `migrate`) creates schema 4; viewer and purge never migrate and exit/fail with `schema is at version 4` while old code runs — a purge timer tick in that window just fails and runs again next hour |
| Rollback | Old code refuses a schema-4 database — see *Rolling back* below |

After the upgrade every existing item is **unfiled**; Claude files items with the folder MCP tools (`docs/api.md`).

**Rolling back.** Old code refuses a schema-4 database, so a rollback restores the step-1 backup:

1. Stop **every** role, not only the timer: `systemctl stop preview-dashboard-admin preview-dashboard-viewer preview-dashboard-purge.timer preview-dashboard-purge.service`.
2. Only once all of them are stopped, remove `db/items.sqlite3-wal` and `db/items.sqlite3-shm` — a leftover WAL from the schema-4 database must never be replayed against the restored (schema-3) file.
3. Copy the step-1 backup into `db/items.sqlite3` (`pdash-admin:pdash` 0660, C24).
4. Reinstall the old checkout and restart the services.

Two kinds of drift can follow a rollback, both expected, neither a corruption:

- **Forward orphans:** items published, edited or trashed after the backup are lost with the restore; their blobs (already on disk, written before the DB commit, C11) become orphans the next orphan sweep removes.
- **Reverse orphans:** if the purge job (or a new revision's pruning, ADR 0019) ran *between* the backup and the rollback, it may have deleted blobs that only the restored (older) rows still reference — after the restore those rows point at a blob that is already gone (a 404/410 serving that file, not a crash or a corrupt row).

To avoid the reverse case, stop `preview-dashboard-purge.timer` as soon as you take the backup (before `git pull`) and avoid trashing items or publishing new revisions until you are sure you will not roll back; both can delete blobs a pre-upgrade backup still depends on.

#### Upgrading to the Claudia inbox (schema 5, ADR 0031)

**TL;DR:** same procedure as schema 4: back up, run `install.sh`, roll back only by restoring that backup. The inbox and approvals themselves are **not** in this file: they live in the separate admin-only Claudia DB (above), created on the first admin start with `claudia_enabled`.

| Step | Why |
|---|---|
| 1. **Back up the database** before `git pull` (see [Backups](#backups)) and stop `preview-dashboard-purge.timer` | Migration 5 (columns `delivery_tasks.long_form`, `notifications.approval_id`) is **forward-only**; existing rows get the defaults (0 / NULL), nothing else changes |
| 2. Run `deploy/install.sh` as usual | It runs `migrate` as `pdash-admin` (schema 4 → 5) in one transaction: a crash leaves schema 4 intact and the next run retries |
| 3. Expect the old viewer/purge to refuse the DB until restarted | They exit/fail with `schema is at version 5` while old code runs; the next purge tick runs again |
| 4. Turning Claudia on later (`claudia_enabled = true`, restart admin) | The admin creates `claudia/claudia.sqlite3` (0700/0600, schema 1); no change to `db/` |
| Housekeeping | With Claudia on, purge also expires overdue approvals and deletes inbox messages older than 30 days and approvals that expired more than 30 days ago (`approvals_expired`, `inbox_deleted`, `approvals_deleted`, `inbox_failed` in the JSON report) |
| Rollback | Old code refuses a schema-5 database: follow *Rolling back* above with the step-1 backup (schema 4); old code never opens `claudia/`. Stop the admin and purge, then remove `claudia/` (or keep it for a later re-upgrade: it is self-contained). Pending approvals are lost (they expire after 600 s anyway) |
| Dev databases from before F-C1a | An unreleased build put `owner_messages`/`approval_requests` into `db/` at schema 5; those tables are now unused. Recreate a dev DB rather than migrating it |

### Uninstalling

```bash
sudo deploy/uninstall.sh                        # stop/disable/remove units + nft rule; keep all data
sudo deploy/uninstall.sh --purge-data            # also remove the DB, blobs, config and tokens
sudo deploy/uninstall.sh --purge-data --purge-users   # also remove every service account + group
```

`--purge-users` also removes `pdash-notify` and `pdash-notifytok` if the notifier was ever installed; `--purge-data` removes `telegram.token`/`notifier.token`/`notifier-admin.env` along with everything else under `/etc/preview-dashboard`.

## Telegram notifications (optional, N5)

**TL;DR:** Off by default. `sudo apt install acl`, then `sudo deploy/install.sh --telegram-chat-id <id> --telegram-token-file <path> ...` installs and enables the notifier; later re-runs keep it without the flags. On a host that never had it, nothing changes: no notifier user, unit, token or egress rule (docs/security.md C33/C38, ADR 0023).

### 1. Create the bot (BotFather)

1. Message [@BotFather](https://t.me/BotFather) on Telegram: `/newbot`, follow the prompts, save the token it gives you (looks like `123456789:AAAA...`) to a local file, e.g. `~/telegram-bot.token` — never paste it into a shell command that ends up in shell history unnecessarily long-term, and never commit it.
2. `/setjoingroups` → **Disable** (the bot must only ever be used in a private 1:1 chat with the owner; ADR 0021).
3. Do not message the bot yet — pairing (step 4 below) needs it unpaired.

### 2. Install with the notifier enabled

Prerequisite (owner action — `install.sh` never installs packages and refuses the notifier without it): the `acl` package.

```bash
sudo apt install acl
```

You need the owner's Telegram **chat id** for the first install. If you don't know it yet, a placeholder is fine — pairing (step 3) prints the real one, which you then set by hand:

```bash
sudo deploy/install.sh --owner-login owner@example.com --host my-host.tailXXXX.ts.net \
    --telegram-chat-id 1 --telegram-token-file ~/telegram-bot.token
```

This, on top of a normal install:
- Refuses up front (exit 1, nothing changed) if `setfacl` is missing, and (exit 2) if an existing `config.toml` already names a **different** `notify_owner_chat_id`.
- Creates system user `pdash-notify` (own primary group, **not** `pdash`) and group `pdash-notifytok` (members: `pdash-admin`, `pdash-notify` — the only shared access between them, scoped to `notifier.token` alone).
- Copies the bot token to `/etc/preview-dashboard/telegram.token` (`root:pdash-notify` 0640 — only the notifier ever reads it).
- Generates `/etc/preview-dashboard/notifier.token` (`root:pdash-notifytok` 0640).
- `config.toml`: a fresh install gets `notify_enabled = true` and `notify_owner_chat_id`; an **existing** file gets the missing key(s) added in place (`notify_enabled = false` is flipped to `true`; owner and mode kept; `deploy/lib/notify_config.py`). A matching chat id is left alone.
- Writes `/etc/preview-dashboard/notifier-admin.env` (`--notifier-peer-uid <uid> --token-group notifier=pdash-notifytok` for the admin unit) and runs `check-config` with `--token-group notifier=pdash-notifytok` too (scoped: that group is trusted for `notifier.token` only, ADR 0024).
- Installs and enables `preview-dashboard-notifier.service` and the nftables egress rules for `pdash-notify`'s uid (`deploy/nftables/notifier-egress.nft.in`: loopback DNS, then no tailnet/private/loopback/link-local/ULA destinations, then TCP 443 only; C38).
- The admin unit's `ExecStartPost` grants `pdash-notify` exactly two POSIX ACL entries: traverse on `/run/preview-dashboard`, read+write on `admin.sock`.

`--telegram-token-file` is optional: without it, the notifier is installed and enabled but not started; place the token yourself (`install -m 0640 -o root -g pdash-notify <file> /etc/preview-dashboard/telegram.token`), then `systemctl start preview-dashboard-notifier`.

**Re-runs** (e.g. after `git pull`) don't need the Telegram flags: once `pdash-notify` or the notifier unit exists, `install.sh` keeps the notifier installed and configured (env file, egress rules, token groups). It (re)starts the notifier only if `config.toml` has `notify_enabled = true` and `telegram.token` exists; with `notify_enabled = false` it stops and disables the unit. Removal is `deploy/uninstall.sh`.

### 3. Pair the bot with your chat

```bash
sudo systemctl stop preview-dashboard-notifier
sudo /opt/preview-dashboard/.venv/bin/preview-dashboard notify pair --token-group telegram=pdash-notify
# Send the printed /start <code> to your bot within 10 minutes.
sudo systemctl start preview-dashboard-notifier
```

`notify pair` prints the real chat id — if it differs from what you passed to `install.sh`, edit the `notify_owner_chat_id` line in `config.toml` by hand (install.sh never overwrites a chat id) and `systemctl restart preview-dashboard-admin preview-dashboard-notifier`. The notifier service must be stopped first (Telegram's `getUpdates` long-poll is single-consumer; a second poller gets HTTP 409).

### 4. Send a test alert

```bash
sudo /opt/preview-dashboard/.venv/bin/preview-dashboard notify test
```

Asks a two-option test question through the admin API (as root, no `--token-group` needed — it uses the admin token, not the notifier one) and prints the question id and a `preview-dashboard question wait <id>` command.

### 5. Owner messages for Claudia (ADR 0031; code M2, switch W1)

**TL;DR:** Off by default. `claudia_enabled = true` in `config.toml` (the only switch, no CLI flag) makes the notifier read your texts, approval taps and authenticator codes and deliver voice replies; restart the notifier after changing it. Off (or a missing/odd value), the bot reads button taps only, exactly as before.

- When on, `getUpdates` asks for `callback_query` **and** `message`; only your own private plain-text messages are accepted (docs/security.md C44); everything else is ignored silently (logged by update id only).
- A message that is just six digits is your authenticator code: it goes to the admin's code check and is **deleted from the chat** right after, whatever the result. A failed delete is retried with backoff for up to 47 h (in memory: a notifier restart forgets it); if it never works the bot sends "Failed: an authenticator code message could not be deleted…" — delete it yourself. Six-digit runs inside other text arrive as `[code redacted]`.
- A code message Telegram delivers twice is checked once; the second copy gets "That code was not checked…" (send a new code if you still need to approve).
- If the admin is down, a text is kept in Telegram and re-read with backoff (stored once, idempotent); a code is not retried — send a fresh one.
- Logs: `owner message <update id>: stored|duplicate`, `code message <update id>: accepted|refused|locked|duplicate`, never text or codes. Rollback: turn the switch off and restart the notifier (no data in the notifier).

### 6. Claudia token and TOTP step-up (ADR 0031, 0032, 0035; code M3, host M4)

**TL;DR:** `claudia_enabled = true` (config file only; needs `notify_enabled`) turns on `/v1/claudia/*` for a third token and the authenticator-code check. Create the token and the TOTP secret once, as root, on a terminal. The secret's group is `pdash-totp` (only `pdash-admin` in it), never the shared `pdash`.

```bash
# Claudia host token (only valid on /v1/claudia/*; must differ from the other two):
/opt/preview-dashboard/.venv/bin/preview-dashboard gen-token \
    --out /etc/preview-dashboard/claudia.token --group pdash-claudiatok
# TOTP secret group (admin only): install.sh (Claudia installed) creates pdash-totp, pdash-admin its only member.
# TOTP secret (refuses a non-TTY, non-root, an existing file without --rotate, or a shared group):
/opt/preview-dashboard/.venv/bin/preview-dashboard claudia totp setup --group pdash-totp
```

- `claudia totp setup` prints an `otpauth://` URI and the manual key (no QR library is installed); add it to your authenticator app and type one current code (3 tries). That code's step is first recorded as used in `<data_dir>/claudia/stepup-state.json` (admin-only dir, owned by the admin user), so it can never approve anything; only then is `totp_secret_file` written (0640, `root:<--group>`). A missing/unusable data dir or state file stops setup before any secret is shown. `--rotate` replaces an existing secret the same way (atomic rename) and keeps the current group unless `--group` is given.
- `--group` is checked before any secret is shown: not root, not the admin's primary group (`pdash`, shared with the viewer), `pdash-admin` must be a member, and nobody else may be. The written file must end up in that group, else it is removed.
- Admin unit flags: `--token-group claudia=pdash-claudiatok`, `--token-group totp=pdash-totp` (required with `claudia_enabled`; root, the admin's primary group and token groups are refused) and `--claudia-peer-uid <host uid>` (only that uid may call `/v1/claudia/*`). The viewer unit lists `totp.secret` in `InaccessiblePaths` (M9).
- Step-up state (replay mark, failures, lockout, the last 32 code messages of the last 24 h) lives in `<data_dir>/claudia/stepup-state.json` (0600, version 2; an M3 version 1 file is read once and upgraded on the next code). An older `<data_dir>/stepup-state.json` (+ `.lock`) is moved there once at admin start or `claudia totp setup`; if both locations hold a file it refuses until you remove the stale one as the admin user. 5 wrong codes in 15 min lock codes for 15 min, across restarts. A corrupt or loosely permissioned file refuses every code — fix or remove it as the admin user.
- Rotating from a `root:pdash` secret (pre-F-C1b): create `pdash-totp`, then `claudia totp setup --rotate --group pdash-totp`, add `--token-group totp=pdash-totp` to the admin unit, restart the admin.
- Every wrong code queues one `failed` alert "Wrong authenticator code" (never the code).
- `POST /v1/claudia/approvals` queues a Telegram prompt (the stored action text + Approve/Deny); after Approve the bot asks for the code. With no enabled channel it answers 503 and cancels the request (fail closed). A prompt whose request was decided, cancelled or expired before the notifier picked it up is never sent.
- `/stop` (host, M4) calls `POST /v1/claudia/approvals/cancel-open`; one request: `POST /v1/claudia/approvals/{id}/cancel` (close-only, ADR 0033).

### Token rotation

The notifier and Telegram tokens follow (the claudia token too: `gen-token --out …/claudia.token.new --group pdash-claudiatok`, `mv -f`, restart admin + Claudia host) the same procedure as the admin token (never overwritten in place):

```bash
# Telegram bot token: get a fresh one from BotFather (/revoke, /token), then:
install -m 0640 -o root -g pdash-notify /path/to/new-telegram.token.new /etc/preview-dashboard/telegram.token.new
mv -f /etc/preview-dashboard/telegram.token.new /etc/preview-dashboard/telegram.token
systemctl restart preview-dashboard-notifier

# Notifier token (admin <-> notifier only, never leaves the host):
/opt/preview-dashboard/.venv/bin/preview-dashboard gen-token \
    --out /etc/preview-dashboard/notifier.token.new --group pdash-notifytok
mv -f /etc/preview-dashboard/notifier.token.new /etc/preview-dashboard/notifier.token
systemctl restart preview-dashboard-admin preview-dashboard-notifier
```

### Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Notifier won't start: `ConditionPathExists` not met | `telegram.token` or `notifier.token` missing | `systemctl status preview-dashboard-notifier` shows "start condition failed"; create the missing file (above), then `systemctl start` |
| Any process refuses a token file with "carries a POSIX ACL" | a `setfacl` grant was left on `admin.token`/`notifier.token`/`telegram.token` itself (not the admin socket) — it can grant access invisible in the file's mode bits | `getfacl <file>`, then `setfacl -b <file>` to strip it; the admin socket's own ACL grant (above) is unaffected |
| Notifier logs "admin socket cannot be trusted" / check.sh: "pdash-notify cannot open the admin socket" | the ACL grant on `/run/preview-dashboard` didn't apply (`setfacl` removed, ACLs off on `/run`, or the socket took > 30 s to appear) | `journalctl -u preview-dashboard-admin` names the reason; `getfacl /run/preview-dashboard /run/preview-dashboard/admin.sock` as root should show `user:pdash-notify` on both; `apt install acl` if needed, then `systemctl restart preview-dashboard-admin preview-dashboard-notifier` |
| `install.sh` stops: "needs setfacl (package 'acl')" | the notifier is requested or already installed, `acl` is not | `sudo apt install acl`, re-run |
| `install.sh` stops: "already has notify_owner_chat_id = …" | `--telegram-chat-id` differs from `config.toml` | edit the line by hand (or pass the matching id), re-run |
| `notify pair` fails with "another process is polling this bot" | `preview-dashboard-notifier` is still running | `systemctl stop preview-dashboard-notifier` first |
| No alerts arrive | `notify_enabled`/`notify_owner_chat_id` wrong, notifier not active, or the nft egress rule missing | `preview-dashboard check-config`; `systemctl status preview-dashboard-notifier`; `deploy/check.sh` (checks the nft rule and token files) |
| Alerts arrive but taps do nothing | wrong chat id paired, or the bot was added to a group (disabled in step 1) | re-run `notify pair`; confirm the chat is a private 1:1 with the bot |

Live verification: `sudo deploy/check.sh` covers the notifier (only when `notify_enabled = true`): the service is active and runs as `pdash-notify`, both token files have the right owner/mode, `pdash-admin` cannot read `telegram.token`, the nft egress rules are loaded (tailnet/private refusal before the 443 accept), `pdash-notify` can open the admin socket (ACL), and the notifier token sent as root on `/v1/health` gets 403, next to a same-uid control that gets through. The admin-token-on-`/v1/notifier/*` direction is proven by the pytest suite instead of a live probe, so the admin token is never handed to a process running as `pdash-notify`. Tokens only ever go to curl on stdin, never on argv — see `docs/security.md` C33/C34/C36/C38.

## Backups

Back up `/var/lib/preview-dashboard/` (SQLite DB + blobs) as a unit — a backup taken mid-write could capture a DB row without its blob or vice versa; prefer a filesystem snapshot, or a consistent DB copy paired with a blob-directory copy taken while writers are quiesced. `staging/` can be excluded from backups (see the layout table above): it never holds anything but in-flight writes, so restoring without it is harmless. Backups stay on the host, mode 0600, and are treated as sensitive as the data itself (C29). Not yet automated; revisit once traffic patterns are known.

For the database file itself (`db/items.sqlite3`), don't `cp` it directly
while a process might be writing (WAL mode means the live state can be
split across `items.sqlite3` and `items.sqlite3-wal`); use one of:

- `sqlite3 /var/lib/preview-dashboard/db/items.sqlite3 ".backup '/path/to/backup.sqlite3'"`
  — SQLite's own online backup API, safe against concurrent writers, produces
  a single self-contained file (no separate `-wal`/`-shm` to copy).
- `sqlite3 /var/lib/preview-dashboard/db/items.sqlite3 "VACUUM INTO '/path/to/backup.sqlite3'"`
  — also online-safe, and additionally compacts the copy (smaller backup,
  no freed-page slack); costs more I/O on a large database than `.backup`.

Either way, `chmod 0600` the resulting file immediately (both commands
create it with the process's default mode, not necessarily 0600) before
it's copied anywhere else, per C29. When restoring it into `db/`, set it
back to `pdash-admin:pdash` 0660 (C24) or the services refuse to start.

The Claudia DB (`claudia/claudia.sqlite3`, ADR 0034) is backed up the same
way, as `pdash-admin`, and restored as `pdash-admin` 0600 inside the 0700
`claudia/` directory (anything looser is refused). It holds owner messages,
so treat its backups like the data itself (C29).

## Registering the MCP server (unit 13; server implemented, unit 10)

Claude Code starts `preview-dashboard-mcp` itself over **stdio** (never networked). Register it once, user scope, **with no `env` block**:

```sh
claude mcp add --scope user preview-dashboard -- /opt/preview-dashboard/.venv/bin/preview-dashboard-mcp
```

| Rule | Why |
|---|---|
| No `--env`/`-e`, no `PDASH_*` at all (incl. `PDASH_CONFIG`, `PDASH_INTAKE_*`) | Intake policy and limits come only from the root-owned `/etc/preview-dashboard/config.toml` (C16/C17/C30); env in the registration is what an injected agent could edit. **Enforced, not just recommended:** the server refuses to start (one stderr line, exit 1) if `os.environ` has any `PDASH_*` key other than `PDASH_CONFIG` when it runs (`_stray_pdash_env_vars`/`main`, unit 10b M1) — a real registration should still set none at all, `PDASH_CONFIG` included |
| No token anywhere in the registration or `.claude.json` | The server reads `admin_token_file` itself at startup, with the same checks as the admin API (C12), but only after first verifying the admin socket itself is trustworthy (`interfaces/mcp/admin_socket.verify_admin_socket`, unit 10b M1) |
| No arguments | The server takes none and refuses to start if given any |

What the server needs on the host:
- Read access to `admin_token_file` (`root:pdash` 0640; as root it also trusts whatever group actually owns the admin socket, derived at runtime rather than hardcoded — ADR 0017 amendment "G") and to the admin socket (`/run/preview-dashboard/admin.sock`, 0660).
- `/proc` mounted (intake checks mount ids via `/proc/self/fdinfo`, fail closed otherwise).
- Files to publish written under an `intake_allowed_roots` entry (default `/root/outbox`).

Startup failures (insecure config/token file, missing token) exit 1 with a one-line reason on **stderr**; stdout carries only MCP protocol messages. Logs (stderr, captured by Claude Code) record tool outcomes, item ids, file counts and error messages (which may name a refused file) — never the token, titles/descriptions, or file contents.

Check: `claude mcp list` shows `preview-dashboard` connected; `claude mcp get preview-dashboard` shows no env vars.

## Troubleshooting (planned)

| Symptom | Likely cause | Check |
|---|---|---|
| Viewer returns 403 for the owner | `owner_login` misconfigured, or Tailscale identity header missing | `journalctl -u preview-dashboard-viewer`, confirm `Tailscale-User-Login` is forwarded |
| Items never leave trash after 14 days | Purge timer not firing | `systemctl status preview-dashboard-purge.timer`, `journalctl -u preview-dashboard-purge`; to free the space now, empty the trash (`dashboard_empty_trash` or `preview-dashboard empty-trash`, permanent, ADR 0030) |
| MCP tool error "admin API unreachable" | Admin service down or socket not accessible | `systemctl status preview-dashboard-admin`, socket perms (0660) |
| MCP tool error "intake refused (<code>)" | The source path broke an intake rule (C10); the message names the rule/character | Copy the files under `intake_allowed_roots`, rename as suggested; see `docs/api.md` intake codes |
| MCP server not connected in Claude | Startup refused (config/token checks) | Run `/opt/preview-dashboard/.venv/bin/preview-dashboard-mcp < /dev/null` as root and read the stderr line |
| Preview content looks broken | CSP/sandbox headers stripped by a proxy | Confirm `tailscale serve` isn't rewriting response headers |
| Publish rejected with "matches secret rule '<label>'" | Content, title, description or a file name matched the admin secret scan (C15) | Redact the sample; there is no bypass (ADR 0008). The message names the rule label and file, never the secret |
| Publish rejected: "rate limit", "quota", "budget", "free disk", "timed out" | `publish_rate_per_hour`, `max_items`/`max_total_bytes` (trashed items count until purged), per-file/per-item limits, `min_free_disk_bytes`, `publish_timeout_seconds` (C18, C11) | Wait for the hourly window, empty the trash / let purge run, or raise limits in the root-owned TOML (`orphan_grace_seconds` must stay > `publish_timeout_seconds`) |

## Claudia

**TL;DR:** `sudo deploy/install.sh … --telegram-chat-id ID --claudia` installs the companion (ADR 0031, deployment ADR 0036) but leaves it **off**. You turn it on: log in to Claude Code as root, run `claudia totp setup`, set `claudia_enabled = true`, re-run install.sh. The host and the weekly gardener run **as root** (they use your root subscription login); the host is not sandboxed — its safety comes from its own checks (docs/security.md C49–C52, C59/C60). Run install.sh from your own terminal (never from Claudia), and restart the viewer after rotating `totp.secret` or `claudia.token`.

### Units

| Unit | Runs as | What | Notes |
|---|---|---|---|
| `claudia-host.service` | `root`, group `pdash-claudiatok` | `python -I -m preview_dashboard.interfaces.claudia.main` | Inbox → screened `claude -p --resume` turns. `Restart=on-failure`, `KillMode=control-group` (`/stop` and a stop kill every run, C58), `UnsetEnvironment=` the API-key variables (C49). Skipped until `claudia.token`, `claudia-settings.json`, `claudia-mcp.json` and `totp.secret` exist |
| `claudia-gardener.service` | `root` (no capabilities), group `pdash-kb` | `python -I -m preview_dashboard.interfaces.claudia.gardener` | One KB pass (C54); writes only `/var/lib/claudia-kb` and `~/.claude` |
| `claudia-gardener.timer` | — | weekly, Sunday ~04:00 (±30 min), `Persistent=true` | Enabled with the host |

### Groups, files, directories

| Path / group | Owner:group | Mode | Who / why |
|---|---|---|---|
| group `pdash-claudiatok` | members: `pdash-admin` | — | admin verifies `claudia.token`; the host holds it as unit `Group=` (C45) |
| group `pdash-totp` | members: `pdash-admin` **only** | — | the TOTP secret's group (C47, S-C1 S2) |
| group `pdash-kb` | no members | — | KB read group; only the viewer unit has it (`SupplementaryGroups=`). Created on every host |
| `/etc/preview-dashboard/claudia.token` | `root:pdash-claudiatok` | 0640 | `gen-token` on first install, never overwritten |
| `/etc/preview-dashboard/totp.secret` | `root:pdash-totp` | 0640 | **you** create it (below); install.sh never does |
| `/etc/preview-dashboard/claudia-settings.json` | `root:root` | 0644 | copy of `deploy/claudia/settings.json` (C50 deny rules + C59/C60 hook), replaced every run |
| `/etc/preview-dashboard/claudia-mcp.json` | `root:root` | 0644 | from `deploy/claudia/mcp.json.in`: dashboard MCP (no args/env; Telegram tools disallowed by the host, C51) + `claudia-kb` pinned to the KB with the `pdash-kb` gid |
| `/etc/preview-dashboard/claudia.env` | `root:root` | 0644 | `PDASH_CLAUDE_BIN` (`--claude-bin`, default `/root/.local/bin/claude`), `PDASH_KB_GID` |
| `/etc/preview-dashboard/claudia-admin.env` | `root:root` | 0644 | admin args: `--claudia-peer-uid 0 --token-group claudia=pdash-claudiatok --token-group totp=pdash-totp` |
| `/var/lib/claudia-kb/` | `root:pdash-kb` | 0750 (files 0640) | knowledge base; viewer `ReadOnlyPaths=` (C57); admin masks it |
| `/var/lib/claudia-host/` (+ `work/`, `voices/`) | `root:root` | 0700 | host state, audit log, run cwd, voice models |
| `/var/lib/preview-dashboard/claudia/` | `pdash-admin` | 0700 | admin-only Claudia DB (ADR 0034) |
| `/var/lib/preview-dashboard/claudia-view/` | `pdash-admin:pdash` | 0750 | sanitized pending-approvals snapshot the viewer may read (M5b writes, M8 reads); viewer read-only via group `pdash`, never masked |
| `/var/lib/preview-dashboard/voice/` | `pdash-admin:pdash` | 0700 | voice notes waiting for delivery; pre-created so the viewer mask applies |
| `/run/claudia-host/` | `root` | 0700 | host runtime dir (C59 hook control socket) |
| `/opt/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook` | `root:root` | 0755 | C59/C60 hook; install.sh stops if it's missing |

Dirs inside `/var/lib/preview-dashboard` (`blobs/`, `staging/`, `claudia/`, `voice/`, `claudia-view/`) are created and fixed **as `pdash-admin`**, never by root, and must then stat as exactly that directory; a symlink or non-directory there stops install.sh (fix it by hand). Reused groups `pdash-kb`, `pdash-claudiatok`, `pdash-totp` with any member beyond the table above (primary-group users included) also stop it.

| Unit | Masks (`InaccessiblePaths=`) |
|---|---|
| viewer | Claudia DB dir (incl. `stepup-state.json`), `voice/`, `/var/lib/claudia-host`, `totp.secret`, `claudia.token` |
| notifier | `totp.secret`, `claudia.token`, the KB |
| gardener | the whole data dir, `/var/lib/claudia-host`, `totp.secret`, `claudia.token`, `notifier.token`, `telegram.token` |
| host (advisory: root can undo it) | `totp.secret`, `notifier.token`, `telegram.token` |

A file mask disappears when the file is replaced by rename, and a `-` path that didn't exist at start is skipped. So **restart the viewer** (`systemctl restart preview-dashboard-viewer`, or re-run install.sh) after `claudia totp setup --rotate` or a `claudia.token` rotation; `check.sh` fails until you do. `stepup-state.json` lives inside the masked `claudia/` dir (owner + 0600 mode also checked).

### Turn it on (owner steps)

```bash
sudo deploy/install.sh --owner-login … --host … --telegram-chat-id ID --claudia   # installed, off
sudo /root/.local/bin/claude          # log in with the subscription as root (never an API key)
sudo /opt/preview-dashboard/.venv/bin/preview-dashboard claudia totp setup --group pdash-totp
sudo editor /etc/preview-dashboard/config.toml   # claudia_enabled = true
                                                 # kb_root = "/var/lib/claudia-kb" (knowledge map)
                                                 # claudia_approvals_snapshot = "/var/lib/preview-dashboard/claudia-view/pending-approvals.json"
sudo deploy/install.sh --owner-login … --host …  # enables + starts the host and the timer
sudo deploy/check.sh
```

- Off again: `claudia_enabled = false`, re-run install.sh (host + timer disabled and stopped). Emergency: send `/stop`, or `systemctl stop claudia-host`.
- Run install.sh from **your** terminal. It refuses to run inside `claudia-host.service` (its admin restart would restart the host and kill the script before its checks); if Claudia must run it, use a separate scope (`systemd-run --scope …`).
- The host refuses to start (exit 2, journal names the reason, never a value) with an API-key variable set, unsafe settings / a hook switched off in any settings source, or an unsafe token / socket.
- **Your coding-session rules don't reach her (F-CL1):** her runs, the screen and the gardener run with `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` and `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` (set by the host, no unit change), so `/root/.claude/CLAUDE.md`, project CLAUDE.md files and auto memory are not loaded; she still uses root's subscription login. She tells you things only in her reply: if she tries the dashboard MCP server, the `preview-dashboard` CLI or the admin socket herself, the hook denies it (`dashboard_bypass` in the audit log).
- **Her tone (F-CL2):** every run gets `/var/lib/claudia-kb/persona.md` after the host rules (friendly, upbeat, 1–3 emojis, tone only). Edit it by hand as root (≤ 4 KiB, no invisible/bidi characters, HTML comments are dropped), then **restart `claudia-host`**: the file is pinned by SHA-256 at host start, so a changed file (a hand edit before the restart, or her Bash writing it) makes runs go without the persona and sends one `failed` alert ("persona.md changed since host start; restart claudia-host after a hand edit"). Writing under `/var/lib/claudia-kb` with Bash or Write needs your approval (C59). Deploy never overwrites the live copy: after an update that changes the seed, copy `src/preview_dashboard/application/claudia/prompts/seed/persona.md` over it yourself. An invalid or missing file → she runs without it and the journal says `persona not used (<reason>)`.
- **Progress pings (F-CL2):** while she works on your message you may see "👀 On it…" (after ~20 s) and "⏳ Still working… 5 min" / "… 10 min" (at most 3, fixed host texts, text only); they stop the moment the run ends, before her reply, and on `/stop`. A ping is skipped once the hour has ≥ 110 replies/pings or when this message's remaining replies would no longer fit after it, so her answer always gets through.
- **Links in her replies** show defanged (`github[.]com/owner/repo`, no `https://`): replies may carry no web address (C35/C56), so the host rewrites them instead of losing the reply.

### Voice replies (optional)

`--voice-models DIR` copies `es_MX-claude-high` and `en_US-amy-medium` (`.onnx` + `.onnx.json`) into a root-only staging dir (`/var/lib/claudia-host/voices.incoming`), checks **the copies** against the SHA-256 hashes in `deploy/claudia/voices.sha256` (copies deleted on a mismatch), then moves them to `/var/lib/claudia-host/voices` (0600), and adds the `claudia-voice` extra (Piper, GPL-3.0, runtime only). Every later run re-checks the installed models and stops on a mismatch. All four hashes are pinned (verified against Hugging Face `rhasspy/piper-voices` on 2026-11-09; licences: es_MX-claude-high apache-2.0, en_US-amy-medium per its MODEL_CARD, MycroftAI/mimic3-voices); install.sh never downloads, so fetch the four files yourself into DIR. Without the flag no voice is installed. The extra has upper bounds and CI runs pip-audit on it (locked export).

### Live checks (`deploy/check.sh`, only with `claudia_enabled = true`)

Host + timer active; no API-key variable in the host unit or its running process; owners/modes of every file above (incl. `claudia-view/` 0750 and `claudia/stepup-state.json` admin 0600); exact members of `pdash-totp` and `pdash-claudiatok` (`pdash-admin` only) and `pdash-kb` (none); the notifier can't read `totp.secret`; inside the viewer's mount namespace: KB readable and on a read-only mount (`findmnt`), `claudia-view/` readable, Claudia DB dir / `totp.secret` / `claudia.token` unreadable, and every viewer mask actually mounted (`findmnt --task`). A `WARN:` (not a failure) appears when `claudia_approvals_snapshot` is unset: the viewer's approvals panel then says "can't be checked".

### Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| `claudia-host` "start condition failed" | `totp.secret` (or another input) missing | run `claudia totp setup --group pdash-totp`, re-run install.sh |
| Host exits 2 | refusal at start (C49/C50/C59/C45) | `journalctl -u claudia-host` names the variable / file / rule |
| install.sh: "needs the Telegram notifier" | `--claudia` without `--telegram-chat-id` on a host without the notifier | add the notifier first |
| install.sh: "…claudia-hook is missing" | code without the M5a hook installed | update the checkout, re-run |
| Every run refused, `failed` alert "settings, hook or MCP config check failed" (C59 preflight; the reason is not logged) | (a) the hook script or a pinned module (`interfaces/claudia/hook.py`, the package `__init__` files) changed while the host ran; (b) a new, bad or unlistable file in `/etc/claude-code/managed-settings.d/` (listed again before each run); (c) a settings source with a broad allow rule: a shell, interpreter or wrapper (`Bash(env:*)`) or Edit/Write over `/`, `/root`, `/etc`, `/opt` | (b)/(c): fix the file, no restart needed. (a) after your own update: `systemctl restart claudia-host` (re-pins); otherwise treat it as tampering and check the files first. A restart runs the start checks, which name the file and rule (exit 2) |
| Gardener fails | `claude` not logged in as root, or its state outside `~/.claude`/`~/.cache` | `journalctl -u claudia-gardener` |
| Knowledge map empty | `kb_root` not set in `config.toml`, or the viewer was started before the KB dir existed | set it, `systemctl restart preview-dashboard-viewer` |
