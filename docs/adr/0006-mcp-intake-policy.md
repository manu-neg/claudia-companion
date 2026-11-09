# ADR 0006: MCP publish-intake policy (advisory layer)

**TL;DR:** The MCP server enforces a narrow source-root allowlist, a case-insensitive secret denylist, TOCTOU-safe regular-file opens, and hard limits before any local file reaches the admin API. Because Claude runs as root, this is an *advisory* layer; the enforcing layer is the admin-side content secret scan (ADR 0008). Env vars may only narrow the policy.

## Context

Claude publishes content by calling MCP tools, which can be pointed (deliberately or via prompt injection) at arbitrary local paths. A naive "publish this path" tool would let an injected instruction exfiltrate `~/.ssh`, cloud credentials, or the admin token into the dashboard. Claude Code runs as **root** on this host: a capable injected agent could read files itself and call the admin API directly, so no check inside the MCP process can be a hard boundary.

## Decision

1. **Allowlist** (`intake_allowed_roots`, default only `/root/outbox`). Config load rejects `/`, `/root`, `/etc`, `/home`, `/var`, `/usr`, anything under `/proc` `/sys` `/dev`, and any root that contains or is inside `/root/.ssh`, the token/config directory, or `data_dir`.
2. **Denylist** (`intake_denied_patterns`): a built-in list (dirs like `.ssh`, `.aws`, `.git`, `.claude`, `.config/gh`; files like `.env*`, `*.pem`, `id_*`, `*.tfstate*`, `*.sqlite*`, …) that is a floor no config can remove. Matching is NFC + casefold, per resolved component; patterns with `/` match consecutive components (`docs/security.md` "Intake denylist semantics").
3. **Safe opens:** walk from the root fd with `dir_fd` + `O_NOFOLLOW|O_DIRECTORY`, final `O_NOFOLLOW|O_NONBLOCK`, `fstat` must be a regular file with `st_nlink == 1`, read only from that fd (C27).
4. **Limits:** `max_files`, `max_file_bytes` ≤ `max_item_bytes`, free-disk floor; global quota and rate limit enforced again in the core (C18).
5. **Env narrow-only:** `PDASH_*` env can only shrink the allowlist, add patterns, and tighten limits; widening needs the root-owned TOML (C16, C17). The MCP registration carries no `PDASH_INTAKE_*` vars (C30).

The admin API accepts only bytes, never paths, and scans every byte for secrets (ADR 0008).

## Consequences

- Stops accidental and naive injected exfiltration cheaply; honest about not stopping a capable root-level agent (`docs/security.md` Known limitations).
- The allowlist is the primary control and is kept tiny; the denylist is best-effort.
- Publishing from elsewhere requires copying into `/root/outbox` or an explicit TOML change — never a runtime bypass.
- Future hardening: run the MCP server as a dedicated non-root user with read-only access to the outbox, turning intake into an OS-enforced boundary.

## Amendment (unit 10a): implementation refinements

- **Whole-publish rejection:** inside a directory bundle, any symlink, FIFO/socket/device, hardlinked file, denylisted name or invalid relpath rejects the entire publish (never silently skipped), so the agent learns exactly what to fix and nothing is half-published.
- **No auto-rename:** names failing `validate_relpath` are reported with the exact character (`U+0025 PERCENT SIGN`) or segment rule and a rename suggestion; renaming silently would break references inside HTML bundles.
- **Root resolution:** each configured root is `realpath`-resolved per request, then opened by walking from `/` with `O_NOFOLLOW` per component; requests match the configured *or* resolved root per component (`is_relative_to`, never `startswith`). The denylist also covers the resolved root's own components.
- **Extra checks beyond C27:** `lstat` before `open` (FIFOs/devices are never opened), `fstat` dev/ino must equal the `lstat` result (swap detection), same `st_dev` as the root (no filesystem crossing), reads via `pread` of exactly the `fstat` size (growth or shrink aborts).
- **fd ownership:** `collect()` returns an `IntakeBundle` holding one open fd per file (no directory fds); the caller must close it (context manager).

## Amendment (unit 10b): follow-up hardening

- **Resolved roots re-validated:** config load checks roots lexically only; a root that is (or sits under) a symlink could point at `/`, `/etc` or the data dir. Each request now re-applies the config rules (`config.check_intake_root`, shared, one implementation) to the realpath-resolved root, against the sensitive paths both as configured and resolved. A failing root refuses only the requests that land in it (`outside_roots`).
- **Mount ids, not just `st_dev`:** `st_dev` can't see a bind mount of the same filesystem (e.g. `/root/.ssh` bind-mounted into the outbox). Every opened dir/file fd must share the root fd's `mnt_id` from `/proc/self/fdinfo/<fd>`; if it can't be read, intake fails closed (`filesystem_boundary`). The `st_dev` check stays as a second signal.
- **Request hygiene:** unpaired surrogates (no real file name; the OS layer would re-encode them) and paths deeper than 64 components are `invalid_request`; OS errors while listing, `fstat`ing or reading map to `unreadable` instead of escaping raw.
- **Denylist floor extended** (PuTTY/Apple keys, GCP service-account JSON, OAuth `token.json`, Docker/S3/boto/Terraform/rclone/1Password configs, `.gitconfig`); known false positives are documented in `docs/security.md`, with no override.
