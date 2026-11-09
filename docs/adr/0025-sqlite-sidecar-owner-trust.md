# ADR 0025: Trust the viewer's uid for the DB's `-wal`/`-shm` only; storage refusals are 503

**TL;DR:** The admin (and purge, `migrate`) now accept `-wal`/`-shm` owned by the viewer's uid (`--trusted-sidecar-uid`, from `/etc/preview-dashboard/viewer-uid.env`) — never the DB file or directories, which stay C24-strict. `UnsafeDatabasePathError` becomes a `StorageUnavailableError` (server-side, 503 + `Retry-After: 5`) instead of a `ValidationError` (400 `invalid_input`). Fixes backlog G2.

## Context

- Incident 2026-09-27 08:06:42–44: three admin long-polls failed with `UnsafeDatabasePathError -> 400` ("database -wal file is owned by an untrusted uid"); the notifier round and `question wait` failed; self-healed 14 s later.
- Root cause (confirmed, `tests/integration/test_sqlite_sidecar_trust.py::TestReproduction`): every repository call opens and closes its own connection, and SQLite deletes `-wal`/`-shm` when the last connection closes. Whichever process opens the DB next recreates them **as its own uid**. When the viewer (`pdash-viewer`, a legitimate DB writer, ADR 0013) got there first, the admin's trust set (its own euid only) refused every connection until the viewer closed. Purge and an upgrade-time `migrate` (viewer still running) hit the same race.
- The viewer's trust set already includes the admin's uid, so the reverse direction never failed.
- The refusal surfaced as 400 `invalid_input`: clients (notifier, `question wait`) treated a server-side condition as their own bad input.

## Decision

- **Sidecar-only trust.** `connect(..., trusted_sidecar_uids)`, `StorageTrust.sidecar_uids`, CLI `--trusted-sidecar-uid UID` on `serve-admin`, `purge`, `migrate`. Those uids may own `-wal`/`-shm`; mode/type/group checks are unchanged. Data dir, `db/` and the DB file still accept only `trusted_uids`.
- **Deploy:** `install.sh` writes `PDASH_VIEWER_UID` to `/etc/preview-dashboard/viewer-uid.env` (root 0644) and passes it to `migrate`. Admin and purge units load that env file (required) and pass `${PDASH_VIEWER_UID}` braced, so if it is missing the value is `""`, which the CLI rejects (exit 2): fail closed.
- **Error class:** new `domain.errors.StorageUnavailableError`; `UnsafeDatabasePathError` derives from it. Admin API maps it to 503 `storage_unavailable` + `Retry-After: 5`, logged at WARNING; the viewer does the same (503 `service_unavailable` + `Retry-After: 5`, WARNING; G4). Clients already retry 5xx (`question wait`, notifier runner).
- **Why this is safe:** `db/` is `pdash-admin:pdash` 2770 and the DB file is 0660, so the viewer can already write the DB and create/unlink entries in `db/`. A viewer-owned sidecar grants it nothing new. Owning a file lets you `chmod` it, but `db/` grants others nothing, so they can't reach the file anyway. Other uids (root, any future `pdash` member) are still refused.

## Alternatives rejected

- **Admin holds one long-lived connection** so the sidecars never disappear: this doesn't cover admin restarts (the viewer may create them while the admin is down), purge or `migrate`. It also adds process-lifetime state, and a keeper connection's POSIX locks are fragile (C24 notes on fd closes).
- **Retry once internally:** this only narrows the window, and a retried refusal would still be a 400.
- **Trust any owner in `pdash`:** that would make the owner check depend on group membership, which is NSS state and not explicit. An explicit uid mirrors the viewer's `--trusted-owner-uid`.

## Consequences

- Needs a redeploy (`install.sh`: new env file, admin/purge unit changes). Without the env file the admin and purge refuse to start. Running old units with new code keeps the old behaviour (flag absent = euid only).
- A persistent C24 refusal (e.g. a DB file restored with the wrong owner) is now a 503 on every request instead of a 400. It is still fail-closed, now with a WARNING log line.
