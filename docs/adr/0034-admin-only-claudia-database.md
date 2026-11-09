# ADR 0034: Claudia's inbox and approvals in an admin-only SQLite file

**TL;DR:** `owner_messages` and `approval_requests` move out of the shared, viewer-writable item DB into `data_dir/claudia/claudia.sqlite3` (dir 0700, file 0600, admin uid only, own schema 1). Review S-C1 S1, unit F-C1a.

## Context
- The item DB is shared-group (ADR 0013): the viewer writes it (trash, pin, prune). Migration 5 (unreleased) put Claudia's tables there, so a compromised viewer could forge an APPROVED/CONSUMED approval or an owner message (C46/C47/C44, C28).
- The outbox's `pending()` joined `approval_requests` to decide whether an approval prompt is still live (ADR 0033).

## Decision
- New module `adapters/sqlite/claudia_db.py`: `connect_claudia(path, create=…)` validates the data dir (owner = admin, no group/other write), `claudia/` (real dir, owner = euid, no group/other bits) and the file and `-wal`/`-shm` (regular, owner = euid, 0600 or stricter, exactly one link), re-checks dir + file inodes after connecting, applies the same pragmas, then migrates (`create=True`) or requires schema 1 (`create=False`). Nothing is ever chmod-ed "back"; a looser entry is refused.
- Only the admin role, with `claudia_enabled`, creates it. Purge opens it (`create=False`) only when Claudia is on; the viewer core has no code path to it (systemd `InaccessiblePaths` for the viewer: M9).
- Migration 5 of the item DB keeps only `delivery_tasks.long_form` and `notifications.approval_id`.
- No cross-file JOIN: `SqliteNotificationOutbox(…, approvals=ApprovalStore)` looks a prompt's request up per row. None / unknown / tampered → settled unsent; storage error → held until the next poll (never sent blind, never blocks other alerts).
- `apply_migrations(conn, steps)` is the shared engine; both DBs refuse a schema newer than the code (S8).

## Consequences
- The viewer can no longer reach approval or inbox rows, even with full control of its own process.
- Two files to back up; a rollback of Claudia restores (or deletes) `claudia/` separately from `db/`.
- An approval prompt costs one extra connection per due prompt in `pending()` (rare, small).
- Purge without Claudia no longer touches inbox housekeeping at all (`inbox_failed` stays false).
