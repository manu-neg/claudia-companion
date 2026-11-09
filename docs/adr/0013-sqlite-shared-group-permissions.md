# ADR 0013: Shared service group for the SQLite database

**TL;DR:** Admin and viewer both write the SQLite DB, so they share a group `pdash`: `db/` is 2770 (setgid), DB files are 0660, both services run with `UMask=0007`. `connect()` creates entries with those exact modes and refuses anything looser (world bits, a foreign writable group, an untrusted owner, symlinks, or a swap during connect).

## Context

- The admin (publish, purge) and the viewer (trash/restore) run as different users (`pdash-admin`, `pdash-viewer`, C28), and both need write access to the database and its `-wal`/`-shm` sidecars. Readers of a WAL database also need write access to `-shm`.
- The first version created the DB file 0600 and left existing permissions alone. 0600 locks the viewer out, and an existing file with world bits (say, a restored backup) was silently accepted.
- A DB file that other users can read leaks item metadata. One that other users can write lets them plant rows that point at arbitrary blobs, or rows the viewer would render.

## Decision

- **Group model:** one service group, `pdash`, holds both service users. `db/` is `pdash-admin:pdash` 2770. setgid is set so the sidecars SQLite creates inherit `pdash`. DB files are 0660. `UMask=0007` in both units.
- **Creation:** `db/` and the DB file are created relative to a directory fd (`O_EXCL|O_NOFOLLOW` for the file), `fchown`-ed to `trusted_gid`, then `fchmod`-ed. The result doesn't depend on the umask and never goes through a symlink.
- **Validation (fail closed):** the data dir, `db/`, the DB file, `-wal` and `-shm` are refused if any of these holds:
  - it is a symlink or the wrong type
  - its owner is not in `trusted_uids`
  - it has any world bit (for the data dir, only world-writable counts)
  - it is group-writable and the group is not `trusted_gid`

  Existing entries are validated but never chmod-ed.
- **Swap detection:** `db/` is opened `O_DIRECTORY|O_NOFOLLOW` and kept open. After `sqlite3.connect`, the `(st_dev, st_ino)` of `db/` and of the DB file must still match what was validated.
- **No fds on DB files:** files are checked with `lstat` through the `db/` fd and never opened by us. On Linux, closing *any* fd on a file releases every POSIX lock the process holds on it. That would silently break SQLite connections in other threads: we saw `SQLITE_PROTOCOL` and lost writes in testing.
- **Wiring:** `connect(db_path, *, trusted_uids, trusted_gid)` takes these values from `bootstrap.py`. The admin trusts its own uid. The viewer trusts both the admin and viewer uids. There is no new config setting.

## Consequences

- Anything in the `pdash` group can read and write the DB. Group membership is therefore part of the trust boundary: only the two service users may be members.
- Blobs are unaffected: they stay admin-owned and not group-writable (C25). The viewer only reads them.
- A restored backup or a manual copy must be put back as `pdash-admin:pdash` 0660, or services refuse to start (docs/operations.md).
- A process that is not a member of `trusted_gid` cannot create the DB. It fails with `UnsafeDatabasePathError` instead of creating files owned by the wrong group.
