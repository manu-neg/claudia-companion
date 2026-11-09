# ADR 0004: SQLite for metadata, filesystem for blobs

**TL;DR:** Item metadata and state live in a single SQLite database (WAL mode); file bytes live as plain files on disk, written atomically and referenced by generated ID. No object storage, no separate DB server.

## Context

This is a single-host, single-owner application with modest scale (limits: 500 files/item, 100 MiB/file, 500 MiB/item). It needs transactional metadata updates (state transitions, pin order) and needs to serve large files (video) efficiently, including HTTP Range requests. Operational simplicity matters — there's one host, one operator, no DBA.

## Decision

- **Metadata and state** (items, files, kind, pin order, trash timestamps) live in SQLite, in WAL mode with `busy_timeout` and `BEGIN IMMEDIATE` for writers, behind the `ItemRepository` port.
- **File bytes** live directly on the filesystem under `data_dir`, named by generated ID (never a user-supplied path), behind the `BlobStore` port. Writes go to a staging path first, then an atomic rename into place, so a crash never leaves a DB row pointing at a missing blob.
- Purge deletes the DB row before the blob, so a crash mid-purge leaves an orphan blob (cleaned by an orphan sweep) rather than a dangling DB reference.

## Consequences

- Zero extra services to run or secure — no Postgres, no S3-compatible store, no network hop for either metadata or bytes.
- Serving files (including Range requests for video) is a direct filesystem read via the viewer process — no proxying through a blob-storage API.
- SQLite's single-writer model is fine at this scale; WAL mode lets reads proceed concurrently with writes. If usage ever outgrows a single host, this ADR would need revisiting (not currently expected).
- The `BlobStore` port keeps the door open for a different backend (e.g. object storage) later without touching `domain/`/`application/` — see `docs/extending.md` and ADR-0001.
- Both the SQLite adapter and the filesystem blob store get their own contract test suites, shared with the in-memory fakes, so drift between fake and real behavior is caught in tests rather than in production.

## Amendment (unit 6 security review)

- **Publish is `link` + `unlink`, not `rename`.** `os.link` fails if the destination exists (a colliding id is surfaced as a bug instead of silently overwriting a blob), and a crash between the two calls leaves a complete blob plus a stale staging file (swept later), never a partial blob. The destination shard directory is `fsync`'d after publish; any newly created directory has its parent `fsync`'d.
- **Confinement uses directory fds.** `FsBlobStore` opens `root`, `blobs/` and `staging/` once with `O_DIRECTORY|O_NOFOLLOW` and performs every later operation relative to those fds (`dir_fd=`, `openat`/`linkat`/`unlinkat`/`mkdirat`, `scandir(fd)`); shard dirs are opened `O_NOFOLLOW` from the `blobs/` fd. Path-string checks (`lstat` then use) were racy: a symlink swapped in after start-up could redirect reads/deletes outside the data dir (I2). Directories must be owned by a trusted uid and not group/world-writable; blobs must be regular files with `st_nlink == 1`, opened `O_NONBLOCK` (FIFO-safe).
- Consequence: the store holds three fds for its lifetime (`close()` / context manager) and ignores layout changes made under it until restarted.
