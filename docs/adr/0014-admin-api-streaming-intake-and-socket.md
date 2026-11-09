# ADR 0014: Admin API — manifest-first streaming multipart, self-bound socket, per-role cores

**TL;DR:** Publishes stream straight from the request body into `PublishService` (no temp files, no whole-file buffering), which requires a `manifest` field before the file parts; the admin process binds its own 0660 Unix socket and tags requests with `SO_PEERCRED`; `bootstrap.build_core` returns a different, minimal service container per process role; connections that don't send a complete request head within 10 s are closed (amendment below).

## Context

- `PublishService.publish` needs every relpath up front (file count, kind detection, manifest checks) before it reads a byte, then consumes each file's chunks in order. A multipart body only reveals file names as it goes.
- The usual framework path (`request.form()`) spools uploads to temp files (content outside `data_dir`, under `/tmp`) and parses the whole body before the handler runs — no streaming limits, no early rejection.
- `uvicorn --uds` chmods a freshly created socket to 0666, and uvicorn exposes no per-connection socket to the app, so peer credentials can't be read from a route.
- Four processes share one core but need very different capabilities (C28 least privilege).
- `PublishService` checks its deadline only between chunks, so a stalled body could pin a quota reservation, a worker thread and a staging file (slowloris).

## Decision

- **Manifest-first multipart:** `POST /v1/items` takes fields `title`, `description`, `kind_hint`, `pinned`, `manifest` (JSON array of relpaths) **before** any file part; each file part is named `file`, and its filename must equal the next manifest entry. The body is parsed incrementally (python-multipart's push parser); once the first file part starts, `publish()` runs in a worker thread and pulls chunks from a bounded (8-chunk) in-memory channel. The last file's end marker is held until the whole body has parsed cleanly, so a malformed tail can never commit an item; any upload error closes the channel and the publish rolls back.
- **Timeouts at the interface:** each body read ≤ 30 s, the whole body ≤ `publish_timeout_seconds` → 408.
- **Own socket:** bind under umask 0177, then set exactly 0660, refusing a non-socket at the path and an untrusted parent; pass the socket to `uvicorn.Server.run(sockets=...)`. A `PeerCredH11Protocol` subclass reads `SO_PEERCRED` once per connection and attaches it to that connection's scopes; `--allowed-peer-uid` optionally enforces it.
- **Per-role cores:** `AdminCore` (publish/queries/lifecycle), `ViewerCore` (queries/archive + `TrashControl` trash/restore only, read-only blob store), `PurgeCore` (purge + staging sweep hook). Each owns its adapters' resources and closes them.
- **Rate limit → 429** via a new `RateLimitedError(LimitExceededError)`, so existing "a limit" handling still works.

## Consequences

- Memory per publish is bounded by the channel (~8 × 64 KiB) regardless of file size; no content touches `/tmp`.
- Clients (the MCP server, unit 10) must send the manifest before the files; field order is enforced (400 otherwise). Max parts is `max_files + 5`.
- More moving parts than `request.form()` (a thread bridge); covered by real-socket tests (chunked upload, stalled and dripping clients).
- Peer credentials are Linux-specific (`SO_PEERCRED`); elsewhere they are simply absent, and an allowlist then fails closed.
- The viewer physically lacks publish/edit capabilities, not just routes for them.

## Amendment (unit 7 follow-up, security review)

- **Header-phase deadline:** uvicorn arms no timer at connection open or while a request head trickles in, and counts idle connections against `limit_concurrency`; 33 idle socket connections made every request a pre-auth 503. `interfaces/http_server.HeaderTimeoutH11Protocol` (shared with the viewer servers) arms `loop.call_later(header_timeout, close)` in `connection_made` and after every response, cancels it once a complete head starts a request (the app's body timeouts and uvicorn's keep-alive timer take over), and never extends it for trickled bytes. `PeerCredH11Protocol` subclasses it. `limit_concurrency` stays (32): it still bounds work, and a slot can now be pinned for at most 10 s per connection.
- **Live socket is never replaced:** before unlinking an existing socket at the path, the server `connect()`s to it; an answer (or an unprobeable socket) refuses startup instead of orphaning a running instance.
- **Per-role schema ownership:** `connect(migrate=False)` for the viewer and purge roles — they never create the DB or run DDL and require `CURRENT_VERSION`; only the admin (and `preview-dashboard migrate`) migrates.
- Smaller hardening: deep-nesting JSON → 400; ASCII-only `limit`; quiet `ClientDisconnect` (one INFO line, rollback); token file group must be root/own/`--token-group`, token needs ≥ 16 distinct chars; a chunk for any other file index aborts the upload instead of being skipped; a secret-scan `relpath` is reported only for content hits.
- **Consequences:** a viewer or purge started before the admin exits until the DB exists; a root-run reader of a `root:pdash` token file must trust that group explicitly (`--token-group`, or `trusted_gids=` in code).
