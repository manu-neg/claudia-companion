# ADR 0015: Viewer routes — URL scheme, trash flag, text render cap, static manifest

**TL;DR:** Item bytes live at `/i/<id>/<relpath>` (inline), `/t/<id>/<relpath>` (capped text) and `/d/<id>[/<relpath>]` (attachment) on the preview origin; trashed items are only served with an explicit `?t=1`; the stored media type is re-checked against the registry on every serve; the UI's static files are an in-memory allowlisted manifest.

## Context

Unit 8a built the security layer around empty routers; unit 8b fills them. The routes must keep I2 (no request value is ever a filesystem path, no listings), C5/C8 (types from the registry, all bytes on the preview origin), C9 (downloads, ranges, zips) and the unit 3/4 obligations (server-side text cap, abort on mid-stream failure, trashed visibility).

## Decision

- **One path shape per purpose**, all `/<letter>/<ULID>/<relpath>`: the letter decides inline (`i`), capped text (`t`) or attachment (`d`), so a response's disposition never depends on a query flag. The relpath comes only from the raw path (decoded once, re-validated); the id segment must be literal.
- **Trash flag `?t=1`:** the owner may preview and download trashed items (the trash view needs it), but only when the URL says so; without it a trashed item is 404, exactly like a missing one. Stops old feed links, bookmarks or a hostile page from reaching trashed content by accident, at no cost to the owner. Same flag on `GET /api/items/{id}`. Queries are strict (unknown/repeated → 400).
- **Tamper defense:** `ItemFile.media_type` must equal the item kind's `media_type(relpath)` at serve time; otherwise (tampered row, changed registry, unknown kind) the file goes out as `application/octet-stream` + `attachment` — never a type that could unlock the PDF CSP exception or execute.
- **Text cap on the server:** `/t` returns at most `render_cap_bytes` as `text/plain; charset=utf-8` (never the original type), trimmed to a UTF-8 boundary, with `X-PDash-Truncated: 1`. Only for `render_capped` kinds (added to `describe()`).
- **Streaming integrity:** full files are checked against the manifest size (one extra-byte read) + SHA-256 **before the final chunk is yielded**; a mismatch is raised, so the server drops the connection with fewer bytes on the wire than `Content-Length` — a client never holds a complete tampered body (checking after the last chunk would be too late: the body already looks complete). The first chunk is read before the headers go out, so an empty or single-chunk mismatch becomes a plain 500. ZIP errors abort the chunked stream without a terminator. Range responses are only checked for a short blob, not hashed (a range can't be hashed without reading the whole file).
- **Polling:** JSON carries a strong ETag and answers 304 to a matching `If-None-Match`, but stays `no-store`; the frontend sends the header itself.
- **Static UI:** files under `static/` with an allowlisted extension are read into memory at start-up (symlinks/special files refuse start-up; each file is opened `O_NOFOLLOW | O_NONBLOCK` and re-checked with `fstat`, so a swap after the walk's `lstat` is refused, not followed); requests are dict lookups.
- **Server:** both apps run as two uvicorn servers in one process; if one stops, both stop (never half the viewer). Both use the shared header-phase deadline protocol (`interfaces/http_server.py`, ADR 0014) so idle connections can't pin `limit_concurrency`, and `timeout_graceful_shutdown=10` so a stuck download can't block a restart.

## Consequences

- Moving/renaming routes means updating the item JSON (`item_json.py`) and the Referer binding prefix (`hints.PREVIEW_ITEM_PREFIX`) together.
- The dashboard cannot read preview bytes (no CORS, by design); TEXT rendering in the UI uses `render_url` in a sandboxed iframe or a preview-origin renderer page (unit 9).
- UI changes need a viewer restart (in-memory manifest); acceptable for a single-owner app.
- Strict query parsing means the frontend must not add cache-busting parameters.

## Amendment (revisions, ADR 0019)

- Every preview path now names a revision: `/i|t|r/<id>/<rev>/<relpath>`, `/d/<id>/<rev>[/<relpath>]`, with `<rev>` = `[1-9][0-9]{0,9}` or `latest` (literal in the raw path; else 400). The JSON always uses numbers; `/api/items/{id}?rev=<n>` serves an older revision's detail.
- Integrity Lows from the 8b review: the real blob size is checked against the manifest before any header on every file response (ranges included); `/t` and `/r` hash-verify files that fit under the cap.
- The dashboard static manifest skips top-level `vendor/` and `preview-render/` (only inlined into `/r/` pages, ADR 0018).
