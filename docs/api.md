# API reference

**TL;DR:** Three surfaces — the **admin API** (Unix socket; admin token for the MCP server and root CLI, a separate notifier token for `/v1/notifier/*` only), the **viewer API** (HTTPS over Tailscale, used by the owner's browser), and the **MCP tools** (stdio, used by Claude). Each section is marked planned or implemented (with its unit).

## Admin API (implemented, unit 7)

Base: Unix socket `/run/preview-dashboard/admin.sock` (mode 0660), `Authorization: Bearer <token>` on **every** request, including `/v1/health`. Local only — never networked. JSON responses carry `Cache-Control: no-store` and `X-Request-Id`. Code: `interfaces/admin/`; decisions: ADR 0003, ADR 0014, ADR 0021, ADR 0022, ADR 0027 (folders).

**Two tokens, two route families (C33, C34, ADR 0022):**

| Token (file) | Accepted on | Elsewhere |
|---|---|---|
| admin (`admin_token_file`) | every route **except** `/v1/notifier/*` | 403 |
| notifier (`notifier_token_file`, loaded only when `notify_enabled`) | `/v1/notifier/*` only | 403 |
| none / wrong | nothing | 401 + `WWW-Authenticate: Bearer` |

The family is decided on the same decoded path the router matches, before routing (an unknown `/v1/notifier/...` path is 403 for the admin token, never 404). The two tokens must differ (else `serve-admin` refuses). With `--allowed-peer-uid` / `--notifier-peer-uid`, each family also only serves its own peer uids (unknown peer → 403).

| Method | Path | Body / query | Success |
|---|---|---|---|
| `POST` | `/v1/items` | multipart (below) | 201 item |
| `POST` | `/v1/items/{id}/revisions` | multipart (below): new content for an existing item | 201 item (head = the new revision) |
| `GET` | `/v1/items` | `kind`, `state` (`active` default \| `trashed`), `limit` (1–200 in ASCII digits, default 50), `cursor`, `folder` (a folder id \| `unfiled`; unknown id → 404, anything else → 400) | 200 `{"items": [item…], "next_cursor": str \| null}` |
| `GET` | `/v1/items/{id}` | — | 200 item (any state) |
| `PATCH` | `/v1/items/{id}` | `application/json` ≤ 64 KiB: any of `title` (str), `description` (str), `pinned` (bool); other keys → 400 | 200 item (active items only; edited text is secret-scanned) |
| `POST` | `/v1/items/{id}/trash` | — | 200 item (idempotent) |
| `POST` | `/v1/items/{id}/restore` | — | 200 item (idempotent) |
| `POST` | `/v1/items/{id}/move` | `application/json` exactly `{"folder_id": <folder id> \| null}` | 200 item (any state; idempotent; unknown item/folder → 404) |
| `POST` | `/v1/items/{id}/revisions/prune` | `application/json` object with any of `keep` (int 1–20, default 1, head included), `expected_revision` (int) | 200 `{"item": item, "revisions_removed", "bytes_freed"}` — **permanent** (below) |
| `POST` | `/v1/trash/empty` | — | 200 `{"items_purged", "blobs_deleted"}` — **permanent** (below) |
| `GET` | `/v1/folders` | — (no query parameters) | 200 `{"folders": [folder + `count`, `trashed_count`…], "unfiled_count", "unfiled_trashed_count"}` (name order, caseless) |
| `POST` | `/v1/folders` | `application/json` exactly `{"name": str}` | 201 folder |
| `PATCH` | `/v1/folders/{id}` | `application/json` exactly `{"name": str}` | 200 folder (renaming to the current name is a no-op) |
| `DELETE` | `/v1/folders/{id}` | — | 200 `{"id", "deleted": true}`; **409** while any item (active **or trashed**) is filed in it |
| `GET` | `/v1/kinds` | — | 200 `{"kinds": [KindRegistry.describe()…]}` |
| `GET` | `/v1/health` | — | 200 `{"status": "ok"}` |
| `POST` | `/v1/questions` | JSON (below) | 201 `{"question": question}` |
| `GET` | `/v1/questions/{id}` | `wait` (0–60, ASCII digits; only parameter) | 200 `{"question": question}` — long-poll (below) |
| `POST` | `/v1/questions/{id}/cancel` | — | 200 `{"question": question}` (idempotent) |
| `POST` | `/v1/notifications` | JSON `{event: "done"\|"failed", title, item_id?}` | 201 `{"notification": {id, event, title, item_id, created_at}}` |
| `GET` | `/v1/notifier/tasks` | `wait` 0–60, `limit` 1–20 | **notifier token**: 200 `{"tasks": [...]}` (docs/notifier.md) |
| `POST` | `/v1/notifier/tasks/{id}/done` \| `/failed` | `{"message_ref"?}` / `{}` | **notifier token**: 200 `{}` |
| `POST` | `/v1/notifier/answers` | `{question_id, key, source, actor_ref}` | **notifier token**: 200 `{"result": ...}` |

There is **no item `DELETE` endpoint**: items leave permanently only via the purge job (trash → purged after `trash_retention_days`) or the two explicit permanent deletes below (ADR 0030). Deleting a folder never deletes items (only empty folders go). Listing orders pinned first, then newest first.

### Permanent deletes (unit R1, ADR 0030, C43)

Admin token only (notifier token → 403); each route re-checks the role.

- **`POST /v1/items/{id}/revisions/prune`** — keep only the newest `keep` revisions (head included; the head is never deleted). Id checked before the body. Unknown fields, non-int / bool / out-of-range values → 400; non-JSON → 415; unknown item → 404; trashed → 409 `invalid_state`; stale `expected_revision` → 409 `conflict`. Compare-and-swap, re-read and retried once on a concurrent change; blobs deleted after the commit (a failed delete is left to the orphan sweep). Nothing to prune → 200 with zero counts and nothing written. `bytes_freed` = the removed revisions' file sizes.
- **`POST /v1/trash/empty`** — purge every trashed item now, regardless of retention, through the purge job's atomic per-item delete: an item restored (or restored and re-trashed) while it runs is kept. Rows first, then unreferenced blobs. Idempotent (empty trash → zero counts).

```python
client.post(f"/v1/items/{item_id}/revisions/prune", json={"keep": 1})  # -> 200, revisions_removed
client.post("/v1/trash/empty")  # -> 200, items_purged
```

**Item JSON:**
```json
{"id": "01J…", "title": "…", "description": "…", "kind": "html", "state": "active",
 "pinned": false, "created_at": "2026-…+00:00", "updated_at": "…", "trashed_at": null,
 "entry_file": "index.html", "total_size": 1234,
 "files": [{"relpath": "index.html", "size": 1200, "sha256": "…", "media_type": "text/html"}],
 "revision": 2, "revision_at": "2026-…+00:00", "stored_size": 2400,
 "revisions": [{"number": 2, "created_at": "…", "kind": "html", "entry_file": "index.html",
                "file_count": 1, "total_size": 1234},
               {"number": 1, "created_at": "…", "kind": "html", "entry_file": "index.html",
                "file_count": 1, "total_size": 1166}],
 "folder": {"id": "01J…", "name": "Plans"} | null,
 "viewer_url": "https://<first allowed_hosts entry>/#/item/01J…"}
```
`folder` is the folder the item is filed in (`null` = unfiled; resolved with one folder read per response, never per item). `viewer_url` is `null` when no `allowed_hosts` is configured. Blob ids are never exposed. `kind`, `entry_file`, `files`, `total_size` describe the **head** revision (`revision`, published at `revision_at`); `revisions` lists every kept revision, newest first (at most 20); `stored_size` is what the item occupies across all of them (counted in the byte quota). The `viewer_url` never changes across revisions.

### Publish: `POST /v1/items` (multipart/form-data, streamed)

Parts, **in this order**:

| Part | Kind | Rules |
|---|---|---|
| `title` | field, required | UTF-8, ≤ 16 KiB raw (domain: 1–200 chars after sanitizing) |
| `description` | field, optional | UTF-8, ≤ 16 KiB raw (domain: ≤ 5000 chars) |
| `kind_hint` | field, optional | a registered kind name; empty = autodetect |
| `pinned` | field, optional | `true`/`false`/`1`/`0` |
| `folder_id` | field, optional | a folder id (ULID): file the new item there; empty = unfiled; malformed → 400, unknown → 404 (checked before any byte is stored, again atomically at commit; C41) |
| `manifest` | field, required | JSON array of relpaths, one per file, in upload order (≥ 1, ≤ `max_files`) |
| `file` × N | file parts | `filename` must equal the next manifest entry exactly; bytes are stored as sent (no `Content-Transfer-Encoding`) |

- Fields after the first file part, unknown/duplicate fields, or file parts not matching the manifest → 400.
- Limits: parts ≤ `max_files` + 6, ≤ 4 headers per part (≤ 4 KiB each), body ≤ `max_item_bytes` + overhead counted on the stream (a lying `Content-Length` doesn't help), each body read within 30 s and the whole body within `publish_timeout_seconds` (else 408). Per-file/item/quota/disk limits are the core's (C18).
- The body streams into the core (no temp files); the item commits only after the whole body parsed cleanly. Any failure deletes every blob of the attempt.

Example (Python `httpx` over the socket):
```python
files = [("index.html", html_bytes)]
data = {"title": "Report", "manifest": json.dumps([p for p, _ in files])}
client.post("/v1/items", data=data, files=[("file", (p, b)) for p, b in files])
```
(httpx sends data fields before files, as required.)

### New revision: `POST /v1/items/{id}/revisions` (multipart/form-data, streamed)

Replaces an **active** item's content with a new head revision (ADR 0019). The item keeps its id, title, description, pin and `viewer_url`; the files sent are the **complete** new content (nothing is carried over from the previous revision). The last 20 revisions are kept; older ones are pruned (and their blobs deleted) automatically. Same streaming rules, limits, timeouts and rollback as publish.

`{id}` must be a canonical ULID (else 400 **before** the body is read). Parts, **in this order**:

| Part | Kind | Rules |
|---|---|---|
| `kind_hint` | field, optional | a registered kind name; empty = autodetect (the kind may differ from the previous revision's) |
| `expected_revision` | field, optional | ASCII digits `[1-9][0-9]{0,9}`; if set, the update applies only while this is still the head revision number, else **409 `conflict`** (use the `revision` you last saw to avoid overwriting a version you haven't seen) |
| `manifest` | field, required | JSON array of relpaths, one per file, in upload order (≥ 1, ≤ `max_files`) |
| `file` × N | file parts | `filename` must equal the next manifest entry exactly |

- Any other field (e.g. `title`, `pinned`) → 400; metadata changes go through `PATCH /v1/items/{id}`.
- Checks (same as publish): rate limit (every attempt counts, shared with publish), file count, relpaths (C7), kind detection, secret scan of relpaths **and** every byte (C15), byte quota (all kept revisions count; no item slot needed), free-disk floor, per-file/per-item limits on streamed bytes, deadline.
- Commit is a compare-and-swap; if a concurrent edit/pin landed meanwhile it is re-read and retried once (a concurrent trash → 409 `invalid_state`; a concurrent revision with `expected_revision` set → 409 `conflict`).
- Success: **201** + the item JSON above (`revision` = the new number, `revisions` newest first).
- Errors: 400 (form/order/manifest/relpath/`expected_revision`/id), 401, 404 `not_found` (unknown item), 408, 409 `invalid_state` (item is in the trash) / `conflict` (stale `expected_revision` or repeated concurrent change), 413 (limits, quota — incl. storage used by old revisions), 422 `secret_detected` / `unsupported_content`, 429 `rate_limited`. On every failure nothing changes and the attempt's blobs are deleted.

Example (Python `httpx` over the socket):
```python
data = {"expected_revision": "1", "manifest": json.dumps(["index.html", "app.css"])}
files = [("file", ("index.html", html)), ("file", ("app.css", css))]
client.post(f"/v1/items/{item_id}/revisions", data=data, files=files)  # -> 201 item, revision 2
```

### Folders (unit F2, ADR 0027)

One level of folders; an item is in at most one folder (else unfiled). Claude organises them (admin token only); the viewer only reads them (C40). Code: `interfaces/admin/folders_api.py`, `api.py` (`move`, `?folder=`).

**Folder JSON:** `{"id": "01J…", "name": "Plans", "created_at": "…+00:00", "updated_at": "…"}` (+ `count` / `trashed_count` in the listing). The name is untrusted display text (C39): sanitized like a title (1–80 chars, invisible/bidi/control characters removed, raw input > 320 chars → 400), secret-scanned raw **and** sanitized (→ 422 `secret_detected` with `rule`, never a `relpath` or the name), unique under caseless/width-folding matching (`Plans` = `PLANS` = fullwidth `Ｐｌａｎｓ` → 409 `conflict`); at most 200 folders (→ 413 `limit_exceeded`). Error messages never echo the name.

| Situation | Status |
|---|---|
| malformed id / body (other keys, wrong types), bad `folder` filter (incl. empty, `Unfiled`) | 400 `invalid_input` |
| unknown folder (rename, delete, move target, publish `folder_id`, `?folder=`) or item | 404 `not_found` |
| name taken (caseless); delete of a non-empty folder; a rename or move that lost a concurrent race | 409 `conflict` |
| folder quota (200) | 413 `limit_exceeded` |
| wrong `Content-Type` | 415 |
| secret-looking name | 422 `secret_detected` |

`move` works in **any** state (a trashed item keeps its folder and returns to it on restore), so Claude can empty a folder of trashed items without restoring them.

### Questions and alerts (unit N3, ADR 0021)

Admin token only. There is **no answer route** for the admin token: answers come only through `/v1/notifier/answers` with the notifier token (C34).

**`POST /v1/questions`** (`application/json`, ≤ 64 KiB; unknown keys → 400):

| Field | Rules |
|---|---|
| `prompt` | string, required (domain: 1–200 chars after sanitizing, no links, secret-scanned) |
| `options` | required list of 2–8 `{"key", "label"}` objects (exactly those keys); key `[a-z0-9_-]{1,16}`, label ≤ 40 chars |
| `session_label` | string, **required** (1–40 chars; names the asking session, shown in the alert) |
| `default_key` | optional, one of the keys (reported on expiry, never auto-answered) |
| `item_id` | optional item ULID (becomes the alert's dashboard link and `viewer_url`) |
| `expires_in_s` | optional integer 60–604800 (default `question_ttl_seconds`, 24 h) |

Checks: the shared alert rate limit (`notify_rate_per_hour`, questions + notifications, every attempt counts → 429), secret scan (→ 422 `secret_detected`, rule label only), domain validation (→ 400). With `notify_enabled`, one Telegram SEND task is queued atomically with the question; otherwise the question is only stored.

**Question JSON:**
```json
{"id": "01J…", "prompt": "…", "options": [{"key": "a", "label": "SQLite"}],
 "default_key": "a" | null, "item_id": "01J…" | null, "session_label": "…",
 "state": "open" | "answered" | "expired" | "cancelled", "answer_key": "a" | null,
 "answer_source": "telegram" | null, "created_at": "…+00:00", "expires_at": "…",
 "resolved_at": "…" | null, "viewer_url": "https://<host>/#/item/01J…" | null}
```

**Long-poll `GET /v1/questions/{id}?wait=N`:** returns as soon as `state != "open"` or after N seconds (N ≤ 60; default 0 = no wait). An open question past `expires_at` is expired on read. The wait runs on the event loop (never a threadpool worker), is woken in-process by the answer/cancel commit and re-reads the store at least every 5 s (expiry by the purge job). At most **16** concurrent waiters; beyond that the current state is returned at once (C37). A client that disconnects frees its slot immediately.

### Notifier routes (unit N3, notifier token only)

Formats: `preview_dashboard.wire.notifier` and docs/notifier.md. `GET /v1/notifier/tasks` serves **one poller at a time** (tasks are not leased): a concurrent second request gets `{"tasks": []}` immediately (C37); the held poll is woken when new deliveries commit. `done`/`failed` on an unknown task → 404, malformed id/body → 400. `answers`: `source` must be an enabled answer source (`telegram` when `notify_enabled`, else none → 400); unknown question ids / unoffered keys → `{"result": "unknown"}` (no existence oracle); the first answer wins (`recorded`, then `already_answered` / `expired` / `cancelled`).

### Viewer route (F-CL6, viewer token only)

`POST /v1/viewer/approvals/{id}/decision`, format `preview_dashboard.wire.viewer_decisions`: body `{"decision": "approve", "code": "[0-9]{6}"}` or `{"decision": "deny"}` (≤ 256 bytes, no other keys → 400) → `{"result": <verdict>}` (values as the dashboard route above). The viewer token is accepted nowhere else and every other token is refused here (403); own peer-uid family (`serve-admin --viewer-peer-uid`). Unknown ids → `unknown`; 20 attempts per 10 min, then `rate_limited`.

### Errors

Body: `{"error": <code>, "message": <caller-safe text>, "request_id": <id>}` (`message` omitted for 401/403/404-route/500). Messages never echo titles, descriptions, prompts, labels or file bytes.

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_input` / `bad_request` | malformed body (incl. absurdly nested JSON), bad relpath/title/cursor/id/`limit`, form order |
| 400 | `client_disconnected` | the client went away mid-body (nothing is actually sent; publish rolled back; one INFO log line) |
| 401 | `unauthorized` | missing/wrong token (`WWW-Authenticate: Bearer`) |
| 403 | `forbidden` | peer uid not allowed for this route family; a token used on the other family (admin ↔ `/v1/notifier/*`) |
| 404 | `not_found` | unknown item or route |
| 408 | `request_timeout` | body stalled / too slow |
| 409 | `invalid_state` / `conflict` | edit, new revision or revision prune of a trashed item; concurrent modification or stale `expected_revision` (`ConflictError`); folder name taken; delete of a non-empty folder |
| 413 | `limit_exceeded` | size, count, quota, free-disk or deadline limit |
| 415 | `unsupported_media_type` | wrong `Content-Type` |
| 422 | `secret_detected` (+ `rule`, and `relpath` only for a hit in a file's content) / `unsupported_content` | secret scan hit (neutral rule label only; a hit in title/description/relpath has no `relpath` key); kind hint doesn't fit |
| 429 | `rate_limited` (+ `Retry-After`) | `publish_rate_per_hour` reached, or the shared alert budget `notify_rate_per_hour` (questions + notifications); failed attempts count |
| 500 | `internal_error` | anything unexpected (details only in the log, by request id) |
| 503 | `storage_unavailable` (+ `Retry-After: 5`) | the DB layout failed a C24 trust check (fail closed, logged WARNING; ADR 0025) — retry with backoff |

## Viewer API (implemented, units 8a + 8b)

Two apps, two origins (ADR 0005). **Dashboard** `https://<host>` (local `viewer_port` 8787): UI + JSON only. **Preview** `https://<host>:8443` (local `preview_port` 8788): item bytes only, no `/api`. Run together by `preview-dashboard serve-viewer` (`interfaces/viewer/server.py`). All routes need the owner identity (C2); POSTs also the CSRF headers (C4). Decisions: ADR 0015.

### Dashboard app (JSON + UI)

| Method | Path | Query | Returns |
|---|---|---|---|
| `GET`/`HEAD` | `/api/kinds` | — | `{"kinds": [describe()...], "render_cap_bytes": N, "preview_origin": "https://<host>:8443"}`; each kind: `name label renderer preview_mode extensions render_capped`; the UI accepts item URLs only on `preview_origin` |
| `GET`/`HEAD` | `/api/items` | `state=active\|trashed` (default active), `kind` (one name or a comma list of ≤ 8, e.g. `html,progress`; empty = all; a repeated `kind` key, empty element, bad name or > 8 → 400), `limit` 1..200 (default 50), `cursor`, `folder=<folder id>\|unfiled` | `{"items": [summary...], "next_cursor": str\|null}`; pinned first, newest first; a bad `folder` value (incl. empty) → 400, an unknown folder id → 404 |
| `GET`/`HEAD` | `/api/items/{id}` | `t=1` to see a trashed item; `rev=<n>` (`[1-9][0-9]{0,9}`) for an older kept revision | summary + `"files": [file...]` of that revision (default: head); trashed item without `t=1` or unknown/pruned `rev` → 404 |
| `GET`/`HEAD` | `/api/folders` | — (no parameters) | `{"folders": [{"id", "name", "count"}...], "unfiled_count": int}` — every folder in name order (caseless), `count` = its **active** items; ETag/304 like `/api/items`. Read only: there is **no** viewer route that creates, renames, deletes folders or moves items (C40) |
| `POST` | `/api/items/{id}/trash` | — | `{"item": summary}`; idempotent (already trashed → 200, `trashed_at` unchanged) |
| `POST` | `/api/items/{id}/restore` | — | `{"item": summary}`; idempotent |
| `POST` | `/api/items/{id}/pin` | — | `{"item": summary}` with `pinned: true`; idempotent (already pinned → 200, nothing written, `updated_at` unchanged); trashed item → 409 `conflict` (ADR 0020) |
| `POST` | `/api/items/{id}/unpin` | — | `{"item": summary}` with `pinned: false`; idempotent; trashed item → 409 `conflict` |
| `POST` | `/api/items/{id}/revisions/prune` | `expected=<n>` (**required**, `[1-9][0-9]{0,9}`: the head the owner saw; missing → 400) | **Permanent** "Delete old versions" (ADR 0030, C43): keeps only the head (keep is fixed at 1; a `keep` parameter → 400). `{"item": summary, "revisions_removed": int, "bytes_freed": int}`; nothing older → 200 with zeros, nothing written; trashed item or `expected` no longer the head → 409. Disk space is freed by the hourly orphan sweep once blobs pass the 1 h grace period, so up to about two hours (the viewer's blob store is read-only) |
| `GET`/`HEAD` | `/api/kb/graph` | — (no parameters) | Knowledge map (unit M8, C57), from a fresh bounded walk of `kb_root`: `{"nodes": [{id, title, category, tags, updated, recent, degree}], "edges": [{source, target, kind: "link"\|"tag"}], "categories": [{name, count}], "skipped": int, "truncated": bool}`. `id` = 32 hex chars, opaque (HMAC of the path with a per-process key; no path ever leaves the server). `title` comes from the file name. 404 when the map is off (no `kb_root`, or the root missing/unsafe). ETag/304 |
| `GET`/`HEAD` | `/api/kb/notes/{id}` | — | One note: the node fields + `body` (text after the frontmatter), `links: [{target, id\|null}]`, `backlinks: [{id, title}]`. Malformed id → 400, unknown id (or map off) → 404 |
| `GET`/`HEAD` | `/api/claudia/approvals` | — | `{"available": bool, "approvals": [{id, action_text, kind, target, state, expires_at}], "decisions": bool}` from the admin's snapshot file (`claudia_approvals_snapshot`, format below). Always 200; no file / unsafe file / any invalid entry → `available: false`, no entries. `decisions` true = Approve/Deny work in the panel (F-CL6) |
| `POST` | `/api/claudia/approvals/{id}/decision` | — | F-CL6 (ADR 0043), only while dashboard decisions are active: Claudia on and `claudia_dashboard_decisions` (default true), else 404. Body `{"decision": "approve", "code": "123456"}` or `{"decision": "deny"}` (no other keys; else 400). Forwarded to the admin, which decides: `{"result": "approved" \| "denied" \| "wrong_code" \| "locked" \| "already_decided" \| "expired" \| "unknown" \| "rate_limited" \| "refused"}`. 429 = more than 20 clicks in 10 min; 503 = admin unreachable (nothing decided) |
| `GET`/`HEAD` | `/` | — | `index.html` (UI) |
| `GET`/`HEAD` | `/static/{name}` | — | a file of `src/preview_dashboard/static/`, from an in-memory manifest (see below) |

- **Summary:** `id title description kind preview_mode pinned state created_at updated_at trashed_at purge_at file_count total_size entry_file preview_url render_url render_page_url download_url revision revision_created_at latest_revision revisions folder`. `folder` = `{"id", "name"}` or `null` (unfiled; also for a folder the read side cannot list, e.g. a row that failed re-validation — never an error), resolved with one folder listing per response. `kind`…`download_url` describe the revision in `revision` (the head unless `?rev=`); `latest_revision` is the head's number; `revisions` = `[{number, created_at, kind, entry_file, file_count, total_size}]`, newest first. Times are ISO 8601 UTC (`...Z`); `purge_at = trashed_at + trash_retention_days` (null when active); `render_url` / `render_page_url` only for `render_capped` kinds (else null).
- **File:** `relpath media_type size sha256 preview_url render_url render_page_url download_url`.
- **Approvals snapshot (format v1, written by the admin, unit M5b):** one JSON file `{"version": 1, "approvals": [{"id": ULID, "action_text": str ≤ 200, "kind": ActionKind value\|null, "target": str ≤ 200\|null, "state": "pending"\|"tapped"\|"approved", "expires_at": ISO 8601 with zone}]}`; exact key sets, ≤ 50 entries, ≤ 256 KiB, no control characters; regular file, one link, not group/world-writable, in a directory that is not group/world-writable. Expired entries are dropped; anything else invalid makes the whole list unavailable.
- **URLs** are absolute on the preview origin and always name a revision **number** (never `latest`), each relpath segment percent-encoded (`encode_relpath_url`); trashed items' URLs end in `?t=1`.
- **Polling:** list/detail/kinds/folders send a strong `ETag` (SHA-256 of the JSON). Send `If-None-Match: <etag>` yourself → `304` with no body. JSON stays `Cache-Control: no-store` (private content never lands in the browser cache), so the browser won't revalidate for you.
- **Strict queries:** unknown or repeated parameters, bad values, non-ASCII → 400. `t` must be exactly `1`.
- **POST errors** (trash/restore/pin/unpin/revisions/prune): 400 bad id or any query parameter (prune: anything but exactly one valid `expected`), 403 CSRF/identity (C4), 404 unknown item, 409 `conflict` (pin/unpin/prune on a trashed item; prune with a stale `expected`; a change that lost the optimistic-concurrency race twice), 413 body > 1 KiB. Nothing changes on any error.
- **Unit 9 fetch wrapper:** POSTs must send exactly `Content-Type: application/json` (no `; charset=...` — anything else is 403), `X-PDash-CSRF: 1`, and a same-origin `Origin` (browsers add it); body `{}` or empty (≤ 1 KiB).
- **Static files:** loaded once at start-up; only `.html .js .css .svg .png .ico .woff2 .json .webmanifest`; dotfiles and the top-level `vendor/` and `preview-render/` directories skipped (they are only inlined into `/r/` pages; → 404 here); a symlink or special file under `static/` makes the dashboard refuse to start. `Cache-Control: private, no-cache` + `ETag` (304 on match). No directory listing: `/static/`, `/static/renderers/` → 404.

### Preview app (item bytes)

| Method | Path | Serves | Notes |
|---|---|---|---|
| `GET`/`HEAD` | `/i/{id}/{rev}/{relpath}` | one file of revision `rev`, **inline**, with its registry type | Range, ETag, If-Range; `?t=1` for trashed items |
| `GET`/`HEAD` | `/t/{id}/{rev}/{relpath}` | TEXT-kind file as `text/plain; charset=utf-8`, at most `render_cap_bytes` | only `render_capped` kinds (else 404); `X-PDash-Truncated: 1` when cut (cut on a UTF-8 boundary); no Range |
| `GET`/`HEAD` | `/r/{id}/{rev}/{relpath}` | TEXT-kind file **rendered**: an HTML page (`text/html; charset=utf-8`) with the capped text embedded as escaped JSON and the renderer + needed vendored libraries inlined (docs/frontend.md) | same rules as `/t` (render-capped kinds only, `?t=1`, cap, `X-PDash-Truncated`); full sandbox CSP; fetch metadata allows it only as a dashboard `iframe`; no `Content-Disposition`; no Range |
| `GET`/`HEAD` | `/d/{id}/{rev}` | whole revision as **attachment**: the file if single-file, else a streamed ZIP (`application/zip`, `download_filename`; `<slug>-v<N>.zip` once an item has been revised) | single file: Range; ZIP: `Accept-Ranges: none`, no `Content-Length` |
| `GET`/`HEAD` | `/d/{id}/{rev}/{relpath}` | one file as **attachment** | Range |

- **Revision segment `{rev}`** (ADR 0019): a kept revision number `[1-9][0-9]{0,9}` (≤ 2³¹−1) or `latest` (the head at request time — a stable link). It must arrive literally (percent-encoded → 400); `0`, `01`, `+1`, `Latest`, … → 400; an unknown or pruned revision → 404. Each revision is served with **its own** kind (a revision may change kind).

- **Relpath** is taken from the raw path, decoded exactly once, re-validated (C7, C20); the id and revision segments must be literal (percent-encoded → 400). Any `%2F`, `%5C` or `%25` anywhere in a path of either app → 400.
- **Type check at serve time (C8):** stored `media_type` must equal `kind.media_type(relpath)`; on mismatch (or unknown kind) → `application/octet-stream` + `attachment`. Text types (except `text/html`) and JSON get `; charset=utf-8`.
- **Disposition:** `inline` for previews; `attachment` for `/d`, DOWNLOAD-mode kinds (`file`), and `application/octet-stream` files.
- **Caching:** strong `ETag` = `"<sha256>"` (`/t`: `"<sha256>-t<cap>"`; `/r`: `"<sha256>-t<cap>-r<renderer build>"`, so a new renderer build invalidates cached pages); `If-None-Match` → 304 carrying the same `Content-Type` and `Content-Disposition` as the 200 on every preview route (so a PDF 304 keeps the PDF CSP; `tests/security/test_content_type_headers.py::test_304_carries_the_same_type_and_disposition_as_200`).
- **Ranges:** one `bytes=` range only → 206 + `Content-Range`; anything else (multi-range, duplicate `Range`, out of bounds) → 416 + `Content-Range: bytes */size`. A mismatched `If-Range` → full 200.
- **Integrity:** the real blob size must equal the manifest before any header is sent (every file response, ranges included → else 500); full-file responses are checked against the SHA-256 while streaming, ZIPs per member; `/t` and `/r` hash-check files that fit under the cap. A mismatch after the headers went out **aborts the connection** (no clean end of body), so a partial file never looks complete.
- **Bundles (ADR 0012):** HTML-bundle pages are sent with `Referrer-Policy: same-origin`; sub-resources get `CORP: cross-origin` (and may be loaded cross-site) only when `Referer` is `<preview origin>/i/<same id>/<same rev segment>/...` (item **and** revision, ADR 0019); always `Vary: Referer`.
- **Trash:** bytes of trashed items only with `?t=1` (the trash view); without it they're 404, like a missing item.
- **TEXT rendering (unit 9a):** the dashboard never renders item text itself and can't `fetch()` preview bytes (no CORS, ever). It frames `render_page_url` (`/r/…`) in `<iframe sandbox="allow-scripts">`; the formatting (markdown, highlighting, JSON tree, CSV table) runs inside that sandbox on the preview origin. Bytes are never proxied through the dashboard origin.

### Viewer security contract (implemented, unit 8a)

Applies to **every** response of both apps, errors included — enforced by middleware wrapped around the whole FastAPI app (`interfaces/viewer/app_factory.py`), so routes (unit 8b) cannot weaken it. Details: `docs/security.md` C2–C6, C19, C21, C22, C31.

**Request gate (both apps, in order):** service-worker fetch (`Service-Worker` header or `Sec-Fetch-Dest: serviceworker`) → 403; exactly one `Host` equal to the app's value (dashboard: bare `allowed_hosts` name; preview: `host:port` of `preview_origin`) else 400 (missing/duplicate) / 421; exactly one `Tailscale-User-Login` equal to `owner_login` else 403; raw path containing `%2F`/`%5C`/`%25` → 400; fetch metadata (C31) else 403.

| App | Methods | Body | Extra |
|---|---|---|---|
| Dashboard | GET, HEAD, POST (else 405 + `Allow`) | ≤ 1 KiB (413) | POST needs `Content-Type: application/json` (exact), `Origin: https://<host>`, `Sec-Fetch-Site: same-origin`, `X-PDash-CSRF: 1` (else 403) |
| Preview | GET, HEAD (else 405 + `Allow`) | none (413) | Routes declare `PreviewHints(preview_mode, bundle_subresource, item_id)` via `set_preview_hints(request.scope, ...)`; relpaths only via `relpath_from_scope` |

**Response headers:**

| Header | Dashboard | Preview |
|---|---|---|
| `Content-Security-Policy` | `dashboard_csp()` (C6, `trusted-types 'none'`) | `csp_for(media type, preview_mode)`: full `sandbox allow-scripts; …` CSP; only `application/pdf` + DOCUMENT → `default-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors <dashboard>` |
| `Cross-Origin-Resource-Policy` | `same-origin` | `same-site` (`cross-origin` for 2xx bundle sub-resources bound by `Referer`; those also `Vary: Referer`) |
| `Referrer-Policy` | `no-referrer` | `no-referrer`; 2xx/304 of HTML-bundle (SANDBOXED) files: `same-origin` |
| `X-Frame-Options` | `DENY` | — (framed by the dashboard; `frame-ancestors` restricts) |
| `Cache-Control` | `no-store` (route may pick another `private`/`no-store` value) | 2xx/304: `private, no-cache`; errors: `no-store` |
| Both | `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Origin-Agent-Cluster: ?1`, `X-DNS-Prefetch-Control: off`, `X-Permitted-Cross-Domain-Policies: none`, `Permissions-Policy` deny-list, `X-Request-Id` | |
| Never | `Set-Cookie`, `Access-Control-*`, `Server`, `Service-Worker-Allowed`, `Link`, `Refresh`, `Report-To`/`NEL` (stripped if a route sets them); a response with two `Content-Type` or two `Content-Disposition` headers is replaced by a generic 500 (preview 2xx: 403) | |

**Errors:** body is always `{"error": "<code>", "request_id": "<X-Request-Id>"}` with `Content-Type: application/json`; codes `bad_request` 400, `forbidden` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `payload_too_large` 413, `unsupported_media_type` 415, `range_not_satisfiable` 416, `misdirected_request` 421, `internal_error` 500, `service_unavailable` 503. Domain errors map `NotFoundError`→404, `ConflictError`/`InvalidStateError`/`AlreadyExistsError`→409, `LimitExceededError`→413, `UnsupportedContentError`→415, `StorageUnavailableError`→503 (ADR 0025), other `ValidationError`/`DomainError`→400.

**Building blocks used by the routes:** `disposition.content_disposition(kind, filename)` (RFC 6266 + `filename*`), `ranges.parse_range(header, size)` (single range or `RangeNotSatisfiableError` → 416 with `Content-Range: bytes */size`), `relpath_url.relpath_from_scope(scope, segments)` / `encode_relpath_url(relpath)` (decode once from `raw_path`, re-validate), `conditional.py` (ETag/If-None-Match/If-Range), `query_params.py` (strict queries), `streaming.py` (blob/ZIP streaming, abort on mismatch).

**Server (`server.py`):** two uvicorn servers in one process on `viewer_host` (`viewer_port`, `preview_port`), h11, `proxy_headers=False`, `forwarded_allow_ips=""`, `server_header=False`, no access log (C29), `limit_concurrency=64`, `timeout_keep_alive=5`, 16 KiB header cap; SIGINT/SIGTERM stop both; if one server stops or fails the other is stopped too; the core is closed on exit. Pre-app errors (malformed HTTP rejected by h11 before any middleware) are uvicorn's bare 400s without our CSP — they carry no content.

## MCP tools (implemented, unit 10)

Server: `preview-dashboard-mcp` (MCP name `preview-dashboard`), official `mcp` SDK `MCPServer` (FastMCP's v2 name), **stdio only**, started by Claude Code (registration: `docs/operations.md`). A thin client of the admin API over its Unix socket (`interfaces/mcp/client.py`); it never touches storage. Code: `interfaces/mcp/server.py`.

| Tool | Arguments | Returns |
|---|---|---|
| `dashboard_publish` | `paths: list[str]` (1–500 absolute paths), `title: str`, `description: str = ""`, `kind: str \| None`, `base: str \| None`, `pinned: bool = false`, `folder_id: str \| None` | item summary + `files` (relpaths) |
| `dashboard_update_content` | `item_id`, `paths: list[str]` (1–500 absolute paths), `base: str \| None`, `kind: str \| None`, `expected_revision: int \| None` | item summary + `files` (relpaths), `revision` bumped |
| `dashboard_list` | `state: "active" \| "trashed" = "active"`, `kind: str \| None`, `limit: 1–200 = 20`, `cursor: str \| None`, `folder: <folder id> \| "unfiled" \| None` | `{"items": [summary…], "next_cursor"}` |
| `dashboard_get` | `item_id` | summary + `description` + `files: [{relpath, size, media_type}]` |
| `dashboard_update` | `item_id`, any of `title`, `description`, `pinned` | summary (active items only) |
| `dashboard_trash` / `dashboard_restore` | `item_id` | summary (idempotent) |
| `dashboard_move` | `item_id`, `folder_id: str \| None` (None = unfiled) | summary (any state; idempotent) |
| `dashboard_folder_create` | `name` (1–320 raw chars; domain: ≤ 80 after sanitizing) | `{"folder": folder summary}` |
| `dashboard_folder_list` | — | `{"folders": [folder summary + count, trashed_count…], "unfiled_count", "unfiled_trashed_count"}` |
| `dashboard_folder_rename` | `folder_id`, `name` | `{"folder": folder summary}` |
| `dashboard_folder_delete` | `folder_id` | `{"deleted": <id>}`; refused (409) unless empty in every state |
| `dashboard_kinds` | — | the kind registry (`KindRegistry.describe()`) |
| `dashboard_prune_revisions` | `item_id`, `keep: 1–20 = 1`, `expected_revision: int \| None` | `{"revisions_removed", "bytes_freed", "item": summary}` — **permanent** (ADR 0030) |
| `dashboard_empty_trash` | — | `{"items_purged", "blobs_deleted"}` — **permanent** (ADR 0030) |
| `dashboard_progress_set` | `status: object` (schema v1, ADR 0029), `item_id?`, `title?`, `folder_id?`, `pinned?`, `expected_revision?` (needs `item_id`) | progress summary (below); new item (kind `progress`) or new revision |
| `dashboard_progress_update` | `item_id`, `unit_id?` + `state?` (`done\|running\|waiting\|blocked`) / `detail?`, `note?` | progress summary; new revision (always guarded by the last revision this host wrote) |
| `dashboard_ask` | `prompt` (1–200), `options: [{key: [a-z0-9_-]{1,16}, label: 1–40}]` (2–8), `session_label` (required, 1–40), `default_key?`, `item_id?`, `expires_in_s?` (60–604800) — schema bounds are the domain constants (imported, not copied) | `{"question": summary, "wait_command": "preview-dashboard question wait <id>", "how_to_wait"}` |
| `dashboard_wait_answer` | `question_id`, `timeout_s` (1–600, default 600) | `{"question": summary, "timed_out": bool, "hint"?}` — loops `?wait=60` |
| `dashboard_notify` | `event: "done" \| "failed"`, `title` (1–200), `item_id?` | `{"notification": {id, event, item_id, created_at, untrusted_item_data: {title}}}` |
| `dashboard_cancel_question` | `question_id` | `{"question": summary}` (idempotent) |

Question tools live in `interfaces/mcp/tools/questions.py` (`register(server, client)`); they use the admin token and can never answer (there is no answer tool, C34). **Question summary:** `id, state, answer_key, default_key, item_id, created_at, expires_at, resolved_at, viewer_url, option_keys` + `untrusted_item_data: {prompt, options: [{key, label}], session_label, answer_label}` — question text is nested like item text. Long waits: run `wait_command` in the background (below).

**CLI `preview-dashboard question wait <id> [--timeout DURATION]`** (root; default 24h; `90`, `45s`, `30m`, `24h`, `2d`, ≤ 8 days): verifies the admin socket, then loops `GET ?wait=60` with the admin token, reconnecting with backoff (1 s … 30 s) while the admin restarts (socket gone, 502/503/504); an immediate "open" reply (waiter cap full) is paced at 5 s. Prints one JSON line `{"id", "state", "answer_key", "answer_label", "default_key"}` and exits **0** answered, **3** expired, **4** cancelled, **5** timeout (still open), **1** error.

**Progress tools** (`interfaces/mcp/tools/progress.py`, ADR 0029, registered by `main()`): live work trackers in one call, no files. `status` is validated against the `progress` kind's schema v1 (`kinds/progress.py`; exact shape in ADR 0029, advertised as the argument's JSON Schema), stamped with `updated_at`, staged as `<first intake root>/progress-state/stage-<hex>/progress.json` (removed afterwards) and published through the normal intake + `publish`/`publish_revision` path with `kind_hint="progress"` (secret scan included). After each success the tool keeps `progress-state/<item id>/state.json` = `{"revision", "status"}`; `_update` patches that copy and sends its `revision` as `expected_revision`. Errors: invalid status → `invalid progress status: <field> ...`; no local state → `no local progress state ...; call dashboard_progress_set with the full status` (nothing fetched); a newer revision elsewhere → `admin API 409 conflict ... -- the item changed since this tracker's last write ...`. On an existing item `_set` applies `title`/`pinned` (`update_item`) and `folder_id` (`move_item`) after the revision. **Progress summary:** `id, kind, revision, pinned, folder_id, viewer_url, updated_at, units_done ("n/m")` + `untrusted_item_data: {title, status_title}`.

**Permanent-delete tools** (ADR 0030, C43): `dashboard_prune_revisions` → `POST /v1/items/{id}/revisions/prune`, `dashboard_empty_trash` → `POST /v1/trash/empty`. Descriptions and the server instructions say they are PERMANENT, cannot be undone and are for when the owner asked; annotated `destructive_hint`. Same error mapping as the routes (trashed → `409 invalid_state`, stale `expected_revision` → `409 conflict`); the item id is checked locally first.

Folder tools live in `interfaces/mcp/tools/folders.py` (`register(server, client)`, always registered). **Folder summary:** `id, [count, trashed_count], created_at, updated_at` + `untrusted_item_data: {name}` — folder names are nested like titles.

**Item summary** (compact JSON text): `id, kind, state, pinned, created_at, total_size, [trashed_at], file_count, revision, viewer_url, folder_id` + `untrusted_item_data: {title, entry_file, folder_name, …}` — `viewer_url` is the dashboard link to hand the owner (`null` if `allowed_hosts` is unset); `revision` is the item's current head revision number (ADR 0019).

**Validation:** arguments are checked against the tool's JSON schema (pydantic) before any work: `item_id` and `folder_id` must be 26-char ULIDs (the client re-checks before building any URL), `folder` a ULID or `unfiled`, `kind` `^[a-z][a-z0-9_-]{0,31}$`, `title` 1–1000 raw chars, `description` ≤ 20000 (the admin API then applies the domain limits, 200/5000 visible chars); `expected_revision` (if given) is `1..2³¹−1`.

**Publish flow:** `IntakePolicy.collect(paths, base=base)` (below) → `AdminClient.publish(bundle.files, …)`, which streams a manifest-first multipart body (ADR 0014) read chunk by chunk from the intake fds (64 KiB chunks, exact `Content-Length`, no temp files, no whole-file buffering). A file that changes size mid-upload aborts the request; the admin API rolls back.

**Revision flow (`dashboard_update_content`, ADR 0019):** items are updatable in place — an artifact Claude keeps iterating on stays one item with a version history, instead of a new item per iteration. Same intake collection as publish, then `AdminClient.publish_revision(item_id, bundle.files, kind_hint=kind, expected_revision=expected_revision)` → `POST /v1/items/{id}/revisions` (same streamed multipart, fields `kind_hint`, `expected_revision`, `manifest`); the id is validated locally before any request is built. The item keeps its id, title, description, pin and `viewer_url`; the files sent are the *complete* new content. `expected_revision` is optional but recommended when Claude has previously read the item, so a concurrent change isn't silently overwritten. Errors: a trashed item → `admin API 409 invalid_state: trashed items cannot be updated`; a stale `expected_revision` or a concurrent revision → `admin API 409 conflict: item is at revision N, not M; re-read and retry` — both one-line, caller-safe (`AdminConflictError`), so the agent can tell "the item is unpublishable right now" apart from "someone changed it, re-read and retry".

**Errors** are tool results with `isError: true` and one caller-safe line (prefixed by the SDK with `Error executing tool <name>:`), never a stack trace, token, or file content:

| Source | Text | Typed exception (`client.py`) |
|---|---|---|
| Intake | `intake refused (<code>): <why + how to fix>` (codes below) | `IntakeError` |
| Admin 400/415 | `admin API 400 invalid_input: <message>` | `AdminInputError` |
| Admin 401/403 | token/peer refused | `AdminAuthError` |
| Admin 404 / 409 | `not_found` / `invalid_state`, `conflict` | `AdminNotFoundError` / `AdminConflictError` |
| Admin 408/413/429 | limit, quota, timeout, rate (`retry_after`) | `AdminLimitError` |
| Admin 422 | secret scan: `rule <label> in '<relpath>'` (never the bytes); `unsupported_content` | `AdminRejectedError` |
| Admin 5xx / other | `admin API 500 internal_error` | `AdminServerError` |
| Socket down / timeout / malformed reply | `admin API unreachable (…)` | `AdminUnavailableError` |
| Bad arguments | pydantic validation summary | — |
| Anything unexpected | `Error executing tool <name>` only (details on stderr) | — |

Admin messages are escaped (`safe_display`) and bounded before reaching the agent.

### Publish input semantics (intake layer — implemented, unit 10a; follow-ups unit 10b)

`IntakePolicy.collect(paths, *, base=None) -> IntakeBundle` in `interfaces/mcp/intake.py`; the tool layer (unit 10b) passes the agent's paths through unchanged.

| Input | Resulting bundle relpaths |
|---|---|
| one file `/root/outbox/x/report.html` | `report.html` (basename) |
| one directory `/root/outbox/site` | its tree, relative to it: `index.html`, `css/app.css` |
| several paths, no `base` | files → basename; directories → their tree relative to themselves (merged) |
| several paths + `base="/root/outbox/site"` | every path relative to `base` (each path must be equal to or under `base`) |

Rules:
- Paths must be absolute strings, without NUL, unpaired surrogates or `..`, at most 64 components deep; at most `max_files` paths.
- Each path must be under an allowed root (per component — `/root/outbox-evil` is *not* under `/root/outbox`). `/proc`, `/sys`, `/dev` are always refused. A root whose **symlink-resolved** path breaks the config rules (`/`, `/root`, `/etc`, …, or overlapping `/root/.ssh`, the token dir or `data_dir`, compared as configured and resolved) is refused (`outside_roots`).
- Directories are walked recursively in sorted order; any symlink, special file, hardlinked file, denylisted component or invalid name **rejects the whole publish**.
- Relpaths must pass `validate_relpath` (C7). Names are **never renamed automatically**; the error names the exact character or rule, e.g. `path '100%.txt' contains U+0025 PERCENT SIGN '%', which is not allowed ... Rename it before publishing`.
- Two files whose relpaths are equal or differ only by case → `duplicate`.
- Limits: `max_files` files (and directories), `max_file_bytes` per file, `max_item_bytes` total, directory depth ≤ 16.

Errors are `IntakeError(code, message)` (`interfaces/mcp/errors.py`); messages name paths relative to their allowed root (or a basename), escape invisible characters, backslashes and `'` (so a name can't close the quotes around it), and never include file contents.

| `code` | Meaning |
|---|---|
| `invalid_request` | malformed path list/base (NUL, surrogate, `..`, too deep), path not under `base` |
| `outside_roots` | not under an allowed root, in `/proc` `/sys` `/dev`, or the root resolves to a forbidden location |
| `denied` | a component matches a denylist pattern (message names the pattern) |
| `symlink` / `not_regular` / `hardlink` | symlink anywhere; FIFO/socket/device; `st_nlink > 1` |
| `filesystem_boundary` | the walk would cross into another filesystem (`st_dev`) or mount, incl. same-filesystem bind mounts (`mnt_id` from `/proc/self/fdinfo`; unverifiable → refused) |
| `not_found` / `unreadable` | missing path/root, or OS error (permission, I/O error during listing, `fstat` or read) |
| `limit` | file count, directory count, per-file or total bytes |
| `relpath` / `duplicate` / `empty` | invalid bundle name; name collision; no files found |
| `changed` | file swapped during intake, or grew/shrank while being read |

Reading: `IntakeFile.open_reader(chunk_size)` yields chunks read with `pread` from the already-verified fd, exactly `IntakeFile.size` bytes. Close the bundle (`with policy.collect(...) as bundle:`) to release fds.
