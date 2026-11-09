# Architecture

**TL;DR:** Hexagonal (ports & adapters). Five processes (viewer, admin, mcp, purge, notifier) share one core built from `domain/` + `application/` + `ports/`, wired together in a single composition root. Frameworks live only in `adapters/` and `interfaces/`.

## Layers and the dependency rule

```
interfaces (viewer HTTP · admin HTTP · MCP · CLI)
      ↓ calls
application services (publish · history · queries · lifecycle · folders · purge · archive · questions · notify · delivery)
      ↓ depends on
domain (Item, Revision, Folder, Question, Notification, safe paths)  ←  ports (Protocols)
                                                      ↑ implemented by
                         adapters (SQLite repo · filesystem blob store · clock · ULID)
```

Dependencies point **inward only**:

- `domain/` and `application/` import **no frameworks** — stdlib and other core modules only. No `fastapi`, `sqlite3`, `httpx`, or `mcp` imports there.
- `application/` depends on **ports** (`typing.Protocol` interfaces), never on concrete adapters.
- `adapters/` implement ports; `interfaces/` translate HTTP/MCP requests into application-service calls and translate domain errors into HTTP/MCP responses.
- Only `bootstrap.py` (the **composition root**) imports both application services and concrete adapters, and wires them together.

This means the domain and application logic can be fully unit-tested with in-memory fakes (`tests/fakes.py`), with no database, filesystem, or network involved.

## Patterns in use

| Pattern | Where | Why |
|---|---|---|
| **Repository** | `ports/repository.py` (Protocol) + `adapters/sqlite/repository.py` (impl) | Application code queries/persists items without knowing about SQL. |
| **Ports & Adapters (hexagonal)** | `ports/*.py`, `adapters/*` | Swap storage, clock, or ID generation without touching domain/application. |
| **Registry + Strategy** | `kinds/base.py` + `kinds/*.py` | Each content kind (image, html, video, ...) is a self-contained strategy registered once; `GET /api/kinds` exposes the registry as the frontend's single source of truth. |
| **Registry + Strategy** | `events/base.py` + `events/*.py` | Each notification event type (question, done, failed) renders a channel-neutral message; channels only format it (ADR 0021). |
| **Transactional outbox** | `ports/questions.py`, `ports/notify.py` | A question/notification and its deliveries commit together; the notifier only pulls and reports (ADR 0021). |
| **Application services as command handlers** | `application/{publish,queries,lifecycle,purge,archive}.py` | One service per use-case cluster; each method is a use case (e.g. `PublishService.publish(cmd)`). See "Application layer" below. |
| **Composition root** | `bootstrap.py` | The only place that constructs adapters and injects them into services — everything else receives collaborators via constructor. |

## Processes

| Process | Listens on | Reachable by | Can do |
|---|---|---|---|
| **viewer** | `127.0.0.1:8787`, exposed via `tailscale serve` HTTPS (443) + a separate preview origin (8443) | Owner, over the tailnet | View, download, trash, restore |
| **admin** | Unix socket `/run/preview-dashboard/admin.sock` (mode 0660) + bearer tokens (admin; notifier for `/v1/notifier/*` only, ADR 0022) | Local processes only | Publish, update, pin, trash, restore, list; prune old revisions, empty the trash (permanent, ADR 0030); ask/cancel questions, done/failed alerts (admin token); hand out deliveries and record answers (notifier token only) |
| **mcp** | stdio, spawned by Claude Code | Claude only | Thin client of the admin API |
| **purge** | systemd timer (hourly) | n/a (scheduled) | Permanently delete trash older than the retention period; sweep orphaned blobs; expire due questions, delete resolved questions/notifications after 30 days. Host CLI (run as `pdash-admin`): `prune-revisions`, `empty-trash` (ADR 0030) |
| **notifier** (code N4; deploy planned, N5) | nothing (outbound HTTPS to Telegram only) | n/a | Pull deliveries from the admin socket with the notifier token, send/edit Telegram messages, submit button taps as answers; with owner messages on (ADR 0031, M2): post owner texts to the inbox, approval taps and codes to the admin, delete code messages, upload voice notes (`docs/notifier.md`) |
| **claudia host** (code M4b + M5b; deploy M9) | `/run/claudia-host/hook.sock` (root 0600, hook decisions only); admin socket client, `claudia` token | n/a | Claim owner messages, screen them, run Claudia's `claude -p --resume` turns (subscription only, fixed tool sets), answer the risky-action hook, run approval round-trips, audit peer messages, post replies (voice with `/voice`), `/stop` kill switch (ADR 0031, 0037, 0038) |

The services run as dedicated non-root users under systemd hardening: **admin** and **purge** as `pdash-admin` (writes `db/` + `blobs/`), **viewer** as `pdash-viewer` (writes `db/` for trash/restore, blobs read-only); both share the group `pdash` (ADR 0013). The **mcp** process runs as whoever launches Claude Code (root on this host), which is why the admin-side secret scan is the enforcing intake layer (see `docs/security.md` C15). Hardening details: `docs/operations.md`.

## Module map

Planned layout (per the project plan). Modules not yet implemented are marked `(planned)`; they exist as empty `__init__.py` placeholders in this scaffold unit unless noted.

```
src/preview_dashboard/
  config.py         Settings (pydantic-settings) — DONE (unit 1)
  bootstrap.py       DONE (unit 7; N3 questions/alerts wiring) composition root: build_core(settings, role=admin|viewer|purge)
  wire/              DONE (N3) — framework-free shared protocols
    notifier.py        JSON format + paths of /v1/notifier/* (admin routes, AdminDeliveryQueue, notifier)
    notifier_messages.py  M2 — /v1/notifier/{messages,approvals,codes} shapes + `p:<ULID>:ok|no` callback data (ADR 0031)
  domain/            DONE (unit 2) — pure stdlib
    errors.py          DomainError hierarchy
    paths.py           validate_relpath: canonical-or-reject bundle paths (security C7)
    text.py            sanitize_title / sanitize_description for untrusted display text
    unicode.py         Default_Ignorable set, blank look-alikes, is_visible, takes_joiner /
                       takes_presentation_selector (ADR 0026), caseless_key (paths/text)
    models.py          ItemId, ItemState, BlobRef, ItemFile, Revision, Item (+ transitions, revisions)
    questions.py       QuestionId, QuestionOption, QuestionState, Question, AnswerResult (N1, ADR 0021)
    notifications.py   MessageContent, DashboardLinks, Notification, DeliveryTask, DeliveryPayload, PendingTask (N1)
    folders.py         FolderId, Folder, folder-name rules, UNFILED filter sentinel (ADR 0027)
    owner_messages.py  M1 — OwnerMessage inbox entity, owner-sender check, code detection + redaction (ADR 0031, C44)
    approvals.py       M1 — ApprovalRequest (bound action, ActionKind, 24 h expiry (legacy 600 s rows valid), CAS successor rule, resume turn) (C46)
    screen_rules.py    M4a — screening parser `scan_message`, strict `parse_screen_output`, ModelRun (C48)
    query.py           ItemQuery (+ folder filter), Page, ordering rule, keyset cursors, reference paginate()
  ports/             DONE (unit 2) — typing.Protocol definitions
    repository.py      ItemRepository
    folders.py         FolderRepository, FolderCounts (ADR 0027)
    blobstore.py       BlobStore
    clock.py           Clock
    ids.py             IdGenerator (ULID, ADR 0007)
    scanner.py         ContentScanner / ScanSession (secret scan, C15) — unit 4
    questions.py       QuestionRepository, QuestionEvents — N1
    notify.py          NotificationOutbox, OutboxEvents; notifier side: DeliveryQueue, NotificationChannel, AnswerSource, AnswerEvent — N1
    owner_messages.py  OwnerMessageStore — M1 (ADR 0031)
    approvals.py       ApprovalStore — M1 (ADR 0031)
    claudia_screen.py  M4b — Screen, ScreenResult, ScreenVerdict, ScreenHealth (implemented by M4a, C48)
    claudia_host.py    M4b — ClaudeRunner, RunRequest/RunOutcome, TranscriptReader, PeerDirectory, AuditLog, HostAlerts, RunPreflight, WindowIds, HostAdmin
  events/            DONE (N1) — pure stdlib, Registry + Strategy for notification event types
    base.py             RenderContext, EventType protocol, EventRegistry, compose_text()
    question.py done.py failed.py   the built-in event types; __init__.default_event_registry()
    reply.py voice.py   M2 — Claudia's `reply` (body ≤ 4096, never via notify) / `voice` (+ Ogg/Opus caps) (C56)
  kinds/             DONE (unit 3) — pure stdlib, Registry + Strategy
    base.py             PreviewMode, ContentKind protocol, KindRegistry, extension_of()
    image.py svg.py html.py video.py audio.py pdf.py markdown.py code.py json.py csv.py text.py diff.py file.py
    progress.py         DONE (P1) `progress` kind (hint-only) + schema v1 validator/JSON Schema (ADR 0029)
  application/       DONE (unit 4) — use-case services, pure core
    publish.py          PublishService (publish + publish_revision), PublishCommand, RevisionCommand, IncomingFile, PublishLimits
    ratelimit.py        RateLimiter protocol, SlidingWindowRateLimiter (in-process)
    queries.py          QueryService, OpenedFile
    lifecycle.py        LifecycleService (update / trash / restore)
    history.py          DONE (R1) HistoryService.prune_revisions -> PruneResult (ADR 0030)
    folders.py          FolderService (create / list with counts / rename / delete / move), FolderListing (ADR 0027)
    purge.py            PurgeService (run, empty_trash — R1), PurgeReport (+ maintenance / post-purge hooks)
    archive.py          ArchiveService (streamed ZIP), download_filename()
    questions.py        QuestionService, AskCommand (N1)
    notify.py           NotifyService, OutboxService + shared alert helpers (N1)
    delivery.py         DeliveryService — the notifier's rounds (N1)
    claudia/screening.py  M4a — ScreenPipeline (`Screen` port): parser OR strict Haiku, retry, degraded, alert (C48)
    claudia/{windows,runs,audit}.py  M4b — WindowTracker + host commands (C58), tool sets + ClaudiaHost (C51), PeerAudit (C52)
    claudia/{persona,pings}.py  F-CL2 — persona loader (after the host rules) + host progress pings (C51, C56)
    claudia/approval_flow.py  M5b — waiting-for-approval → request from the hook's deny → wait → consume → resume (C46, C55)
    approvals_snapshot.py  M5b — admin writes the viewer's pending-approvals snapshot on every change (C46 view)
  adapters/
    sqlite/{connection,migrations,repository}.py   DONE (unit 5) — SQLite ItemRepository, WAL mode, migrations
    sqlite/questions.py   DONE (N2) — SqliteQuestionRepository + SqliteNotificationOutbox (one store, migration 3)
    sqlite/folders.py     DONE (F1) — SqliteFolderRepository (same database as the items, migration 4)
    sqlite/{owner_messages,approvals}.py   M1 — SqliteOwnerMessageStore + SqliteApprovalStore (admin-only Claudia DB, ADR 0031/0034)
    sqlite/claudia_db.py   F-C1a — admin-only Claudia database: connect_claudia, schema 1 (ADR 0034)
    fs_blobstore.py       DONE (unit 6) — filesystem BlobStore, atomic writes, sharded layout, dirfd confinement
    clock.py               DONE (unit 6) — SystemClock (real UTC wall clock)
    ulid.py                 DONE (unit 6) — UlidGenerator (stdlib-only, canonical ULIDs)
    secret_scan.py          DONE (unit 4) — RegexSecretScanner (ContentScanner, stdlib re)
    admin_queue.py          DONE (N4) — AdminDeliveryQueue (DeliveryQueue over the admin socket, notifier token)
    wakeups.py              DONE (N3) — AsyncioQuestionEvents / AsyncioOutboxEvents (in-process long-poll wake-ups)
    haiku_screen.py         M4a — HaikuScreenRunner: `claude -p --model haiku`, no tools, 0700 temp cwd, allowlisted env (C48, C49)
    claude_cli.py           M4b — API-key refusal, `child_env` allowlist, run argv template, CliClaudeRunner (process groups), `claude agents` peers (C49, C51, C58)
    transcripts.py          M4b — JsonlTranscripts: `SendMessage` calls appended since an offset, O_NOFOLLOW, bounded (C52)
    claudia_admin_client.py M4b — ClaudiaAdminClient (`/v1/claudia/*` incl. A1 cancel routes, M5b approvals + voice), ReplyAlerts (C45, C58)
    approvals_snapshot.py  M5b — FileSnapshotSink (`claudia-view/pending-approvals.json`, 0640, atomic)
    claudia_audit_log.py    M4b — JsonlAuditLog: one 0600 JSONL file per day, no message text (C52)
    telegram/{client,channel,answers,pairing}.py   DONE (N4) — Bot API client (sole token holder), TelegramChannel, TelegramAnswerSource, pairing
                                                   M2: + upload/sendVoice, deleteMessage, approval callbacks (C46, C47, C56)
    telegram/updates.py   M2 — TelegramUpdateSource: one poller for taps + owner messages/codes (C44)
  interfaces/        (planned, units 7-10)
    viewer/            DONE (units 8a security layer, 8b routes + server)
      app_factory.py     build_dashboard_app / build_preview_app: middleware stack around FastAPI
      origins.py         ViewerOrigins (owner, hosts, origins) — fail-closed from Settings
      identity.py csrf.py limits.py service_worker.py fetch_metadata.py   request gates
      headers.py hints.py   per-app/per-file security headers (csp_for)
      errors.py request_id.py   generic error bodies + request id
      disposition.py ranges.py relpath_url.py   pure helpers for item routes
      conditional.py query_params.py streaming.py   ETag/Range helpers, strict queries, blob/ZIP streaming
      services.py        ViewerServices Protocol (satisfied by bootstrap.ViewerCore; folders = read-only FolderLookup) + ViewerOptions
      item_json.py       Item -> JSON with preview-origin URLs (encode_relpath_url, ?t=1 for trash) + folder ref
      static_assets.py   in-memory allowlisted manifest of static/ (no fs access per request)
      routes/dashboard.py  /api/kinds, /api/items[?folder=][/{id}[/trash|/restore|/pin|/unpin|/revisions/prune]], /api/folders (read only), /, /static/*
      routes/preview.py    /i/{id}/{rev}/{relpath} inline, /t/... capped text, /r/... rendered text page, /d/{id}/{rev}[/{relpath}] download/ZIP
      renderer_page.py     /r page builder: escaped JSON + inlined renderer/vendor assets (unit 9a)
      server.py          serve(core): dashboard + preview uvicorn servers in one process
    admin/{app,auth,api,errors,multipart,server}.py  DONE (unit 7) FastAPI app over the Unix socket
    admin/{questions_api,notifier_api,longpoll}.py   DONE (N3) question/alert routes (admin token), /v1/notifier/* (notifier token), long-poll caps
    admin/folders_api.py                             DONE (F2) /v1/folders list/create/rename/delete (admin token); move + ?folder= live in api.py
    admin/cleanup_api.py                             DONE (R1) POST /v1/items/{id}/revisions/prune, POST /v1/trash/empty (admin token, ADR 0030)
    admin/claudia_api.py                             M3 /v1/claudia/* (claudia token): inbox long-poll + handled, replies, approvals create/get/consume, health (ADR 0031, 0032)
    folder_refs.py                                   DONE (F2) FolderLookup Protocol + `folder` JSON refs (one folder listing per response), shared by admin + viewer
    mcp/{server,client,intake,denylist,relpaths,errors}.py  DONE (unit 10) stdio MCP server (MCPServer, ex-FastMCP) + admin client + intake policy
    mcp/tools/questions.py                            DONE (N3) dashboard_ask / _wait_answer / _notify / _cancel_question (register(server, client))
    mcp/tools/folders.py                              DONE (F2) dashboard_folder_create / _list / _rename / _delete (always registered); dashboard_move lives in server.py
    mcp/tools/progress.py                             DONE (P1) dashboard_progress_set / _update + ProgressStateStore (ADR 0029, C42)
    notifier/{runner,commands}.py                     DONE (N4) run loop, serve/pair/test command functions
    notifier/owner_updates.py                         M2 OwnerUpdateRouter: owner texts → inbox, taps → approvals, codes → admin + deleted (ADR 0031)
    claudia/{main,settings}.py                        M4b Claudia host: start checks, poller + worker threads; host settings + settings-source checks (C49, C50, C58, C59); M5b `wire_host`
    claudia/mcp_config.py                             M5b host MCP config check + recap copy (C51, C53)
    question_wait.py                                  DONE (N3) shared wait loop (CLI `question wait`, MCP wait tool), duration parsing
    token_file.py                                     shared token file loader (admin, notifier, Telegram tokens; C12, C36)
    http_server.py                                    shared uvicorn h11 protocol with a header-phase deadline (C26)
    cli.py                                            DONE (unit 7, N3, R1, M3) serve-admin, serve-viewer, serve-notifier, purge, prune-revisions, empty-trash, gen-token, migrate, check-config, question wait, notify pair|test, claudia totp setup
  static/            DONE (unit 9a) dashboard UI — vanilla ES modules, no build step (docs/frontend.md)
    index.html app.css app.js api.js dom.js feed.js item.js chrome.js … renderers/*.js preview-render/* vendor/*   OS-neutral
    os-boot.js os/{registry,storage,shell,shell-menu,background,os-picker}.js os/shell.css                      OS layer (docs/frontend-os.md, ADR 0028)
    os/platinum/{theme.css,chrome.css,shell.js,backgrounds.js,fx/*}                                               Platinum, the default OS
```

## Domain model

All entities are frozen, slotted dataclasses that validate on construction
(also via `dataclasses.replace`), so an invalid `Item` cannot exist.

| Type | Fields / role | Key invariants |
|---|---|---|
| `ItemId` | `NewType` over `str` | canonical ULID (26 chars, uppercase Crockford base32); `parse_item_id` validates untrusted input |
| `BlobRef` | `blob_id, size, sha256` — returned by `BlobStore.put` | blob id is a ULID, `0 <= size < 2**63`, sha256 = 64 lowercase hex |
| `ItemFile` | `relpath, blob_id, size, sha256, media_type` | `relpath` passes `validate_relpath`; media type is lowercase `type/subtype`, no params |
| `Revision` | `number, kind, files, entry_file, created_at` — one published version of an item's content | number 1..2³¹−1; kind syntax; the manifest rules of `Item` below |
| `Item` | `id, title, description, kind, files, entry_file, created_at, updated_at, pinned, state, trashed_at, revision, revision_at, history, folder_id` (None = unfiled, ADR 0027) — `kind`/`files`/`entry_file` are the **head** revision (`revision`, published at `revision_at`, default `created_at`); `history` = older kept revisions, oldest first (ADR 0019) | title 1..200 / description <= 5000 chars after sanitizing (raw input > 4x the limit rejected up front; title needs >= 1 visible char); >= 1 file; relpaths unique under compatibility caseless matching (`caseless_key`) and no file doubles as a directory; `entry_file` in files; datetimes tz-aware (stored UTC; unrepresentable in UTC → `ValidationError`), `updated_at >= created_at`; `trashed_at` set iff TRASHED and `>= created_at`; revisions: numbers strictly increase (history < head), ≤ `MAX_REVISIONS` (20) in total, times never before `created_at` nor decreasing, `revision_at <= updated_at`, no blob id used twice across kept revisions; `folder_id` None or a canonical ULID, kept by every transition, changed only by `moved_to` (any state) |
| `Folder` | `id, name, created_at, updated_at` (ADR 0027) | id canonical ULID; name sanitized like a title, 1..80 chars, ≥ 1 visible char; `name_key` = `caseless_key(name)` (uniqueness); `updated_at >= created_at`; `renamed(name, at)` never runs time backwards |
| `ItemQuery` | `kind` (one kind, shorthand) or `kinds` (tuple; empty = all), `state (=ACTIVE), limit (=50, max 200), cursor, folder` (None = all, a `FolderId`, or `UNFILED`) | kinds: each `validate_kind`ed, at most `MAX_QUERY_KINDS` (8, counted before dedupe), not both `kind` and `kinds`; normalised to `kinds` sorted + deduplicated (adapters read only `kinds`); cursor is position-only, so paging works across several kinds; cursor strictly decoded, `created_us` within the datetime range (`MIN/MAX_CREATED_US`); folder a canonical ULID or the `UNFILED` sentinel; invalid → `ValidationError` |
| `Page[T]` | `items: tuple[T, ...], next_cursor` | `next_cursor` None on the last page |

### Questions and notifications (ADR 0021)

| Type | Fields / role | Key invariants |
|---|---|---|
| `QuestionOption` | `key, label` | key `[a-z0-9_-]{1,16}`; label sanitized single line, 1..40 chars, ≥ 1 visible char |
| `Question` | `id, prompt, options, created_at, expires_at, updated_at, default_key, item_id, session_label, state, answer_key, answer_source, resolved_at` | prompt 1..200 sanitized; 2..8 options, unique keys; `default_key` ∈ keys; session label ≤ 40; `created_at < expires_at ≤ created_at + 7 d`; OPEN has no outcome; ANSWERED has an offered key + source name; terminal states have `created_at ≤ resolved_at ≤ updated_at`, EXPIRED also `resolved_at ≥ expires_at` |
| `MessageContent` | `text, buttons, link` — channel-neutral message | text 1..300 (C35); `long_form=True` (set only by `reply`/`voice`, C56) allows 1..4096 UTF-16 units and no buttons; no control (except `\n`)/bidi/surrogate/private-use chars; ≤ 8 `MessageButton`s, unique keys; link only `https://host/...` (built by `DashboardLinks`) |
| `Notification` | `id, event_type, title, created_at, item_id, question_id` | title sanitized 1..200; only question notifications carry `question_id` |
| `DeliveryTask` | `id, notification_id, channel, action (SEND/RESOLVE), content, created_at, next_attempt_at, state (PENDING/DONE/FAILED), attempts, message_ref, final_state` | attempts 0..8; `message_ref` (≤ 64 visible ASCII) only when DONE; RESOLVE has a terminal `final_state` and no buttons |
| `DeliveryPayload` / `PendingTask` | what the notifier receives (`content, question_id, final_state` / `id, channel, action, payload, message_ref`) | buttons and `final_state` need a `question_id`; RESOLVE needs `message_ref` + `final_state`, SEND neither |

```
          answered(key, source, at)  [OPEN, key offered, at < expires_at]
  OPEN ──────────────────────────────▶ ANSWERED
    │ expired(at)   [at ≥ expires_at] ─▶ EXPIRED      (never auto-answered; default_key is only reported)
    └ cancelled(at)                   ─▶ CANCELLED
```

- Illegal transitions → `InvalidStateError`; an unknown key or a bad source → `ValidationError`; `at < updated_at` → `ValidationError`. `next_change_at(now)` stamps every change strictly after `updated_at` (the CAS version), like items.
- Delivery: `failed_attempt(now)` backs off 5 s × 4ⁿ⁻¹ (≤ 30 min) and gives up (FAILED) at the 8th failure; `dropped()` marks a RESOLVE whose message never went out. The policy lives here, not in adapters.

### State machine

```
            trashed(at)                    retention elapsed (is_purgeable)
  ACTIVE ───────────────▶ TRASHED ─────────────────────────────▶ purged (row deleted)
     ▲                       │
     └──── restored(at) ─────┘
```

- `trashed` on TRASHED, `restored` on ACTIVE, `with_metadata` on TRASHED, and
  `ensure_purgeable` before retention → `InvalidStateError`.
- Time never runs backwards through a transition: `trashed(at)` needs
  `at >= updated_at`, `restored(at)` needs `at >= trashed_at` → else `ValidationError`.
- `is_purgeable(now, retention)`: TRASHED and `now - trashed_at >= retention` (boundary inclusive).
- Metadata (title, description, pinned) is editable only while ACTIVE.
- `with_revision(kind, files, entry_file, at)` (ACTIVE only, `at >= updated_at`) → `(item, pruned)`: the old head moves into `history`, the oldest revisions beyond 20 are returned as `pruned`; id, title, description, pin stay. `next_change_at(now)` = `max(now, updated_at + 1 µs)`, the stamp every change uses (the CAS version).
- `without_history(keep, at=...)` (ACTIVE only, `keep` 1..20 incl. the head via `validate_keep_revisions`) → `(item, dropped)`: keeps the newest `keep - 1` history revisions next to the head, returns the rest oldest first; nothing to drop → the same item, unstamped (ADR 0030).
- Purged is not a state: the row is deleted (then blobs; security C11).

### Ordering and paging

Every listing orders by **pinned first, then `created_at` desc, then `id` desc**
(`domain.query.item_sort_key`). Paging is keyset-based: `next_cursor` encodes
the sort key of the page's last item; the next page holds items whose key is
strictly lower. Cursors are opaque, versioned (`v1`) and must round-trip
exactly. SQL adapters use `(pinned, created_us, id) < (?, ?, ?)`; a decoded
`created_us` is always in the datetime-representable range, and
`created_us_to_datetime` converts it without any possible `OverflowError`. Pinning an
item between two page loads can move it across the cursor (skip or repeat);
accepted for a single-owner feed.

### Errors (`domain/errors.py`)

| Error | Meaning | Typical HTTP mapping |
|---|---|---|
| `ValidationError` (`InvalidPathError` subclass) | input breaks an invariant | 400/422 |
| `NotFoundError` | unknown item/blob | 404 |
| `AlreadyExistsError` | duplicate id on `add` | 409 |
| `InvalidStateError` | illegal transition | 409 |
| `LimitExceededError` | size/count limit | 413 |
| `UnsupportedContentError` | content does not fit a kind | 415/422 |
| `SecretDetectedError` | content/metadata matched a secret rule (`rule` label + `relpath`; never the bytes) | 422 |
| `StorageUnavailableError` | storage refused to serve safely (e.g. `UnsafeDatabasePathError`, C24) — server-side, not input | 503 + `Retry-After` (ADR 0025) |

### Ports

| Port | Methods | Errors |
|---|---|---|
| `ItemRepository` | `add`, `get`, `list(query) -> Page[Item]`, `save(item, *, expected_updated_at)` (compare-and-swap on `updated_at`), `delete -> bool` (idempotent), `delete_if_purgeable(id, cutoff) -> Item \| None` (atomic: only if TRASHED and `trashed_at <= cutoff`), `list_purgeable(now, retention)` (oldest trash first), `all_blob_ids()`, `usage() -> RepositoryUsage(item_count, total_bytes)` (all states, **all kept revisions**); items round-trip with every revision; `save` replaces the stored revisions | `AlreadyExistsError` (add), `NotFoundError` (get, save), `ConflictError` (save: stored `updated_at` != expected) |
| `FolderRepository` (fake; `SqliteFolderRepository`, ADR 0027) | `add(folder, *, max_folders)` (quota + caseless-unique name, atomic), `get`, `list()` (by `name_key`, then id), `rename(folder)` (name + `updated_at`; uniqueness atomic), `delete_if_empty(id)` (atomic), `counts(state) -> FolderCounts(by_folder, unfiled)` (one snapshot; every folder, 0 if empty). Shares its store with the `ItemRepository`, whose `add`/`save` raise `NotFoundError` for a missing `folder_id` | `LimitExceededError`, `AlreadyExistsError` (add, rename), `NotFoundError`, `ConflictError` (delete: an item in any state references it) |
| `BlobStore` | `put(chunks, max_bytes) -> BlobRef`, `open(blob_id) -> BinaryIO` (seekable), `delete` (idempotent), `list_ids(created_before=None)` (complete canonical blobs only), `free_bytes()` | `LimitExceededError` (put over `max_bytes` **or disk full**; nothing partial left), `NotFoundError` (open, incl. malformed ids) |
| `Clock` | `now()` → tz-aware UTC | — |
| `IdGenerator` | `new_item_id()`, `new_blob_id()` → canonical ULIDs | — |
| `ContentScanner` | `new_session() -> ScanSession`; session `feed(chunk)`, `finish()` — chunking-independent | `SecretDetectedError` (feed/finish) |
| `QuestionRepository` (fake; `SqliteQuestionRepository`) | `add_with_notification(question, notification, tasks)` (one transaction), `get`, `save(question, *, expected_updated_at, tasks=())` (CAS + tasks in the same transaction), `list_expirable(now)` (OPEN, `expires_at <= now`), `delete_resolved_before(cutoff) -> int` | `AlreadyExistsError`, `NotFoundError`, `ConflictError`, `ValidationError` (tasks of another notification/question) |
| `NotificationOutbox` (fake; `SqliteNotificationOutbox`) | `add(notification, tasks)` (non-question only), `pending(now, limit) -> [PendingTask]`, `get_task`, `mark_done(task_id, message_ref)`, `mark_failed(task_id, *, now)`, `notification_for_question`, `message_ref_for(question_id, channel)`, `delete_before(cutoff) -> int` | `AlreadyExistsError`, `NotFoundError`, `ValidationError`; done/failed on a non-PENDING task = no-op |
| `OwnerMessageStore` (fake; `SqliteOwnerMessageStore`, ADR 0031) | `add(message) -> OwnerMessage` (idempotent on `update_id` + `telegram_message_id`: returns the stored one), `get`, `list_unhandled(limit)` (RECEIVED, oldest first, 1..100), `mark_handled(id, at)` (CAS), `delete_received_before(cutoff) -> int` | `AlreadyExistsError` (id of another update), `NotFoundError`, `InvalidStateError` (already handled), `ValidationError` |
| `ApprovalStore` (fake; `SqliteApprovalStore`, ADR 0031) | `add(request)` (PENDING only; one open, unexpired request per window, atomic), `get`, `save(request, *, expected_updated_at)` (CAS + `check_successor` under the same lock), `find_consumed(window, action_kind, target, *, consumed_since)` (hook lookup, C59), `list_open(window=None)`, `list_expirable(now)`, `delete_expired_before(cutoff) -> int` | `AlreadyExistsError`, `ConflictError` (open request in window; stale version), `NotFoundError`, `InvalidStateError` (illegal step), `ValidationError` (granted create, immutable field changed) |
| `QuestionEvents` / `OutboxEvents` | `notify(...)` (thread-safe, after commit), `async wait(..., timeout) -> bool` — advisory wake-ups for long-polls | — |
| `DeliveryQueue` (notifier side) | `pending(wait)`, `done(task_id, ref)`, `failed(task_id)`, `submit_answer(question_id, key, source, actor_ref) -> AnswerResult` | transport errors propagate |
| `NotificationChannel` / `AnswerSource` (notifier side) | `name`, `send(payload) -> ref`, `resolve(ref, payload)` / `name`, `poll(timeout) -> [AnswerEvent]`, `ack(handle, text)` | any exception = failed try |

Port obligations (docstrings in `ports/` are normative):

- **BlobStore:** validate the id as a canonical ULID before building any
  path; never follow symlinks (refuse a symlinked root/blob dir, open blobs
  `O_NOFOLLOW`); never expose staging files; disk full → `LimitExceededError`
  with nothing left behind; `created_before` compares against the moment the
  blob became visible, on the same clock the application uses.
- **ItemRepository:** parameterized queries only; rebuild entities through
  their constructors on read so tampered rows are re-validated.
- **QuestionRepository / NotificationOutbox** (one shared store): the same
  two rules; a RESOLVE is handed out only after the SEND of the same
  notification + channel is DONE with a ref (returned as its `message_ref`),
  waits while that SEND is PENDING, and is marked FAILED by `pending` if the
  SEND is missing, FAILED or has no ref. `tests/fakes.py` is the reference.

#### Orphan-sweep protocol

A publish writes blobs first, then commits the DB row (C11), so between the
two a blob is unreferenced but not an orphan. The sweep (`application/purge.py`) is:

1. `candidates = blobs.list_ids(created_before=now - grace)` — snapshot **first**;
2. `referenced = repo.all_blob_ids()` — read references **second**;
3. delete `candidates - referenced`.

`grace` (`orphan_grace_seconds`, default 3600) must exceed the **hard publish
timeout** (`publish_timeout_seconds`, default 600; `Settings` rejects
`grace <= timeout`) that `PublishService` enforces: a publish that has not
committed within the timeout is aborted and never commits afterwards (the
deadline is re-checked immediately before `repo.add`; the remaining gap is
microseconds against a 50-minute margin). Any blob in the snapshot is then either
referenced by a committed row (seen in step 2) or belongs to an aborted
publish. Reversing steps 1 and 2 would race a publish that commits in between.

### Contract tests

`tests/contracts/item_repository.py` (`ItemRepositoryContract`) and
`tests/contracts/blob_store.py` (`BlobStoreContract`) are base classes: a
concrete adapter test subclasses one and overrides a single fixture (`repo` /
`store`). They run today against the fakes (`tests/unit/test_fake_contracts.py`),
since unit 5 against `SqliteItemRepository`
(`tests/integration/test_sqlite_repository.py`), and since unit 6 against
`FsBlobStore` (`tests/integration/test_fs_blobstore.py`), all unchanged.
`ItemRepositoryContract` also needs a `folders` fixture (the folder
repository over the same store) for its folder tests; `tests/contracts/folder_repository.py`
(`FolderRepositoryContract`, fixture `store` → `FolderStore(items, folders)`)
runs against the fakes and SQLite (`tests/integration/test_sqlite_folders.py`).
`tests/contracts/question_store.py` (`QuestionRepositoryContract`,
`NotificationOutboxContract`; fixture `store` → `NotifyStore(repo, outbox)`
over one shared backend) runs against the fakes and, since N2, SQLite
(`tests/integration/test_sqlite_questions.py`).
`tests/contracts/{owner_message_store,approval_store}.py` (fixtures `ms` / `aps`)
run against the fakes and SQLite (`tests/integration/test_sqlite_claudia_stores.py`). See
`docs/extending.md`. The blob-store suite has two optional hooks (skipped
unless overridden): `outside_sentinel` (a file outside the store root that
traversal-shaped ids must never open or delete) and `store_with_capacity(n)`
(a store that is "full" after n bytes).

## Application layer

**TL;DR:** `application/` holds one service per use-case cluster. Each takes
its collaborators (ports, `KindRegistry`, plain limit values) through its
constructor; none imports an adapter, `config.py` or a framework —
`bootstrap.py` maps `Settings` to `PublishLimits`/durations and wires them.

| Service | Methods | Notes |
|---|---|---|
| `PublishService` | `publish(PublishCommand) -> Item`, `publish_revision(RevisionCommand) -> Item` | Limits, quotas, rate limit, secret scan, deadline, rollback (below); a revision takes no item slot, commits by CAS (one retry), deletes pruned revisions' blobs after the commit; `PublishCommand.folder_id` files the new item (folder checked right after the rate limit, again atomically by `repo.add`) |
| `FolderService` (ADR 0027) | `create(name) -> Folder`, `get(id)`, `list(*, state=ACTIVE) -> FolderListing(folders=(FolderEntry(folder, count), ...), unfiled_count)`, `rename(id, name)`, `delete(id)`, `move(item_id, folder_id \| None) -> Item` | names sanitized by `Folder`, then scanned raw + sanitized (C15, C39); quota `max_folders` (200); rename/move to the current value are no-ops; `move` works in any item state, is an item CAS stamped by `next_change_at`, one re-read + retry on `ConflictError`; missing folder → `NotFoundError` (C41) |
| `QueryService` | `list(query)`, `get(id)`, `revision(id, number, *, allow_trashed) -> (Item, Revision)`, `open_file(id, relpath, *, allow_trashed, revision=None) -> OpenedFile` (`.revision` = the file's revision), `kinds()` | relpath is validated, then only a **manifest lookup key** (exact match), never a path (I2); a hidden trashed item and a missing one raise the same `NotFoundError` |
| `LifecycleService` | `update(id, title?, description?, pinned?)`, `trash(id)`, `restore(id)` | `trash` of a trashed item / `restore` of an active one are **idempotent no-ops** (double clicks never error; `trashed_at` isn't bumped, so retention isn't extended); `update` of a trashed item → `InvalidStateError`; edited text is secret-scanned (raw and sanitized); every save is a compare-and-swap on `updated_at`, stamped strictly after the item's last change (clock steps back are clamped); `trash`/`restore` re-read and retry once on `ConflictError`, `update` raises it (→ 409) |
| `PurgeService` | `run(now=None) -> PurgeReport(items_purged, blobs_deleted, orphans_deleted, maintenance)`, `empty_trash() -> PurgeReport` | Conditional row delete first, then blobs; orphan sweep; hooks (below). `empty_trash` (ADR 0030): every TRASHED item now, listed first (all pages), each deleted by `delete_if_purgeable(id, its listed trashed_at)` so a restore mid-run wins; unreferenced blobs after; failures left to the sweep; post-purge hooks if rows went |
| `HistoryService` (ADR 0030) | `prune_revisions(id, *, keep=1, expected_revision=None) -> PruneResult(item, revisions_removed, bytes_freed)` | ACTIVE only; CAS save via `Item.without_history`, re-read + recomputed once on `ConflictError`; dropped blobs deleted after the commit (failures logged, swept later); nothing to prune → no write |
| `ArchiveService` | `stream_zip(id, *, allow_trashed=False, revision=None) -> Generator[bytes]`, `download_filename(item, revision=None)` | Lookup is eager (404 before streaming); bytes lazy |
| `QuestionService` | `ask(AskCommand) -> Question`, `get(id)`, `answer(id, key, source) -> AnswerResult`, `cancel(id)`, `expire_due(now=None) -> int` | ask: rate limit → options → `Question.new` → scan raw + sanitized prompt/keys/labels/session → question + notification + one SEND per enabled channel in one transaction. Every resolution is a CAS save with its RESOLVE tasks, then `events.notify`; one re-read + retry on `ConflictError`. `get` expires lazily; `answer` never raises on untrusted id/key (`UNKNOWN`) and expires instead of answering past the deadline; `cancel` is idempotent (a resolved question is returned as is) |
| `NotifyService` | `notify(event_type, title, item_id=None) -> Notification` | non-actionable types only (`done`, `failed`); same shared rate limiter as `ask`; title scanned raw + sanitized; link from `DashboardLinks` only |
| `OutboxService` | `pending(limit)`, `done(task_id, message_ref)`, `failed(task_id)` | what `/notifier/*` may do (N3); answers go through `QuestionService.answer` |
| `DeliveryService` (notifier) | `run_once_deliveries() -> int`, `run_once_answers() -> int` | routes tasks to channels by name; channel error → `failed` (backoff); taps → `submit_answer` → ack (`Recorded: <key>`, `Already answered`, `Expired`, `Withdrawn`, `Unknown`; admin unreachable → `Not recorded, try again`); logs ids and exception type names only (C36) |
| `SlidingWindowRateLimiter` | `acquire()` | Implements the `RateLimiter` protocol; thread-safe, **in-process** (one admin process); every attempt counts, including failed publishes; timed on an injected **monotonic** clock (wall-clock jumps can't reopen the window) |

### Publish sequence

```
publish(cmd)
 1. deadline = monotonic() + timeout            (injected monotonic clock)
 2. rate_limiter.acquire()                      every attempt counts (C18)
 3. len(files) <= max_files; validate_relpath each
 4. kind = registry.detect(relpaths, hint)      hint syntax-checked first (validate_kind)
 5. Item.new(...) on placeholder files          real invariants before any byte moves
 6. scan raw AND sanitized title/description   metadata is content too (C15); sanitized
    + relpaths                                   = placeholder item's values (ZWSP/NFC tricks)
 7. free_bytes() > min_free_disk_bytes
 8. quota.reserve()                             item slot + byte budget, counting in-flight publishes
 9. per file: session = scanner.new_session()
        blobs.put(guarded(chunks), max_bytes = min(max_file, item budget left, free - floor))
        guarded(): deadline check + session.feed(chunk) before yielding each chunk
        session.finish()
        media_type = item_kind.media_type(relpath)   never client input, never media_type_for (C8)
10. deadline check -> Item.new(...) -> deadline check -> repo.add(item)
 on ANY exception (BaseException): delete every blob stored so far (best effort), re-raise
   - once repo.add was entered: only if repo.get(id) -> NotFoundError (else keep
     the blobs the stored row references; get fails -> keep all; sweep = backstop)
 finally: quota.release()
```

- Limits are enforced on **streamed bytes**; there is no declared size.
- Budget errors name the file and the byte budget (not which of per-file /
  per-item / quota / disk bound it, since disk-full `put` errors look the same).
- A secret found inside `put` propagates out of the chunk iterator (the
  store leaves nothing behind) and is re-raised with the file's relpath.

### Revision sequence (ADR 0019)

```
publish_revision(cmd)          same steps 1-4 as publish (deadline, rate limit, files, kind)
 5. Revision(...) on placeholder files     manifest checks before any byte moves
 6. scan relpaths                          (title/description don't change here)
 7. current = repo.get(id); ACTIVE? expected_revision == current.revision?
 8. free-disk floor; quota.reserve(new_item=False)   byte budget only
 9. stream + scan every file (as publish)
10. (item, pruned) = current.with_revision(..., at=current.next_change_at(now))
    deadline check -> repo.save(item, expected_updated_at=current.updated_at)
    ConflictError -> re-read, re-check 7, retry once
 on failure: rollback as publish (after save was entered: keep blobs the stored item references)
 after commit: delete the blobs of `pruned` (best effort; orphan sweep = backstop)
```

### Purge

0. With `questions=QuestionHousekeeping(expire_due, questions, outbox,
   retention=30 d)` (ADR 0021), **before** step 1: expire due questions
   (enqueues their RESOLVEs), delete notifications (with their tasks) created
   before `now - 30 d`, then resolved questions resolved before it. Post-purge
   `PurgeReport` gains
   `questions_expired`, `questions_deleted`, `notifications_deleted`.
1. For each `list_purgeable(now, retention)` item: `repo.delete_if_purgeable(id,
   now - retention)` — atomic, so an item the owner restored after the
   listing survives. The blob ids of **every kept revision** of the
   returned items become candidates.
2. Delete `candidates - repo.all_blob_ids()` (a blob still referenced
   elsewhere is kept).
3. `post_purge` hooks (e.g. SQLite WAL checkpoint) — only if step 0 or 1 removed rows.
4. Orphan sweep (protocol above).
5. `maintenance` hooks, every run, e.g. `{"staging": lambda:
   fs.sweep_staging(older_than=grace)}` — the core never knows about staging files.

Every step is idempotent; a crash between 1 and 2 leaves orphans for step 4
of a later run, never a dangling row.

### Secret scan (C15, ADR 0008)

`adapters/secret_scan.py` (`RegexSecretScanner`) runs one compiled regex per
rule, each starting with a literal (fast prefix search, ~100+ MB/s), with a
token-boundary lookbehind right after the literal and bounded/possessive
quantifiers (linear time on adversarial input). A session buffers 256 KiB of
new bytes per pass and keeps a 16 KiB overlap (> the longest possible match,
12,304 bytes), so detection does not depend on chunking. Errors carry only a
neutral rule label (e.g. `AWS access key id`) and the relpath.

## Composition root (`bootstrap.py`, unit 7)

**TL;DR:** `build_core(settings, role=...)` is the only code that constructs
adapters; it returns a frozen, role-specific container (least privilege)
that owns and closes the adapters' resources.

| Role | Container | Services | Notes |
|---|---|---|---|
| `admin` | `AdminCore` | `publish`, `queries`, `lifecycle`, `folders` (`FolderService`), `history` (`HistoryService`), `trash_bin` (`TrashBin`: `empty()` only, over a `PurgeService` with the WAL-compact hook), `kinds`, `questions`, `notify`, `outbox`, `question_events`, `outbox_events`, `answer_sources` | `RegexSecretScanner`, `SlidingWindowRateLimiter(publish_rate_per_hour / 1 h)`, `PublishLimits` from `Settings`; questions/alerts: `SqliteQuestionRepository` + `SqliteNotificationOutbox` on the same connection factory, **one** `SlidingWindowRateLimiter(notify_rate_per_hour)` shared by ask + notify, `DashboardLinks(dashboard_base_url)`, channels/answer sources `("telegram",)` only when `notify_enabled`, TTL `question_ttl_seconds`, asyncio wake-ups (`adapters/wakeups.py`) |
| `viewer` | `ViewerCore` | `queries`, `archive`, `trash` (`TrashControl`: trash/restore only), `pins` (`PinControl`: pin flag only, ADR 0020), `folders` (`FolderReader`: `list`/`get` only, C40), `kinds` | blob store wrapped in `ReadOnlyBlobStore` (`put`/`delete` → `PermissionError`); **no** publish or text-edit capability |
| `purge` | `PurgeCore` | `purge` (never touches folders), `history` (CLI `prune-revisions`) | maintenance hook `staging` → `FsBlobStore.sweep_staging(orphan_grace)`; post-purge `repo.compact()` (WAL checkpoint + truncate); `QuestionHousekeeping` (its own `QuestionService.expire_due` over the SQLite store, same channels, so expiries enqueue RESOLVEs; wake-ups are no-ops there) |

Every role: `verify_config_file_secure()` on the TOML (C16) → open the DB
once (`connect(default_db_path(data_dir), trusted_uids, trusted_gid,
migrate=role == "admin")`: validates layout, fail fast; only the admin
creates/migrates — viewer and purge require an existing DB at
`CURRENT_VERSION`, never running DDL) → `SqliteItemRepository(factory)`
→ `FsBlobStore(data_dir, reserve_bytes=min_free_disk_bytes,
trusted_owner_uids)` → `SystemClock`, `UlidGenerator`, `default_registry()`.
`StorageTrust(uids, gid, sidecar_uids)` carries who may own the layout
(viewer: add the admin uid, via `serve-viewer --trusted-owner-uid`) and who
may additionally own the DB's `-wal`/`-shm` only (admin/purge/`migrate`:
the viewer uid, via `--trusted-sidecar-uid`, ADR 0025). Use `with build_core(...)
as core:` (or `core.close()`) to release the blob store's directory fds.

Interfaces receive a core, never adapters: `interfaces/admin/app.build_admin_app(core, token=..., notifier_token=...)`,
`interfaces/cli.py` (process entry points), and the viewer server module
(`interfaces/viewer/server.serve(core)`, unit 8b).

### Admin interface (`interfaces/admin/`)

| Module | Responsibility |
|---|---|
| `app.py` | `build_admin_app(core, token, notifier_token, allowed_peer_uids, notifier_peer_uids, form_limits)`: FastAPI (no docs, no debug) inside request-id → access-log → catch-all → peer-policy → bearer-auth middleware |
| `auth.py` | `load_admin_token` (file checks), `TokenVerifier` (constant time), `BearerAuthMiddleware` (admin vs notifier token per route family, role in scope), `SO_PEERCRED` helpers, `PeerPolicyMiddleware` (allowlist per family) — ADR 0022 |
| `api.py` | `/v1` item routes (incl. `POST /v1/items/{id}/move`, `?folder=`); hand-parsed inputs; blocking service calls via `anyio.to_thread` (`run_blocking`); item JSON gains `folder` via `interfaces/folder_refs.py` |
| `folders_api.py` | `/v1/folders` list (active + trashed counts) / create / rename / delete over `FolderService` (ADR 0027) |
| `cleanup_api.py` | `POST /v1/items/{id}/revisions/prune` over `HistoryService`, `POST /v1/trash/empty` over `TrashBin` — permanent deletes, `require_admin` first (ADR 0030, C43) |
| `questions_api.py` | `/v1/questions` (ask, get + long-poll, cancel), `/v1/notifications` — admin token; no answer route (C34) |
| `notifier_api.py` | `/v1/notifier/tasks` (long-poll, one poller), `.../done`, `.../failed`, `/v1/notifier/answers` (the only path to `QuestionService.answer`); M3: `/v1/notifier/messages` (inbox, refusals → 422), `/approvals` (Approve/Deny tap), `/codes` (TOTP, the only path to APPROVED) — notifier token |
| `claudia_api.py` | `/v1/claudia/messages` (`?wait=0..60&limit=1..20`, one poller) + `/{id}/handled`, `/replies`, `/approvals` (create, always PENDING), `/approvals/{id}` (`?wait`), `/approvals/{id}/consume` (single use), `/health` — claudia token; 400 when `claudia_enabled` is off (C45) |
| `longpoll.py` | `WaiterSlots` (16 question waiters, 1 notifier poller, 1 Claudia inbox poller, 4 approval waiters), `long_poll` (event-loop wait, 5 s re-read, stops on client disconnect) |

**Token families (C45):** `auth.route_family(path)` maps `/v1/notifier/*` → notifier, `/v1/claudia/*` → claudia, everything else → admin. Wrong family 403, no/unknown token 401; the three tokens must differ (startup refuses). Peer-uid allowlists are per family (`--claudia-peer-uid`).

**Claudia application services (M3, `bootstrap.ClaudiaCore`):**

| Module | Responsibility |
|---|---|
| `application/inbox.py` | `InboxService` (owner re-check, re-redact, idempotent add, handled CAS), `ScreenHealthBoard` |
| `application/approvals.py` | `ApprovalService`: create (secret scan; `flagged_message` text built from the stored message), tap, approve, consume, cancel / cancel_open (close-only, A1), lazy expiry (24 h; legacy 600 s); every step a store CAS |
| `application/approval_prompts.py` | `OutboxApprovalPrompts` (A1): one `approval` notification with `approval_id` + one SEND per channel; text = stored action text; the channel adds Approve/Deny `p:<id>:ok\|no` |
| `application/stepup.py` | `StepUpService.submit_code`: owner only, duplicate update, lockout, one TAPPED request, RFC 6238 ±1 step, burn step before approving, wrong-code alert |
| `application/replies.py` | `ReplyService` (policy, scan, 3/message + 120/hour budget) → `OutboxReplyQueue` (event `reply`, long-form outbox task) |
| `domain/totp.py` | HOTP/TOTP, strict base32, `StepUpState` (replay mark, failures, lockout, last update id) |
| `ports/stepup.py`, `ports/claudia.py` | `TotpSecretSource`, `StepUpStateStore`; `ChangeEvents`, `ApprovalPrompts`, `ReplyOutbox` |
| `adapters/totp_secret.py`, `adapters/stepup_state.py` | secret file (0640, root/trusted group, no ACL, re-read per code); `stepup-state.json` (0600, atomic replace) in `data_dir` |

`ApprovalPrompts` is wired to `OutboxApprovalPrompts` (ADR 0033): the outbox hands a prompt out only while its request is PENDING and unexpired (`notifications.approval_id` looked up in the admin-only Claudia DB through the injected `ApprovalStore`, ADR 0034; else settled unsent); no channel → create 503 + request cancelled. `claudia totp setup` burns its confirmation step via `FileStepUpState(owner_uid=…)`.
| `multipart.py` | streaming publish intake: push parser → bounded channel → `PublishService` in a worker thread (ADR 0014) |
| `errors.py` | domain error → status/code mapping, generic 500, request ids, access log |
| `server.py` | binds the 0660 socket itself (refusing to replace a live instance's), `PeerCredH11Protocol` (peer creds + the header deadline from `interfaces/http_server.py`), hardened `uvicorn.Config` |

### Claudia screening (unit M4a, C48/C49)

**TL;DR:** the host screens every inbox message with `ScreenPipeline.screen(message)` (the `Screen` port, `ports/claudia_screen.py`): no-AI parser first, then strict Haiku with parser hits as hints. Only "no parser hit + not forwarded + valid `ok`" is actionable; everything else runs read-only. `screen()` never raises.

| Module | Responsibility |
|---|---|
| `domain/screen_rules.py` | `scan_message(text, forwarded, quote)` → `ParseResult` (rule names + line numbers only, ≤ 50 hits); `parse_screen_output(stdout)` → `ok` / `suspicious` / None; `ModelRun`, `ModelRunStatus` |
| `application/claudia/screening.py` | `ScreenPipeline(runner, alerts)`: payload (hints + `<owner_message>` block), 15 s + 1 retry on timeout, failure streak → one `HostAlerts.failed` at 3, `health()`; `ScreenModelRunner` Protocol; `SCREEN_SYSTEM_PROMPT` (V4 prompt + D14 carve-out) |
| `adapters/haiku_screen.py` | `HaikuScreenRunner`: fixed argv (`screen_argv`), message on stdin, fresh 0700 temp cwd, `child_env` allowlist, own process group killed on timeout, stderr discarded |

Parser rules (any hit flags): instruction phrases EN/ES (regex on the NFKC + look-alike-folded line, plus a leetspeak "skeleton" of the whole message), role prefixes, role/tool tags (incl. the `owner_message` delimiter), resume-turn look-alikes (`Approved/Denied by the owner`, `Treat flagged message`, `request <26 chars>`), shell commands incl. prose `rm`/`curl`, fences, links, emails, base64/long tokens, secrets, forwarded/quoted lines, invisible chars (emoji ZWJ/VS16 allowed), non-Latin letters, non-ASCII digits, stacked marks, > 6 lines, > 1500 chars, forwarded flag, quoted reply.

| Model step outcome | Verdict (no parser hit) | Counts as failure |
|---|---|---|
| valid `ok` | `ok` | no (resets streak) |
| valid `suspicious` | `flagged` | no |
| timeout twice | `flagged` | yes |
| invalid output (bad JSON, extra/duplicate keys, fence, `is_error`) | `flagged` | yes |
| non-zero exit | `flagged` | yes |
| CLI missing / not executable | `degraded` | yes |
| exception (runner or parser) | `flagged` | yes |

A parser hit or the forwarded flag makes every row `flagged`. Health: 0 failures `ok`, 1–2 `degraded`, ≥ 3 `down`. Reasons are fixed labels (`parser:<rule>`, `haiku:ok`, `screen:timeout`, …); the model's own `reason` text is validated but dropped (hostile-shaped). Tests: `tests/security/test_screening.py` (fake runner + fake `claude` script; fixtures `tests/fixtures/screen_samples.jsonl` = V4 40 + 22 M4a cases).

### Claudia host (unit M4b, C49–C52, C58)

**TL;DR:** `interfaces/claudia/main.py` refuses to start with an API key set or unsafe settings, then a **poller** thread claims each inbox message (handled CAS) and runs `/stop` `/status` `/voice` at once, while a **worker** thread runs every other message through `ClaudiaHost`: screen → full or read-only tool set → `claude -p` turn (own process group, prompt on stdin; host rules + her persona appended) → transcript audit → reply. Long runs get fixed host progress pings ("👀 On it…", "⏳ Still working… N min"), cancelled before the reply (F-CL2, ADR 0040). An **approvals** thread watches parked approval requests and queues their settle work for the worker (F-CL3, ADR 0041).

| Module | Responsibility |
|---|---|
| `application/claudia/windows.py` | `WindowTracker` (one window; idle 3 h, cap 8 h, never while busy; `/stop` halt flag + halt epoch: a message queued before the stop never clears it), `parse_host_command` (exact whole-message match) |
| `application/claudia/runs.py` | `TOOL_SETS` (full / read-only / recap; Telegram tools always disallowed; `builtins` = exact `--tools` list from `KNOWN_BUILTINS`), `build_prompt` (ok = owner text verbatim; else host note + text between per-turn nonce markers), `ClaudiaHost` (message flow, recap on close, `/stop` = generation bump + halt + `kill_all(epoch=…)` + cancel-open; every run re-checks its generation right before spawning, `/status` health only) |
| `application/claudia/persona.py` | F-CL2: `PersonaLoader.block()` reads `persona.md` through the KB read port at every run (all sets), `check_persona` (≤ 4 KiB, C53 character rules, every `<!-- -->` comment stripped), pinned by SHA-256 at host start (changed file → run without it + one `failed` alert, F-CL2b), framed `[Claudia persona — tone and style only; the host rules above always win]`; missing/invalid → run without it + one log line (reason class) |
| `application/claudia/pings.py` | F-CL2: `ProgressPings` / `PingTicket` — host-sent fixed texts for owner-message runs only ("👀 On it…" at 20 s, "⏳ Still working… N min" at 5 and 10 min, ≤ 3); `cancel()` returns only when no ping is in flight, called before the final reply, on `/stop` and on shutdown; `is_ping_text` (the admin's allow-list) |
| `application/claudia/audit.py` | `PeerAudit`: every `SendMessage` of a run → audit entry (target, summary, length, SHA-256; no text); missing prefix / unapproved interactive or unknown target / unreadable transcript → violation → alert + `/stop` |
| `adapters/claude_cli.py` | `refuse_api_credentials`, `child_env` (allowlist), `build_run_argv` (fixed template, `=`-form tool lists, validated window UUID), `CliClaudeRunner` (`start_new_session`, bounded stdout, timeout, `busy()` while a run's group has members; stop-epoch check + spawn + pid registration under one lock; `/stop` also kills `setsid`-detached descendants still linked in `/proc`), `ClaudeAgentsDirectory` (unknown kind → interactive) |
| `adapters/transcripts.py` | `JsonlTranscripts`: `<projects>/<cwd slug>/<window>.jsonl`, reads only bytes after the pre-run offset, `O_NOFOLLOW`, ≤ 16 MiB slice, ≤ 1 MiB line |
| `adapters/claudia_admin_client.py` | `ClaudiaAdminClient` (bounded, token only in headers; reply refusal → `False`, handled 409 → `False`), A1 cancel routes, `ReplyAlerts` (fixed `Alert (failed): …` replies) |
| `interfaces/claudia/settings.py` | `load_host_settings` (root-owned, not group/world-writable, no symlink, every C50 deny rule, exactly the C59 hook entry, no `disableAllHooks`/bypass), `check_settings_sources` (user/project/local/managed: no switch-off, no own `PreToolUse`/`PermissionRequest` hook), `SettingsPreflight` (both, plus "unchanged since start", before every run) |
| `deploy/claudia/settings.json` | the host settings file (installed as `/etc/preview-dashboard/claudia-settings.json`; hook command = M5's `preview-dashboard-claudia-hook`) |

Run argv (C51): `claude -p --output-format json --permission-mode auto --strict-mcp-config --mcp-config <host> --settings <host> --tools=<exact built-ins> --allowedTools=<set> --disallowedTools=<set> (--session-id|--resume) <window uuid> --append-system-prompt=<HOST_RULES_PROMPT>[\n\n<framed persona>]`; golden tests in `tests/security/test_claudia_runs.py` (persona order: `tests/security/test_claudia_tone_pings.py`). Turn → tool set: `ok` → full; `flagged` / `degraded` → read-only (quoted); window close → recap (read-only + KB tool, `--mcp-config <state_dir>/recap-mcp.json` = same servers with `claudia-kb --caller recap`). Both MCP configs are pinned (SHA-256) at start; `McpConfigPreflight` (chained after `SettingsPreflight`) refuses a run if either changed (ADR 0039). `build_host` (M5b) wires M4a's `ScreenPipeline(HaikuScreenRunner, ReplyAlerts)` as the screen; see "Claudia approval flow" below for the rest of the wiring. Tests: `tests/security/test_claudia_{env,runs,settings,stop}.py`, `tests/security/test_peer_audit.py` (fixture `tests/fixtures/claudia_transcript.jsonl`), `tests/unit/test_claudia_windows.py`; runner tests use a stand-in CLI script, never `claude`.

### Claudia knowledge base (unit M6, C53)

**TL;DR:** Claudia changes her notes only through the host MCP server `claudia-kb` (`kb_read`, `kb_write`, `kb_delete`). `KbService` enforces the fixed layout, caps and the C15 secret scan; `FsKbStore` stores with fd-relative `O_NOFOLLOW` I/O and one git commit per run. `persona.md` is read-only for every caller.

| Module | Responsibility |
|---|---|
| `application/claudia/kb.py` | `KbService` (`read`/`write`/`delete`/`commit_run`/`seed`), `classify` (layout regexes, ASCII `[a-z0-9-]{1,48}` segments), caps, frontmatter `sources` check, `load_prompt`; refusals are `KbRefusedError` (message = the reason, never content) |
| `ports/claudia_kb.py` | `KbStore` Protocol (`read`, `size`, `write`, `delete`, `stats`, `commit`) |
| `adapters/kb_store.py` | `FsKbStore`: dir fds opened `O_NOFOLLOW`, temp file + atomic rename, regular single-link files only (symlink / FIFO / hardlink refused), dirs 0750 / files 0640 (+ optional viewer gid), `git` via argv with scrubbed env, fixed identity, hooks off, no remote, only `*.md` staged |
| `interfaces/claudia/kb_mcp.py` | stdio MCP server (`--root`, `--caller`, `--viewer-gid`); commits once when the run ends (also on SIGTERM) |
| `application/claudia/prompts/` | `recap.md` (window-close prompt) and `seed/{persona,index,now}.md` templates; a leading `<!-- -->` header is stripped on load |

Caps: `now.md` 40 lines / 4 KiB; `index.md` 100 lines / 8 KiB; `_topic.md` 150 words; note 300 words / 4 KiB; journal 10 bullets / 4 KiB; work-log 16 KiB; 2000 notes; 8 MiB total. Notes, journal and work-log need frontmatter with a non-empty `sources:` (pointers written `kind:ref@version`: dashboard revision, git commit or mtime, PR `updated_at`). Tests: `tests/security/test_kb_writes.py`, `tests/unit/test_kb_mcp.py`. The host (M4b) must call `KbService.commit_run` after a run too (idempotent) and pass the `claudia-kb` entry in its `--mcp-config`.

### Claudia risky-action hook (unit M5a, C59, C60)

**TL;DR:** `preview-dashboard-claudia-hook` (PreToolUse, registered by `deploy/claudia/settings.json`) forwards each Bash / Edit / Write / NotebookEdit / SendMessage / dashboard call to the host over `/run/claudia-host/hook.sock` (root, 0600, 5 s) and prints **only** `deny` (exit 2) or nothing (exit 0, the guard decides). The host's `HookGate` denies a risky call unless the run in progress holds an unused CONSUMED approval with the same `action_kind` + `action_target`. It never grants (ADR 0037).

| Module | Responsibility |
|---|---|
| `domain/shell_lex.py` | Strict bash lexer: words (quote removal; `dynamic` / `pattern` flags), operators, redirections, heredocs; `$(…)`, backticks, `<(…)`, expanding heredoc bodies lexed recursively; bad quoting / > 16 levels / > 256 KiB → `ShellSyntaxError` |
| `domain/risky_actions.py` | `classify_tool_call(tool, input, cwd, *, realpath)` → `None` or `RiskyAction(kind, target)` (kind None = `unknown`); target builders `pr_target`, `push_target`, `rm_target`; `is_protected_path`; `PEER_MESSAGE_PREFIX` |
| `application/claudia/hook_gate.py` | `HookGate`: `begin_run(window, covers)` / `end_run()`, `decide(raw) -> HookDecision` (never raises); C60 for `SendMessage`; audit `hook_deny` / `hook_cover_used` (kind + target only) |
| `interfaces/claudia/hook.py` | The hook command (stdlib only): trims the call, checks the socket (socket, trusted owner, no group/other bits), 5 s budget, 8 s alarm, strict reply parse; every failure → deny |
| `interfaces/claudia/control_socket.py` | `ControlSocketServer(gate, path).start()` / `close()`: root-owned non-writable dir, umask 0177 + chmod 0600, `SO_PEERCRED` uid check, one JSON line per connection (≤ 512 KiB, 5 s), ≤ 16 at once |

Classifier rules (each has its own test in `tests/security/test_risky_hook.py`):

| Form | Result |
|---|---|
| `gh pr merge N\|URL` (+ `-R/--repo`, `GH_REPO=`) | `pr_merge`, target `owner/repo#N` (no repo or a branch → no target) |
| `*/install.sh`, `bash … install.sh`, `source install.sh` | `deploy`, target = resolved script path |
| `git push` with no refspec, `--all/--branches/--mirror/--delete/-d/--prune`, `:ref`, `HEAD`/`@`, a glob or any destination `main`/`master` | `git_push_main`, target `<repo dir> <remote>` (after `-C`; `--git-dir`/`--work-tree` → no target) |
| `rm` / `unlink` / `shred` / `rmdir` | `rm`, target = sorted, shell-quoted resolved paths; globs, `~`, `$x`, `..`, xargs, a `cd` in the command → no target |
| `find -delete`, `find -exec rm` | `rm`, no target |
| Edit/Write/NotebookEdit or a Bash write (`>`, `tee`, `cp`, `sed`, `dd of=`, …) to `.claude/settings*.json`, the host settings file, managed settings, `/opt/preview-dashboard/**`, `deploy/claudia/settings.json` | `settings_edit`, target = resolved path (also checked through `realpath`) |
| `dashboard_trash` / `dashboard_prune_revisions` / `dashboard_empty_trash` | `dashboard_delete`, target item id / `trash` |
| `gh api` non-GET, `-f/-F/--field/--raw-field/--input`, `graphql`; `gh alias set`; `python -c`, `node -e`, `perl -e`, `bash -c`, `sh -c`, code on stdin; `claude`, `eval`, `trap`, `alias`, `awk system()`; `$CMD`, globbed or `$'…'` names; `git -c alias.*`; unknown wrapper or git options; unparseable | `unknown` (no approval covers it) |

Wrappers stripped first: `sudo`, `doas`, `pkexec`, `env`, `xargs`, `command`, `builtin`, `nice`, `ionice`, `timeout`, `stdbuf`, `exec`, `time`, `nohup`, `setsid`, `flock`, `chrt`, `taskset`, `unbuffer`, `busybox`, absolute paths, a leading `\`, assignments, keywords. Two different risky actions in one call → `unknown`; several `rm`s merge their path sets.

**M5b wiring (done; F-CL3 dropped the peer lookup):** `gate = HookGate(DenialRecorder(audit_log), clock, realpath=os.path.realpath)`; `ControlSocketServer(gate).start()` at host start (dir `/run/claudia-host`, systemd `RuntimeDirectory` 0700; unsafe dir → exit 2); around **every** run `gate.begin_run(window.id, covers)` … `gate.end_run()` in a `finally` (also the recap run). Hook `session_id` must equal the window id (`--session-id` / `--resume`): **to verify at deploy** (live `claude` not run in development; C60 check). Tests: `tests/security/test_{risky,peer}_hook.py`, `tests/unit/test_shell_lex.py`.

### Claudia approval flow (unit M5b, C46 resume, C55; ADR 0038)

**TL;DR:** a full-set run that ends with the line `waiting for approval: <description>` makes the **host** open one request for the action the C59 hook **last denied in that run** (kind + target from the classifier, never from her words; text `<label>: <target> (<description>)`), long-poll it (since F-CL3 parked and polled off the worker, see below), consume it once approved and resume with the stored request's `resume_turn()` in a full run whose only cover is that approval. A denial in that run is a guard block: one `failed` alert, no re-run, action locked for the window (C55).

```
run ends "waiting for approval: …"
  ├─ read-only turn (flagged/degraded) → flagged_message request (admin builds text) ─┐
  └─ full turn → DenialRecorder.last(window) → action / peer_message request ─────────┤
       (none → fixed "the check didn't see the exact step"; C55-locked → fixed text)   │
POST /approvals (PENDING) ← ApprovalAdmin.request_approval  ◄──────────────────────────┘
GET /approvals/{id}?wait=50 … until not PENDING/TAPPED (deadline = expiry + 5 s; /stop → cancel, silent)
  DENIED   → read-only run, prompt = resume_turn() ("Denied by the owner: … Do not run it.")
  APPROVED → POST /consume (must be `consumed`) → full run, prompt = resume_turn(),
             gate covers = (consumed,) [flagged_message: none], audit approved_sessions = peer target
             permission_denials > 0 with an action cover → C55: alert, lock text + kind/target, stop
  EXPIRED  → fixed text; CANCELLED → nothing
≤ 3 chained round-trips per owner message.
```

| Module | Responsibility |
|---|---|
| `application/claudia/approval_flow.py` | `parse_waiting_request` (last non-empty line only), `build_action_text` (structured head first, unsafe description dropped), `DenialRecorder` (`AuditLog` decorator in front of the gate's log; keeps the last `hook_deny` with a canonical kind + target per window, cleared at every run start), `ApprovalFlow` (`follow`, `status_line`, C55 locks per window, dropped on window close) |
| `application/claudia/runs.py` | `ClaudiaHost`: `_run` wraps every run in `gate.begin_run/end_run`, commits the KB (`KbService.commit_run`) after it, passes approved peer sessions to `PeerAudit.audit_run`; `_reply_run` speaks the reply with `/voice` on (`VoiceComposer` → `POST /v1/claudia/voice`, text fallback); `/status` adds the open approval (kind, state, minutes left; never its text) |
| `ports/claudia_host.py` | `ApprovalAdmin`, `RunGate`, `KbCommits`, `VoiceReplies`; `RunRequest.recap` |
| `adapters/claudia_admin_client.py` | `request_approval` (409 → `ConflictError`, 400/413/422 → `ValidationError`, answer must be PENDING and match), `get_approval` (same id), `cancel_approval` (result code; `busy` retried), `cancel_open_approvals` (`{"window_id"}` body, parses `{"cancelled": [...]}`), `cancel_all_open_approvals` (`{}`: every window; host start, shutdown and `/stop`, F-CL3b), `send_voice` |
| `interfaces/claudia/mcp_config.py` | `load_mcp_config` (root-owned, exactly `preview-dashboard` + `claudia-kb`, `python -I -m …kb_mcp --root <abs> --caller claudia [--viewer-gid N]`, no `env`), `write_recap_config` (0600, atomic) |
| `interfaces/claudia/main.py` | `wire_host`: screen pipeline, gate + control socket, flow, `KbService(FsKbStore(kb root from the MCP config))`, voice (`<state_dir>/voices` present → Piper) |
| `application/approvals_snapshot.py`, `adapters/approvals_snapshot.py` | admin side: `SnapshotOnChange` wraps the approval change events; every change rewrites `<data_dir>/claudia-view/pending-approvals.json` (0640, dir group, atomic; open + unexpired only; > 50 or any failure → file removed) in M8's format (`application/pending_approvals.py`) |

Tests: `tests/security/test_approval_flow.py` (C46 resume, C55, gate/KB/voice wiring), `tests/security/test_approvals_snapshot.py`, `tests/security/test_claudia_wiring.py`.

### Claudia unblock (unit F-CL3, ADR 0041)

**TL;DR:** she can ask directly with `request_approval` (claudia-kb MCP server → host control socket → `ApprovalFlow.request_from_tool`); requests live 24 h and are **parked**, not waited on: a third host thread polls them and queues settle work for the worker, so she keeps chatting and an approval after the window closed resumes in the current or a new window with a carried cover. Peer messages need only the prefix; deny reasons say what to do.

```
her run ─ mcp__claudia-kb__request_approval(kind, target, reason)
  kb_mcp (caller claudia only) ─ HostApprovals ─ root 0600 control socket {"v":1,"approval":{…,"nonce"}}
    (nonce = CLAUDIA_RUN_NONCE: made per run by ClaudiaHost._run, set in the child env by the runner)
    ControlSocketServer ─ ApprovalFlow.request_from_tool: run nonce, run + actionable, kind ∈ APPROVABLE_KINDS,
      target normalized like the hook, reason 1–120 safe chars, 1 per turn, chain < 3, not C55-locked
      → ApprovalAdmin.request_approval (same admin route + limits) → park → "pending <id>"
approvals thread: HostLoop.watch_once → flow.poll_parked() (GET ?wait, deadline expiry + 5 s)
  → queue _Settle(decided) → worker: ClaudiaHost.settle_approval (stale generation → dropped)
    APPROVED → consume → run_resume_turn: current window or WindowTracker.open_for_resume
      → gate.begin_run(window, (consumed,), carry_over=window ≠ asked window)
host start / shutdown / /stop: ClaudiaHost.cancel_stranded_approvals / stop → cancel-open {} (all windows, F-CL3b)
```

| Module | F-CL3 change |
|---|---|
| `domain/approvals.py` | `APPROVAL_TTL` 24 h, `LEGACY_APPROVAL_TTL` 600 s, `APPROVAL_TTLS` (the only accepted lifetimes), `APPROVABLE_KINDS` |
| `application/claudia/approval_flow.py` | `RunContext`, `ParkedApproval`, `ToolAnswer`; `begin_run/end_run`, `request_from_tool`, `poll_parked`, `settle`, `cancel_parked`, `open_approvals`; `status_line` → `approvals open: N (kind, state, expires in XhYYm)` |
| `application/claudia/hook_gate.py` | `HookGate(audit, clock, *, realpath)` (no peer lookup); `begin_run(…, carry_over=False)`; C60 = prefix only; `needs_approval`, `REASON_UNKNOWN_ACTION`, `REASON_PATTERN` |
| `application/claudia/runs.py` | `APPROVAL_TOOLS` (FULL only), host rules 4–6, `has_approvals`, `poll_approvals`, `settle_approval`, `run_resume_turn(… message_id, generation, chain)`; `/stop` cancels parked requests too |
| `application/claudia/windows.py` | `WindowTracker.open_for_resume(generation)` (never past a halt or newer stop epoch) |
| `application/approvals_snapshot.py` | panel lists PENDING + TAPPED only |
| `interfaces/claudia/approval_tool.py` | `HostApprovals.request(kind, target, reason)` (socket owner/mode checked, fixed texts on failure) |
| `interfaces/claudia/control_socket.py` | `ControlSocketServer(…, approvals=)`: strict `approval` line → `ApprovalRequester` |
| `interfaces/claudia/kb_mcp.py` | `request_approval` tool registered for caller `claudia` only |
| `interfaces/claudia/main.py` | `_Settle` work item, `HostLoop.watch_once`, `approvals` thread |

Tests: `tests/security/test_claudia_unblock.py`, `test_peer_hook.py`, `test_peer_audit.py`, `test_approvals.py::test_fcl3_*`, `test_approvals_snapshot.py::test_fcl3_*`.

### Claudia gardener (unit M7, C54)

**TL;DR:** weekly: free rule pre-pass over the KB, Haiku (KB tool only) fixes the flagged notes, the host re-checks every changed file and reverts the run on any violation.

| Piece | Role |
|---|---|
| `application/claudia/garden_rules.py` | Pure `analyze(notes, today)`: duplicates, oversized, orphans, broken `[[links]]`, stale / unversioned / `updated since` pointers, journals > 30 days. Detail text is rule-made and sanitised. |
| `application/claudia/garden.py` | `Gardener`: baseline commit, pre-pass (nothing found: no model), model, commit, verify (<= 30 files, layout, caps, secret scan, `persona.md` untouched, no `index.md`/`now.md` delete), revert via one commit, report. Ports only. |
| `ports/claudia_gardener.py` | `KbGit`, `GardenModel`, `GardenReporter`. |
| `adapters/kb_git.py`, `adapters/gardener_runner.py` | git history/revert; `claude -p --model haiku --tools "" --strict-mcp-config` with a KB-only MCP config (`--caller gardener`), `--max-turns 20`, allowlisted env. |
| `interfaces/claudia/gardener.py` | Entry (refuses API-key env, exit 2), admin-API reporter: one summary item + one `done`/`failed` alert. The systemd timer is unit M9. |

Tests: `tests/security/test_gardener.py`, `tests/unit/test_garden_rules.py` (fake model, real tmp git repo).

### Knowledge map (unit M8, C57)

**TL;DR:** the dashboard app (never the preview app) reads Claudia's KB **read-only** on each request: a bounded fd-relative walk → a stdlib parser (only `[[links]]` + frontmatter `tags`/`updated`) → nodes, edges, categories with opaque ids → `#/knowledge` draws them as SVG. It also lists open approvals from a snapshot file the admin writes. Off (404) without `kb_root` or with an unsafe root.

| Piece | Role |
|---|---|
| `ports/kb_source.py` | `KbSource.walk() -> KbWalk(notes, skipped, truncated)`, `ApprovalsSnapshotSource.read() -> bytes \| None`. |
| `adapters/kb_reader.py` | `FsKbReader`: root must be its own realpath, a root-owned directory, not group/world-writable; `O_DIRECTORY\|O_NOFOLLOW` per level, names `[A-Za-z0-9._-]` without a leading dot, depth ≤ 4, regular `.md` with one link, ≤ 64 KiB each, ≤ 2000 files / 8 MiB per walk, inode re-checked after open, strict UTF-8; skipped entries are **counted** (logs carry no names). `FileApprovalsSnapshot`: same no-follow rules, ≤ 256 KiB, else None. |
| `application/kb_graph.py` | `KbGraphService.graph()` / `.note(id)`: parser caps (frontmatter 40 lines / 4 KiB, 20 tags, 200 links), categories (`topics/<cat>/…`, top level = `core`, else first dir), titles from file names, Obsidian-style link resolution (path suffix; ambiguous → same folder or unresolved), tag edges chained (n−1 per tag), ≤ 20 000 edges, `recent` = updated in the last 7 days. Ids = HMAC-SHA256(per-process key, relpath)[:32]; a note is found again in a fresh walk, so ids never encode a path. |
| `application/pending_approvals.py` | `PendingApprovalsService.current()`: strict v1 snapshot (format in `docs/api.md`), expired entries dropped, any invalid entry → unavailable. Never raises. |
| `interfaces/viewer/knowledge.py` | `build_knowledge(settings)`: wires the two adapters for the viewer entry point (the map is viewer-only, so it is not part of `build_core`). |
| `interfaces/viewer/routes/kb.py` | `GET/HEAD /api/kb/graph`, `/api/kb/notes/{id}`, `/api/claudia/approvals` behind the same gates as every dashboard route; no query parameters; ETag/304. |
| `static/knowledge-map.js` + `kmap-*.js` | The window (docs/frontend.md). |

Config (TOML only; env cannot set them): `kb_root` (absolute, unset = map off), `claudia_approvals_snapshot` (absolute, unset = "nothing waiting"). Tests: `tests/security/test_kb_source.py`, `tests/security/test_viewer_approvals.py`, `tests/unit/test_kb_graph.py`, `tests/unit/test_kmap_js.py`.

### Viewer interface (`interfaces/viewer/`, units 8a + 8b)

`server.serve(core)` builds both apps from the `ViewerCore` (which satisfies the `ViewerServices` Protocol in `services.py`: `kinds`, `queries`, `trash`, `pins`, `archive`, `folders` — read only) and runs them as two uvicorn servers in one process. Routes: `docs/api.md`; decisions: ADR 0005, 0012, 0015.

| App | Routes | Reads | Writes |
|---|---|---|---|
| dashboard (`routes/dashboard.py`) | `/api/kinds`, `/api/items[?folder=][&kind=a,b]` (`kind`: one name or a comma list of ≤ 8 — never a repeated key; empty element, bad name or > 8 → 400), `/api/items/{id}[?rev=]`, `/api/folders`, `POST .../trash`, `POST .../restore`, `POST .../pin`, `POST .../unpin`, `POST .../revisions/prune`, `/`, `/static/*` | `QueryService.list/revision`, `FolderReader.list/get` (one listing per response for `folder` refs), registry, in-memory static manifest (without `vendor/`, `preview-render/`) | `TrashControl.trash/restore`, `PinControl.set_pinned`, `RevisionPruner.prune_old` (keep=1, blobs left to the orphan sweep; ADR 0030) only (no folder writes, C40) |
| preview (`routes/preview.py`) | `/i/{id}/{rev}/{relpath}`, `/t/…`, `/r/…`, `/d/{id}/{rev}`, `/d/{id}/{rev}/{relpath}` (`rev` = number or `latest`) | `QueryService.open_file/revision`, `ArchiveService.stream_zip` | nothing |

Item byte request, e.g. `GET /i/<id>/3/sub/a.css`:

1. Middleware gates (request id → headers → catch-all → SW guard → Host/identity → raw-path guard → GET/HEAD → no body → fetch metadata).
2. Route: literal id + revision check → revision segment parsed (`latest` → head) → strict query (`t=1`) → `relpath_from_scope` (raw, decoded once, validated) → `QueryService.open_file` (revision → manifest lookup → blob id → `BlobStore.open`).
3. `plan_for`: stored type == the **revision's** kind type? else octet-stream attachment; disposition; `PreviewHints(mode, bundle_subresource, item_id, revision)`.
4. Real blob size == manifest, else 500 before headers; then 304 / 416 / 206 / 200 via `BlobStreamResponse` (verifies SHA-256 on full files; closes the blob on end, error or disconnect).
5. On the way out: fetch-metadata verdict (incl. Referer binding for bundle sub-resources) and per-file CSP/CORP/Referrer-Policy.

## SQLite ItemRepository (`adapters/sqlite/`, unit 5)

`SqliteItemRepository` implements the `ItemRepository` port over SQLite.
Three small modules, one responsibility each:

| Module | Responsibility |
|---|---|
| `connection.py` | `connect(db_path, *, trusted_uids=None, trusted_gid=None) -> sqlite3.Connection`: validates (or creates: `db/` 2770 setgid, file 0660) the location under the shared-group model, re-checks `db/` and the file inodes after connecting, applies the hardening pragmas (WAL asserted), then migrates. Errors: `UnsafeDatabasePathError`, `DatabaseSetupError`. `default_db_path(data_dir)` returns `data_dir/db/items.sqlite3`. |
| `migrations.py` | Versioned, forward-only schema via `PRAGMA user_version`; one `migrate(conn)` entry point over the shared `apply_migrations(conn, steps)` engine (refuses a newer schema). |
| `claudia_db.py` | `connect_claudia(db_path, *, create=True)` / `default_claudia_db_path(data_dir)`: the admin-only Claudia DB (0700/0600, own schema 1; see "Claudia database" below). |
| `repository.py` | `SqliteItemRepository(conn_factory, *, sleep=time.sleep)`: the port implementation, plus adapter-only `compact(*, attempts=10, delay_seconds=0.05) -> bool` (WAL TRUNCATE checkpoint; purge `post_purge` hook). |
| `questions.py` | `SqliteQuestionRepository(conn_factory)` + `SqliteNotificationOutbox(conn_factory)` over one store (N2, ADR 0021): same connection-per-call, `BEGIN IMMEDIATE` writers, static SQL and rebuild-on-read rules. |

**Connections and concurrency:** `SqliteItemRepository` opens one connection
per call (via an injected `conn_factory`, normally
`functools.partial(connect, db_path)`) and closes it before returning — no
connection is ever shared across threads or held between calls, which is
what makes the adapter safe for the admin, viewer and purge processes to
open the same file concurrently (docs/security.md C11). Every write starts
with an explicit `BEGIN IMMEDIATE` (acquire the write lock up front, not
opportunistically) and every connection sets `busy_timeout=5000`, so a
writer that loses the race waits instead of failing with "database is
locked" under ordinary contention; `journal_mode=WAL` lets readers and
writers proceed without blocking each other. Reads that need more than one
statement (`get`, `list`, `list_purgeable`: item rows, then file rows) run
in one deferred read transaction, so they see a single snapshot — a
concurrent delete can't make an item appear without its files. This was
chosen over one big JOIN: the static per-shape SQL constants stay simple,
and the per-item file lookup is an in-process index probe (SQLite's "N+1"
costs microseconds, not round trips). `delete_if_purgeable` runs its check
and delete inside one `BEGIN IMMEDIATE`; so does `save`, whose `UPDATE ...
WHERE id = ? AND updated_us = ?` is the optimistic-concurrency
compare-and-swap (rowcount 0 → existence check → `NotFoundError` or
`ConflictError`). The adapter never opens (and so
never closes) an fd on a DB file itself: closing any fd on a file drops all
of the process's POSIX locks on it, which would break SQLite connections in
other threads; files are `lstat`-ed through a held `db/` fd instead.
`synchronous=NORMAL` is safe
specifically because the connection is in WAL mode (see the docstring on
`connection.connect` for the full reasoning) — it cannot corrupt the
database on a crash, only possibly lose the single most recent commit.

**Schema** (migration 1, then migration 2 for revisions, `migrations.py`):

```
items (id PK, title, description, kind, entry_file,
       created_us, updated_us INTEGER, pinned INTEGER CHECK(0|1),
       state TEXT CHECK('active'|'trashed'), trashed_us INTEGER NULL) STRICT

revisions  (item_id FK -> items(id) ON DELETE CASCADE, number CHECK(>= 1),
            kind, entry_file, created_us, PRIMARY KEY (item_id, number)) STRICT

item_files (item_id, revision, relpath, blob_id UNIQUE, size, sha256, media_type,
            position, PRIMARY KEY (item_id, revision, relpath),
            FK (item_id, revision) -> revisions ON DELETE CASCADE) STRICT
```

Migration 2 (ADR 0019) adds `items.revision` (head number, default 1),
creates `revisions` (one row per existing item: revision 1 at its
`created_us`) and rebuilds `item_files` with a `revision` column (create,
copy, drop, rename; SQLite can't change a primary key in place).
`items.kind`/`entry_file` stay as copies of the head's values so
`list()`'s kind filter keeps its index; a row whose copies disagree with
its head revision fails closed on read. Deleting an item cascades to its
revisions and their files; `save` deletes and re-inserts the revisions
(pruned ones disappear with their file rows).

Migration 3 (N2, ADR 0021) adds the question/outbox store (all `STRICT`,
enum columns `CHECK`ed, children `ON DELETE CASCADE`):

```
questions        (id PK, prompt, default_key, item_id, session_label, created_us,
                  expires_us, updated_us, state, answer_key, answer_source, resolved_us)
question_options (question_id FK, position, key, label; PK (question_id, position), UNIQUE key)
notifications    (id PK, event_type, title, item_id, question_id UNIQUE FK -> questions, created_us)
delivery_tasks   (id PK, notification_id FK, channel, action, state, attempts,
                  next_attempt_us, created_us, message_ref, final_state, text, link)
delivery_buttons (task_id FK, position, key, label; PK (task_id, position), UNIQUE key)
```

| Rule | How |
|---|---|
| Atomic ask / resolution | question + options + notification + tasks + buttons in one `BEGIN IMMEDIATE`; `save` = `UPDATE ... WHERE id = ? AND updated_us = ?` (CAS) + RESOLVE inserts in the same transaction, so only the winning answer enqueues |
| One message per channel | partial `UNIQUE (notification_id, channel) WHERE action = 'send'`; a RESOLVE `LEFT JOIN`s that SEND |
| `pending` | one read snapshot (no write lock on the long-poll path), lazy scan in `(next_attempt_us, created_us, id)` order; RESOLVEs with nothing to edit are then marked FAILED in a short write (`WHERE state = 'pending'`; that condition never reverts) |
| Indexes | partial `questions (expires_us, id) WHERE state = 'open'` (`list_expirable`), `questions (resolved_us) WHERE state <> 'open'`, `notifications (created_us)`, partial `delivery_tasks (next_attempt_us, created_us, id) WHERE state = 'pending'`, `delivery_tasks (notification_id)` (cascade); enum literals are written in the SQL so partial indexes apply |
| Deletes | `delete_before` cascades to tasks/buttons; deleting a question also cascades to its notification (purge deletes notifications first anyway); `item_id` has no FK (items may be purged first) |
| Re-validation | every question, option, notification, task and button is rebuilt through its constructor (tamper tests in `tests/integration/test_sqlite_questions.py`) |

Migration 4 (F1, ADR 0027) adds folders; every existing item becomes unfiled:

```
folders (id PK, name, name_key UNIQUE, created_us, updated_us) STRICT
items.folder_id TEXT NULL REFERENCES folders (id) ON DELETE RESTRICT
idx_items_folder_order ON items (folder_id, state, pinned DESC, created_us DESC, id DESC)
```

| Rule | How |
|---|---|
| Quota / unique names | `add` counts and checks `name_key` inside `BEGIN IMMEDIATE`; `UNIQUE name_key` is the backstop (`IntegrityError` → `AlreadyExistsError`) |
| No dangling reference | item `add`/`save` check the folder under the same write lock (`NotFoundError`); the FK rejects anything else |
| Only empty folders go | `delete_if_empty` checks `items` (any state) under the write lock; `ON DELETE RESTRICT` is the backstop (`ConflictError`) |
| Listings | `folder_id IS ?` (NULL = unfiled) + state + feed order, all from `idx_items_folder_order` (no sort step; `tests/integration/test_sqlite_folders.py::TestFolderQueryPlans`) |
| Re-validation | folders rebuilt through `Folder(...)`; a stored `name_key` that isn't the key of the stored name → `ValidationError` |

Migration 5 (M3 + A1, ADR 0031/0033) adds only outbox columns: `delivery_tasks.long_form INTEGER NOT NULL DEFAULT 0 CHECK (0, 1)` (reply tasks up to 4096 UTF-16 units; existing rows stay 0 = 300-char alerts) and `notifications.approval_id TEXT NULL` (no FK). Any schema newer than the code is refused by `migrate()` (`DatabaseSetupError`, checked before and under `BEGIN IMMEDIATE`).

**Claudia database** (`claudia_db.py`, ADR 0034): Claudia's inbox and approval requests live in a **separate, admin-only file**, `data_dir/claudia/claudia.sqlite3` (dir 0700, file + sidecars 0600, owner = the admin uid; looser modes, another owner, symlinks, hardlinks or a swapped inode → `UnsafeDatabasePathError`, never fixed). Only the admin (Claudia on) creates and migrates it (`connect_claudia(path, create=True)`, own `user_version` 1, shared `apply_migrations` engine); purge opens it with `create=False`; the viewer never does. Reason: the viewer writes the item DB, so rows there could be forged (S-C1 S1). The outbox's `pending()` asks the injected `ApprovalStore` whether a prompt's request is PENDING and unexpired (no cross-file JOIN); no store / gone / tampered → settled unsent, unreadable DB → held for the next poll. Schema 1:

```
owner_messages (id PK, update_id, telegram_message_id, text, received_us, is_forwarded 0/1,
                reply_to_message_id NULL, quote_text NULL, state received|handled, handled_us NULL,
                UNIQUE (update_id, telegram_message_id)) STRICT
approval_requests (id PK, window_id, kind action|flagged_message|peer_message, action_kind NULL,
                   action_target NULL, action_text, message_id NULL (no FK), state (7 values),
                   created_us, expires_us, updated_us, tapped_us, approved_us, resolved_us) STRICT
idx_owner_messages_unhandled (received_us, id) WHERE state = 'received'; idx_owner_messages_received (received_us)
idx_approval_requests_open (window_id, created_us, id) WHERE state IN open states
idx_approval_requests_consumed (window_id, action_kind, action_target, resolved_us) WHERE state = 'consumed'
idx_approval_requests_expires (expires_us, id)
```

| Rule | How |
|---|---|
| Inbox idempotency | `add` looks up the Telegram pair and inserts under one `BEGIN IMMEDIATE`; `UNIQUE` is the backstop |
| Handled once | `UPDATE … WHERE id = ? AND state = 'received'` (CAS), after the domain transition |
| No granted create / one open per window | `add` refuses non-PENDING; checks open, unexpired requests of the window under the insert's write lock |
| Approval steps | `save` re-reads + rebuilds the row, CAS on `updated_us`, `check_successor` (one legal edge, bound action immutable), then writes only mutable columns (immutables also in the `WHERE`) |
| Re-validation | rows rebuilt through `OwnerMessage` / `ApprovalRequest`; a planted code or an `action_kind` outside the closed enum (e.g. `unknown`) → `ValidationError`; batch reads skip such rows (id logged, never text) |
| Housekeeping | purge's `InboxHousekeeping` (only when `claudia_enabled`): first `ApprovalService.expire_due` (overdue open requests → EXPIRED), then messages with `received_us` and approvals with `expires_us` older than 30 days |

Datetimes are stored as integer microseconds since the Unix epoch, UTC —
the same encoding `domain.query`'s cursors use, so paging needs no
conversion beyond `domain.query.created_us_to_datetime` (which also bounds
the value, so a tampered row can't overflow on read). `STRICT` tables
reject the wrong storage class outright; `ON DELETE CASCADE` (needs
`PRAGMA foreign_keys=ON`, set on every connection) removes a deleted item's
files in the same statement. Five indexes back the query shapes `list()`,
`list_purgeable()` and `usage()` need: `(state, pinned DESC, created_us
DESC, id DESC)`, `(state, kind, pinned DESC, created_us DESC, id DESC)`,
`(folder_id, state, pinned DESC, created_us DESC, id DESC)` (migration 4),
`(state, trashed_us)` and `(item_id, revision, position)`.

**Queries and injection safety (docs/security.md C24):** every value is
bound as a parameter, never formatted into SQL text; every SQL text is a
module-level string constant (migrations too: one constant per statement),
and `list()`'s twelve shapes (folder filter × none/one/several kinds × cursor present; several
kinds = a literal `kind IN (?, …)` of exactly `MAX_QUERY_KINDS` placeholders, padded by repeating
a kind) are picked among
them by `_list_query`. `tests/security/test_sqlite_injection.py` proves
this two ways: SQL-metacharacter payloads round-trip through every
free-text field unchanged, and a static AST **allowlist** requires the SQL
argument (positional or `sql=`) of every `execute()`/`executemany()`/
`executescript()` call in `adapters/sqlite` to be a string literal, a
module-level str constant bound exactly once, or a local bound once from a
same-module helper whose every `return` yields such a constant. Negative
self-tests prove it catches an f-string built in a variable, `sql=` with
concatenation, `" ".join(...)` and a helper call.

**Re-validation on read:** `SqliteItemRepository` never returns a row as an
`Item` directly — every read rebuilds it via `Item(...)`/`ItemFile(...)`,
which re-run every domain invariant (`__post_init__`). A row that bypassed
those invariants (corruption, or a bug elsewhere writing raw SQL) surfaces
as `ValidationError` on the next read instead of silently becoming a
usable item; `tests/integration/test_sqlite_repository.py::TestTamperedRows`
covers this for a title stripped to nothing by `sanitize_title`, a
traversal `relpath`, and an inconsistent `state`/`trashed_us` combination
that only the DB's own `CHECK` constraint doesn't already reject.

## Filesystem BlobStore (`adapters/fs_blobstore.py`, unit 6)

`FsBlobStore` implements the `BlobStore` port over a local filesystem. Every
blob id it's given is validated as a canonical ULID (`is_ulid`) *before* any
filesystem call (so is every id its generator returns), and every
filesystem call is made relative to directory fds opened once at start-up,
so the store can never read, list, write or delete outside the directories
it opened — even if the layout is tampered with while it runs
(docs/security.md C7, C20, I2).

On-disk layout under a configured `root` (all three must be on the same
filesystem — see below):

```
root/
  blobs/<AB>/<ULID>      final, immutable blobs (<AB> = last 2 chars; 32² = 1024 shards)
  staging/<ULID>.part    in-progress writes only
```

- **Lifecycle:** the constructor opens `root`, `blobs/`, `staging/` with
  `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` and keeps the fds until
  `close()` (idempotent; `with FsBlobStore(...) as store:` also works). A
  closed store raises `RuntimeError`. The composition root owns and closes it.
- **Sharding:** blobs are placed under `blobs/<AB>/` keyed by the **last**
  two characters of the id, not the first two. A ULID's first 10 characters
  are a millisecond timestamp, so ids minted close together (a burst of
  publishes) would otherwise all collide on the same one or two shard
  directories; the trailing, random characters spread evenly.
- **Atomic `put`:** bytes are written (unbuffered `os.write`) to
  `staging/<id>.part` opened `O_CREAT|O_EXCL|O_NOFOLLOW` relative to the
  staging fd, hashed while streaming, `fsync`'d, then published with
  `linkat` into the shard (opened `O_NOFOLLOW` from the `blobs/` fd, created
  with `mkdirat` + exact `fchmod` if missing, parent `fsync`'d) followed by
  `unlinkat` of the staging name — never `rename` (ADR 0004) — so a crash
  between the two calls leaves a complete blob plus a stale staging file,
  never a half-written blob. The shard is `fsync`'d. Any exception removes
  the staging file (and a just-published link) before propagating.
  Chunk sizes are counted as `memoryview(chunk).nbytes`; non-buffers raise
  `TypeError`. On `LimitExceededError` the chunk iterator's `close()` is called.
- **Trust checks (fail closed):** `root`, `blobs/`, `staging/` and every
  shard must be real directories (never symlinks), owned by a uid in
  `trusted_owner_uids` (default: the process euid) and not group/world
  writable. Violations raise `UnsafeStorageLayoutError` at construction and
  in `put`; `open`/`delete`/`list_ids` treat an untrusted or symlinked shard
  as absent. `open()` additionally requires a regular file with
  `st_nlink == 1`, opened `O_NOFOLLOW|O_NONBLOCK` (a planted symlink,
  hardlink, FIFO or device is `NotFoundError`, and never blocks); the fd is
  switched back to blocking after the check. `delete()` uses `unlinkat`,
  which never dereferences a symlink.
- **Disk-full handling:** `free_bytes()` and a per-chunk guard inside
  `put()` go through an injectable `free_bytes_provider` (defaults to
  `fstatvfs` on the `blobs/` fd), so tests can force a "disk full"
  `LimitExceededError` deterministically. `reserve_bytes` (bootstrap:
  `min_free_disk_bytes`) refuses a chunk that would leave less than the
  floor free. A real `ENOSPC`/`EDQUOT` anywhere in `put` (staging open,
  write, fsync, shard mkdir, link) is translated to `LimitExceededError`.
- **`list_ids`:** walks `blobs/<AB>/` (fresh fds, via `scandir(fd)`) and
  returns only regular files whose name is a canonical ULID ending in the
  shard's own two chars (staging files, which live in a different
  directory and carry a `.part` suffix, are never considered). `created_before`
  is compared against the blob file's **mtime** — set when the staging
  write completes, i.e. as soon as the blob's bytes exist on disk, which is
  exactly the instant the orphan-sweep grace period needs.
- **`sweep_staging(older_than) -> int`** (adapter-specific, *not* on the
  `BlobStore` port): removes staging files older than `older_than`,
  matched strictly by the `<ULID>.part` naming pattern. It's not on the
  port because "staging files" are an implementation detail of this
  adapter's atomic-write strategy — a different backend (e.g. S3) would
  sweep abandoned multipart uploads instead, which isn't the same shape of
  operation. Intended to be called periodically by the purge job.

`adapters/clock.py` (`SystemClock`) and `adapters/ulid.py` (`UlidGenerator`)
are the real `Clock`/`IdGenerator` adapters: `SystemClock.now()` is
`datetime.now(UTC)`; `UlidGenerator` builds canonical ULIDs from
`time.time_ns()` plus `os.urandom` (stdlib only, per ADR 0007), monotonic
within a millisecond in one process as a nice-to-have.

## Content kinds

`kinds/` is the Registry + Strategy implementation of "what is this file and
how should the viewer show it". `kinds/base.py` defines `PreviewMode`,
the `ContentKind` protocol and `KindRegistry`; `kinds/__init__.py`'s
`default_registry()` is the one place that lists every built-in kind. Type
comes **only** from the registry's extension map — never sniffed from
content or taken from a client — matching docs/security.md I4/C8.

| Kind | Extensions | Preview mode | Renderer | Notes |
|---|---|---|---|---|
| `image` | `.png .jpg .jpeg .gif .webp .avif` | MEDIA | `image` | Not SVG — see `svg`. |
| `svg` | `.svg` | MEDIA | `svg` | Shown only via `<img>`, never framed/navigated (can embed scripts). |
| `html` | `.html .htm` | SANDBOXED | `html` | Bundles need a root `index.html`; `html` owns the media type of every bundle member via its own closed web-asset map (css/js/json/images/fonts/media/txt/csv — `.xml`/`.wasm`/anything else stays `application/octet-stream`), not the member's own kind — see ADR 0009 amendment. |
| `video` | `.mp4 .webm .mov` | MEDIA | `video` | `.mov` → `video/quicktime`. |
| `audio` | `.mp3 .wav .ogg .m4a .flac` | MEDIA | `audio` | |
| `pdf` | `.pdf` | DOCUMENT | `pdf` | No sandbox (Chrome can't render a sandboxed PDF); strict CSP instead. |
| `markdown` | `.md .markdown` | TEXT | `markdown` | Rendered client-side, DOMPurify-sanitized; never served as `text/html`. |
| `code` | `.py .js .ts .tsx .jsx .css .scss .sh .bash .go .rs .java .c .h .cpp .hpp .rb .php .sql .yaml .yml .toml .ini .xml .swift .kt` | TEXT | `code` | Always `text/plain`, never `text/html`/a JavaScript type — inert as a *standalone* item. A same-extension file (`.js`, `.css`, ...) that is a member of an `html` bundle instead gets its type from `html`'s own map (see `html` row), not from `code`. |
| `json` | `.json` | TEXT | `json` | |
| `csv` | `.csv .tsv` | TEXT | `csv` | `.tsv` → `text/tab-separated-values`. |
| `text` | `.txt .log` | TEXT | `text` | |
| `diff` | `.diff .patch` | TEXT | `diff` | `text/x-diff`. |
| `progress` | (none) | TEXT | `json` (interim; `progress` once P2 lands) | Live work tracker, ADR 0029: exactly one `progress.json` (`application/json`), strict schema v1 validated in the MCP tools, never on the server (I4). Confidence 1 and no extensions, so it is **never auto-detected** (`json` wins) — only `kind="progress"` / the progress tools select it. |
| `file` | (none) | DOWNLOAD | `file` | Fallback: `detect()` always returns confidence 1, so it only wins when nothing else claims the files. Always `application/octet-stream`. |

**Detection (`KindRegistry.detect(relpaths, hint=None)`):** with an
explicit `hint` (the publisher's requested kind), that kind is used if its
own `detect()` is > 0, else the publish is rejected — a hint never silently
falls back to autodetection. Without a hint, every registered kind scores
its confidence (0..100) and the highest wins, ties broken by registration
order. Every extension-only kind (everything but `html` and `file`) scores
all-or-nothing: 100 if *every* file in the item matches its extension set,
else 0 — so a mixed-type bundle (e.g. one image plus one code file) is
never claimed by chance; it falls through to `file`. `html` additionally
matches a multi-file bundle only if it has a root `index.html`. Previewing
*multiple* files that share one kind (an image gallery, say) is not built
yet — the kind is still detected correctly, but `entry_file()` just picks
the lexicographically-first file as a deterministic placeholder.

**Extension matching** (`extension_of()`) is case-insensitive and looks
only at the final `/`-segment's last dot, so `notes.html.png` is an image
and a dotfile like `.env` has no extension. An unmatched extension gets
`application/octet-stream` from `KindRegistry.media_type_for()` and is
detected as `file` (DOWNLOAD) — never guessed at.

**Media-type assignment at publish time:** once an item's kind is decided
(via `detect()`), every file the item contains is typed by calling *that
kind's* `media_type(relpath)` — not `KindRegistry.media_type_for(relpath)`
per file. For every kind but `html` this makes no difference (each owns a
disjoint extension set). For `html` it's the point: a bundle member is
typed from `html`'s own closed web-asset map, which can differ from what
the same extension would get as a standalone item of its own kind (see the
`html`/`code` rows above and ADR 0009's amendment) — never from client
input, never sniffed (docs/security.md C8).

`GET /api/kinds` (unit 8b) serves `KindRegistry.describe()` verbatim —
`{name, label, renderer, preview_mode, extensions, render_capped}` per kind —
plus `render_cap_bytes`, as the frontend's single source of truth for which
kinds exist and how to render them.

## Extension points

- **New content kind:** add one file in `kinds/` implementing the `ContentKind` protocol (`kinds/base.py`; `SimpleExtensionKind` covers every extension-only kind), and register one instance in `kinds/__init__.py`'s `default_registry()`. Add one frontend renderer in `static/renderers/`. No edits to unrelated code — the registry is the single source of truth (`GET /api/kinds`). See docs/extending.md for the concrete steps.
- **New notification channel / event type / answer source:** see docs/extending.md (one adapter implementing `NotificationChannel` or `AnswerSource`, or one file in `events/` + a registry line; ADR 0021).
- **New OS environment (look + effects):** add one folder `static/os/<name>/` (tokens, scoped chrome CSS, shell script, background set, optional `fx/`), one registry entry, one `os-boot.js` allowlist entry and its tags in `index.html`. No functional code changes — the functional frontend never names an OS. See docs/frontend-os.md (ADR 0028).
- **New storage backend:** add one adapter implementing `ports/repository.py` (with `ports/folders.py` over the same store) or `ports/blobstore.py`, and run the shared port-contract test suites (`tests/contracts/`) against it. No changes to `application/` or `domain/`.
- **New interface:** add a module under `interfaces/` that depends only on `application/` services (via `bootstrap.py`), never directly on `adapters/`.

### Claudia voice (unit M10, C56)

**TL;DR:** Her reply can also be spoken. The host speaks only text that already passed the reply policy and the secret scan (local Piper, no network), uploads the Ogg/Opus note to `POST /v1/claudia/voice`, and the admin spends the normal reply budget; the text is always sent too. Optional install: `uv sync --extra claudia-voice`.

| Piece | Responsibility |
|---|---|
| `application/claudia/voice.py` | `VoiceComposer` (policy + scan → language pick ES/EN → speak; > 700 chars or audio over 60 s / 1 MiB → leading sentences + fixed pointer, full text still sent), `VoiceService` (admin: audio checked first, text via the reply path, audio kept per reply id until `release`), `VoiceToggle` (`/voice` state for M4b) |
| `adapters/piper_tts.py` | `PiperTextToSpeech`: models `es_MX-claude-high` / `en_US-amy-medium` from a configured dir only, resample 22.05 → 24 kHz, `soundfile` writes OGG/Opus in memory; imports are lazy so the base install works without the extra |
| `adapters/voice_store.py` | `FsVoiceStore`: `<ULID>.ogg`, dir 0700 / files 0600, ≤ 50 waiting, deleted on delivery / give-up and by `purge_older_than` |
| `ports/claudia_voice.py`, `wire/claudia_voice.py` | `TextToSpeech`, `VoiceStore` ports; `POST /v1/claudia/voice` body `{text, audio (base64), message_id?, item_id?}` (own body cap, audio ≤ 1 MiB) |

Licences: `piper-tts` and espeak-ng are GPL-3.0 and a runtime dependency only (never vendored); each Piper voice has its own model-card licence.
Not done here: the notifier fetching the stored audio and calling `send_voice` (needs a payload field + migration; see the backlog) — until then the voice note is stored and swept, and the text reply is delivered as usual.
