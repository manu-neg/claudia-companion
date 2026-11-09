# ADR 0019: Item revisions — stable id, last 20 kept, revision in every preview URL

**TL;DR:** Every item is updatable: new content becomes a new **revision** of the same item (same id, title, pin, dashboard link). The last 20 revisions are kept (older ones pruned automatically on commit, their blobs deleted), all of them count against the byte quota. Preview URLs carry a revision segment, `/<letter>/<id>/<rev>/<relpath>` with `<rev>` a number or `latest`, and bundle Referer binding covers item **and** revision.

## Context

- Owner decision: Claude often iterates on one artifact (typically an HTML page). Publishing a new item per iteration floods the feed and breaks links; the owner wants one stable item with a version history.
- "Artifacts" are not a separate type: any item can get revisions. No persistent state for artifacts in v1 (sandboxed JS has no storage API).
- Items are immutable blobs + one metadata row today; the viewer serves bytes by `id + relpath`; HTML-bundle sub-resources are bound to their bundle by `Referer` (ADR 0012).

## Decision

- **Model.** `Item` = its **head** revision (`kind`, `files`, `entry_file`, `revision`, `revision_at`) + `history` (older kept revisions, oldest first) — `Revision(number, kind, files, entry_file, created_at)`. Existing constructors keep working (defaults: revision 1, no history). `Item.with_revision(...)` (ACTIVE only) returns the new item and the pruned revisions; invariants: numbers strictly increase, ≤ 20 in total, times never run backwards, no blob shared across revisions. Kind may change between revisions; serving always uses the **revision's** kind.
- **Storage.** SQLite migration 2: new `revisions` table; `item_files` rebuilt with a `revision` column and a cascading composite FK to `revisions`; `items.revision` points at the head; `items.kind`/`entry_file` stay as head copies (list-by-kind keeps its index) and a row whose copies disagree with its head fails closed on read. Existing items become revision 1 (created at the item's `created_at`). `save` rewrites the revisions (pruned ones cascade away).
- **Publish path.** `PublishService.publish_revision(RevisionCommand(item_id, files, kind_hint?, expected_revision?))` reuses every publish check (rate limit, file count, manifest precheck, secret scan of relpaths and bytes, quotas, free disk, streamed limits, deadline, rollback). No item slot is reserved; the full byte budget is. Commit is the repository compare-and-swap, re-read and retried once on a conflict (re-checking ACTIVE and `expected_revision`). Pruned revisions' blobs are deleted after the commit; the orphan sweep is the backstop; purge deletes every revision's blobs.
- **Admin API.** `POST /v1/items/{id}/revisions`: the same manifest-first streamed multipart as publish, fields `kind_hint`, `expected_revision`, `manifest`. The id is validated before the body is read.
- **Viewer URLs.** `/i|t|r/<id>/<rev>/<relpath>` and `/d/<id>/<rev>[/<relpath>]`. `<rev>` is `[1-9][0-9]{0,9}` (≤ 2³¹−1) or `latest` (= head at request time), must arrive literally; anything else → 400; a pruned revision → 404. The API's JSON always names **numbers**, so a bundle page and its sub-resources come from one revision. `GET /api/items/{id}?rev=<n>` returns the detail of an older revision; every item JSON lists `revisions` (newest first).
- **Referer binding.** `PreviewHints.revision` carries the URL's revision segment; a bundle sub-resource is bound only if `Referer` starts with `<preview>/i/<id>/<same segment>/`.

## Consequences

- One stable link per artifact; the dashboard shows a version switcher when more than one revision is kept.
- Storage cost grows with revisions (no dedup: revisions never share blobs, which keeps pruning and purge trivially safe). A revision needs a full byte budget even when it will prune one.
- The URL scheme changed (the revision segment is mandatory); nothing was deployed with the old scheme.
- `latest` links can mix revisions inside one bundle if a revision lands mid-load (documented limitation; the dashboard doesn't use `latest`).
- Future: reverting to an old revision (copy as new head) and blob dedup are possible additions, not built.
