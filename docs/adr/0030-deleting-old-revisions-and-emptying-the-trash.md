# ADR 0030: Deleting old revisions and emptying the trash

**TL;DR:** Two explicit, permanent deletes join the timed purge: **prune an item's old revisions** (keep the newest `keep`, head included, default 1) and **empty the trash now**. Both are admin-token only (admin API, MCP tools, host CLI), plus the owner's own "Delete old versions" button in the viewer (keep=1, R2); they commit the DB change first and delete blobs after, and are safe against concurrent writers. This ends "Claude can never permanently delete" — an owner decision.

## Context

- Owner request (2026-10-26): "a way to delete old versions" (revisions use disk: up to 20 full copies per item, ADR 0019) and "empty the bin now"; owner decision (2026-10-26, answering the Telegram plan v2: "Go, also as a Claude MCP tool"): a viewer button (unit R2), a host CLI **and** a Claude MCP tool.
- Until now permanent deletion was the purge job's alone: trash → purged after `trash_retention_days`, plus the automatic pruning beyond 20 revisions. No admin route deleted anything (C26).
- The admin process (publish, edits), the viewer (trash/restore/pin) and the purge job write the same rows concurrently (C32).

## Decision

- **Domain.** `Item.without_history(keep, *, at) -> (item, dropped)`: ACTIVE only (trashed → `InvalidStateError`), `keep` an int in 1..20 (`validate_keep_revisions`, else `ValidationError`), the head is never dropped, dropped revisions are returned oldest first, nothing to drop → the same item (no new `updated_at`, no write). ADR 0019's invariants hold unchanged.
- **Prune** (`application/history.py`, `HistoryService.prune_revisions(item_id, *, keep=1, expected_revision=None) -> PruneResult(item, revisions_removed, bytes_freed)`): re-check ACTIVE + `expected_revision` → compare-and-swap save (re-read and retry once on a conflict, so a revision published meanwhile is kept) → **then** delete the dropped blobs. A failed blob delete is logged and left to the orphan sweep; it never un-commits. `bytes_freed` = the dropped revisions' file sizes (the quota they used).
- **Empty trash** (`PurgeService.empty_trash() -> PurgeReport`): list every TRASHED item first (all pages), then `delete_if_purgeable(id, cutoff = that item's listed trashed_at)` per item — atomic, so an item restored (or restored and re-trashed) after the listing survives; blobs after their rows, only if unreferenced; failures left to the sweep; post-purge hooks (WAL compact) if rows went. No sweep/maintenance/question housekeeping (the hourly job's).
- **Surfaces** (all admin family, ADR 0022): `POST /v1/items/{id}/revisions/prune` (`{keep?, expected_revision?}`), `POST /v1/trash/empty`; MCP `dashboard_prune_revisions`, `dashboard_empty_trash` (descriptions say PERMANENT, `destructive_hint`); CLI `preview-dashboard prune-revisions <id> [--keep N]`, `empty-trash` (purge role, run as `pdash-admin`). The admin core gets `history` and a `TrashBin` narrowed to `empty()`; the purge core gets `history`. No item `DELETE` route.
- **Viewer (R2, amended 2026-10-26):** `POST /api/items/{id}/revisions/prune` (dashboard app, CSRF/Fetch-Metadata checks of C4 like trash/restore; **required** `?expected=<head>` (missing → 400; the UI always sends it, so no blind permanent delete), no `keep`; admin/MCP/CLI keep it optional). The viewer core gets a `RevisionPruner` narrowed to `prune_old` (keep=1 only) over `HistoryService(delete_blobs=False)` on its read-only blob store: the DB prune commits, no blob delete is attempted (no per-blob warning, one INFO line), and the **hourly orphan sweep frees the space**, but only blobs older than `orphan_grace_seconds` (1 h), so it can take about two hours. The button's confirm dialog and result toast say "Space is freed within about two hours". The viewer gets no empty-trash.

## Consequences

- Claude can now permanently delete (old revisions of one item; everything already in the trash). Owner decision: the MCP server is the owner's local agent. Mitigations: admin token only (C43), tool descriptions and server instructions say permanent and "only when the owner asked", nothing outside the trash or older than the head can go, and plain trash keeps its retention.
- A prune after `publish_revision` keeps numbering (the next revision is head + 1); old `/i/<id>/<n>/` links of pruned revisions become 404, like automatic pruning.
- The owner can delete old versions from the viewer; the disk space comes back within about two hours (hourly orphan sweep, 1 h grace period), not at once, and the UI says so.
- A prune that committed runs the same best-effort WAL compact as the purge (`HistoryService(post_commit=…)`, wired for admin, purge and viewer), so pruned page images don't linger in `-wal` (C24). A failing post-purge/post-commit hook is logged by exception type and never undoes or fails the delete.
- New security control C43; the threat "irreversible deletion by an injected agent" is in the threat table (`docs/security.md`).
