# ADR 0020: The viewer may pin and unpin (its third and fourth state change)

**TL;DR:** The dashboard app gains `POST /api/items/{id}/pin` and `/unpin`, behind exactly the same controls as trash/restore (owner identity C2, Host C3, CSRF matrix + 1 KiB body C4). The viewer gets a separate narrow capability, `PinControl`, exposing only `LifecycleService.set_pinned` — never title/description edits. Pin/unpin is idempotent and refuses trashed items (409).

## Context

- Owner decision (backlog R2): pinning from the dashboard, not only via Claude/MCP.
- Until now the viewer's only write capability was `TrashControl` (trash/restore), deliberately narrowed so the owner-facing process could not edit metadata. Text edits need the secret scan (C15) and have no place in a read-mostly viewer.
- `LifecycleService.update(pinned=...)` already existed, but it always writes (bumps `updated_at`, so polling ETags change on a repeated click) and raises on any concurrent write instead of retrying.

## Decision

- **Application.** New `LifecycleService.set_pinned(item_id, *, pinned)`: no-op (no write) when the flag already matches; trashed item → `InvalidStateError` whatever its stored flag; one re-read + retry on `ConflictError`, like trash/restore. Uses `Item.with_metadata(pinned=...)`, no new domain logic.
- **Capability.** `bootstrap.PinControl` (its own class, not a widened `TrashControl`) exposes only `set_pinned`; `ViewerCore.pins` and the `PinActions` port in `interfaces/viewer/services.py`. Both controls share one `LifecycleService` per viewer core.
- **Routes.** `POST /api/items/{id}/pin|unpin`, no query parameters, body `{}`/empty; response `{"item": summary}` (same shape as trash/restore). 409 `conflict` for a trashed item or a repeated concurrent change. No rate limit (trash/restore have none; the CSRF matrix and owner identity are the gate).

## Consequences

- The viewer's write surface is now trash, restore, pin, unpin — still no text edits and no deletes. `tests/security/test_viewer_state_changes.py` runs the CSRF/identity matrix on every real POST route and fails if a new POST route is added without being listed.
- A hostile page that bypassed C4 could at worst reorder the feed; the gate is unchanged, so this is not a new trust assumption.
- Admin/MCP pinning keeps using `update(pinned=...)` (unchanged semantics).
