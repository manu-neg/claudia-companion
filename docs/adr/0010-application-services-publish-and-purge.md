# ADR 0010: Application services — publish limits, deadline and purge safety

**TL;DR:** Publish enforces every limit on streamed bytes, reserves quota for in-flight publishes, has a hard monotonic deadline shorter than the orphan-sweep grace, and rolls back all blobs on any failure; purge deletes rows with an atomic conditional delete; trash/restore are idempotent.

## Context

Unit 4 turns the domain + ports into use cases. Three concerns shape it: a
prompt-injected publisher trying to exhaust disk or probe the secret scan;
concurrency between the admin, viewer and purge processes (publish commits
racing the orphan sweep, the owner restoring an item while purge runs); and a
clean core (no `config.py`/pydantic, no adapters inside `application/`).

## Decision

- **Plain limit values in, not `Settings`:** `PublishLimits` (and durations
  for purge) are built by `bootstrap.py`; the application stays framework-free.
- **Quotas count in-flight publishes:** `_QuotaGate` reserves an item slot and
  a byte budget (`min(max_item_bytes, total left)`) under a lock before
  streaming and releases it afterwards, so N concurrent publishes cannot
  overshoot `max_items`/`max_total_bytes` N-fold. Trashed items count (they
  still occupy disk until purged).
- **Rate limit counts attempts:** `SlidingWindowRateLimiter.acquire()` runs
  first; failed publishes (e.g. secret-scan probes) are not free. In-process,
  behind a `RateLimiter` protocol so a shared implementation can replace it.
- **Hard deadline:** monotonic (injected), checked between chunks and right
  before `repo.add`; `Settings` requires `orphan_grace_seconds >
  publish_timeout_seconds`, so the sweep never deletes blobs of a publish that
  can still commit.
- **Validate before streaming:** the real `Item.new` runs on placeholder files
  first, so bad titles/duplicate paths cost no I/O.
- **Rollback on `BaseException`:** every blob stored for the publish is
  deleted (best effort; the orphan sweep is the backstop).
- **Purge:** `ItemRepository.delete_if_purgeable(id, cutoff)` (new port
  method) deletes atomically only if still TRASHED and due, returning the item
  for blob cleanup; blobs still referenced elsewhere are kept. Adapter-specific
  cleanup is injected as hooks (`maintenance` every run; `post_purge` only
  after items were purged, e.g. a SQLite WAL checkpoint).
- **Lifecycle idempotency:** trash-of-trashed and restore-of-active are no-ops
  (the requested end state already holds; `trashed_at` is not bumped, so
  retention is not extended by repeated clicks). Editing a trashed item stays
  an `InvalidStateError`.

## Consequences

- Quota/rate state is per process; correct for the single admin process,
  reset on restart (committed usage still bounds quotas).
- A publish that needs more than `publish_timeout_seconds` (default 10 min)
  fails; raising it requires raising the grace too (validator).
- New port method `delete_if_purgeable` must be implemented by every
  repository adapter (contract tests enforce it).

## Amendment (unit 4 follow-up): optimistic concurrency, rollback after `add`

- **`save` is a compare-and-swap** (`save(item, *, expected_updated_at)`,
  new `ConflictError`): admin edits and viewer trash/restore can race across
  processes; last-write-wins would silently drop one. Chosen over a version
  column: `updated_at` already exists, and `LifecycleService` stamps every
  change strictly after the stored one, so it is a real version with no
  migration. `trash`/`restore` retry once after re-reading (their intent is
  absolute and stays idempotent); `update` raises `ConflictError` → 409.
- **Rollback after `repo.add` was entered** deletes blobs only if
  `repo.get(id)` raises `NotFoundError` (keeping those the stored row
  references; nothing if `get` fails). An `add` that committed and then
  raised must not leave a row pointing at deleted blobs; leftovers are the
  orphan sweep's job.
- **Rate limiter on a monotonic clock** (injected), so wall-clock steps
  can't expire the window early. `PostPurgeHook` is `Callable[[], object]`
  so `compact() -> bool` fits without a wrapper; purge cutoffs that
  overflow raise `ValidationError`.
