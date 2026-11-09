# ADR 0007: ULID identifiers and canonical-or-reject paths

**TL;DR:** Items and blobs are identified by generated, canonical (uppercase) ULIDs, which also serve as storage keys. Bundle-relative paths are validated canonical-or-reject: invalid input is refused, never rewritten.

## Context

Ids appear in URLs, file names on disk (blob store) and SQL keys, and the ordering rule needs a deterministic tiebreak when two items share a `created_at`. Bundle paths come from a semi-trusted publisher (Claude, which can be prompt-injected) and end up in preview URLs and in zip arcnames extracted on the owner's machines (including Windows/macOS).

## Decision

- **ULIDs** (26 chars, Crockford base32) for `ItemId` and blob ids, generated behind the `IdGenerator` port; only the canonical uppercase spelling is accepted (`is_ulid`, `parse_item_id`, `validate_blob_id`), so each id has exactly one string form and is always a safe single filename.
- Ids are never derived from user input; the blob store generates blob ids itself (`BlobStore.put`).
- `validate_relpath` **rejects** anything non-canonical (non-NFC, `..`, `a//b`, trailing dot, ...) instead of normalizing it, and returns the input unchanged — so validation is idempotent and two different strings can never map to the same file.
- Display text (title/description) is the opposite trade-off: it is sanitized (invisible/bidi chars removed), because rejecting a whole publish over a stray zero-width space helps nobody and the text is never used as a key.

## Consequences

- No filesystem path is ever built from user data; path traversal via ids is impossible by construction.
- ULIDs are time-sortable and unique without coordination; used as the final ordering tiebreak (`id` desc).
- Some legitimate but unusual file names (trailing dots, leading `~`, `:`) cannot be published; the error says why. Accepted: fail closed.
- **Ids are not secrets.** A ULID's first 10 chars are a timestamp and the random part is not treated as a capability; knowing an item or blob id grants nothing. Access is gated by identity (Tailscale ACL + viewer auth, ADR 0002), never by id unguessability.
- The fake `SequentialIdGenerator` emits zero-padded digits, which are valid canonical ULIDs, so tests stay deterministic.
