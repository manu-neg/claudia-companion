# ADR 0035: TOTP secret group, code re-delivery guard, code delete retries (unit F-C1b)

**TL;DR:** The TOTP secret lives in its own admin-only group `pdash-totp` (`serve-admin --token-group totp=pdash-totp`); the admin's shared primary group is never trusted on it. Re-delivered code messages are recognised by exact `(update_id, message_id)` pairs (last 32, 24 h), not an update-id high-water mark. A failed `deleteMessage` of a code is retried with backoff for up to 47 h, then the owner gets one fixed notice. Replies that fail to queue give their budget back.

## Context
Review S-C1 (07c9837..a01d1aa) found: (S0) the step-up state kept `last_update_id` and called any code with a lower id a duplicate; Telegram may restart update numbering lower, which would silently block every fresh code. (S2/S6) the secret was trusted in `root:<admin egid>`, and the admin's egid is `pdash`, shared with the viewer; setup's `--group` was optional. (S5) a failed code delete was only logged, leaving the code readable in the chat. (S11) a reply that failed after the budget was taken still used it.

## Decision
- **Dedup:** `StepUpState.seen` = up to 32 `SeenCode(update_id, message_id, seen_at)` from the last 24 h; the same pair again is `duplicate` (not a try), anything else is checked. Replay stays blocked by `last_step`. State file version 2; a version 1 file is read once with the mark dropped. A `duplicate` verdict makes the notifier send one fixed "code not checked" notice (`OwnerNotice`, `TelegramChannel.send_notice`, no caller text).
- **Secret group:** `load_totp_secret` trusts root plus explicit `trusted_gids` only (the process's egid is not implied). `serve-admin` takes `--token-group totp=GROUP` and refuses root, its own primary group, and any token file's group; `claudia_enabled` without it refuses to start. `claudia totp setup` needs `--group` (or, with `--rotate`, keeps the current file's group) and checks before showing a secret that the group is not root or the admin's primary group, contains the admin, and nobody else. The written file must carry that gid (else it is removed).
- **Delete retries:** in-memory queue (≤ 64) in `OwnerUpdateRouter`, 30 s doubling to 1 h, honouring `retry_after`; last try at 47 h (Telegram's 48 h delete window). A 400 other than "not found" or a bad id is permanent. Giving up sends one fixed "could not be deleted" notice.
- **Reply budget:** `ReplyBudget` (sliding window with `release`); `ReplyService` refunds the hourly and per-message budget when `queue_reply` raises.

## Consequences
- Deploy (unit M9) must create `pdash-totp` (member `pdash-admin` only), pass `--token-group totp=pdash-totp`, and add `totp.secret` to the viewer unit's `InaccessiblePaths`.
- Pending delete retries are lost on a notifier restart (logged when queued); the owner then deletes the code by hand.
- The notifier's notices go straight to the chat, outside the admin's C37 alert budget: they are fixed texts, at most one per code message.
