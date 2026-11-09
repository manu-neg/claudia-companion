# ADR 0032: Claudia admin routes and TOTP step-up (unit M3)

**TL;DR:** A third bearer token family (`/v1/claudia/*`), approvals that only a notifier tap plus a TOTP code can grant, step-up state in a 0600 JSON file, admin-built `flagged_message` text, and approval prompts that fail closed until the channel can send them.

## Context
ADR 0031 (C45–C47, C56) needs the Claudia host to read the inbox, reply and ask for approvals, while it can never grant one itself. TOTP needs persisted replay/lockout state; prompt delivery (Approve/Deny buttons) needs outbox and channel work owned by the notifier units.

## Decision
- **Token family:** `route_family(path)` → admin / notifier / claudia; wrong family 403. The three tokens must differ (startup refuses). Peer-uid allowlists per family. No claudia route can tap, approve, cancel or answer; consume is the only state change it may cause after create.
- **Grant path:** create → PENDING (claudia) → TAPPED (notifier `/approvals`) → APPROVED (notifier `/codes`, valid TOTP) → CONSUMED (claudia, once). Every step is a store CAS; 600 s expiry is checked lazily on every read. Transition times are clamped to the stored `updated_at` so same-tick steps stay ordered.
- **TOTP:** stdlib RFC 6238 (SHA1, 6 digits, 30 s, ±1 step); all candidates compared with `hmac.compare_digest`. The used step is burnt (saved) *before* approving. A code with no single TAPPED request counts as wrong. Re-delivered updates (`update_id` ≤ last seen) answer `duplicate` and are not counted.
- **State file, not DB:** `<data_dir>/stepup-state.json` (0600, owner-only, nlink 1, dir_fd + O_NOFOLLOW, atomic replace). Avoids a migration for one row; any tamper or parse failure refuses codes (fail closed).
- **Secret file:** 0640 root:group, no ACL, trusted parent, re-read per code. `claudia totp setup` needs root + TTY, refuses overwrite without `--rotate`, and writes only after one valid code. No QR (no library installed): the `otpauth://` URI is printed on the TTY.
- **`flagged_message`:** the admin builds the text from the stored inbox message; a client text is refused; a secret-bearing excerpt is dropped.
- **Prompts:** `ApprovalPrompts` port; the default `UnwiredApprovalPrompts` raises, so create answers 503 and cancels the request.
- **Replies:** 3 per inbox message, 120 per hour (separate from the alert budget); stored as long-form outbox tasks (`delivery_tasks.long_form`, added to unreleased migration 5).

## Consequences
- Approvals are unusable until a later unit wires prompt delivery (`approval_id` on the delivery payload + `p:<id>:ok|no` buttons). **Resolved by ADR 0033 (A1).**
- No cancel route for the host: `/stop` (C58) needs a separate decision. **Resolved by ADR 0033 (A1): close-only cancel routes.**
- The setup's confirmation code is not burnt; it could be replayed within ~90 s by someone who saw it on the terminal. Accepted: that person already has the secret. **Resolved by ADR 0033 (A1): the step is burnt.**
