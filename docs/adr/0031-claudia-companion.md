# ADR 0031: Claudia companion (owner free text, approvals as chat turns, TOTP step-up)

**TL;DR:** The owner can message Claudia (our only Telegram bot) freely. The notifier stays the sole Telegram reader and posts owner-only text to an admin inbox; a new **Claudia host** screens each message (parser + strict Haiku), runs `claude -p --resume` as root **on the subscription only**, and replies through `reply`/`voice` events. Risky steps stop and become an **approval request**: Approve tap + **authenticator (TOTP) code**, both verified by the admin, then the host resumes her with a turn naming the action; a host-owned PreToolUse hook denies a fixed risky set without such a consumed approval. A Markdown knowledge base is written only through the host and shown read-only in the viewer. Partially supersedes ADR 0021 ("choice-only answers"). Controls C44–C60.

## Context

- Owner request and decisions D1–D17 (2026-11-08, from the owner's companion plan, third and final revision): a companion to chat with, dispatch work, use the dashboard; subscription only (D15); voice replies (D13, Piper); other sessions (D14); a knowledge map (D9, D10).
- Phase-0 checks (live spikes run on the owner's host before any code was written): **V1** a Telegram text as the `-p` prompt and a resumed "Approved by the owner …" turn both count as user input for the auto-mode guard; **V3** `claude -p` runs on the subscription login without an API key; **V4** parser + Haiku: 0 false negatives on 40 EN/ES samples, p95 7.1 s, max 8.3 s; **V5** runs can list, read and message other sessions, and receivers see peer turns as non-approvals; **V6** local Piper voices.
- ADR 0021 allowed only fixed-option answers; free text needs a new ADR. Claude runs as root, so every in-process control is advisory against a capable injected agent.

## Decision

- **Inbound** (C44): notifier accepts private text only from `from.id == chat.id == owner`, keeps the forwarded flag; exact ASCII 6-digit messages go to the TOTP route only and are deleted from the chat; other 6-digit runs are redacted.
- **Scopes** (C45): new `claudia` token on `/v1/claudia/*` only (inbox, replies, approval *requests*); taps and codes only via the notifier token; nothing lets Claudia grant an approval.
- **Approvals as chat turns** (C46, C55): bound action text + structured action (kind + target), single use, 600 s expiry, CAS states; the host builds every resume and `flagged_message` text; pending requests also listed read-only in the viewer; guard block → stop + `failed`, never retry/reword.
- **Risky-action hook** (C59, C60; owner "add-hook" 2026-11-08, after review S-ADR found "risky needs a code" unenforced): a host-owned PreToolUse hook denies `gh pr merge`, `deploy/install.sh`, `git push` to main/master, `rm`, dashboard trash/prune/empty-trash, settings edits and unapproved/unprefixed `SendMessage` unless the window has a consumed approval with the same kind + target; fail closed. Approvals stay chat turns; the hook only enforces them.
- Hook never grants: on a match it returns no decision so the permission guard still decides, and never emits `allow` (C59).
- Hook cannot be disabled: the host refuses a run if any settings source has `disableAllHooks` or overriding hooks; hook/settings paths are deny-listed and count as `settings_edit` (C59, C50).
- One canonical `action_kind` list lives in C59 (`unknown` classifier-only); bypass forms (`gh api`, wrappers, git options, refspecs, `find -exec rm`, inline interpreters) have classifier rules and tests; `rm` targets are the exact resolved path set (C59).
- C55 counts only denials after a consume; a hook deny with no approval does not lock the action.
- **Step-up** (C47): RFC 6238 in the admin, secret file Claude never reads, no replay, lockout + alert on wrong codes.
- **Screening** (C48): parser OR strict Haiku (no tools, neutral cwd, **15 s** timeout + 1 retry; plan said ~10 s, raised after V4's 8.3 s max); flagged/degraded → read-only turn until a code.
- **Runs** (C49–C51, C58): no API keys (refuse to start), allowlisted env, host-owned settings with memory/settings deny rules, explicit tool sets without her own Telegram tools, 3 h idle / 8 h windows, `/stop` kill switch.
- **Peers** (C52): prefix + confirm before interactive sessions, enforced by the hook (C60) and audited from the transcript after each run.
- **Knowledge base** (C53, C54, C57): host-only writes with layout, caps and secret scan; gardener confined to the KB with revert; viewer gets **one** read-only root, amending I2 and I4 narrowly (stated in the invariants).
- **Outbound** (C56): `reply` ≤ 4096 under the C35 policy, own budget; voice only from scanned text.

## Consequences

- **Owner-accepted risk ("risky-only", Telegram 2026-11-08):** no code at window start, so a Telegram account holder (or a compromised notifier) can start normal (non-risky) root-Claude work by text; the hook blocks the fixed risky set without a consumed approval. Owner mitigation: Telegram 2FA; authenticator on a separate device.
- The hook enforces only the risky set it can classify (not scripts run indirectly); other calls in an approved turn are unlimited; a compromised notifier can relabel the phone (TOTP proves presence, not intent; the viewer list is the cross-check); all in-process controls stay advisory while Claude runs as root (Known limitations).
- Guard behaviour, hooks in `-p --resume` and transcript formats are Claude Code 2.1.x internals: re-run V1/V5 and the hook check after upgrades; if hooks do not fire for `SendMessage`, a host-owned send tool replaces it (C60).
- New DB tables (M1 migration), a new systemd service + timer and a viewer read-only path (M9): every unit merge is an owner Telegram ask.
