# ADR 0021: Notifications and choice answers (Telegram, transactional outbox)

**Status:** partially superseded by [ADR 0031](0031-claudia-companion.md) (2026-11-08): "choice-only answers" now also admits owner free text, approval taps and TOTP codes; the rest stands.

**TL;DR:** Claude can ask the owner a **choice question** (2–8 fixed options, never free text) and send **done/failed** alerts. A separate, network-only **notifier** process (user `pdash-notify`, no DB access) pulls deliveries from a transactional outbox over the admin socket with its own scoped token and turns Telegram button taps into answers. Only the notifier token can record an answer; the first answer wins. The app becomes "one-way content, choice-only answers".

## Context

- Owner decisions D1–D9 (backlog §5, plan `telegram-notify-plan.md`): real question text on Telegram (secret-scanned), 24 h expiry (then report `default_key`, never auto-answer), events question/done/failed, 20 alerts/hour, long-polling everywhere, waiting via CLI.
- Admin (`PrivateNetwork=yes`) and viewer (`IPAddressDeny=any`) must stay network-locked, so Telegram traffic needs its own process.
- Claude runs as root and can be prompt-injected: it must never be able to answer its own questions, spam, phish, or exfiltrate through alerts.

## Decision

- **Domain** (`domain/questions.py`, `domain/notifications.py`): `Question` (OPEN → ANSWERED | EXPIRED | CANCELLED, CAS on `updated_at`), `Notification`, `DeliveryTask` (SEND/RESOLVE per channel, 8 tries, backoff 5 s × 4ⁿ ≤ 30 min, policy in the domain), channel-neutral `MessageContent` (plain text ≤ 300, ≤ 8 buttons, optional link). Prompt/labels/session label/title reuse `domain/text.py` sanitizing (`sanitize_line`).
- **Event types** are a registry like `kinds/` (`events/`: question, done, failed); a new type = one file + one registry line.
- **Transactional outbox:** a question, its notification and its SEND tasks commit in one transaction (`QuestionRepository.add_with_notification`); a resolution commits the question and its RESOLVE tasks in one CAS (`save(..., tasks=)`), so exactly the winning writer enqueues them. The notifier never touches the DB: it long-polls `GET /notifier/tasks` and reports done/failed. A RESOLVE waits for its SEND and is dropped if that message never went out.
- **Answers:** `QuestionService.answer` is the only way to record one; interfaces expose it only to the notifier token. Untrusted callback data never raises: unknown question or key → `UNKNOWN` (no existence oracle). Past the deadline → `EXPIRED`, never answered.
- **Links** are built only by `DashboardLinks` from the configured dashboard origin and a validated ULID; no caller can supply one. Caller text may not contain a web address at all (`://`, `www.`, `host.tld/path`, look-alikes after NFKC → `ValidationError`), and channels defang bare hostnames (amendment F-A, after review S-A).
- **Session label** is required on every question and shown in its alert; it is self-reported by the caller, so it informs the owner but authenticates nothing.
- **Rate limit:** one `SlidingWindowRateLimiter` shared by ask and notify (default 20/hour), every attempt counts.
- **Ids:** questions, notifications and tasks take ULIDs from the existing `IdGenerator.new_item_id()` (no port change).
- **Wake-ups:** `QuestionEvents` / `OutboxEvents` ports (in-process, advisory; waiters re-read the DB).
- **Housekeeping:** the purge job expires due questions and deletes notifications, then resolved questions, older than 30 days. It runs **after** the item purge and sweeps, with its errors contained (logged by type, flagged in the report), so it can never block trash deletion.
- **Outbox hygiene:** a SEND whose question is already resolved is settled unsent; a row that fails re-validation is marked FAILED (tasks) or skipped (questions) by id, so one bad row can't stall delivery or expiry.

## Consequences

- New attack surface: an internet-connected process (C33, C38), answer authorization (C34), outbound content (C35), bot/notifier tokens (C36), alert/long-poll caps (C37). I5 unchanged (nothing new listens).
- Whoever holds the owner's Telegram account can pick an offered option on open questions — nothing more (no free text, no other actions). Owner action: Telegram 2FA.
- If Telegram is down for more than ~1.5 h an alert is given up (FAILED); the question itself still works via the CLI wait and expiry.
- Free-text answers, dashboard answer buttons (N6) and more channels are later changes; free text needs a new ADR.
