# ADR 0022: Admin API token scopes, per-family peer uids, and event-loop long-polls

**TL;DR:** The admin socket serves two route families: `/v1/notifier/*` (notifier token only) and everything else (admin token only); a token used on the other family gets 403, decided before routing. Peer-uid allowlists are per family too. Long-polls wait on the event loop with in-process wake-ups, capped at 16 question waiters and a single notifier poller.

## Context

- ADR 0021: only the notifier may record answers; Claude (admin token, root) may ask, wait, cancel and notify but never answer, and the internet-facing notifier must not publish or read items.
- Both processes reach the same Unix socket; one bearer check for everything would let either token do everything.
- Owner decision D8: long-polling everywhere, no fixed-interval polling. The admin's uvicorn has `limit_concurrency` 32 and a small threadpool that publishes need.
- The outbox hands out due tasks without leasing them (`NotificationOutbox.pending`).

## Decision

- **Token scope by path family**, in `BearerAuthMiddleware`: family = `/v1/notifier` or below vs the rest, classified on the same decoded `scope["path"]` the router matches. Both tokens are compared (constant time) on every request; no/wrong token → 401, right token on the wrong family → 403 (also for unknown paths, so nothing can be probed). The accepted role goes into the scope and every question/notifier route re-checks it (defense in depth). Identical tokens are refused at startup; the notifier token is loaded only when `notify_enabled`, so otherwise `/v1/notifier/*` accepts nothing.
- **Peer uids per family:** `serve-admin --allowed-peer-uid` (admin family) and `--notifier-peer-uid` (notifier family). If either is given, both lists are enforced (an empty one = nobody). A stolen notifier token is then useless from root's uid 0 unless the peer uid also matches.
- **Long-polls** (`interfaces/admin/longpoll.py`): the route awaits `QuestionEvents`/`OutboxEvents.wait` (asyncio adapter, thread-safe `notify` via `call_soon_threadsafe`, no-op without waiters), re-reads the store at least every 5 s (the purge process can expire questions; its wake-ups reach nobody), and stops as soon as the client disconnects. Service calls still run in the threadpool, but only for the short reads. Caps: 16 concurrent question waiters (beyond → immediate reply), 1 notifier poller (a concurrent second poll → `{"tasks": []}` at once, so a task is never handed out twice).
- **Env can only switch notifications off** and can never set `notify_owner_chat_id` (C16); rate/TTL may only be lowered from env.
- **Shared wire format** moves to `preview_dashboard/wire/notifier.py` (framework-free), so `adapters/admin_queue.py` no longer imports `interfaces/`.

## Consequences

- Deployment must pass `--notifier-peer-uid <pdash-notify uid>` (else the notifier routes are closed whenever `--allowed-peer-uid` is used) and make `notifier.token` readable by the admin service and the notifier, and `telegram.token` by the notifier only.
- "Admin token never answers" stays advisory against a root attacker (it can read any file or change uid); the per-family peer check narrows the easy path.
- A held long-poll can delay admin shutdown by up to 60 s (uvicorn waits for in-flight requests).
- A lost wake-up (notify between the read and the wait) costs at most 5 s of latency.
