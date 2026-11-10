# Notifier (Telegram alerts and answer buttons)

**TL;DR:** `preview-dashboard serve-notifier` runs two long-poll loops: deliveries come from the admin socket (`GET /v1/notifier/tasks?wait=60`, notifier token) and go to Telegram; taps come from Telegram (`getUpdates`, 50 s) and go back to the admin (`POST /v1/notifier/answers`). With **owner messages on** (Claudia, ADR 0031, M2) the same single poller also reads the owner's texts (→ `/v1/notifier/messages`), approval taps (→ `/v1/notifier/approvals`) and authenticator codes (→ `/v1/notifier/codes`, message then deleted). It has no DB access, listens on nothing, holds the bot token and the notifier token, and logs no tokens or content. ADR 0021, 0031; controls C33–C36, C44, C46, C47, C56.

## Pieces
| Module | Role |
|---|---|
| `wire/notifier.py` | **The** JSON format and paths of `/v1/notifier/*` (admin routes, `AdminDeliveryQueue` and the notifier import it; framework-free, outside `interfaces/`). Strict parsers, domain re-validation |
| `interfaces/admin/notifier_api.py` | The admin side of those routes (N3): notifier token only, one poller at a time, answers → `QuestionService.answer` |
| `adapters/admin_queue.py` | `AdminDeliveryQueue` (`DeliveryQueue` port) over the admin Unix socket with the notifier token |
| `adapters/telegram/client.py` | `TelegramBotClient` + `BotToken`: the only holder of the bot token |
| `adapters/telegram/channel.py` | `TelegramChannel` (`NotificationChannel`): `sendMessage` / `editMessageText` |
| `adapters/telegram/answers.py` | `accept_callback` (owner-only callback parsing: `a:` answers, `p:` approval taps), `TelegramAnswerSource` (`AnswerSource`, callback-only poller): `getUpdates` + `answerCallbackQuery` |
| `adapters/telegram/updates.py` | `TelegramUpdateSource` (M2): the poller once owner messages are on; `accept_message` (C44 owner checks, code routing, redaction, forwarded/quote metadata), `rewind` |
| `wire/notifier_messages.py` | **The** JSON format of `/v1/notifier/{messages,approvals,codes}` and the `p:<ULID>:ok\|no` callback data (M2 defines, M3 serves) |
| `adapters/telegram/pairing.py` | `/start <code>` matching for `notify pair` |
| `interfaces/notifier/runner.py` | `NotifierRunner`: two daemon threads, backoff, graceful stop |
| `interfaces/notifier/owner_updates.py` | `OwnerUpdateRouter` (M2): the `AnswerSource` with owner messages on; routes each update to its admin route, deletes code messages, re-reads unstored texts |
| `interfaces/notifier/commands.py` | `serve_notifier`, `pair`, `send_test` (wired by `interfaces/cli.py`); `owner_messages=True` selects the router |
| `application/delivery.py` | `DeliveryService` (N1): one round of deliveries / answers |

## Wire format (`/v1/notifier/*`, notifier token only)
| Method + path | Body | Reply |
|---|---|---|
| `GET /v1/notifier/tasks?wait=0..60&limit=1..20` | — | `{"tasks": [task…]}` (≤ 20) |
| `POST /v1/notifier/tasks/{id}/done` | `{"message_ref": str \| null}` (`{}` allowed) | 200 (body ignored) or 204 |
| `POST /v1/notifier/tasks/{id}/failed` | `{}` | 200 (body ignored) or 204 |
| `POST /v1/notifier/answers` | `{"question_id", "key", "source", "actor_ref"}` | `{"result": "recorded" \| "already_answered" \| "expired" \| "cancelled" \| "unknown"}` |

```json
{"id": "01J…", "channel": "telegram", "action": "send" | "resolve",
 "payload": {"text": "❓ …", "buttons": [{"key": "a", "label": "SQLite"}],
             "link": "https://<dashboard>/#/item/01J…" | null,
             "question_id": "01J…" | null, "final_state": "answered" | "expired" | "cancelled" | null,
             "approval_id": "01J…",    // approval prompts only (A1); absent otherwise
             "approval_outcome": "denied"},  // a decided prompt's RESOLVE only (F-CL5)
 "message_ref": "<chat_id>:<message_id>" | null}
```
- Approval prompt (C46, ADR 0033): `approval_id` set, `buttons: []`, `link: null`, no `question_id`/`final_state`/`long_form`; `text` is the request's stored action text. The admin hands it out only while the request is PENDING and unexpired (else settles it unsent); the channel draws exactly `[Approve p:<id>:ok][Deny p:<id>:no]`.
- Approval outcome edit (C46, F-CL5, ADR 0041 addendum): `action: "resolve"`, `approval_id` + `approval_outcome` (`approved` \| `consumed` \| `denied` \| `cancelled` \| `expired`), `text` exactly that outcome's fixed text (`APPROVAL_OUTCOME_TEXTS`), still no `final_state`. The channel edits the prompt to its own copy of that constant with an empty keyboard (buttons gone); an approval edit without an outcome is refused.
- `wait`/`limit`: ASCII digits only (`parse_wait_param`, `parse_limit_param`). Unknown JSON keys → 400.
- Answer `question_id`/`key` are raw strings ≤ 64 chars: the admin turns anything unknown into `unknown` (C34).
- A task the notifier cannot validate is reported `failed` (so backoff retires it) and skipped. `text` and button labels must already be clean (`reject_invisible`, C35): invisible chars (ZWSP, word joiner, tag chars, blank look-alikes such as braille blank or U+FFFC, Hangul filler, soft hyphen, CGJ, bidi, and ZWJ/ZWNJ/VS16 outside emoji or complex-script sequences, ADR 0026) are refused, never stripped.
- `done`/`failed` for a vanished task (404) are ignored by the notifier.
- `payload.text` is ≤ 300 chars (C35) unless the payload carries `"long_form": true` (only `reply`/`voice`, whose event types declare `max_chars = 4096`; ≤ 4096 UTF-16 units, no buttons, C56). Alert payloads never carry the key.

## Owner updates (`wire/notifier_messages.py`, M2; server side M3)
| Method + path | Body | Reply |
|---|---|---|
| `POST /v1/notifier/messages` | `{"update_id", "message_id", "sender_id", "text", "is_forwarded", "reply_to_message_id": int \| null, "quote_text": str \| null}` | `{"result": "stored" \| "duplicate"}` |
| `POST /v1/notifier/approvals` | `{"request_id": ULID, "decision": "approve" \| "deny", "source", "actor_ref"}` | `{"result": "tapped" \| "denied" \| "already_decided" \| "expired" \| "unknown"}` |
| `POST /v1/notifier/codes` | `{"update_id", "message_id", "sender_id", "code": "[0-9]{6}"}` | `{"result": "accepted" \| "refused" \| "locked" \| "duplicate"}` |
| `POST /v1/notifier/media` (C61, `wire/notifier_media.py`) | `{"update_id", "message_id", "sender_id", "kind": "voice" \| "photo", "data": base64, "caption": str \| null, "is_forwarded", "reply_to_message_id"?, "quote_text"?}` | `{"result": "stored" \| "duplicate"}`; 422 = refused for good (switch off, not Ogg/Opus or JPEG, over a cap) |

- Messages: idempotent on `update_id` + `message_id`; `text` already redacted (every 6-digit run → `[code redacted]`), verbatim otherwise; `sender_id` = the owner id (the admin re-checks it against its own config). 400/413/422 → the notifier drops the update; anything else → it is re-read (offset rewound, later updates of the batch with it) after the runner's backoff, given up after 8 tries.
- Approval buttons: `callback_data = "p:<request ULID>:ok|no"` (`approval_callback_data`); toasts are fixed (`TAP_ACK_TEXTS`, admin down → `Not recorded, try again`). After a `tapped` verdict the notifier also sends one fixed chat message, `CODE_PROMPT_TEXT` ("send your authenticator code"), via `TelegramChannel.send_code_prompt()` (no text argument); a failure there is logged by type and never blocks the loop.
- Codes: never retried, never in the inbox, never logged; the code message is deleted (`deleteMessage`) after the post, whatever the outcome. A repeated `update_id` + `message_id` must answer `duplicate` (not a second wrong try). Feedback to the owner comes as outbox alerts from the admin.

- Media (C61): only the owner's own voice note (≤ 120 s, ≤ 2 MiB, `audio/ogg`) or photo (largest size ≤ 10 MiB, sides ≤ 4096). Metadata is checked before `getFile`; the file is then streamed from `api.telegram.org/file/bot…/<file_path>` with a byte cap. Switch off → dropped, notice `MEDIA_OFF`; over a cap, album, document, unsafe path or a 400/413/422 verdict → dropped, notice `MEDIA_REFUSED`. Each notice is sent at most once per hour. Transient errors rewind like messages. The admin checks the bytes again and strips JPEG metadata.

**Switch:** owner-message intake and voice delivery are on only when `config.claudia_enabled` is exactly `true` (default false = the notifier behaves as before Claudia); a missing or odd value means off. Owner voice/photo intake also needs `claudia_voice_input_enabled` / `claudia_photo_input_enabled` exactly `true` (default false, C61).

## Telegram
| Aspect | Rule |
|---|---|
| Base URL | fixed `https://api.telegram.org`; methods allowlisted (`getUpdates`, `sendMessage`, `editMessageText`, `answerCallbackQuery`, `getMe`, `deleteMessage`, `sendVoice`, `getFile`); file download only via `TelegramBotClient.download` (validated `file_path`, streamed, ≤ 10 MiB, kind cap below that, C61); `sendVoice` only through `upload` (multipart file ≤ 1 MiB), never as JSON (no audio by URL / file id) |
| Voice (C56) | `TelegramChannel.send_voice(audio)`: `events.voice.validate_voice_audio` first (one Ogg/Opus stream, ≤ 1 MiB, ≤ 60 s), no caption (the text goes as its own message); task plumbing lands with M10 |
| Owner messages (C44, opt-in) | `allowed_updates=["callback_query", "message"]`; a message counts only if `from.id == chat.id == notify_owner_chat_id`, private chat, `is_bot` false, plain `text` ≤ 4096 (no media/caption, not `via_bot`/`sender_chat`/edited); ignored ones get no reply, logged by update id only. Forwarded (`forward_origin`, `is_automatic_forward`, legacy `forward_*`, `external_reply`) → `is_forwarded`; `reply_to_message.message_id` and `quote.text` kept as metadata. Whole text ASCII `[0-9]{6}` (spaces removed) → code route |
| HTTP | httpx, TLS verify, `trust_env=False` (client **and** transport), no redirects, identity encoding, replies ≤ 1 MiB, connect 10 s / read 20 s (long-poll: wait + 15 s) |
| Messages | plain text (no `parse_mode`), link previews off; one button row per option, `callback_data = "a:<question_id>:<key>"` (≤ 64 B); dashboard link only as a URL button |
| Link pin | the URL button is sent only if the link is on exactly the dashboard origin (`is_dashboard_link`; origin = `dashboard_origin(allowed_hosts)` from the notifier's own config, same as the admin's). Otherwise the alert goes out without it and a warning names the question id only; empty `allowed_hosts` → never any link button (warned at startup) |
| Message ref | `"<chat_id>:<message_id>"`; `resolve` edits only messages in the owner chat, replaces the keyboard (buttons gone, link kept); "message is not modified" = success |
| Taps | `allowed_updates=["callback_query"]`, ≤ 20 per poll; accepted only if `from.id == message.chat.id == notify_owner_chat_id` and data matches `a:<ULID>:[a-z0-9_-]{1,16}`; everything else dropped, logged by reason only |
| Offset | in memory, advanced past every update (accepted or not); re-read taps after a restart are harmless (first answer wins) |
| Ack | `answerCallbackQuery` with `Recorded: <key>` / `Already answered` / `Expired` / `Withdrawn` / `Unknown` / `Not recorded, try again` |

## Process
- Startup (`build_notifier`, fail closed → `NotifierError`): `notify_enabled` true, `notify_owner_chat_id` a positive int, both token files pass the C12 loader with per-file groups (ADR 0024: `telegram.token` may be the notifier's own group, `notifier.token` never; the two never share a non-root group), bot token shape `<digits>:<30..100 url-safe>`, admin socket passes `verify_admin_socket` **before** the notifier token is used.
- Loops: error → log exception **type name** → back off 1 s, 2 s, … 60 s; a round that returns in < 1 s with no work sleeps 1 s (no busy loop).
- Stop: SIGTERM/SIGINT → stop flag; current rounds get 10 s, then the process exits (abandoned long-polls are safe). A crashed loop stops the process with exit 1 (systemd restarts it).

## Commands (wired by `interfaces/cli.py`, unit N3)
| Command | Function | Notes |
|---|---|---|
| `serve-notifier [--token-group [KIND=]G]` | `serve_notifier(settings, token_groups=…)` | returns 0 on requested stop, 1 on a crashed loop; `NotifierError` → one line, exit 2 |
| `notify pair [--token-group [KIND=]G]` | `pair(settings.telegram_token_file, out, token_groups=…)` | root, notifier stopped (else 409 → clear error); prints an 8-char code, waits ≤ 10 min for `/start <code>` from a private chat, prints `notify_owner_chat_id = <id>` for config (never written automatically, C16) |
| `notify test [--token-group [KIND=]G]` | `send_test(AdminClient.ask_question, out)` | root; verifies the admin socket, then posts `notify_test_body()` to `POST /v1/questions` with the admin token; prints `{"id", "state", "wait_command"}` |
| `question wait <id> [--timeout 24h]` | `interfaces/question_wait.py` | root, admin token; exit 0 answered / 3 expired / 4 cancelled / 5 timeout / 1 error (docs/api.md) |

Token files are loaded with one `TokenLoader` per process (`interfaces/token_file.py`, `TokenKind.NOTIFIER` / `TELEGRAM`), so each file gets its own trusted groups and errors name the right token. `--token-group GROUP` stays accepted; `--token-group notifier=GROUP` binds a group to one file only (ADR 0024). The admin loads `notifier.token` itself (only when `notify_enabled`) and refuses one identical to the admin token (ADR 0022).

## Logging (C36)
- Never: tokens, URLs, message text, labels, callback data, Telegram user ids of strangers.
- `httpx`/`httpcore` loggers are forced to ≥ WARNING when a `TelegramBotClient` is built (their INFO lines contain the URL with the token).
- Errors raised by the adapters carry method/route, status, and a scrubbed, printable, ≤ 120-char Telegram description; transport failures carry only the exception type name and are raised with no chained context.

## Tests
`tests/unit/test_telegram_*.py`, `tests/unit/test_notifier_*.py` (incl. an in-memory end-to-end run through the wire format), `tests/security/test_notifier_security.py`; M2: `tests/security/test_notifier_owner_updates.py` (C44/C46/C47), `tests/security/test_reply_events.py` (C56), `tests/unit/test_telegram_updates.py`, `tests/unit/test_notifier_messages_wire.py`; A1: `tests/security/test_approval_prompts.py` (prompt payload, buttons, code prompt). All HTTP goes through `httpx.MockTransport` (`tests/telegram_support.py`); no network.
