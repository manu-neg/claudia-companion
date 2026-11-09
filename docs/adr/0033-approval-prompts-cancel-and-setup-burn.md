# ADR 0033: Approval prompt delivery, host cancel routes, setup code burn (unit A1)

**TL;DR:** Approval prompts ride the existing outbox as an `approval` notification with `approval_id`; the channel alone draws Approve/Deny `p:<id>:ok|no`; prompts go out only for a live PENDING request. The `claudia` token gets two cancel routes (close-only, CAS) for `/stop`. `claudia totp setup` burns its confirmation step in the admin's step-up state.

## Context
ADR 0032 left three gaps: `UnwiredApprovalPrompts` made every create 503, there was no way for the host to cancel open requests on `/stop` (C58), and the setup's confirmation code stayed replayable for ~90 s.

## Decision
- **Prompts:** `OutboxApprovalPrompts` (application) stores one `approval` notification (`notifications.approval_id`, folded into unreleased migration 5, no FK) plus one SEND per channel; the text is the request's **stored** action text, verbatim. The payload carries `approval_id` and no buttons/link/question/long form (domain invariant); `TelegramChannel` builds exactly `[Approve p:<id>:ok][Deny p:<id>:no]`. Stored labels can't influence the keyboard.
- **Live check in the outbox:** `pending()` joins `approval_requests`; a prompt whose request is not PENDING, is past `expires_at`, or is gone is settled DONE unsent (like a resolved question's SEND). No RESOLVE edit of a prompt (left for later).
- **Text rebuilt at handout (amendment, F-C1a/F-C1b):** the prompt text handed to the notifier is re-rendered from the request in the admin-only Claudia DB (ADR 0034), never read from the outbox row (the viewer can write that database); a differing row is logged and the stored text sent. A second prompt notification for one request, or any RESOLVE for a prompt, can only be forged and fails closed (`ValidationError`, nothing sent).
- **Create bounds (amendment):** `create` takes a 10/hour budget first (refused attempts count, 429) and admits at most 3 open unexpired requests across all windows (409). The request's `action_kind` + `action_target` come from the hook's last deny (ADR 0038), and a `dashboard_delete` target names the tool (`trash:<id>`, `prune:<id>:keep=N`, `empty:trash`).
- **Notices outside the alert budget:** the code prompt and the owner notices (C47) are fixed texts the notifier sends itself, so they don't use the 20/hour alert budget (C37).
- **Fail closed:** no enabled channel or any prompt error → create cancels the request and fails. `approval` is actionable, so `NotifyService` (`dashboard_notify`) refuses it.
- **Code prompt:** after the admin answers `tapped`, the notifier sends one fixed text (`CODE_PROMPT_TEXT`) via `TelegramChannel.send_code_prompt()`, which takes no text argument.
- **Cancel:** `POST /v1/claudia/approvals/{id}/cancel` (`cancelled | already_resolved | busy | unknown`) and `POST /v1/claudia/approvals/cancel-open` (`{}` or `{"window_id"}` → `{"cancelled": [ids]}`). Open → CANCELLED only, by CAS with up to 3 retries, so a concurrent tap can't outrun `/stop`; resolved requests are never rewritten. C45's "no state change but consume" becomes "consume and close-only cancel".
- **Setup burn:** `StepUpState.with_burned_step` (replay mark `max`, counters untouched); `FileStepUpState(owner_uid=<data_dir owner>)` lets root write it chowned to the admin. Burn happens before the secret is written; an unusable state aborts setup before the secret is shown.

## Consequences
- Approvals are usable end to end once the host (M4/M5) calls create/consume/cancel.
- A prompt for a cancelled/decided request already on the phone keeps its buttons; taps answer `already_decided`. Editing it away is future work.
- The setup and the admin can both write the state file; a simultaneous write could drop one wrong-code count (rare, accepted).
