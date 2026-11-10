# ADR 0041: Claudia unblock: request_approval tool, 24 h requests, peer prefix only

**TL;DR:** Claudia asks for a risky step with the host-owned `request_approval` tool (kind + exact target + short reason, host-checked, same admin path as the reply-line marker). Requests live 24 h (legacy 600 s rows still valid, no migration), outlive their window and resume in a new one with a carried, exact, single-use cover. Peer messages need only the exact prefix. Deny reasons say what to do. Unit F-CL3; C46, C52, C58, C59, C60. Owner decision 2026-11-09. Addendum F-CL5: decided prompts are edited to a fixed outcome text, `cancel_approval`, clearer host rules.

## Context
- Approvals expired after 600 s while the owner was often away; the host worker blocked on the wait, so the owner could not chat meanwhile, and the window closing (3 h idle, 8 h cap, `/new`) dropped the request.
- Claudia could only ask with a marker line on the last line of her reply after a hook deny; she often missed it or rewrote the target.
- Messages to owner-attached sessions needed a `peer_message` approval; the owner found this blocking and decided the prefix alone is enough.
- Deny reasons named only the kind, so she retried in other forms (chains, `sh -c`) instead of asking.

## Decision
- **Tool:** `mcp__claudia-kb__request_approval(action_kind, action_target, reason)` on the existing `claudia-kb` MCP server (so the pinned C51 MCP config keeps exactly two servers), registered only for caller `claudia`, in the FULL set only. The server forwards over the host's root 0600 control socket (same socket and peer checks as the hook); the host checks run + actionable message, kind in the six approvable kinds, target normalized like the hook's, reason 1–120 chars (invisible / web address refused), one call per turn, ≤ 3 chained asks, C55 lock; then creates through the same admin route. The tool answers id + "pending" or a fixed refusal text. The reply-line path stays.
- **Lifetime:** new requests expire 24 h after creation. The domain accepts exactly `{600 s, 24 h}` (`APPROVAL_TTLS`); no schema change, no data rewrite.
- **Parking:** the worker never waits. Created requests are parked; a third host thread polls their decisions and queues settle work for the worker (ordered with messages, tagged with the stop generation). An approval whose window closed resumes in the current window or a new one (`WindowTracker.open_for_resume`, never past a halt or newer stop epoch); `HookGate.begin_run(carry_over=True)` accepts that one cover from another window for that run only.
- **Peers:** `SendMessage` with the exact prefix → no decision for any live session; without it → deny quoting the prefix + audit; the C52 audit drops its interactive-approval rule. No `updatedInput`.
- **Deny reasons:** risky → "call request_approval with action_kind=… and the exact action_target …"; `unknown` → one plain command per call, never approvable. Nothing suggests a way around a block.
- **Panel:** the snapshot lists PENDING and TAPPED only; the reader drops expired entries by its own clock.

## Consequences
- Fewer blocked turns; the owner can chat while a request waits.
- New risk: an approval may land hours after the ask (Known limitations, 24 h stale approval); mitigated by the restated action text, exact single-use cover, TOTP and `/stop` cancelling every open request.
- Owner-attached sessions can receive her messages without a code (Known limitations).
- A host restart forgets parked requests; see "F-CL3b" below (they are cancelled, the owner re-asks).
- Unchanged:

## F-CL3b: review fixes (S-CL3 single review)
- **Stranded requests:** parked requests live only in memory, and a 24 h request holds one of the 3 open-cap slots, so a restart (or an approved request queued when `/stop` arrived) could block new asks for a day. The host now cancels **every** open request of every window through the existing admin route (`POST /v1/claudia/approvals/cancel-open` with `{}`, claudia token; new `HostAdmin.cancel_all_open_approvals`) at start, at shutdown and in `/stop` (after the window-scoped cancel, which still resets that window's budgets). The count is logged; a failure sends one `failed` alert. Cost: the owner re-asks after a restart or deploy.
- **Run-bound tool:** `request_approval` must present a per-run random nonce. The host makes it in `ClaudiaHost._run` (`secrets.token_hex(16)`), keeps it in the `RunContext` the flow checks (constant-time compare; empty or wrong = "no run"), and passes it as `RunRequest.run_nonce`; the runner adds it to that run's child env as `CLAUDIA_RUN_NONCE` (`run_env`). The `claudia-kb` MCP server inherits the env, so the pinned MCP config (C51) stays unchanged; the control-socket message gains a `nonce` field. Recap runs get none. It ties the tool to the run in progress, it does not authenticate against the run itself (Known limitations); Claude Code must hand its env to stdio MCP servers (verify at deploy, fails closed to the reply-line path).
- **Cleanup:** the unused `HOOK_PEER_LOOKUP_TIMEOUT` is gone; `ClaudeAgentsDirectory` stays (the C52 audit record still resolves `interactive`). Approve + TOTP, single use, exact target, `unknown` never approvable, the hook never allows, C55.

## F-CL5: approvals clarity (owner request 2026-11-09)
- **Context:** the owner saw a decided prompt keep its Approve/Deny buttons, did not know the panel row and the Telegram message were the same request, and Claudia offered to approve or relay approval for other sessions.
- **Host rules:** one Claudia bot chat for everything; one `request_approval` = Telegram prompt + panel row (never ask twice); the owner decides on Telegram (Approve + code), the panel is for checking, both update by themselves; only the owner approves: she never approves, relays or implies approval for another session, which must ask the owner itself (she may tell it so).
- **Outcome edit:** why the domain forbade `final_state` on approval payloads: the outbox DB is viewer-writable (ADR 0034), so nothing in a prompt row may decide what the phone shows; the only RESOLVE path was therefore "forged". Kept true: `final_state` stays question-only and still forbidden with `approval_id`; a new `approval_outcome` field carries the request's state, which the admin **reads from the admin-only DB at handout** and maps to one fixed text (`APPROVAL_OUTCOME_TEXTS`, no action text); the row's text and `final_state` (a schema placeholder: answered / cancelled / expired, no migration) are ignored. A RESOLVE while the request is PENDING or TAPPED is still forged and fails closed. The channel edits with its own copy of the constant and an empty keyboard.
- **Best effort:** `ApprovalService` queues the edit (`ApprovalResolutions` port, `OutboxApprovalResolutions`) after approve / deny / cancel / expiry is stored; any failure is logged and swallowed, so the decision is never blocked or changed. Consume queues none (its text equals approved). Purge expiries queue it too.
- **`cancel_approval(request_id)`:** a second host-owned `claudia-kb` tool, same socket, nonce, run and full-set checks as `request_approval`, only for a request the host has parked (no oracle), through the existing close-only cancel route. FULL set only; it only reduces power.
- **Refused:** Claudia approving other sessions' actions (she would stand in for the owner; the guards accept only the owner's own chat OK anyway).
- **Consequence:** the edited message no longer shows which action it was (fixed texts only); Claudia's reply after the decision gives the context.
