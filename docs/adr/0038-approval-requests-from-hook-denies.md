# ADR 0038: Approval requests are built from the hook's deny; a blocked step after consume is final

**TL;DR:** When Claudia's run ends `waiting for approval: …`, the host asks for exactly the action the C59/C60 hook last denied in that run (classifier kind + target), not for what her text says; the shown text starts with that structured action. After an approved resume, any permission denial ends the step for good (C55). The admin mirrors open requests into a viewer-readable snapshot on every change. Unit M5b; C46, C55.

## Context
- C46 binds an approval to a structured `action_kind` + `action_target`; the hook (ADR 0037) only lets a call through when a consumed approval matches them exactly. Something has to produce that pair for the request.
- The model's words are untrusted (prompt injection, C48): if she named kind and target herself, a misleading description could get the owner to approve something else, or a target that never matches.
- The hook gate already classifies the call and records `hook_deny` with kind + target (no command text) in the host's audit log.
- C55 and the owner's rule: a guard block after approval → stop, alert, never retry, reword or reroute.
- The owner needs an independent view of pending requests (C46, Known limitations: a compromised notifier can relabel the phone); the viewer must never open the Claudia DB (ADR 0034).

## Decision
- `DenialRecorder` sits in front of the gate's audit log and keeps, per window, the last deny with a canonical kind and an exact target; it is cleared at the start of every run. Protocol for Claudia: try the step (harmless: the hook denies it), then end the run with `waiting for approval: <short description>`.
- The host builds the action text `<label>: <target> (<description>)`; a description that breaks the text rules is dropped; a target too long to show refuses the request. No recorded deny → no request (fixed reply). Read-only turns can only ask for a `flagged_message` approval of their message.
- The host waits by long-polling (`?wait=50`, deadline = expiry + 5 s, `/stop` cancels), consumes once, and resumes with the stored request's `resume_turn()`; the consumed approval is that run's only gate cover. At most 3 round-trips per owner message.
- C55: in a run holding an action cover, `permission_denials > 0` = guard block → one `failed` alert naming the action text, no re-run, and that text and kind + target are refused for the rest of the window (locks drop when the window closes).
- Admin: `SnapshotOnChange` wraps the approval change events; each change rewrites `<data_dir>/claudia-view/pending-approvals.json` (open + unexpired only, M8's format v1, 0640 in the directory's group, atomic; any failure or > 50 entries removes it).

## Consequences
- An approval always names what the classifier saw; a `rm` or push must be attempted before it can be approved (one extra, denied tool call).
- Any denial in an approved run (even of an unrelated second step) locks the approved action for the window: conservative, the owner decides what next.
- The worker thread blocks while waiting (≤ ~10 min); `/stop` and `/status` still run on the poller thread.
- Expiry seen only by the purge job does not rewrite the snapshot; the viewer drops expired entries itself.
