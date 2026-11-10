/*
  "Waiting for your approval" group box of the knowledge-map window: the open approvals the admin
  recorded (GET /api/claudia/approvals), so the owner can check a phone prompt against them. With
  dashboard decisions on (F-CL6) each row also has Approve (asks for the authenticator code here)
  and Deny (asks to confirm): the click is POSTed to the viewer, which forwards it to the admin;
  the admin decides and the result shown is one fixed text per verdict. Action text is untrusted
  (textContent in <bdi>). No valid snapshot = nothing confirmed (fail closed). The code lives only
  in its input box until it is sent in a POST body, and the box is emptied right after.
*/
import { apiGet, apiPost, startPolling } from "./api.js";
import { confirmAction } from "./dialog.js";
import { clear, h, relativeTime, toast, ULID_RE, untrusted } from "./dom.js";

const KIND_LABELS = {
  pr_merge: "Merge a pull request",
  deploy: "Deploy",
  git_push_main: "Push to main",
  rm: "Delete files",
  dashboard_delete: "Delete from the dashboard",
  settings_edit: "Change settings",
  peer_message: "Message another session",
};

const STATE_LABELS = {
  pending: "Waiting for your decision",
  tapped: "Waiting for your code",
  approved: "Approved, about to run",
};

// One fixed sentence per admin verdict; nothing from the server is ever shown as text.
const RESULT_TEXTS = {
  approved: "Approved. Claudia carries on.",
  denied: "Denied. Claudia won't run it.",
  wrong_code: "Wrong code. Nothing was approved.",
  locked: "Too many wrong codes: codes are locked for 15 minutes.",
  already_decided: "Already decided (on Telegram or here).",
  expired: "This request has expired.",
  unknown: "This request is no longer open.",
  rate_limited: "Too many tries. Wait a few minutes.",
  refused: "The code couldn't be checked right now. Nothing was decided.",
};
const UNAVAILABLE_TEXT = "Couldn't reach the server. Nothing was decided.";
// Verdicts after which the row is settled (the next load drops it from the list).
const FINAL_RESULTS = new Set(["approved", "denied", "already_decided", "expired", "unknown"]);
const DECIDABLE_STATES = new Set(["pending", "tapped"]);
const CODE_RE = /^[0-9]{6}$/;

/** Keep only entries whose shape the server promised; anything else is dropped. */
function valid(approval) {
  return (
    approval &&
    typeof approval.id === "string" &&
    ULID_RE.test(approval.id) &&
    typeof approval.action_text === "string" &&
    typeof approval.expires_at === "string"
  );
}

/** POST one decision; resolves to a RESULT_TEXTS key, or null when the server can't be reached. */
async function sendDecision(id, body) {
  try {
    const result = await apiPost(`/api/claudia/approvals/${encodeURIComponent(id)}/decision`, { body });
    const verdict = result.data && result.data.result;
    return typeof verdict === "string" && Object.hasOwn(RESULT_TEXTS, verdict) ? verdict : null;
  } catch (error) {
    return error && error.status === 429 ? "rate_limited" : null;
  }
}

/** Build the group box; returns `{root, stop}` (stop ends its polling). */
export function approvalsPanel() {
  const body = h("div", { class: "kmap-approvals-body", "aria-live": "polite" });
  const root = h(
    "section",
    { class: "group kmap-approvals", "aria-labelledby": "kmap-approvals-title" },
    h("h2", { class: "group-title", id: "kmap-approvals-title", text: "Waiting for your approval" }),
    body,
  );
  let etag = null;
  // While the owner types a code or a decision is in flight, polls don't redraw the list
  // (that would drop the half-typed code); the newest data is drawn once he is done.
  let busy = false;
  let deferred = null;

  function settle(statusLine, verdict) {
    const text = verdict ? RESULT_TEXTS[verdict] : UNAVAILABLE_TEXT;
    statusLine.textContent = text;
    toast(text);
  }

  function finish(refresh) {
    busy = false;
    if (refresh) {
      etag = null; // the decision changed the list: fetch it fresh
      load().catch(() => show(null));
    } else if (deferred) {
      const data = deferred;
      deferred = null;
      show(data);
    }
  }

  function decisionControls(approval) {
    const statusLine = h("p", { class: "kmap-approval-status", role: "status" });
    const approve = h("button", { type: "button", class: "button button-primary", text: "Approve…" });
    const deny = h("button", { type: "button", class: "button", text: "Deny…" });
    const actions = h("div", { class: "buttons kmap-approval-actions" }, approve, deny);
    const codeId = `kmap-code-${approval.id}`;
    const input = h("input", {
      type: "text",
      id: codeId,
      class: "kmap-code-input",
      inputmode: "numeric",
      autocomplete: "one-time-code",
      pattern: "[0-9]{6}",
      maxlength: "6",
      spellcheck: "false",
      "aria-describedby": `${codeId}-hint`,
    });
    const send = h("button", { type: "button", class: "button button-primary", text: "Approve" });
    const cancel = h("button", { type: "button", class: "button", text: "Cancel" });
    const codeBox = h(
      "div",
      { class: "kmap-approval-code", role: "group", "aria-label": "Approve with your authenticator code", hidden: true },
      h("label", { class: "kmap-code-label", for: codeId, text: "Authenticator code" }),
      h("div", { class: "kmap-code-row" }, input, send, cancel),
      h("p", { class: "kmap-approvals-note", id: `${codeId}-hint`, text: "Six digits from your authenticator app. Wrong codes count towards a 15-minute lock." }),
    );

    function setDisabled(disabled) {
      for (const control of [approve, deny, input, send, cancel]) control.disabled = disabled;
    }

    function closeCode() {
      input.value = "";
      codeBox.hidden = true;
      actions.hidden = false;
    }

    approve.addEventListener("click", () => {
      busy = true;
      statusLine.textContent = "";
      actions.hidden = true;
      codeBox.hidden = false;
      input.focus();
    });

    cancel.addEventListener("click", () => {
      closeCode();
      approve.focus();
      finish(false);
    });

    async function submitCode() {
      const code = input.value.trim();
      if (!CODE_RE.test(code)) {
        statusLine.textContent = "Enter the six digits from your authenticator app.";
        input.focus();
        return;
      }
      input.value = ""; // the code leaves the page once, in the POST body below
      setDisabled(true);
      statusLine.textContent = "Checking…";
      const verdict = await sendDecision(approval.id, { decision: "approve", code });
      setDisabled(false);
      settle(statusLine, verdict);
      if (verdict === "wrong_code") {
        input.focus(); // let him retype; the lockout bounds the tries
        return;
      }
      closeCode();
      finish(FINAL_RESULTS.has(verdict));
    }

    send.addEventListener("click", submitCode);
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        submitCode();
      } else if (event.key === "Escape") {
        event.preventDefault();
        cancel.click();
      }
    });

    deny.addEventListener("click", async () => {
      busy = true;
      const sure = await confirmAction({
        title: "Deny this request?",
        body: "Claudia will be told not to run it. This can't be undone.",
        confirmLabel: "Deny",
        danger: true,
      });
      if (!sure) {
        finish(false);
        deny.focus();
        return;
      }
      setDisabled(true);
      statusLine.textContent = "Sending…";
      const verdict = await sendDecision(approval.id, { decision: "deny" });
      setDisabled(false);
      settle(statusLine, verdict);
      finish(FINAL_RESULTS.has(verdict));
    });

    return [actions, codeBox, statusLine];
  }

  function entry(approval, decisions) {
    const kind = KIND_LABELS[approval.kind] || "Confirm a message";
    const what = approval.target ? [kind, ": ", untrusted(approval.target)] : [kind];
    const decidable = decisions && DECIDABLE_STATES.has(approval.state);
    return h(
      "li",
      { class: "kmap-approval", dataset: { approvalId: approval.id } },
      h("span", { class: "kmap-approval-text" }, untrusted(approval.action_text)),
      h("span", { class: "kmap-approval-meta" }, what),
      h("span", { class: "kmap-approval-meta" }, `${STATE_LABELS[approval.state] || "Open"}, expires ${relativeTime(approval.expires_at)}`),
      // relativeTime may end in "hr." itself, so the id goes on its own line, not after a period.
      h("span", { class: "kmap-approval-meta" }, "Request ID ", h("code", { class: "kmap-approval-id", text: approval.id })),
      decidable ? decisionControls(approval) : null,
    );
  }

  function show(data) {
    if (busy) {
      deferred = data;
      return;
    }
    clear(body);
    const available = Boolean(data && data.available === true);
    const decisions = available && data.decisions === true;
    const list = available && Array.isArray(data.approvals) ? data.approvals.filter(valid) : [];
    if (list.length) {
      body.appendChild(h("ul", { class: "kmap-approval-list" }, list.map((a) => entry(a, decisions))));
      body.appendChild(
        h("p", {
          class: "kmap-approvals-note",
          text: decisions
            ? "Approve here with your authenticator code, or on Telegram. Whichever you do first counts."
            : "Tap Approve on your phone only for a request listed here, with the same text.",
        }),
      );
      return;
    }
    body.appendChild(h("p", { class: "kmap-approvals-none", text: "Nothing is waiting for your approval." }));
    if (!available) {
      body.appendChild(
        h("p", {
          class: "kmap-approvals-note",
          text: "This list can't be checked right now, so approve nothing on your phone until it can.",
        }),
      );
    }
  }

  async function load() {
    const result = await apiGet("/api/claudia/approvals", { etag });
    if (result.status === 304) return;
    etag = result.etag;
    show(result.data);
  }

  load().catch(() => show(null));
  const stop = startPolling(() => load().catch(() => show(null)));
  return { root, stop };
}
