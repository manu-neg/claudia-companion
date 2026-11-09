/*
  "Waiting for your approval" group box of the knowledge-map window: the open approvals the admin
  recorded (GET /api/claudia/approvals), so the owner can check a phone prompt against them before
  tapping Approve (security.md §15.1a M2). Read only: there is nothing to approve here. Action text
  is untrusted (textContent in <bdi>). No valid snapshot = nothing confirmed (fail closed).
*/
import { apiGet, startPolling } from "./api.js";
import { clear, h, relativeTime, ULID_RE, untrusted } from "./dom.js";

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
  pending: "Waiting for your tap",
  tapped: "Waiting for your code",
  approved: "Approved, about to run",
};

function entry(approval) {
  const kind = KIND_LABELS[approval.kind] || "Confirm a message";
  const what = approval.target ? [kind, ": ", untrusted(approval.target)] : [kind];
  return h(
    "li",
    { class: "kmap-approval", dataset: { approvalId: approval.id } },
    h("span", { class: "kmap-approval-text" }, untrusted(approval.action_text)),
    h("span", { class: "kmap-approval-meta" }, what),
    h("span", { class: "kmap-approval-meta" }, `${STATE_LABELS[approval.state] || "Open"}, expires ${relativeTime(approval.expires_at)}`),
    // relativeTime may end in "hr." itself, so the id goes on its own line, not after a period.
    h("span", { class: "kmap-approval-meta" }, "Request ID ", h("code", { class: "kmap-approval-id", text: approval.id })),
  );
}

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

  function show(data) {
    clear(body);
    const list = data && data.available === true && Array.isArray(data.approvals) ? data.approvals.filter(valid) : [];
    if (data && data.available === true && list.length) {
      body.appendChild(h("ul", { class: "kmap-approval-list" }, list.map(entry)));
      body.appendChild(
        h("p", { class: "kmap-approvals-note", text: "Tap Approve on your phone only for a request listed here, with the same text." }),
      );
      return;
    }
    body.appendChild(h("p", { class: "kmap-approvals-none", text: "Nothing is waiting for your approval." }));
    if (!data || data.available !== true) {
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
