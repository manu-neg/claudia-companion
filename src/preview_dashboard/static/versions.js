/*
  Version switcher for item revisions (ADR 0019). Renders only when the item JSON lists more than
  one kept revision (`revisions`, newest first); tolerates the field being absent or malformed.
  Labels are built from numbers and timestamps only (no item text) and set via textContent.
  The switcher is a "Version:" field row (dt/dd) for the Get Info window's field list, with a
  "Delete old versions" button beside the popup (ADR 0030, C43): confirm dialog with the count
  and size, then POST revisions/prune guarded by the head the owner saw (`?expected=`).
*/
import { ApiError, apiPost } from "./api.js";
import { popup } from "./chrome.js";
import { confirmAction } from "./dialog.js";
import { formatBytes, h, relativeTime, toast } from "./dom.js";

function validRevisions(item) {
  const list = Array.isArray(item?.revisions) ? item.revisions : [];
  return list.filter((r) => r && typeof r === "object" && Number.isInteger(r.number) && r.number > 0);
}

function latestOf(item, revisions) {
  return Number.isInteger(item?.latest_revision) ? item.latest_revision : revisions[0]?.number ?? null;
}

/**
 * What "Delete old versions" would remove: `{count, bytes, latest}` (every kept revision except
 * the latest; bytes = their sizes), or null when there is nothing older to delete.
 */
export function olderVersions(item) {
  const revisions = validRevisions(item);
  const latest = latestOf(item, revisions);
  if (latest === null) return null;
  const older = revisions.filter((r) => r.number !== latest);
  if (!older.length) return null;
  const bytes = older.reduce((sum, r) => sum + (Number.isInteger(r.total_size) && r.total_size > 0 ? r.total_size : 0), 0);
  return { count: older.length, bytes, latest };
}

function versionsText(count) {
  return count === 1 ? "1 older version" : `${count} older versions`;
}

/** Fixed dialog copy for `olderVersions()` (numbers only, never item text). */
export function pruneDialogText({ count, bytes, latest }) {
  return {
    title: `Delete ${versionsText(count)} (${formatBytes(bytes)})?`,
    body: `Only version ${latest}, the latest, stays. This can't be undone. Space is freed within about two hours.`,
  };
}

/**
 * Confirm, then delete every version of `item` but the latest. Toasts the result.
 * Returns whether anything was deleted.
 */
export async function deleteOldVersions(item) {
  const older = olderVersions(item);
  if (!older) return false;
  const ok = await confirmAction({
    ...pruneDialogText(older),
    confirmLabel: "Delete old versions",
    danger: true,
    iconId: "i-trash-full",
  });
  if (!ok) return false;
  try {
    const path = `/api/items/${encodeURIComponent(item.id)}/revisions/prune?expected=${older.latest}`;
    const { data } = await apiPost(path);
    const removed = Number.isInteger(data?.revisions_removed) ? data.revisions_removed : older.count;
    toast(`Deleted ${removed === 1 ? "1 old version" : `${removed} old versions`}. Space is freed within about two hours.`);
    return true;
  } catch (err) {
    if (err instanceof ApiError && err.status === 409) toast("This item changed meanwhile. Check its versions and try again.");
    else if (err instanceof ApiError && err.status === 404) toast("This item no longer exists.");
    else toast("That didn't work. Try again.");
    return false;
  }
}

function revisionLabel(revision, latest) {
  const when = typeof revision.created_at === "string" ? relativeTime(revision.created_at) : "";
  const tag = revision.number === latest ? "latest" : when;
  return tag ? `Version ${revision.number} (${tag})` : `Version ${revision.number}`;
}

/**
 * A "Version:" field row (`<div><dt><label><dd>popup select`) of revisions, or null when there is nothing to switch between.
 * The option for `item.revision` (the one being shown) is selected. `onSelect(number, isLatest)`
 * runs when the owner picks another version. With `onPrune` (active items only), a
 * "Delete old versions" button sits beside the popup and calls it when pressed.
 */
export function versionSwitcher(item, onSelect, onPrune = null) {
  const revisions = validRevisions(item);
  if (revisions.length <= 1) return null;
  const latest = latestOf(item, revisions);
  const id = `version-${item.id}`;
  const select = h(
    "select",
    {
      id,
      class: "select",
      on: {
        change: (event) => {
          const number = Number(event.currentTarget.value);
          if (Number.isInteger(number) && number > 0) onSelect(number, number === latest);
        },
      },
    },
    revisions.map((revision) =>
      h("option", {
        value: String(revision.number),
        selected: revision.number === item.revision,
        text: revisionLabel(revision, latest),
      }),
    ),
  );
  const prune =
    typeof onPrune === "function" && olderVersions(item)
      ? h("button", {
          type: "button",
          class: "button button-danger-quiet version-prune",
          text: "Delete old versions",
          dataset: { hint: "Delete old versions: keep only the latest version and free the space." },
          on: { click: onPrune },
        })
      : null;
  return h(
    "div",
    { class: "field version-switcher" },
    h("dt", {}, h("label", { for: id, text: "Version:" })),
    h("dd", {}, popup(select), prune),
  );
}

/** A short notice with a "Show latest" button when an older revision is on screen, else null. */
export function olderVersionNotice(item, onLatest) {
  if (!Number.isInteger(item?.revision) || !Number.isInteger(item?.latest_revision)) return null;
  if (item.revision === item.latest_revision) return null;
  return h(
    "p",
    { class: "version-notice", role: "status" },
    `You're viewing version ${item.revision}. `,
    h("button", { type: "button", class: "link-button", text: "Show the latest version", on: { click: onLatest } }),
  );
}
