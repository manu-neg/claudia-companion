/*
  Desktop icons (Feed, Trash): item counts under each icon, and the trash can drawn full when
  the trash holds anything. Counts come from the list API (first 200 per state, "200+" beyond),
  revalidated with ETags so an idle dashboard mostly gets 304s.
*/
import { apiGet, itemsPath, startPolling } from "./api.js";

const LIMIT = 200;
const COUNT_POLL_MS = 30_000;
const etags = { active: null, trashed: null };

function label(count, more) {
  if (more) return `${count}+ items`;
  return count === 1 ? "1 item" : `${count} items`;
}

async function refreshState(state) {
  const result = await apiGet(itemsPath({ state, limit: LIMIT }), { etag: etags[state] });
  if (result.status === 304) return;
  etags[state] = result.etag;
  const items = Array.isArray(result.data?.items) ? result.data.items : [];
  const more = Boolean(result.data?.next_cursor);
  for (const slot of document.querySelectorAll(`[data-count="${state}"]`)) {
    slot.textContent = label(items.length, more);
  }
  const link = document.querySelector(`[data-nav="${state === "trashed" ? "trash" : "feed"}"]`);
  if (link) link.dataset.countValue = String(items.length);
  if (state === "trashed") {
    const can = document.querySelector("[data-trash-icon]");
    if (can) can.setAttribute("href", items.length ? "#i-trash-full" : "#i-trash");
  }
}

/** Refresh both counts now (after navigation, trash or restore). Errors leave the old text. */
export async function refreshCounts() {
  await Promise.allSettled([refreshState("active"), refreshState("trashed")]);
}

/** Keep the counts fresh while the page is visible. Returns a stop function. */
export function startCountPolling() {
  return startPolling(refreshCounts, COUNT_POLL_MS);
}
