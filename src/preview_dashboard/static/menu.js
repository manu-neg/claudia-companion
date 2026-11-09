/*
  Popup/context menu (R4): one menu open at a time, opened by right-click,
  long-press (touch), the row "…" button or Menu key/Shift+F10; closes on Escape, an outside
  pointer, Tab, or after an item runs. Also holds the item actions the menu offers (pin/unpin,
  trash/restore with the existing confirm dialog, download) so feed.js and item.js share one
  implementation instead of duplicating the network calls. Uses api.js only (C23: no storage).
*/
import { ApiError, apiPost } from "./api.js";
import { confirmAction } from "./dialog.js";
import { h, toast } from "./dom.js";

const LONG_PRESS_MS = 500;
const MOVE_TOLERANCE_PX = 10;
const FIRED_LONG_PRESS_RESET_MS = 600;

let open = null; // {root, anchor, restoreFocus}

function items(root) {
  return Array.from(root.querySelectorAll('[role="menuitem"]:not([aria-disabled="true"])'));
}

function focusAt(root, index) {
  const list = items(root);
  if (!list.length) return;
  const i = ((index % list.length) + list.length) % list.length;
  list[i].focus();
}

function onOutsidePointer(event) {
  if (open && !open.root.contains(event.target)) closeMenu();
}

function onKeydown(event) {
  if (!open) return;
  const list = items(open.root);
  const current = list.indexOf(document.activeElement);
  if (event.key === "Escape") {
    event.preventDefault();
    closeMenu();
  } else if (event.key === "ArrowDown") {
    event.preventDefault();
    focusAt(open.root, current + 1);
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    focusAt(open.root, current - 1);
  } else if (event.key === "Home") {
    event.preventDefault();
    focusAt(open.root, 0);
  } else if (event.key === "End") {
    event.preventDefault();
    focusAt(open.root, list.length - 1);
  } else if (event.key === "Tab") {
    closeMenu();
  } else if (event.key === "Enter" || event.key === " ") {
    // A plain <div role="menuitem"> gets no native Enter/Space activation (unlike <button>/<a>).
    event.preventDefault();
    if (document.activeElement && list.includes(document.activeElement)) document.activeElement.click();
  }
}

/** Close the open menu, if any, and return focus to whatever opened it. */
export function closeMenu() {
  if (!open) return;
  const { root, restoreFocus } = open;
  open = null;
  root.remove();
  document.removeEventListener("pointerdown", onOutsidePointer, true);
  document.removeEventListener("keydown", onKeydown, true);
  document.removeEventListener("scroll", closeMenu, true);
  window.removeEventListener("resize", closeMenu);
  if (restoreFocus && document.contains(restoreFocus)) restoreFocus.focus();
}

function place(root, { x, y, anchor }) {
  document.body.appendChild(root);
  const rect = root.getBoundingClientRect();
  const vw = document.documentElement.clientWidth;
  const vh = document.documentElement.clientHeight;
  let left = x;
  let top = y;
  if (typeof left !== "number" || typeof top !== "number") {
    const box = anchor.getBoundingClientRect();
    left = box.left;
    top = box.bottom + 2;
  }
  left = Math.min(Math.max(4, left), vw - rect.width - 4);
  top = Math.min(Math.max(4, top), vh - rect.height - 4);
  root.style.left = `${Math.round(left)}px`;
  root.style.top = `${Math.round(top)}px`;
}

/**
 * Open a popup menu of `entries` (`"sep"` or `{label, action, disabled, danger}`) at
 * `(x, y)` or, when omitted, below `anchor`. Only one menu is open at a time. Focus returns to
 * `restoreFocus` (default: `anchor`) on close.
 */
export function openMenu({ x, y, anchor, entries, restoreFocus = anchor || null }) {
  closeMenu();
  const nodes = entries.map((entry) => {
    if (entry === "sep") return h("hr", { class: "ctx-menu-sep", role: "separator" });
    const node = h(
      "div",
      {
        role: "menuitem",
        class: `ctx-menu-item${entry.danger ? " is-danger" : ""}`,
        tabindex: "-1",
        "aria-disabled": entry.disabled ? "true" : null,
      },
      entry.label,
    );
    if (!entry.disabled) {
      node.addEventListener("click", () => {
        closeMenu();
        entry.action();
      });
    }
    return node;
  });
  const root = h("div", { class: "ctx-menu", role: "menu", dataset: { window: "menu" } }, nodes);
  place(root, { x, y, anchor });
  open = { root, restoreFocus };
  // Safe to attach immediately: the event that triggered this open (pointerdown/click/keydown,
  // already fully dispatched by the time its handler calls openMenu) is never a "pointerdown"
  // arriving at these new listeners, so it can't immediately re-close the menu it just opened.
  document.addEventListener("pointerdown", onOutsidePointer, true);
  document.addEventListener("keydown", onKeydown, true);
  document.addEventListener("scroll", closeMenu, true);
  window.addEventListener("resize", closeMenu);
  focusAt(root, 0);
  return root;
}

/**
 * Wire `el` to open a menu built by `getEntries()` (called fresh each time, so it can reflect
 * the item's current state) on right-click, a ~500 ms touch press, or Menu key/Shift+F10.
 * `anchor` (default `el`) positions a keyboard-opened menu; a pointer-opened one follows the
 * pointer. Focus always returns to `el` itself (the thing the owner right-clicked/pressed/had
 * focused), regardless of `anchor`.
 */
export function attachContextTrigger(el, getEntries, { anchor = el } = {}) {
  // Marks the element for balloon.js: it already owns a touch long-press (the context menu),
  // so the balloon skips arming its own long-press timer on the same gesture there.
  el.dataset.contextTrigger = "true";
  let timer = null;
  let start = null;
  // A long press must not also fire the row link's normal click/navigation afterwards, but
  // touch browsers often send no click at all after the long-press gesture, so this can't
  // rely on a click to clear it: the next pointerdown (the row's next tap) and a short
  // timeout fallback both reset it too, or that next tap would be silently swallowed.
  let firedLongPress = false;
  let firedLongPressTimer = null;
  const clearFiredLongPress = () => {
    firedLongPress = false;
    if (firedLongPressTimer !== null) clearTimeout(firedLongPressTimer);
    firedLongPressTimer = null;
  };
  const cancelPress = () => {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    start = null;
  };
  el.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    cancelPress();
    openMenu({ x: event.clientX, y: event.clientY, anchor, entries: getEntries(), restoreFocus: el });
  });
  el.addEventListener("keydown", (event) => {
    if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
      event.preventDefault();
      openMenu({ anchor, entries: getEntries(), restoreFocus: el });
    }
  });
  el.addEventListener("pointerdown", (event) => {
    // The next tap starts a fresh gesture: whatever a previous long-press left behind is done.
    clearFiredLongPress();
    if (event.pointerType !== "touch") return;
    start = { x: event.clientX, y: event.clientY };
    timer = setTimeout(() => {
      timer = null;
      firedLongPress = true;
      // Fallback for touch browsers that never send the click that would otherwise clear this.
      firedLongPressTimer = setTimeout(clearFiredLongPress, FIRED_LONG_PRESS_RESET_MS);
      openMenu({ x: start.x, y: start.y, anchor, entries: getEntries(), restoreFocus: el });
    }, LONG_PRESS_MS);
  });
  el.addEventListener("pointermove", (event) => {
    if (!start) return;
    if (Math.hypot(event.clientX - start.x, event.clientY - start.y) > MOVE_TOLERANCE_PX) cancelPress();
  });
  el.addEventListener("pointerup", cancelPress);
  el.addEventListener("pointercancel", cancelPress);
  el.addEventListener(
    "click",
    (event) => {
      if (!firedLongPress) return;
      clearFiredLongPress();
      event.preventDefault();
      event.stopPropagation();
    },
    true,
  );
}

/** Open (download) the https URL `url` (already checked by `httpsUrl`); no-op when null. */
export function triggerDownload(url) {
  if (!url) return;
  const a = h("a", { href: url, rel: "noopener noreferrer" });
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/** Pin or unpin `item`; toasts the result. Returns whether it succeeded. */
export async function setPinned(item, pinned) {
  try {
    await apiPost(`/api/items/${encodeURIComponent(item.id)}/${pinned ? "pin" : "unpin"}`);
    toast(pinned ? "Pinned" : "Unpinned");
    return true;
  } catch (err) {
    toast(err instanceof ApiError && err.status === 409 ? "Trashed items can't be pinned." : "That didn't work. Try again.");
    return false;
  }
}

/** Confirm, then trash or restore `item`; toasts the result. Returns whether it succeeded. */
export async function changeItemState(item, toTrash) {
  const ok = await confirmAction(
    toTrash
      ? {
          title: "Move to trash?",
          body: "It stays in the trash for a while before it's deleted for good. You can restore it until then.",
          confirmLabel: "Move to trash",
          danger: true,
          iconId: "i-trash-full",
        }
      : { title: "Restore this item?", body: "It goes back to the feed.", confirmLabel: "Restore", iconId: "i-folder" },
  );
  if (!ok) return false;
  try {
    await apiPost(`/api/items/${encodeURIComponent(item.id)}/${toTrash ? "trash" : "restore"}`);
    toast(toTrash ? "Moved to trash" : "Restored");
    return true;
  } catch (err) {
    toast(err instanceof ApiError && err.status === 404 ? "This item no longer exists." : "That didn't work. Try again.");
    return false;
  }
}
