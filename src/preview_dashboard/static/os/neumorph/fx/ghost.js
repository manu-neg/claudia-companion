/*
  Exits for surfaces the functional code removes at once (a window on navigation, the context
  menu, the confirm dialog and its veil, the full-screen preview's veil): just before or as one
  goes, an empty, aria-hidden "ghost" slab of the same size takes its place and sinks back into
  the surface (fx.css), then removes itself. Ghosts hold no content (never item data), ignore
  the pointer, and only ever follow what the app already did: nothing is delayed or prevented.
*/

const GHOST = "neumorph-ghost";
const CLEAR_MS = 450; // a little over the slowest exit, in case animationend never fires

/** Drop an empty ghost of `kind` at a box (viewport px); `fixed` = viewport-pinned overlay. */
function ghost(kind, box, fixed) {
  const el = document.createElement("div");
  el.className = `${GHOST} ${GHOST}-${kind}`;
  el.setAttribute("aria-hidden", "true");
  if (box) {
    // Positions go through CSSOM custom properties (CSP: no style attribute strings).
    const dx = fixed ? 0 : window.scrollX;
    const dy = fixed ? 0 : window.scrollY;
    el.style.setProperty("--neu-gx", `${Math.round(box.left + dx)}px`);
    el.style.setProperty("--neu-gy", `${Math.round(box.top + dy)}px`);
    el.style.setProperty("--neu-gw", `${Math.round(box.width)}px`);
    el.style.setProperty("--neu-gh", `${Math.round(box.height)}px`);
  }
  document.body.appendChild(el);
  let gone = false;
  const remove = () => {
    if (gone) return;
    gone = true;
    el.remove();
  };
  el.addEventListener("animationend", remove, { once: true });
  setTimeout(remove, CLEAR_MS);
}

// --- windows: our hashchange listener is registered before the router's (app.js adds its own
// after an API round trip), so the old window is still in place when we measure it. ---

function onHashChange() {
  const win = document.querySelector("#main > [data-window]");
  if (!win) return;
  const box = win.getBoundingClientRect();
  if (box.width > 0 && box.height > 0) ghost("window", box, false);
}

// --- menu and dialog: remember where each one sits while it is open (its untransformed layout
// box, so a running entrance doesn't shrink the ghost), drop a ghost there when it is removed. ---

const boxes = new WeakMap();

function layoutBox(node) {
  const width = node.offsetWidth;
  const height = node.offsetHeight;
  if (node.matches("dialog")) {
    // A modal dialog is centred in the viewport.
    return { left: (innerWidth - width) / 2, top: (innerHeight - height) / 2, width, height };
  }
  const style = getComputedStyle(node);
  return { left: Number.parseFloat(style.left) || 0, top: Number.parseFloat(style.top) || 0, width, height };
}

function onBodyChange(records) {
  for (const record of records) {
    for (const node of record.addedNodes) {
      if (node.nodeType === 1 && node.matches(".ctx-menu, dialog.dialog")) boxes.set(node, layoutBox(node));
    }
    for (const node of record.removedNodes) {
      const box = node.nodeType === 1 ? boxes.get(node) : null;
      if (!box || box.width === 0) continue;
      if (node.matches("dialog")) {
        ghost("veil", null, true);
        ghost("dialog", box, true);
      } else {
        ghost("menu", box, true);
      }
    }
  }
}

// --- full-screen preview: expand.js toggles html.has-overlay with it; on close, the veil fades. ---

function watchOverlay() {
  const html = document.documentElement;
  let open = html.classList.contains("has-overlay");
  new MutationObserver(() => {
    const now = html.classList.contains("has-overlay");
    if (open && !now) ghost("veil", null, true);
    open = now;
  }).observe(html, { attributes: true, attributeFilter: ["class"] });
}

export function initGhosts() {
  window.addEventListener("hashchange", onHashChange);
  new MutationObserver(onBodyChange).observe(document.body, { childList: true });
  watchOverlay();
}
