/*
  Close fade: a plain click on a window's close control ([data-box="close"], a same-page hash
  link back to the list) first plays the Aero fade-down (.aero-closing, fx.css), then follows
  the link's own hash. Only the timing changes: modified clicks, other buttons and links whose
  hash is already current pass straight through, and a timeout guarantees the navigation.
*/

const CLOSING = "aero-closing";
const FALLBACK_MS = 220; // a little over --aero-dur-fast, in case animationend never fires
const CLEANUP_MS = 1000;

export function initClose() {
  document.addEventListener("click", onClick);
}

function onClick(event) {
  if (event.defaultPrevented || event.button !== 0) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const link = event.target.closest?.('[data-titlebar] a[data-box="close"]');
  const win = link?.closest("[data-window]");
  if (!link || !win) return;
  const hash = link.hash;
  if (!hash || hash === location.hash) return;
  event.preventDefault();
  if (win.classList.contains(CLOSING)) return;
  win.classList.add(CLOSING);

  let done = false;
  const go = () => {
    if (done) return;
    done = true;
    location.hash = hash;
    // The router normally replaces the window; if it's still here, show it again.
    setTimeout(() => win.classList.remove(CLOSING), CLEANUP_MS);
  };
  win.addEventListener("animationend", go, { once: true });
  setTimeout(go, FALLBACK_MS);
}
