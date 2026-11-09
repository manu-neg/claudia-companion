/*
  Platinum cosmetic layer entry point (backlog R5; docs/frontend-fx.md). Loaded by its own
  <script type="module"> tag in index.html, independent of the functional app and of the shared
  OS layer: it never imports app.js/api.js/dom.js/feed.js/item.js/chrome.js/menu.js, never calls
  fetch, never touches storage. Does nothing unless html[data-os] is "platinum". Every effect is
  wrapped so one throwing can't take the others (or the functional app) down with it - see
  tests/unit/test_fx_isolation.py, which also proves the app works with this directory deleted.
*/
import { initClock } from "./clock.js";
import { initCursor } from "./cursor.js";
import { initScreensaver } from "./screensaver.js";
import { initShade } from "./shade.js";
import { initSplash } from "./splash.js";
import { initZoom } from "./zoom.js";

const OS = "platinum";

// backlog §4: reduced motion turns off *animation*, not the whole layer.
// The clock, window shade (instant either way) and the watch cursor stay;
// only the two effects that are animation for animation's sake - the
// startup splash and the idle screensaver - are skipped entirely. Zoom-open's
// actual animation is removed on the CSS side (fx.css @media
// prefers-reduced-motion), not by skipping initZoom.
const REDUCE_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Run `fn`; a thrown error is logged and swallowed so other effects still run. */
function safe(name, fn) {
  try {
    fn();
  } catch (err) {
    console.error(`fx: ${name} failed`, err);
  }
}

function start() {
  if (document.documentElement.dataset.os !== OS) return;
  safe("zoom", initZoom);
  safe("shade", initShade);
  safe("clock", initClock);
  safe("cursor", initCursor);
  if (!REDUCE_MOTION) {
    safe("splash", initSplash);
    safe("screensaver", initScreensaver);
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
