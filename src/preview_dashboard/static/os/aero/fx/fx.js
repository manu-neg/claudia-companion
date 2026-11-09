/*
  Aero effects entry point (docs/frontend-os.md#aero, docs/frontend-fx.md). Loaded by its own
  <script type="module"> tag; does nothing unless html[data-os] is "aero". Never imports
  functional modules, never touches the network or storage; each effect runs inside safe() so
  one throwing can't stop the others (or the app). Most motion is pure CSS in fx.css.
*/
import { initAmbient } from "./ambient.js";
import { initBadges } from "./badge.js";
import { initClock } from "./clock.js";
import { initClose } from "./close.js";
import { initScreensaver } from "./screensaver.js";
import { initSplash } from "./splash.js";

const OS = "aero";

// Reduced motion turns off animation, not the layer: the clock still runs; the splash,
// screensaver, close fade, badge pop and ambient pausing (nothing moves anyway) are skipped.
const REDUCE_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Run `fn`; a thrown error is logged and swallowed so other effects still run. */
function safe(name, fn) {
  try {
    fn();
  } catch (err) {
    console.error(`aero fx: ${name} failed`, err);
  }
}

function start() {
  if (document.documentElement.dataset.os !== OS) return;
  safe("clock", initClock);
  if (REDUCE_MOTION) return;
  safe("close", initClose);
  safe("badges", initBadges);
  safe("ambient", initAmbient);
  safe("splash", initSplash);
  safe("screensaver", initScreensaver);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
