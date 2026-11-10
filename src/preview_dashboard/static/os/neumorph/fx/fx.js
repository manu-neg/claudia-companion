/*
  Neumorph effects entry point (docs/frontend-os.md#neumorph "Motion", docs/frontend-fx.md).
  Loaded by its own <script type="module">; does nothing unless html[data-os] is "neumorph".
  Never imports functional modules, never touches the network or storage; each effect runs in
  safe() so one throwing can't stop the others (or the app). Entrances, hover/press and the
  picker/balloon/toast exits are pure CSS (chrome.css, fx.css); these scripts add the clock,
  the exits of surfaces the app removes at once (ghost.js), the badge pop, splash, saver and
  the knowledge map's wave, channel flow, ripple and pointer light (kmap.js).
*/
import { initBadges } from "./badge.js";
import { initClock } from "./clock.js";
import { initGhosts } from "./ghost.js";
import { initKmap } from "./kmap.js";
import { initScreensaver } from "./screensaver.js";
import { initSplash } from "./splash.js";

const OS = "neumorph";

// Reduced motion turns off animation, not the layer: only the clock runs.
const REDUCE_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Run `fn`; a thrown error is logged and swallowed so other effects still run. */
function safe(name, fn) {
  try {
    fn();
  } catch (err) {
    console.error(`neumorph fx: ${name} failed`, err);
  }
}

function start() {
  if (document.documentElement.dataset.os !== OS) return;
  // The clock is not motion: it runs under reduced motion too.
  safe("clock", initClock);
  if (REDUCE_MOTION) return;
  safe("ghosts", initGhosts);
  safe("badges", initBadges);
  safe("splash", initSplash);
  safe("screensaver", initScreensaver);
  safe("kmap", initKmap);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
