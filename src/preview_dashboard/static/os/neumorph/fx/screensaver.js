/*
  Idle screensaver, a calm breathing relief: after 5 minutes with no input the porcelain covers
  the desk and one large dome slowly breathes in and out of it inside a few engraved rings (CSS
  animations; fx.css). Any input lets it sink away and resets the timer; as in the other OSes'
  savers (S2 F1) the dismissing input never reaches what's underneath. `fxIdleMs` in the URL
  overrides the threshold for local/Playwright testing only (read-only, never persisted, never
  touches the network; values under 1 s are ignored). While the tab is hidden the idle timer is
  cleared and the overlay removed, so nothing animates or ticks in the background.
*/

const DEFAULT_IDLE_MS = 5 * 60 * 1000;
const CLICK_SWALLOW_MS = 400;
const LEAVE_MS = 420;
const MIN_IDLE_MS = 1000;

function idleThreshold() {
  const raw = new URLSearchParams(location.search).get("fxIdleMs");
  const n = raw === null ? Number.NaN : Number(raw);
  return Number.isFinite(n) && n >= MIN_IDLE_MS ? n : DEFAULT_IDLE_MS;
}

function scene() {
  const overlay = document.createElement("div");
  overlay.className = "neumorph-screensaver";
  overlay.setAttribute("role", "presentation");
  for (const size of ["outer", "mid", "inner"]) {
    const ring = document.createElement("span");
    ring.className = `neumorph-ss-ring neumorph-ss-ring-${size}`;
    overlay.appendChild(ring);
  }
  const dome = document.createElement("span");
  dome.className = "neumorph-ss-dome";
  overlay.appendChild(dome);
  return overlay;
}

export function initScreensaver() {
  const idleMs = idleThreshold();
  let timer = null;
  let overlay = null;
  let swallowClickTimer = null;

  const swallowNextClick = (event) => {
    document.removeEventListener("click", swallowNextClick, true);
    clearTimeout(swallowClickTimer);
    event.preventDefault();
    event.stopPropagation();
  };

  const show = () => {
    if (overlay) return;
    overlay = scene();
    document.body.appendChild(overlay);
  };
  const hide = () => {
    if (!overlay) return;
    const leaving = overlay;
    overlay = null;
    leaving.classList.add("neumorph-leaving");
    let gone = false;
    const remove = (ev) => {
      if (gone || (ev && ev.target !== leaving)) return;
      gone = true;
      leaving.remove();
    };
    leaving.addEventListener("animationend", remove);
    setTimeout(remove, LEAVE_MS);
  };
  function reset() {
    hide();
    clearTimeout(timer);
    timer = setTimeout(show, idleMs);
  }
  // Hidden tabs get no timer and no overlay (battery); becoming visible restarts the idle clock.
  function onVisibility() {
    if (document.hidden) {
      clearTimeout(timer);
      timer = null;
      if (overlay) {
        overlay.remove();
        overlay = null;
      }
    } else {
      reset();
    }
  }
  function onInput(event) {
    const wasShowing = Boolean(overlay);
    reset();
    if (!wasShowing) return; // ordinary idle-reset input; nothing to swallow
    if (event.type === "pointerdown") {
      document.addEventListener("click", swallowNextClick, true);
      swallowClickTimer = setTimeout(
        () => document.removeEventListener("click", swallowNextClick, true),
        CLICK_SWALLOW_MS,
      );
    } else if (event.type === "keydown") {
      event.preventDefault();
      event.stopPropagation();
    }
  }
  // keydown can't be passive (it may need preventDefault above); the rest stay passive.
  document.addEventListener("keydown", onInput);
  for (const type of ["pointerdown", "pointermove", "wheel", "touchstart"]) {
    document.addEventListener(type, onInput, { passive: true });
  }
  document.addEventListener("visibilitychange", onVisibility);
  if (document.hidden) onVisibility();
  else reset();
}
