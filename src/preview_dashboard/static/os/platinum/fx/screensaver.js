/*
  Idle screensaver: after 5 minutes with no input, dims the screen with a
  drifting pattern; any input dismisses it immediately and resets the idle
  timer. Dismissing input must not also reach whatever's underneath once the
  overlay's gone (S2 F1 fix, mirrors splash.js): the click a dismissing
  pointerdown/tap synthesizes next is swallowed once, in the capture phase
  (short timeout fallback for pointer types that never produce one), and the
  dismissing keydown itself is prevented + stopped so e.g. Enter can't also
  activate a focused control. Ordinary idle-reset input (no overlay showing)
  is untouched and stays passive. fx.js never calls this under reduced
  motion, so it never runs there. `fxIdleMs` in the URL overrides the
  threshold for local/Playwright testing only (read-only, never persisted,
  never touches the network; values under 1 s are ignored).
*/

const DEFAULT_IDLE_MS = 5 * 60 * 1000;
const CLICK_SWALLOW_MS = 400;
const MIN_IDLE_MS = 1000;

function idleThreshold() {
  const raw = new URLSearchParams(location.search).get("fxIdleMs");
  const n = raw === null ? Number.NaN : Number(raw);
  return Number.isFinite(n) && n >= MIN_IDLE_MS ? n : DEFAULT_IDLE_MS;
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
    overlay = document.createElement("div");
    overlay.className = "fx-screensaver";
    overlay.setAttribute("role", "presentation");
    const pattern = document.createElement("div");
    pattern.className = "fx-screensaver-pattern";
    overlay.appendChild(pattern);
    document.body.appendChild(overlay);
  };
  const hide = () => {
    if (!overlay) return;
    overlay.remove();
    overlay = null;
  };
  function reset() {
    hide();
    clearTimeout(timer);
    timer = setTimeout(show, idleMs);
  }
  function onInput(event) {
    const wasShowing = Boolean(overlay);
    reset();
    if (!wasShowing) return; // ordinary idle-reset input; nothing to swallow
    if (event.type === "pointerdown") {
      // Mirrors splash.js: swallow the click a dismissing pointerdown/tap
      // synthesizes next, so it can't also activate whatever's underneath.
      document.addEventListener("click", swallowNextClick, true);
      swallowClickTimer = setTimeout(
        () => document.removeEventListener("click", swallowNextClick, true),
        CLICK_SWALLOW_MS,
      );
    } else if (event.type === "keydown") {
      // Prevent + stop so this same keydown can't also activate a focused
      // control underneath (e.g. Enter on a button) once the overlay is gone.
      event.preventDefault();
      event.stopPropagation();
    }
  }
  // keydown can't be passive (it may need preventDefault above); the rest stay passive.
  document.addEventListener("keydown", onInput);
  for (const type of ["pointerdown", "pointermove", "wheel", "touchstart"]) {
    document.addEventListener(type, onInput, { passive: true });
  }
  reset();
}
