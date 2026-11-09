/*
  Idle screensaver, after Vista's "Bubbles": after 5 minutes with no input the desktop dims and
  iridescent bubbles float across it, bouncing off the edges (CSS animations; each bubble's size,
  speeds and phase are custom properties set via CSSOM - never a style attribute, per CSP). Any
  input fades it away and resets the timer; as in Platinum's (S2 F1), the dismissing input never
  reaches what's underneath. `fxIdleMs` in the URL overrides the threshold for local/Playwright
  testing only (read-only, never persisted, never touches the network; values under 1 s are
  ignored so a typo can't make it flash constantly). While the tab is hidden the idle timer is
  cleared and the overlay removed, so no animation or timer runs in the background.
*/

const DEFAULT_IDLE_MS = 5 * 60 * 1000;
const CLICK_SWALLOW_MS = 400;
const LEAVE_MS = 360;
const MIN_IDLE_MS = 1000;

function idleThreshold() {
  const raw = new URLSearchParams(location.search).get("fxIdleMs");
  const n = raw === null ? Number.NaN : Number(raw);
  return Number.isFinite(n) && n >= MIN_IDLE_MS ? n : DEFAULT_IDLE_MS;
}

const between = (low, high) => low + Math.random() * (high - low);

function bubble() {
  const lane = document.createElement("span");
  lane.className = "aero-ss-lane";
  const float = document.createElement("span");
  float.className = "aero-ss-float";
  const body = document.createElement("span");
  body.className = "aero-ss-bubble";
  float.appendChild(body);
  lane.appendChild(float);
  const dx = between(14, 26);
  const dy = between(11, 21);
  lane.style.setProperty("--aero-ss-size", `${Math.round(between(48, 150))}px`);
  lane.style.setProperty("--aero-ss-dx", `${dx.toFixed(2)}s`);
  lane.style.setProperty("--aero-ss-dy", `${dy.toFixed(2)}s`);
  lane.style.setProperty("--aero-ss-delay-x", `${(-between(0, dx * 2)).toFixed(2)}s`);
  lane.style.setProperty("--aero-ss-delay-y", `${(-between(0, dy * 2)).toFixed(2)}s`);
  return lane;
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
    overlay.className = "aero-screensaver";
    overlay.setAttribute("role", "presentation");
    const count = window.innerWidth < 600 ? 6 : 11;
    for (let i = 0; i < count; i += 1) overlay.appendChild(bubble());
    document.body.appendChild(overlay);
  };
  const hide = () => {
    if (!overlay) return;
    const leaving = overlay;
    overlay = null;
    leaving.classList.add("aero-leaving");
    const remove = () => leaving.remove();
    leaving.addEventListener("animationend", remove, { once: true });
    setTimeout(remove, LEAVE_MS);
  };
  function reset() {
    hide();
    clearTimeout(timer);
    timer = setTimeout(show, idleMs);
  }
  // (ambient.js owns the aero-paused class that also freezes any overlay animation.)
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
