/*
  Balloon Help hints (backlog W1 item 1): one shared balloon shown
  for whichever `[data-hint]` control the owner is pointing at, focused on,
  or long-pressing. Hint text is a fixed string set by builder code on
  `data-hint` (never item data - C23). Positioned via CSSOM only
  (`balloon.style.left`/`top`, JS property assignment - same rule as
  menu.js's popup: the CSP has no `style-src 'unsafe-inline'`).
  Delegated on `document`, so it needs no per-control wiring and picks up
  controls added later (e.g. the OS layer's shell-bar triggers)
  without either file importing the other. `hashchange` only ever fires on
  `window` (and doesn't bubble), so that one listener is on `window`; every
  other listener stays on `document` (F-W2).
*/
import { h } from "./dom.js";

const HOVER_DELAY_MS = 500;
const LONG_PRESS_MS = 500;
const MOVE_TOLERANCE_PX = 10;
const FIRED_LONG_PRESS_RESET_MS = 600;
const EDGE_MARGIN = 4;
const BALLOON_ID = "balloon-help";

let balloonEl = null;
let current = null; // the element the balloon currently describes
let hoverTarget = null;
let hoverTimer = null;
let touchStart = null;
let touchTimer = null;
// A fired long-press must not also activate the control afterwards (same
// idea as menu.js's firedLongPress): the next click is swallowed once.
let firedLongPress = false;
let firedLongPressTimer = null;

function ensureBalloon() {
  if (!balloonEl) {
    balloonEl = h("div", { class: "balloon-help", role: "tooltip", id: BALLOON_ID, hidden: true });
    document.body.appendChild(balloonEl);
  }
  return balloonEl;
}

function hintTarget(node) {
  return node && typeof node.closest === "function" ? node.closest("[data-hint]") : null;
}

// Elements wired to menu.js's attachContextTrigger (feed rows) already use a
// touch long-press for their context menu; skip the hint's own long-press
// there so the two timers on the same gesture never race. Hover/keyboard
// focus hints still work on those elements.
function ownsLongPress(target) {
  return Boolean(target.closest('[data-context-trigger="true"]'));
}

function clearHoverTimer() {
  if (hoverTimer !== null) clearTimeout(hoverTimer);
  hoverTimer = null;
  hoverTarget = null;
}

function clearTouchTimer() {
  if (touchTimer !== null) clearTimeout(touchTimer);
  touchTimer = null;
  touchStart = null;
}

function clearFiredLongPress() {
  firedLongPress = false;
  if (firedLongPressTimer !== null) clearTimeout(firedLongPressTimer);
  firedLongPressTimer = null;
}

/** Clamp the balloon to the viewport, tail pointing back at `target`. */
function place(target) {
  const balloon = ensureBalloon();
  balloon.style.left = "0px";
  balloon.style.top = "0px";
  const rect = target.getBoundingClientRect();
  const vw = document.documentElement.clientWidth;
  const vh = document.documentElement.clientHeight;
  const bw = balloon.offsetWidth;
  const bh = balloon.offsetHeight;
  let top = rect.bottom + 8;
  let tail = "top";
  if (top + bh > vh - EDGE_MARGIN) {
    top = rect.top - bh - 8;
    tail = "bottom";
  }
  const left = Math.min(Math.max(EDGE_MARGIN, rect.left), vw - bw - EDGE_MARGIN);
  top = Math.min(Math.max(EDGE_MARGIN, top), vh - bh - EDGE_MARGIN);
  balloon.style.left = `${Math.round(left)}px`;
  balloon.style.top = `${Math.round(top)}px`;
  balloon.dataset.tail = tail;
}

function show(target) {
  // A previous control must never keep the balloon or its aria-describedby:
  // switching straight to a new target, or finding the old one already
  // removed from the DOM (e.g. a re-rendered Pin/Unpin button), both count
  // (F-W1).
  if (current && (current !== target || !current.isConnected)) hide();
  const text = target.dataset.hint;
  if (!text || current === target) return;
  current = target;
  const balloon = ensureBalloon();
  balloon.textContent = text;
  balloon.hidden = false;
  target.setAttribute("aria-describedby", BALLOON_ID);
  place(target);
}

function hide() {
  if (!current) return;
  current.removeAttribute("aria-describedby");
  current = null;
  if (balloonEl) balloonEl.hidden = true;
}

function onPointerOver(event) {
  if (event.pointerType !== "mouse") return;
  const target = hintTarget(event.target);
  if (!target || target === hoverTarget) return;
  clearHoverTimer();
  if (current && current !== target) hide();
  hoverTarget = target;
  hoverTimer = setTimeout(() => {
    hoverTimer = null;
    show(target);
  }, HOVER_DELAY_MS);
}

function onPointerOut(event) {
  if (event.pointerType !== "mouse") return;
  const target = hintTarget(event.target);
  if (!target) return;
  const to = event.relatedTarget;
  if (to && target.contains(to)) return; // moved to a child within the same control
  clearHoverTimer();
  if (current === target) hide();
}

function onFocusIn(event) {
  const target = hintTarget(event.target);
  if (!target) return;
  clearHoverTimer();
  show(target);
}

function onFocusOut(event) {
  const target = hintTarget(event.target);
  if (target && current === target) hide();
}

function onKeydown(event) {
  if (event.key === "Escape" && current) hide();
}

function onScroll() {
  if (current) hide();
  clearHoverTimer();
}

function onPointerDown(event) {
  // A new gesture always starts clean, whatever pointer type it is.
  clearFiredLongPress();
  if (event.pointerType !== "touch") return;
  if (current) hide();
  const target = hintTarget(event.target);
  if (!target || ownsLongPress(target)) return;
  touchStart = { x: event.clientX, y: event.clientY };
  touchTimer = setTimeout(() => {
    touchTimer = null;
    firedLongPress = true;
    // Fallback for touch browsers that never send the click that would otherwise clear this.
    firedLongPressTimer = setTimeout(clearFiredLongPress, FIRED_LONG_PRESS_RESET_MS);
    show(target);
  }, LONG_PRESS_MS);
}

function onPointerMove(event) {
  if (!touchStart) return;
  if (Math.hypot(event.clientX - touchStart.x, event.clientY - touchStart.y) > MOVE_TOLERANCE_PX) clearTouchTimer();
}

function onPointerEnd() {
  clearTouchTimer();
}

function onClickCapture(event) {
  // A fired long-press's click must still be swallowed (not also activate
  // the control) and must NOT hide the balloon it just opened.
  if (firedLongPress) {
    clearFiredLongPress();
    event.preventDefault();
    event.stopPropagation();
    return;
  }
  // Any other click means the owner just activated a control (e.g. Pin,
  // which re-renders itself): its hint is done, so drop it before a
  // replaced control can leave a stale balloon (F-W2).
  hide();
}

/** Wire the shared balloon to every `[data-hint]` control on the page. Call once at startup. */
export function initBalloonHints() {
  document.addEventListener("pointerover", onPointerOver);
  document.addEventListener("pointerout", onPointerOut);
  document.addEventListener("pointerdown", onPointerDown);
  document.addEventListener("pointermove", onPointerMove);
  document.addEventListener("pointerup", onPointerEnd);
  document.addEventListener("pointercancel", onPointerEnd);
  document.addEventListener("focusin", onFocusIn);
  document.addEventListener("focusout", onFocusOut);
  document.addEventListener("keydown", onKeydown);
  document.addEventListener("scroll", onScroll, true);
  document.addEventListener("click", onClickCapture, true);
  // A hash-route change (e.g. the Close box's link) tears down the current
  // view without necessarily firing a focusout/pointerout on the removed
  // control first (F-W1). hashchange fires on `window` and doesn't bubble,
  // so a `document` listener never runs (F-W2).
  window.addEventListener("hashchange", hide);
}
