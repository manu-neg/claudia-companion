/*
  Watch cursor while a navigation feels "in flight". fx never imports api.js
  (isolation rule, docs/frontend-fx.md), so this approximates "a request is
  running" from public signals only: the hashchange the router already fires,
  held until #main is repopulated (observed, not polled), with a minimum
  show time so it never flickers and a max timeout so it can never get stuck.
*/

const BUSY_CLASS = "fx-busy";
const MIN_MS = 150;
const MAX_MS = 4000;

export function initCursor() {
  const main = document.getElementById("main");
  if (!main) return;
  let hideTimer = null;
  let minTimer = null;
  let minElapsed = true;
  let wantHide = false;

  const hide = () => {
    document.documentElement.classList.remove(BUSY_CLASS);
    clearTimeout(hideTimer);
    wantHide = false;
  };
  const maybeHide = () => {
    wantHide = true;
    if (minElapsed) hide();
  };
  const show = () => {
    document.documentElement.classList.add(BUSY_CLASS);
    minElapsed = false;
    wantHide = false;
    clearTimeout(minTimer);
    minTimer = setTimeout(() => {
      minElapsed = true;
      if (wantHide) hide();
    }, MIN_MS);
    clearTimeout(hideTimer);
    hideTimer = setTimeout(hide, MAX_MS);
  };

  window.addEventListener("hashchange", show);
  const observer = new MutationObserver(() => maybeHide());
  observer.observe(main, { childList: true });
}
