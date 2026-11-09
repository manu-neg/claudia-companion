/*
  Zoom-open: a short scale+fade transition when a new window ([data-window])
  is appended to #main. The dashboard CSP forbids inline styles, so this is
  a CSS-only approximation of the classic "zoom rectangles" open (exact
  transform-origin/keyframes live in fx.css, keyed off body[data-view]); the
  observer here only ever adds/removes a class, never touches layout state
  or the window's own content.
*/

const ZOOM_CLASS = "fx-zoom-in";

export function initZoom() {
  const main = document.getElementById("main");
  if (!main) return;
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1 && node.matches?.("[data-window]")) {
          node.classList.add(ZOOM_CLASS);
          const clear = () => node.classList.remove(ZOOM_CLASS);
          // Reduced motion removes the animation in CSS, so "animationend"
          // never fires there; a timeout fallback cleans the class up either way.
          node.addEventListener("animationend", clear, { once: true });
          setTimeout(clear, 250);
        }
      }
    }
  });
  observer.observe(main, { childList: true });
}
