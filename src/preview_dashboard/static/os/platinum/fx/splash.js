/*
  Startup splash: a full-screen "Previews" splash shown once per page load,
  dismissed by any pointer/keyboard input or a short timeout. The overlay
  keeps pointer-events (it must catch the dismissing input, per
  docs/frontend-fx.md), but that same input must not also reach whatever's
  underneath once the overlay's gone (S2 F1 fix): the click a dismissing
  pointerdown/tap synthesizes next is swallowed once, in the capture phase
  (a short timeout clears the swallow for pointer types that never produce
  one), and the dismissing keydown itself is prevented + stopped so e.g.
  Enter can't also activate a focused control.
*/

const AUTO_DISMISS_MS = 2200;
const CLICK_SWALLOW_MS = 400;

export function initSplash() {
  const overlay = document.createElement("div");
  overlay.className = "fx-splash";
  overlay.setAttribute("role", "presentation");

  const panel = document.createElement("div");
  panel.className = "fx-splash-panel";
  const title = document.createElement("p");
  title.className = "fx-splash-title";
  title.textContent = "Previews";
  const hint = document.createElement("p");
  hint.className = "fx-splash-hint";
  hint.textContent = "Starting up…";
  panel.append(title, hint);
  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  let dismissed = false;
  let timer = null;
  let swallowClickTimer = null;

  const swallowNextClick = (event) => {
    document.removeEventListener("click", swallowNextClick, true);
    clearTimeout(swallowClickTimer);
    event.preventDefault();
    event.stopPropagation();
  };

  const dismiss = (event) => {
    if (dismissed) return;
    dismissed = true;
    overlay.remove();
    document.removeEventListener("pointerdown", dismiss);
    document.removeEventListener("keydown", onKeydown);
    clearTimeout(timer);
    if (event && event.type === "pointerdown") {
      // The pointerdown that dismissed us is followed by a synthesized click on
      // whatever's now underneath; swallow exactly that one so dismissal can't
      // also activate it. Capture phase so it's caught before the target's own
      // handlers run; the timeout covers pointer types that never produce a click.
      document.addEventListener("click", swallowNextClick, true);
      swallowClickTimer = setTimeout(
        () => document.removeEventListener("click", swallowNextClick, true),
        CLICK_SWALLOW_MS,
      );
    }
  };
  const onKeydown = (event) => {
    // Prevent + stop so this same keydown can't also activate a focused
    // control underneath (e.g. Enter on a button) once the overlay is gone.
    event.preventDefault();
    event.stopPropagation();
    dismiss(event);
  };
  document.addEventListener("pointerdown", dismiss, { once: true });
  document.addEventListener("keydown", onKeydown, { once: true });
  timer = setTimeout(dismiss, AUTO_DISMISS_MS);
}
