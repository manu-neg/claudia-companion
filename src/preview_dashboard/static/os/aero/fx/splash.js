/*
  Startup splash: the glossy orb lights up with a soft bloom on a deep-blue welcome screen, then
  "Previews" fades up; the whole screen fades away after a short time or on any pointer/keyboard
  input. As in Platinum's splash (docs/frontend-fx.md, S2 F1), the dismissing input never reaches
  what's underneath: the click a dismissing pointerdown synthesizes is swallowed once (capture
  phase, short timeout), and a dismissing keydown is prevented + stopped. While fading out the
  overlay ignores the pointer (.aero-leaving), so nothing is blocked after dismissal.
*/

const AUTO_DISMISS_MS = 2100;
const CLICK_SWALLOW_MS = 400;
const LEAVE_MS = 360; // a little over --aero-dur-slow, in case animationend never fires

export function initSplash() {
  const overlay = document.createElement("div");
  overlay.className = "aero-splash";
  overlay.setAttribute("role", "presentation");

  const orb = document.createElement("div");
  orb.className = "aero-splash-orb";
  const bloom = document.createElement("span");
  bloom.className = "aero-splash-bloom";
  orb.appendChild(bloom);
  const title = document.createElement("p");
  title.className = "aero-splash-title";
  title.textContent = "Previews";
  const hint = document.createElement("p");
  hint.className = "aero-splash-hint";
  hint.textContent = "Starting up…";
  overlay.append(orb, title, hint);
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
    document.removeEventListener("pointerdown", dismiss);
    document.removeEventListener("keydown", onKeydown);
    clearTimeout(timer);
    overlay.classList.add("aero-leaving");
    const remove = () => overlay.remove();
    overlay.addEventListener("animationend", remove, { once: true });
    setTimeout(remove, LEAVE_MS);
    if (event && event.type === "pointerdown") {
      document.addEventListener("click", swallowNextClick, true);
      swallowClickTimer = setTimeout(
        () => document.removeEventListener("click", swallowNextClick, true),
        CLICK_SWALLOW_MS,
      );
    }
  };
  const onKeydown = (event) => {
    event.preventDefault();
    event.stopPropagation();
    dismiss(event);
  };
  document.addEventListener("pointerdown", dismiss, { once: true });
  document.addEventListener("keydown", onKeydown, { once: true });
  timer = setTimeout(dismiss, AUTO_DISMISS_MS);
}
