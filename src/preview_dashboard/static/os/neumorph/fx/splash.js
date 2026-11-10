/*
  Startup splash: the porcelain surface alone; the app knob rises out of it and its iris LED
  lights, "Previews" surfaces under it; then the splash sinks away and the shell bar and window
  rise into place (html.neumorph-splashing holds them flat until then, html.neumorph-arriving
  plays their entrance; fx.css). Dismissed after a short time or by any pointer/keyboard input;
  as in the other OSes' splashes (docs/frontend-fx.md, S2 F1) the dismissing input never reaches
  what's underneath: the click a dismissing pointerdown synthesizes is swallowed once (capture
  phase, short timeout), a dismissing keydown is prevented + stopped. While leaving, the overlay
  ignores the pointer (.neumorph-leaving).
*/

const AUTO_DISMISS_MS = 1700;
const CLICK_SWALLOW_MS = 400;
const LEAVE_MS = 420; // a little over the leave animation, in case animationend never fires
const ARRIVE_MS = 900; // the bar and window entrances, then the class goes

export function initSplash() {
  const html = document.documentElement;
  const overlay = document.createElement("div");
  overlay.className = "neumorph-splash";
  overlay.setAttribute("role", "presentation");
  const knob = document.createElement("div");
  knob.className = "neumorph-splash-knob";
  const led = document.createElement("span");
  led.className = "neumorph-splash-led";
  knob.appendChild(led);
  const title = document.createElement("p");
  title.className = "neumorph-splash-title";
  title.textContent = "Previews";
  overlay.append(knob, title);
  html.classList.add("neumorph-splashing");
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
    overlay.classList.add("neumorph-leaving");
    html.classList.remove("neumorph-splashing");
    html.classList.add("neumorph-arriving");
    setTimeout(() => html.classList.remove("neumorph-arriving"), ARRIVE_MS);
    let gone = false;
    const remove = (ev) => {
      if (gone || (ev && ev.target !== overlay)) return;
      gone = true;
      overlay.remove();
    };
    overlay.addEventListener("animationend", remove);
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
