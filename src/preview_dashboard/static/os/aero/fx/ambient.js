/*
  Ambient desktop motion (shimmering rays, drifting bubbles; fx.css) pauses while the tab is
  hidden: html.aero-paused sets animation-play-state: paused on the scenery.
*/

const PAUSED = "aero-paused";

export function initAmbient() {
  const sync = () => document.documentElement.classList.toggle(PAUSED, document.hidden);
  document.addEventListener("visibilitychange", sync);
  sync();
}
