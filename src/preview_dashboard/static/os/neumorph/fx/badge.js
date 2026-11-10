/*
  Count badge pop: when a Feed/Trash count rises (the data-count-value hook desktop.js keeps on
  each [data-nav] link), its number rises out of its sunken well once and settles back
  (.neumorph-badge-pop, fx.css). The first value after load never pops; counts are only read.
*/

const POP = "neumorph-badge-pop";
const CLEAR_MS = 450; // a little over --neu-dur-pop

export function initBadges() {
  for (const link of document.querySelectorAll("[data-nav]")) {
    let last = Number.parseInt(link.dataset.countValue ?? "", 10);
    new MutationObserver(() => {
      const now = Number.parseInt(link.dataset.countValue ?? "", 10);
      if (Number.isFinite(last) && Number.isFinite(now) && now > last) pop(link);
      last = now;
    }).observe(link, { attributes: true, attributeFilter: ["data-count-value"] });
  }
}

function pop(link) {
  link.classList.remove(POP);
  // Next frame, so a pop already running restarts instead of being ignored.
  requestAnimationFrame(() => {
    link.classList.add(POP);
    setTimeout(() => link.classList.remove(POP), CLEAR_MS);
  });
}
