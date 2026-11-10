/*
  Neumorph shell (docs/frontend-os.md#neumorph): swaps the raised soft-UI art into the shared
  sprite (icons.js) and moves the Feed/Trash desktop icons into the shell bar's nav slot, where
  chrome.css draws them as soft pill keys. No decorative DOM of its own (the app knob, LEDs and
  relief are pure CSS). Does nothing unless html[data-os] is "neumorph"; no functional imports,
  no network, no storage.
*/
import { swapSprite } from "./icons.js";

const OS = "neumorph";

// Functional code finds Feed/Trash by their [data-nav] hooks at use time, wherever they sit.
function moveDeskIcons() {
  const icons = document.querySelector(".desktop > .desk-icons");
  const slot = document.querySelector('[data-shellbar] [data-slot="nav"]');
  if (icons && slot) slot.appendChild(icons);
}

/** Run `fn`; a thrown error is logged and swallowed so the other parts still apply. */
function safe(name, fn) {
  try {
    fn();
  } catch (err) {
    console.error(`neumorph shell: ${name} failed`, err);
  }
}

function start() {
  if (document.documentElement.dataset.os !== OS) return;
  safe("sprite", swapSprite);
  safe("desk icons", moveDeskIcons);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
