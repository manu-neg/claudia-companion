/*
  Background picker (docs/frontend-os.md): fills the shell bar's [data-slot="background"] with a
  "Background" drop-down of the active OS's background set (os/<name>/backgrounds.js via the
  registry) and applies the choice as body[data-background] - on `body` so it fills the whole
  viewport (W1 item 6). The OS's chrome.css paints each id (CSS only, no url()). Remembered per
  OS through storage.js (C23 exception); never touches the functional modules or the network.
*/
import { activeOs, backgroundsOf } from "./registry.js";
import { loadBackground, saveBackground } from "./storage.js";
import { createShellMenu } from "./shell-menu.js";

function applyBackground(target, os, id) {
  const options = backgroundsOf(os);
  const valid = options.some((entry) => entry.id === id);
  target.dataset.background = valid ? id : options[0].id;
}

export function initBackground() {
  const os = activeOs();
  const slot = document.querySelector('[data-shellbar] [data-slot="background"]');
  if (!os || !slot || backgroundsOf(os).length === 0) return;

  applyBackground(document.body, os, loadBackground(os));

  const menu = createShellMenu({
    slot,
    name: "background",
    label: "Background",
    hint: "Background: choose a background pattern.",
    options: backgroundsOf(os),
    current: loadBackground(os),
    onChoose: (id) => {
      applyBackground(document.body, os, id);
      saveBackground(os, id);
      menu.setChecked(id);
    },
  });
}
