/*
  OS picker (docs/frontend-os.md): fills the shell bar's [data-slot="os"] with an "OS" drop-down
  of the registry's OSes. A pick is saved as `pdash.os` (storage.js, C23 exception) and the page
  reloads so os-boot.js applies it before any stylesheet. Shown only when there is a choice
  (two or more OSes): a menu with one entry would be a false affordance.
*/
import { activeOs, osLabel, OSES } from "./registry.js";
import { saveOs } from "./storage.js";
import { createShellMenu } from "./shell-menu.js";

export function initOsPicker() {
  const slot = document.querySelector('[data-shellbar] [data-slot="os"]');
  if (!slot || OSES.length < 2) return;
  const current = activeOs();
  createShellMenu({
    slot,
    name: "os",
    label: "OS",
    hint: "OS: switch the whole desktop look (reloads the page).",
    options: OSES.map((id) => ({ id, label: osLabel(id) })),
    current,
    onChoose: (id) => {
      if (id !== current && saveOs(id)) location.reload();
    },
  });
}
