/*
  OS registry (docs/frontend-os.md): the allowlist of installable OSes, the default, and each
  OS's display label and background set. The single source for os/storage.js and the pickers;
  os-boot.js repeats OSES/DEFAULT_OS as literals (it can't import) and a test keeps them equal.
*/
import aeroBackgrounds from "./aero/backgrounds.js";
import neumorphBackgrounds from "./neumorph/backgrounds.js";
import platinumBackgrounds from "./platinum/backgrounds.js";

export const DEFAULT_OS = "platinum";

const INFO = Object.freeze({
  platinum: Object.freeze({ label: "Platinum", backgrounds: platinumBackgrounds }),
  aero: Object.freeze({ label: "Aero", backgrounds: aeroBackgrounds }),
  neumorph: Object.freeze({ label: "Neumorph", backgrounds: neumorphBackgrounds }),
});

/** Allowlisted OS names, in picker order. */
export const OSES = Object.freeze(["platinum", "aero", "neumorph"]);

/** Display label of an allowlisted OS (never item data). */
export function osLabel(os) {
  return OSES.includes(os) ? INFO[os].label : "";
}

/** `[{id, label}]` backgrounds of an allowlisted OS (first = default); [] otherwise. */
export function backgroundsOf(os) {
  return OSES.includes(os) ? INFO[os].backgrounds : [];
}

/** The OS os-boot.js applied (html[data-os]), or null if it's missing or not allowlisted. */
export function activeOs() {
  const os = document.documentElement.dataset.os;
  return OSES.includes(os) ? os : null;
}
