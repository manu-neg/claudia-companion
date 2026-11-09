/*
  Aero's background set (docs/frontend-os.md): the ids the Background picker offers under this
  OS, first entry = default. Each id is painted by a body[data-background="<id>"] rule in
  chrome.css (gradients plus the CSS-only scenery shell.js adds). Data only: imported by
  os/registry.js, nothing else.
*/

export default Object.freeze([
  Object.freeze({ id: "sky", label: "Sky" }),
  Object.freeze({ id: "aurora", label: "Aurora" }),
  Object.freeze({ id: "ocean", label: "Ocean" }),
  Object.freeze({ id: "dusk", label: "Dusk" }),
  Object.freeze({ id: "plain", label: "Plain" }),
]);
