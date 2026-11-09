/*
  Platinum's background set (docs/frontend-os.md): the ids the Background picker offers under
  this OS, first entry = default. Each id is painted by a body[data-background="<id>"] rule in
  chrome.css (gradients only). Data only: imported by os/registry.js, nothing else.
*/

export default Object.freeze([
  Object.freeze({ id: "standard", label: "Standard" }),
  Object.freeze({ id: "pinstripe", label: "Pinstripe" }),
  Object.freeze({ id: "weave", label: "Weave" }),
  Object.freeze({ id: "waves", label: "Waves" }),
  Object.freeze({ id: "zen", label: "Zen Dots" }),
  Object.freeze({ id: "static", label: "Static" }),
]);
