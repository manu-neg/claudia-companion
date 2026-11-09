/*
  Platinum shell (docs/frontend-os.md): the OS contract requires every OS to ship a shell.js, but
  Platinum adds no DOM of its own (no decorative controls: every control must work). start() is a
  deliberate no-op hook; never imports functional modules, touches the network or storage.
*/

const OS = "platinum";

function start() {
  if (document.documentElement.dataset.os !== OS) return;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
