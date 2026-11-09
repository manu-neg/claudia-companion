/*
  Shared OS-layer entry (docs/frontend-os.md): the controls every OS gets in the shell bar - the
  Background picker and the OS picker. Loaded by its own <script type="module"> tag, independent
  of the functional app and of each OS's own shell.js/fx; each control is wrapped so one throwing
  can't stop the other. Never imports functional modules, never touches the network.
*/
import { initBackground } from "./background.js";
import { initOsPicker } from "./os-picker.js";

function safe(name, fn) {
  try {
    fn();
  } catch (err) {
    console.error(`os: ${name} failed`, err);
  }
}

function start() {
  safe("background", initBackground);
  safe("os-picker", initOsPicker);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
