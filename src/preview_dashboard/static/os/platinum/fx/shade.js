/*
  Window shade: double-clicking a title bar (or a plain click on its decorative .box-shade
  square) collapses the window to just the title bar, classic Mac OS "WindowShade". This module
  also draws that square: it appends it to every title bar ([data-titlebar]) that appears in
  #main, so the square only exists while the effect that gives it meaning is loaded. Purely a CSS
  class toggle on the window's [data-window] section (fx.css hides .window-body); the body stays
  in the DOM untouched and keeps working the moment it's unshaded.
*/

const SHADE_HINT = "Shade: collapse this window to its title bar.";

export function initShade() {
  const main = document.getElementById("main");
  if (main) {
    addShadeBoxes(main);
    // Microtask timing: the square is in place before the new window is first painted.
    new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === 1) addShadeBoxes(node);
        }
      }
    }).observe(main, { childList: true });
  }
  document.addEventListener("dblclick", onTitlebarActivate);
  document.addEventListener("click", onShadeBoxClick);
}

function addShadeBoxes(root) {
  const bars = root.matches?.("[data-titlebar]") ? [root] : root.querySelectorAll("[data-titlebar]");
  for (const bar of bars) {
    if (bar.querySelector(".box-shade")) continue;
    const box = document.createElement("span");
    box.className = "box box-shade";
    // Pointer-only hint (hover/long-press): the square stays aria-hidden and unfocusable, since
    // double-clicking the title bar does the same (accepted in F-W2).
    box.setAttribute("aria-hidden", "true");
    box.dataset.hint = SHADE_HINT;
    bar.appendChild(box);
  }
}

function windowOf(el) {
  return el.closest("[data-window]");
}

function toggle(win) {
  if (win) win.classList.toggle("fx-shaded");
}

function onTitlebarActivate(event) {
  const titlebar = event.target.closest("[data-titlebar]");
  if (titlebar) toggle(windowOf(titlebar));
}

function onShadeBoxClick(event) {
  const box = event.target.closest(".box-shade");
  if (box) toggle(windowOf(box));
}
