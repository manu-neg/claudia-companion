/*
  Expand-to-full-screen overlay for previews (images, frames). A CSS overlay rather than the
  Fullscreen API so it also works on iPhone Safari; Escape or the close button leaves it and
  focus returns to the control that opened it.
*/
import { h } from "./dom.js";

/**
 * Make `stage` expandable. Returns `{open, close, button}`; `button` is an "Expand" control
 * to place in the preview's toolbar.
 */
export function expandable(stage, { label = "Expand" } = {}) {
  let opener = null;
  const closeButton = h("button", {
    type: "button",
    class: "stage-close",
    text: "Close",
    dataset: { hint: "Close: return to the normal view." },
    on: { click: () => close() },
  });
  const onKey = (event) => {
    if (event.key === "Escape") close();
  };
  function open(from) {
    if (stage.classList.contains("is-expanded")) return;
    opener = from || document.activeElement;
    stage.classList.add("is-expanded");
    stage.setAttribute("role", "dialog");
    stage.setAttribute("aria-modal", "true");
    stage.prepend(closeButton);
    document.documentElement.classList.add("has-overlay");
    document.addEventListener("keydown", onKey);
    closeButton.focus();
  }
  function close() {
    if (!stage.classList.contains("is-expanded")) return;
    stage.classList.remove("is-expanded", "is-zoomed");
    stage.removeAttribute("role");
    stage.removeAttribute("aria-modal");
    closeButton.remove();
    document.documentElement.classList.remove("has-overlay");
    document.removeEventListener("keydown", onKey);
    if (opener && opener.isConnected) opener.focus();
  }
  const button = h("button", {
    type: "button",
    class: "button",
    text: label,
    dataset: { hint: `${label}: fill the screen with this preview.` },
    on: { click: (event) => open(event.currentTarget) },
  });
  return { open, close, button };
}
