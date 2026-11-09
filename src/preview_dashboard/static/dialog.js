/*
  Confirmation dialog built on native <dialog> (focus trap, Escape and backdrop handled by the
  browser), drawn as an alert box: icon, text, Cancel and the ringed default button.
  Resolves true only when the owner presses the confirm button.
*/
import { icon } from "./chrome.js";
import { h } from "./dom.js";

/**
 * Ask for confirmation; `danger` styles the confirm button as destructive. `iconId`: a sprite
 * icon shown at the left (default: caution).
 */
export function confirmAction({ title, body, confirmLabel, danger = false, iconId = "i-caution" }) {
  return new Promise((resolve) => {
    const cancel = h("button", { type: "button", class: "button", text: "Cancel", value: "cancel" });
    const confirm = h("button", {
      type: "button",
      class: `button button-primary${danger ? " button-danger" : ""}`,
      text: confirmLabel,
      value: "confirm",
    });
    const titleId = `dialog-title-${Date.now()}`;
    const dialog = h(
      "dialog",
      { class: "dialog", "aria-labelledby": titleId, dataset: { window: "dialog" } },
      h(
        "div",
        { class: "alert" },
        icon(iconId, "icon-lg alert-icon"),
        h(
          "div",
          { class: "alert-text" },
          h("h2", { class: "alert-title", id: titleId, text: title }),
          h("p", { class: "alert-body", text: body }),
        ),
      ),
      h("div", { class: "buttons dialog-actions" }, cancel, confirm),
    );
    let result = false;
    cancel.addEventListener("click", () => dialog.close());
    confirm.addEventListener("click", () => {
      result = true;
      dialog.close();
    });
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(result);
    });
    document.body.appendChild(dialog);
    dialog.showModal();
    cancel.focus();
  });
}
