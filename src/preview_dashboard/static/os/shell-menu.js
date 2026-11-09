/*
  Shared shell-bar drop-down (docs/frontend-os.md): a trigger + radio menu placed in one
  [data-slot] of the shell bar, used by the Background and OS pickers. OS-neutral markup and
  behaviour only (classes shell-menu-*); each OS styles it in its chrome.css. Text comes from
  fixed labels, never item data; no network, no storage.
*/

/**
 * Build a drop-down inside `slot`.
 * `name`: hook value (`data-shell-trigger`); `label`/`hint`: fixed trigger text and balloon hint;
 * `options`: `[{id, label}]`; `current`: checked id; `onChoose(id)`: called on a pick.
 * Returns `{setChecked(id)}`.
 */
export function createShellMenu({ slot, name, label, hint, options, current, onChoose }) {
  // Anchor wraps trigger + menu so the popup is positioned with plain CSS under its trigger.
  const anchor = document.createElement("span");
  anchor.className = "shell-menu-anchor";
  slot.appendChild(anchor);

  const trigger = document.createElement("span");
  trigger.className = "shell-menu-trigger";
  trigger.dataset.shellTrigger = name;
  // Read by balloon.js (functional, loaded separately) via the shared [data-hint] hook - the OS
  // layer never imports it, balloon.js never imports the OS layer.
  trigger.dataset.hint = hint;
  trigger.textContent = label;
  trigger.setAttribute("role", "button");
  trigger.tabIndex = 0;
  trigger.setAttribute("aria-haspopup", "true");
  trigger.setAttribute("aria-expanded", "false");
  anchor.appendChild(trigger);

  const menu = document.createElement("ul");
  menu.className = "shell-menu";
  menu.hidden = true;
  menu.setAttribute("role", "menu");
  menu.setAttribute("aria-label", label);

  function setChecked(id) {
    for (const button of menu.querySelectorAll(".shell-menu-option")) {
      button.setAttribute("aria-checked", String(button.dataset.option === id));
    }
  }

  for (const option of options) {
    const item = document.createElement("li");
    item.setAttribute("role", "none");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "shell-menu-option";
    button.setAttribute("role", "menuitemradio");
    button.setAttribute("aria-checked", "false");
    button.dataset.option = option.id;
    button.textContent = option.label;
    button.addEventListener("click", () => {
      closeMenu();
      trigger.focus();
      onChoose(option.id);
    });
    item.appendChild(button);
    menu.appendChild(item);
  }
  setChecked(current);
  anchor.appendChild(menu);

  // CSS anchors the menu under the trigger; on a narrow viewport nudge it back left via CSSOM
  // (never an inline style= attribute, per CSP) just enough to keep it fully on screen.
  function clampMenuPosition() {
    const edgeMargin = 8; // matches --space-2
    menu.style.left = "";
    const anchorRect = anchor.getBoundingClientRect();
    const overflow = anchorRect.left + menu.offsetWidth + edgeMargin - window.innerWidth;
    if (overflow > 0) menu.style.left = `${-overflow}px`;
  }

  function openMenu() {
    menu.hidden = false;
    clampMenuPosition();
    trigger.setAttribute("aria-expanded", "true");
    menu.querySelector(".shell-menu-option")?.focus();
  }
  function closeMenu() {
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
  }
  function toggleMenu() {
    if (menu.hidden) openMenu();
    else closeMenu();
  }

  trigger.addEventListener("click", toggleMenu);
  trigger.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleMenu();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !menu.hidden) {
      closeMenu();
      trigger.focus();
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (!menu.hidden && !menu.contains(event.target) && event.target !== trigger) closeMenu();
  });

  return { setChecked };
}
