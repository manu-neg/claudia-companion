/*
  Window chrome builders (OS-neutral markup; the active OS under os/ styles it): pixel icons from
  the index.html sprite, windows with title bars, popup-menu selects and alert boxes. Builders
  only; no data access. Icon ids come from a fixed allowlist (never from item data), and every
  text argument is set via h()/textContent.
*/
import { isBundle } from "./bundle.js";
import { h, untrusted } from "./dom.js";

// Sprite symbols in index.html. A kind whose renderer has no icon gets the generic file icon.
const ICONS = new Set([
  "i-html", "i-svg", "i-image", "i-csv", "i-diff", "i-markdown", "i-code", "i-video", "i-audio",
  "i-pdf", "i-json", "i-text", "i-file", "i-progress", "i-bundle", "i-folder", "i-trash",
  "i-trash-full", "i-caution", "i-app", "i-pin", "i-sort", "i-popup", "i-grow", "i-kmap",
]);

let svgNamespace = null;

// Read from the sprite rather than written out: dashboard JS holds no URL literals (C23 grep).
function namespace() {
  if (!svgNamespace) svgNamespace = document.querySelector("svg.sprite")?.namespaceURI || null;
  return svgNamespace;
}

/**
 * An SVG element (the knowledge map's dots and lines). `attrs` are set via setAttribute; event
 * handler and style attributes are refused like in h(). Returns null without the sprite.
 */
export function svgElement(tag, attrs = {}) {
  const ns = namespace();
  if (!ns) return null;
  const node = document.createElementNS(ns, tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (/^(?:on|style$|href$)/i.test(name)) throw new Error(`refused attribute ${name}`);
    if (value !== null && value !== undefined) node.setAttribute(name, String(value));
  }
  return node;
}

/** An aria-hidden `<svg><use href="#id"></svg>` icon; unknown ids fall back to the file icon. */
export function icon(id, className = "icon") {
  const ns = namespace();
  if (!ns) return h("span", { class: className, "aria-hidden": "true" });
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = document.createElementNS(ns, "use");
  use.setAttribute("href", `#${ICONS.has(id) ? id : "i-file"}`);
  svg.appendChild(use);
  return svg;
}

/** Icon id for a kind (by its renderer id from /api/kinds; e.g. `progress` → `i-progress`). */
export function kindIconId(kind) {
  const id = kind ? `i-${kind.renderer}` : "i-file";
  return ICONS.has(id) ? id : "i-file";
}

/** Icon id for a whole item: `i-bundle` for a bundle (bundle.js rule), else its kind's icon. */
export function itemIconId(item, kind) {
  return isBundle(item) ? "i-bundle" : kindIconId(kind);
}

/** Icon id for one file of an item, from its extension via the kind registry. */
export function fileIconId(relpath, kindList) {
  const dot = typeof relpath === "string" ? relpath.lastIndexOf(".") : -1;
  if (dot < 0) return "i-file";
  const ext = relpath.slice(dot).toLowerCase();
  const kind = kindList.find((k) => Array.isArray(k.extensions) && k.extensions.includes(ext));
  return kindIconId(kind || null);
}

/**
 * A window: `<section data-window=name>` with a title bar (neutral parts only - title, optional
 * close control, body; the active OS styles and places them and may add decoration).
 * `title`: string or Node(s) for the title bar heading. `close`: optional `{href, label, hint}`
 * makes the close control a link (e.g. back to the list) - omitted, none is drawn at all
 * (a box that did nothing was a false affordance; W1 item 3). Returns `{root, body, title}`
 * (`title` is the heading element, so callers can refill it).
 */
export function windowFrame({ name, title, headingLevel = "h1", close = null, className = "" }) {
  const headingId = `window-title-${name}`;
  const heading = h(headingLevel, { class: "titlebar-title", id: headingId }, title);
  const closeBox = close
    ? h("a", {
        class: "titlebar-control titlebar-close",
        href: close.href,
        "aria-label": close.label,
        dataset: { box: "close", hint: close.hint },
      })
    : null;
  const titlebar = h("div", { class: "titlebar", dataset: { titlebar: name } }, closeBox, heading);
  const body = h("div", { class: "window-body" });
  const root = h(
    "section",
    { class: `window window-${name} ${className}`.trim(), "aria-labelledby": headingId, dataset: { window: name } },
    titlebar,
    body,
  );
  return { root, body, title: heading };
}

/**
 * The Back button (nav.js gives `{href, text, name}`): a real button that sets the hash, so it
 * never leaves the app. `name` is an untrusted folder name: text node inside <bdi> only.
 */
export function backButton({ href, text, name = null }) {
  return h(
    "button",
    {
      type: "button",
      class: "button back-button",
      dataset: { hint: "Back: return to where you came from.", backHref: href },
      on: { click: () => { location.hash = href; } },
    },
    text,
    name === null ? null : [" ", untrusted(name)],
  );
}

/** Wrap a `<select>` as a popup menu (the active OS draws its end cap around the double arrow). */
export function popup(select) {
  return h("span", { class: "popup" }, select, icon("i-popup", "popup-arrow"));
}

/**
 * An alert box (not-found and error pages): icon, heading, text and optional actions.
 * `actions`: Nodes (links or buttons) placed bottom right.
 */
export function alertWindow({ iconId = "i-caution", title, body = null, actions = [] }) {
  return h(
    "section",
    { class: "window window-alert", dataset: { window: "alert" }, "aria-labelledby": "alert-title" },
    h(
      "div",
      { class: "alert" },
      icon(iconId, "icon-lg alert-icon"),
      h(
        "div",
        { class: "alert-text" },
        h("h1", { class: "alert-title", id: "alert-title", text: title }),
        body ? h("p", { class: "alert-body", text: body }) : null,
      ),
    ),
    actions.length ? h("div", { class: "buttons" }, actions) : null,
  );
}
