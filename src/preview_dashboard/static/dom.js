/*
  Safe DOM helpers for the dashboard: element builder, bidi-isolated untrusted text, URL checks,
  formatting. Untrusted strings only ever become Text nodes or attribute values (never HTML):
  there is no HTML sink in the dashboard, so Trusted Types (ADR 0011) never has to allow one.
*/

// Attributes that could run script or restyle the page are refused outright.
const FORBIDDEN_ATTRIBUTE = /^(?:on|srcdoc$|style$|formaction$|action$)/i;

// Ids from the API (items, folders) are ULIDs (Crockford base32, 26 chars); anything else
// never reaches a request. Single source of truth so every module checks ids the same way.
export const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/**
 * Build an element. `props`: `class`, `text` (textContent), `on` ({event: handler}),
 * `dataset`, or any other attribute (set via setAttribute; `true` → empty value).
 * Children: Nodes, strings (become Text nodes), arrays, or null/false (skipped).
 */
export function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = String(value);
    else if (name === "on") {
      for (const [event, handler] of Object.entries(value)) node.addEventListener(event, handler);
    } else if (name === "dataset") Object.assign(node.dataset, value);
    else if (FORBIDDEN_ATTRIBUTE.test(name)) throw new Error(`refused attribute ${name}`);
    else node.setAttribute(name, value === true ? "" : String(value));
  }
  append(node, children);
  return node;
}

/** Append children (Nodes, strings as Text nodes, nested arrays; null/false skipped). */
export function append(parent, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(parent, child);
    else if (child instanceof Node) parent.appendChild(child);
    else parent.appendChild(document.createTextNode(String(child)));
  }
  return parent;
}

/** Untrusted text, isolated from surrounding bidi context (titles, filenames, descriptions). */
export function untrusted(value, className = "") {
  return h("bdi", { class: className || null, text: value ?? "" });
}

/** Remove every child of `node`. */
export function clear(node) {
  node.replaceChildren();
}

// The preview origin (GET /api/kinds); item URLs must point there and nowhere else.
let previewOrigin = null;

/**
 * Set the preview origin once, from the server's `/api/kinds`. It must be a bare https origin
 * (scheme, host, optional port; no path). Throws otherwise, or if it would change.
 */
export function setPreviewOrigin(origin) {
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error("invalid preview origin");
  }
  if (parsed.protocol !== "https:" || parsed.origin !== origin) throw new Error("invalid preview origin");
  if (previewOrigin !== null && previewOrigin !== origin) throw new Error("preview origin changed");
  previewOrigin = origin;
}

/**
 * `url` if it is an absolute https: URL on the preview origin (item URLs from the API), else
 * null. Fails closed until `setPreviewOrigin` ran: data can never point a frame, image or link
 * anywhere else, even if the API were tricked into returning another URL.
 */
export function httpsUrl(url) {
  if (typeof url !== "string" || previewOrigin === null) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" && parsed.origin === previewOrigin ? parsed.href : null;
  } catch {
    return null;
  }
}

export function formatBytes(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`;
}

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" });
const ABSOLUTE = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const DAY = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });
const STEPS = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
];

/** "3 hours ago" style text for an ISO timestamp. */
export function relativeTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const seconds = (date.getTime() - Date.now()) / 1000;
  for (const [unit, size] of STEPS) {
    if (Math.abs(seconds) >= size) return RELATIVE.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

export function absoluteTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : ABSOLUTE.format(date);
}

export function dayOnly(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : DAY.format(date);
}

/** A <time> element showing relative time, with the exact time as tooltip. */
export function timeEl(iso) {
  return h("time", { datetime: iso, title: absoluteTime(iso), text: relativeTime(iso) });
}

/** Show a short status message in the page's live region. */
export function toast(message) {
  const region = document.getElementById("toast");
  if (!region) return;
  region.textContent = message;
  region.classList.add("is-visible");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => region.classList.remove("is-visible"), 3500);
}
