/*
  Knowledge-map note reader: turns a note's untrusted text into DOM with textContent only (C57,
  C23). Headings, bullets, quotes and code fences get their own elements; `[[links]]` become
  in-app buttons that open the linked note by its id (never a URL); anything else stays text.
  No HTML is ever parsed. `splitLinks` is pure and node-testable.
*/
import { h, untrusted } from "./dom.js";

const LINK_RE = /\[\[([^\[\]\n|#]{1,120})(#[^\[\]\n|]{0,120})?(\|[^\[\]\n]{0,120})?\]\]/g;
const MAX_BLOCKS = 600;

/**
 * Split one line into text and link parts: `[{text}, {link: target, label}]`. `label` is the
 * `|shown text` when given, else the target. Same pattern as the server's parser.
 */
export function splitLinks(line) {
  const parts = [];
  let last = 0;
  for (const match of String(line).matchAll(LINK_RE)) {
    if (match.index > last) parts.push({ text: line.slice(last, match.index) });
    const target = match[1].trim();
    const label = match[3] ? match[3].slice(1).trim() || target : target;
    parts.push({ link: target, label });
    last = match.index + match[0].length;
  }
  if (last < line.length) parts.push({ text: line.slice(last) });
  return parts;
}

/** Inline content of one line: text nodes and link buttons (`resolve(target)` -> id | null). */
function inline(line, resolve, onOpen) {
  return splitLinks(line).map((part) => {
    if (part.text !== undefined) return part.text;
    const id = resolve(part.link);
    if (!id) {
      return h("span", { class: "kmap-link is-missing", title: "No note with this name yet" }, untrusted(part.label));
    }
    return h(
      "button",
      { type: "button", class: "kmap-link", dataset: { noteId: id }, on: { click: () => onOpen(id) } },
      untrusted(part.label),
    );
  });
}

/**
 * The note body as block elements. `links`: [{target, id}] from the API; `onOpen(id)` opens a
 * linked note. Returns an array of Nodes.
 */
export function noteBlocks(body, links, onOpen) {
  const ids = new Map();
  for (const link of Array.isArray(links) ? links : []) {
    if (link && typeof link.target === "string") ids.set(link.target.toLowerCase(), link.id || null);
  }
  const resolve = (target) => ids.get(target.toLowerCase()) || null;
  const blocks = [];
  let list = null;
  let paragraph = null;
  let code = null;
  const flush = () => {
    list = null;
    paragraph = null;
  };
  for (const raw of String(body || "").split("\n")) {
    if (blocks.length >= MAX_BLOCKS) break;
    const line = raw.replace(/\r$/, "");
    if (code) {
      if (/^\s*```/.test(line)) code = null;
      else code.append(line, "\n");
      continue;
    }
    if (/^\s*```/.test(line)) {
      flush();
      code = h("code");
      blocks.push(h("pre", { class: "kmap-code" }, code));
      continue;
    }
    if (!line.trim()) {
      flush();
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      const level = heading[1].length <= 1 ? "h3" : "h4";
      blocks.push(h(level, { class: "kmap-heading" }, inline(heading[2], resolve, onOpen)));
      continue;
    }
    const bullet = /^\s*(?:[-*+]|\d{1,3}[.)])\s+(.*)$/.exec(line);
    if (bullet) {
      paragraph = null;
      if (!list) {
        list = h("ul", { class: "kmap-list" });
        blocks.push(list);
      }
      list.appendChild(h("li", {}, inline(bullet[1], resolve, onOpen)));
      continue;
    }
    const quote = /^\s*>\s?(.*)$/.exec(line);
    if (quote) {
      flush();
      blocks.push(h("blockquote", { class: "kmap-quote" }, inline(quote[1], resolve, onOpen)));
      continue;
    }
    list = null;
    if (!paragraph) {
      paragraph = h("p", { class: "kmap-para" });
      blocks.push(paragraph);
    } else {
      paragraph.append(" ");
    }
    paragraph.append(...inline(line, resolve, onOpen));
  }
  return blocks;
}
