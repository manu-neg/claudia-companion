/*
  Back navigation: remembers, in memory only, the hash route the owner came from, and works out
  where a "Back" control should lead (item view and folder window). Preferred over stepping browser history
  so Back can never leave the app; a direct link or reload has no origin and uses fallbacks.
  Pure functions plus two module variables - no DOM, so they are unit-testable under node.
*/
import { ULID_RE } from "./dom.js";

let currentHash = null;
let previous = null;

/** Called by the router on every render; a repeated identical hash keeps the recorded origin. */
export function recordRoute(hash) {
  if (hash === currentHash) return;
  previous = currentHash;
  currentHash = hash;
}

/** The hash route the owner came from, or null (first load / reload / direct link). */
export function previousHash() {
  return previous;
}

/** Test hook: forget everything, as after a page reload. */
export function resetNav() {
  currentHash = null;
  previous = null;
}

/** Parse a hash into a known place, or null. Only these places can be a Back destination. */
function place(hash) {
  if (typeof hash !== "string") return null;
  if (hash === "#/") return { href: "#/", view: "feed" };
  if (hash === "#/trash") return { href: "#/trash", view: "trash" };
  const folder = /^#\/folder\/([^/]+)$/.exec(hash);
  if (folder && ULID_RE.test(folder[1])) return { href: hash, view: "folder", folderId: folder[1] };
  return null;
}

/**
 * Where Back goes from an item view.
 * @param trashed  the item is shown from `#/trash/<id>`
 * @param folder   `{id, name}` of the item's folder, or null when unfiled
 * @param origin   the recorded previous hash (or null)
 * @returns `{href, text, name, folderId}`: the button reads `text`, then `name` (untrusted, a
 *   folder name: render it via untrusted() only) when set. `folderId` is set when that name
 *   still has to be looked up (origin folder differs from the item's own folder).
 */
export function itemBack({ trashed, folder = null, origin = null }) {
  const { id: ownId, name: ownName } = folder ?? {};
  // The id comes from the API; validate it before it becomes part of a hash route.
  const own = folder && ULID_RE.test(ownId) ? { id: ownId, name: ownName } : null;
  const from = place(origin);
  if (trashed) return { href: "#/trash", text: "Back to Trash", name: null, folderId: null };
  if (from && from.view === "feed") return { href: "#/", text: "Back to Feed", name: null, folderId: null };
  if (from && from.view === "folder") {
    if (own && own.id === from.folderId) return { href: from.href, text: "Back to", name: own.name, folderId: null };
    return { href: from.href, text: "Back to folder", name: null, folderId: from.folderId };
  }
  if (own) return { href: `#/folder/${own.id}`, text: "Back to", name: own.name, folderId: null };
  return { href: "#/", text: "Back to Feed", name: null, folderId: null };
}

/**
 * Where Back goes from a folder window: always the Feed. The recorded origin is ignored on
 * purpose: honouring an item or another folder would let two views bounce between each other.
 */
export function folderBack() {
  return { href: "#/", text: "Back to Feed", name: null, folderId: null };
}
