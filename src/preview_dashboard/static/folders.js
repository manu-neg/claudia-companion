/*
  Folders data layer (backlog §7.1, unit F4): `GET /api/folders`, degraded to "no folders" on
  any failure (the route not existing yet, a network error, or a malformed body) - callers never
  need to special-case "not built yet". `feed.js` is the only caller: it renders folder rows at
  the root of the Feed window and looks a folder up by id for `#/folder/<id>`. No rendering here
  (F3's desktop icons and separate folder windows are gone - see feed.js and app.js).
*/
import { apiGet } from "./api.js";
import { ULID_RE } from "./dom.js";

function isValidFolder(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof value.id === "string" &&
    ULID_RE.test(value.id) &&
    typeof value.name === "string" &&
    Number.isFinite(value.count)
  );
}

/**
 * `GET /api/folders`, degraded to an empty list on any failure (the route not existing yet,
 * a network error, or a malformed body) - callers never need to special-case "not built yet".
 */
export async function loadFolders() {
  try {
    const { data } = await apiGet("/api/folders");
    const folders = Array.isArray(data?.folders) ? data.folders.filter(isValidFolder) : [];
    return { folders };
  } catch {
    return { folders: [] };
  }
}
