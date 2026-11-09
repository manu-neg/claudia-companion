/*
  The bundle rule (backlog §10, owner decision 2026-09-30): which items the dashboard presents as
  a "Bundle" of files instead of as their entry file's kind. Pure functions only (no DOM, no
  network), so the rule is unit-tested on its own; a bundle keeps its real kind for previewing.
*/

/**
 * True when `item` is a bundle: two or more files, and not an HTML site (an HTML page plus its
 * assets is shown as HTML). `item` is an API item summary (`file_count`, `kind` = kind name).
 */
export function isBundle(item) {
  if (!item || typeof item !== "object") return false;
  const count = item.file_count;
  return Number.isInteger(count) && count >= 2 && item.kind !== "html";
}

/** "N files" (N ≥ 2 for a bundle; "1 file" kept correct anyway). */
export function filesText(count) {
  return count === 1 ? "1 file" : `${count} files`;
}

/** The bundle's secondary text, e.g. "10 files · Image" (`kindLabel` = the entry kind's label). */
export function bundleDetail(item, kindLabel) {
  return kindLabel ? `${filesText(item.file_count)} · ${kindLabel}` : filesText(item.file_count);
}
