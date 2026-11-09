/*
  The only module that touches localStorage (docs/security.md C23 exception, docs/frontend-os.md):
  `pdash.os` (the chosen OS; os-boot.js only reads it) and one `pdash.background.<os>` per OS,
  with the key built only from an allowlisted OS name. Every value is checked against the
  registry on read and write, every access is wrapped in try/catch (private mode, blocked storage).
*/
import { backgroundsOf, OSES } from "./registry.js";

export const OS_KEY = "pdash.os";
const BACKGROUND_PREFIX = "pdash.background.";
// Pre-O1 keys (B1's single key, R5's original one): both held Platinum background ids.
const LEGACY_KEYS = Object.freeze(["pdash.background", "pdash.desktop"]);
const LEGACY_OS = "platinum";

/** `pdash.background.<os>` for an allowlisted OS, else null (never a key built from other data). */
export function backgroundKey(os) {
  return OSES.includes(os) ? BACKGROUND_PREFIX + os : null;
}

function isBackground(os, value) {
  return backgroundsOf(os).some((entry) => entry.id === value);
}

/**
 * One-time move of a legacy Platinum background (`pdash.background`, then `pdash.desktop`) to
 * `pdash.background.platinum`. Only an allowlisted value is carried over; the legacy keys are
 * removed once the new key is set, and junk is never copied. An existing new value wins (the legacy keys are still removed).
 */
export function migrateLegacyBackground() {
  const key = backgroundKey(LEGACY_OS);
  if (key === null) return;
  try {
    if (localStorage.getItem(key) === null) {
      let moved = null;
      for (const legacyKey of LEGACY_KEYS) {
        const legacy = localStorage.getItem(legacyKey);
        if (moved === null && isBackground(LEGACY_OS, legacy)) moved = legacy;
      }
      if (moved !== null) localStorage.setItem(key, moved);
    }
    // Removed even when the new key already exists, so no legacy key lingers (C23).
    for (const legacyKey of LEGACY_KEYS) localStorage.removeItem(legacyKey);
  } catch {
    // Storage unavailable: nothing to migrate, defaults apply.
  }
}

/** The remembered background of `os`, or its default if unset/invalid/unreadable ("" if none). */
export function loadBackground(os) {
  const fallback = backgroundsOf(os)[0]?.id ?? "";
  const key = backgroundKey(os);
  if (key === null) return fallback;
  migrateLegacyBackground();
  try {
    const value = localStorage.getItem(key);
    return isBackground(os, value) ? value : fallback;
  } catch {
    return fallback;
  }
}

/** Remember `value` as the background of `os`; does nothing unless both are allowlisted. */
export function saveBackground(os, value) {
  const key = backgroundKey(os);
  if (key === null || !isBackground(os, value)) return;
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage unavailable: the background still applies for this page view.
  }
}

/** Remember the chosen OS (read by os-boot.js on the next load). Returns true once stored. */
export function saveOs(os) {
  if (!OSES.includes(os)) return false;
  try {
    localStorage.setItem(OS_KEY, os);
    return true;
  } catch {
    return false;
  }
}
