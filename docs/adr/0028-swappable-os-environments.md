# ADR 0028: Swappable OS environments — neutral app, one folder per OS

**TL;DR:** The dashboard's look is an **OS** (owner, 2026-09-29: "themes = the whole OS"): a folder `static/os/<name>/` with tokens, chrome CSS, a small shell script, optional effects (`fx/`) and a background set. The functional app (`index.html`, `app.css`, `app.js`, `feed.js`, `chrome.js`, …) is OS-neutral and never names an OS. A classic `os-boot.js` sets `html[data-os]` from `pdash.os` before any stylesheet; **every** OS is linked, and every OS rule is scoped to `:root[data-os="<name>"]`, so only the active one applies. Platinum is the first and default OS and looks pixel-identical to before (unit O1); Aero follows (A1).

## Context

- The owner wants to switch between whole desktop environments (Platinum 1998, Aero), each with its own chrome and animations, and wants "functions/environment separated from the OS".
- Before O1, Platinum was spread over `theme.css`, `app.css` (bevels, pinstripes, boxes), `index.html` (File/Edit/View/Special) and `chrome.js` (the shade box), plus the `fx/` layer.
- Constraints: CSP `script-src 'self'`, `style-src 'self'` (no inline anything), **no dynamic `import()`** (C23 grep), Trusted Types with no policy, no build step. The dashboard renders no HTML from data.

## Decision

- **Layout.** `static/os-boot.js` (classic, render-blocking, in `<head>` before the CSS); `static/os/` holds the shared OS layer (`registry.js`, `storage.js`, `shell.js`, `shell-menu.js`, `background.js`, `os-picker.js`, `shell.css`) and one folder per OS: `theme.css` (contract tokens), `chrome.css` (signature look), `shell.js` (OS-only decorative DOM), `backgrounds.js` (its background set), optional `fx/`.
- **Selection without dynamic import.** All OS stylesheets and scripts are linked as independent tags; CSS applies through scoping, and each OS entry script starts with `if (document.documentElement.dataset.os !== OS) return;`. Adding an OS = one folder + one registry entry + one line in `os-boot.js` + its tags in `index.html`.
- **Neutral core.** `app.css` keeps structure plus a flat, token-driven look; each OS's `chrome.css` adds bevels/shadows/textures/decorations. Scoped rules (+0,2,0 specificity) always win over neutral ones, so an OS never fights the cascade. Functional JS builds neutral parts only (e.g. `chrome.js` window = title, close control, body).
- **Default and fallback.** The default OS's token block also matches bare `:root`: with no `data-os` (boot script missing) the app renders neutrally with the default tokens, and `/r/` preview pages (no `data-os`) inline that same file.
- **Storage.** C23's exception becomes exactly `pdash.os` (read by `os-boot.js`, written by `os/storage.js`) and `pdash.background.<os>` (key built only from an allowlisted OS name). B1's `pdash.background` and R5's `pdash.desktop` migrate once to `pdash.background.platinum`.
- **OS picker** (shared control in the shell bar's `os` slot) appears only when two or more OSes exist; a pick saves `pdash.os` and reloads, so `os-boot.js` applies it before first paint.

## Consequences

- Every OS's CSS downloads on every load (small, cached; only the active one applies). The page reloads on an OS switch (no flash of the wrong OS, no live re-theming code).
- `tests/unit/test_os_contract.py` enforces the contract for every registered OS: allowlists agree, required files and tags, exact token contract, scoping + prefixed `@keyframes`, reduced motion, no literal colors outside custom properties, import isolation both ways, storage keys, boot fallback, functional code free of OS names.
- Token contract changed: `--titlebar-stripes` became Platinum-private (declared in its `chrome.css`); `--icon-accent`, `--icon-folder`, `--icon-folder-tab`, `--icon-folder-shade` added so an OS can recolour the sprite (it is shared imagery; per-OS icon sets would be a later decision).
- `/r/` pages always use the default OS's tokens, whatever OS is active.
- How to add an OS: `docs/frontend-os.md`.
