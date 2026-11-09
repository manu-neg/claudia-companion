# Frontend: cosmetic layer (`static/os/<name>/fx/`)

**TL;DR:** Each OS may ship an `fx/` folder: a self-contained, optional layer
of effects. Platinum's (`static/os/platinum/fx/`, moved from `static/fx/` by
O1) is Mac OS 8-style chrome (Aero's own `fx/` is described in docs/frontend-os.md#aero): zoom-open, window shade, watch cursor, startup
splash, menu-bar clock, idle screensaver. It only reads the DOM hooks in
`docs/frontend.md#hooks-for-later-layers`, runs only while its OS is active
(`html[data-os]`), never imports the functional modules, never touches the
network or storage. Delete the directory, or make any file in it throw, and
the dashboard works exactly the same — that's the whole point, and it's what
`tests/unit/test_fx_isolation.py` checks. The Background picker and the only
storage code moved to the shared OS layer (`static/os/`, docs/frontend-os.md).

## Why a separate layer

The functional UI (routing, data, CSRF, rendering untrusted content) has to
stay simple to audit. The 1998-theme "extras" the owner asked for (backlog
§4) are pure decoration with real failure modes of their own (animation
loops, idle timers, `localStorage`) that have no business being anywhere
near `dom.js`/`api.js`. Keeping them in their own directory (one per OS), loaded by their
own `<script type="module">`/`<link>` tags, means a bug or a deliberate
removal of `fx/` can never take the real app down with it.

## Files

| File | Effect |
|---|---|
| `fx.js` | Entry point. Returns at once unless `html[data-os]` is `platinum`. Calls each effect's `init*()` inside a `try`/`catch` (`safe()`), so one throwing effect never stops the others. Under `prefers-reduced-motion: reduce`, skips only `initSplash`/`initScreensaver` (backlog §4: "no animation, screensaver off") — the clock, shade and the watch cursor still run. |
| `zoom.js` | `MutationObserver` on `#main`; when a new `[data-window]` appears it gets a one-shot `fx-zoom-in` class (CSS scale+fade — the dashboard CSP has no `style-src 'unsafe-inline'`, so exact per-window pixel rects aren't possible; this is the CSS-only approximation of the classic zoom rectangles). |
| `shade.js` | Draws the decorative `.box-shade` square into every title bar that appears in `#main` (moved here from `chrome.js` by O1, so the square only exists while the effect behind it is loaded; styled by `os/platinum/chrome.css`). Double-click a title bar, or a plain click on that square, toggles `.fx-shaded` on the `[data-window]` section; `fx.css` hides `.window-body`. The body stays in the DOM. The square carries a `data-hint` (balloon.js, W1 item 1) but stays `aria-hidden` and non-focusable — it's an optional fx convenience with an equivalent (double-clicking the title bar), so its hint is pointer-only (hover/long-press), never reachable by keyboard focus; accepted in F-W2. |
| `clock.js` | Fills the empty, `aria-hidden` `[data-slot="clock"]` span with the current time. |
| `cursor.js` | Watch cursor (`cursor: wait`) from `hashchange` until `#main` is repopulated (observed) or a 4s cap elapses, with a 150ms minimum so it never flickers. fx never imports `api.js`, so this approximates "a request is running" rather than tracking one exactly. |
| `splash.js` | Full-screen "Previews" splash on load; dismissed by any pointer/keyboard input or after 2.2s. The dismissing input can't also reach whatever's underneath (see Isolation rules). |
| `screensaver.js` | After 5 minutes idle (any `pointerdown`/`pointermove`/`keydown`/`wheel`/`touchstart` resets the timer), shows a dimmed, drifting overlay. A `?fxIdleMs=N` query param overrides the threshold for local/Playwright testing only — never persisted, never sent anywhere; values under 1000 ms are ignored (F-A1). Same dismiss-swallow behaviour as `splash.js`. |
| `fx.css` | Every rule above, each scoped to `:root[data-os="platinum"]`, `@keyframes` prefixed `platinum-`; no images, no `url()`. (The six backgrounds now live in `os/platinum/chrome.css`, the picker in `os/background.js`.) |

## Isolation rules (all enforced by `tests/unit/test_fx_isolation.py`, `tests/unit/test_os_contract.py` and the OS-layer checks in `tests/unit/test_static_ui.py`)

- fx modules only ever `import` each other (relative, staying inside `fx/`); functional modules never import `fx/` (or anything in `os/`).
- The entry (`fx.js`) no-ops unless its OS is the active one (`const OS = "<name>"` + the `data-os` guard); every CSS rule is scoped to that OS.
- No `fetch`, no `XMLHttpRequest`, no `https://` literals, no `/api/` — fx never talks to the network, full stop (unlike `api.js`, it has no exception).
- No storage at all (since O1). The OS layer's two keys (`pdash.os`, `pdash.background.<os>`) belong to `os/storage.js` and `os-boot.js` only (docs/frontend-os.md, C23).
- Every `<script type="module">` fx uses is its own tag, separate from `app.js`'s — a 404 or a thrown error in one can't block the other (this is normal browser behaviour for independent module scripts, not something fx has to work around).
- Overlays that only dismiss (`.fx-splash`, `.fx-screensaver`) keep default pointer-events so they can catch the dismissing input. Dismissal must not also reach what's underneath once the overlay is gone (S2 F1 fix): a dismissing `pointerdown`/tap synthesizes a `click` on the next frame that targets whatever's now on top, so both files arm a one-shot, capture-phase `click` listener the instant they dismiss and `preventDefault`/`stopPropagation` it, with a short timeout (400ms) that clears the listener for pointer types that never produce a click; a dismissing `keydown` (e.g. Enter, Space) gets `preventDefault()` + `stopPropagation()` directly, so it can't also activate a focused control. `screensaver.js`'s other idle-reset listeners (`pointermove`, `wheel`, `touchstart`, and any `keydown`/`pointerdown` that only resets the timer without the overlay showing) are untouched and stay passive. Nothing else in fx creates a covering overlay.
- Reduced motion (`fx.js`'s `matchMedia("(prefers-reduced-motion: reduce)")` check) disables *animation*, not the layer: `initSplash` and `initScreensaver` are skipped outright (backlog §4); the clock, window shade (already instant, no animation either way) and the watch cursor keep running. Zoom-open (`zoom.js`) still runs too — its actual animation is removed in `fx.css` (`@media (prefers-reduced-motion: reduce)` sets `.fx-zoom-in`/`.fx-screensaver-pattern` to `animation: none`), so the window just appears at full size instantly instead of skipping the effect in JS.
- `fx.css` loads nothing external: no `url()`, no `@import`.

## Deleting or breaking an OS's `fx/`

`tests/unit/test_fx_isolation.py::test_static_assets_load_fine_with_fx_entirely_deleted`
copies `static/` without `os/platinum/fx/` and confirms `StaticAssets.load()` (the
in-memory manifest every dashboard response is served from) works exactly
the same, byte-for-byte, for every functional file. The equivalent
real-browser proof — deleting `static/os/platinum/fx/` and separately making `fx.js`
throw, then loading the app in Chromium and WebKit via Playwright — was run
by hand during R5 and again in O1 (fx deleted + a junk `pdash.os`: every route renders, menus work, only the expected 404s; see the hand-off report); it isn't part of `pytest`/CI
because there's no headless browser in CI yet (`docs/frontend.md`).

## Theming

fx effects reuse their OS's theme tokens (colors, spacing, type). Like the
OS's `chrome.css`, `fx.css` may declare private custom properties (scoped to
its OS) and use contract tokens; literal colors only inside those
declarations (`tests/unit/test_os_contract.py`).
