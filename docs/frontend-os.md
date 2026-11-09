# Frontend: OS environments (`static/os/`)

**TL;DR:** The dashboard's look is an **OS**: one folder `static/os/<name>/` (tokens, chrome CSS, a shell script, a background set, optional `fx/`). The functional app is OS-neutral. `os-boot.js` sets `html[data-os="<name>"]` from `pdash.os` before any CSS loads; every OS is linked, every OS rule is scoped to `:root[data-os="<name>"]`, every OS script no-ops unless its name is active. Two OSes ship: Platinum (default) and Aero (unit A1). Why: ADR 0028. This page is the complete recipe for adding one; `tests/unit/test_os_contract.py` enforces it for every registered OS.

## Layers

```
index.html  app.css  app.js feed.js item.js chrome.js menu.js dialog.js balloon.js …   functional, OS-neutral
os-boot.js                                                                             picks the OS (classic script)
os/  registry.js storage.js shell.js shell-menu.js background.js os-picker.js shell.css shared OS layer
os/<name>/  theme.css chrome.css shell.js backgrounds.js  fx/{fx.js,fx.css,…}          one OS
```

- **Functional → OS:** never. Functional files never import `os/`, never read `data-os`, never name an OS (not even in comments), never create an OS's private classes. They emit neutral markup + the hooks below.
- **OS → functional:** never imports a functional module either. An OS reads the DOM hooks, adds decoration, styles everything.
- **Shared OS layer:** the Background and OS pickers and the only storage code. May import only inside `os/`; only `registry.js` reaches into an OS folder (its `backgrounds.js`).

## Files of one OS

| File | Required | What it holds |
|---|---|---|
| `theme.css` | yes | Exactly the contract tokens (below) in one block `:root[data-os="<name>"] { … }`, `color-scheme`, and a `@media (prefers-reduced-motion: reduce)` block setting `--motion-duration: 0ms`. Nothing else: no `@font-face`, `url()`, `@import`. Only the **default** OS also matches bare `:root` (`:root, :root[data-os="platinum"]`): that's the fallback with no `data-os`, and the file `/r/` preview pages inline. |
| `chrome.css` | yes | The OS's signature look on top of `app.css`: bevels/glass/shadows, title bar geometry and decoration, shell-bar look, desk icons, balloons, buttons, menus, dialogs, toast, and one `body[data-background="<id>"]` rule per background. May declare **OS-private tokens** in a scoped `:root[data-os="<name>"] { --x: … }` block (e.g. Platinum's `--titlebar-stripes`); must not redeclare contract tokens. |
| `shell.js` | yes | ES module. `const OS = "<name>";` and `function start() { if (document.documentElement.dataset.os !== OS) return; … }`. Adds OS-only **decorative** DOM (aria-hidden, no behaviour) — e.g. Platinum's File/Edit/View/Special titles after `[data-slot="app"]`. May move the desk icons into `[data-slot="nav"]` (functional code queries hooks at use time). No network, no storage. |
| `backgrounds.js` | yes | `export default Object.freeze([Object.freeze({ id, label }), …])`; first = default. Ids match `[a-z][a-z0-9-]{0,31}`, each painted by a scoped `body[data-background="<id>"]` rule in `chrome.css` (gradients only, no `url()`). Data only. |
| `fx/fx.js` + `fx/fx.css` | optional | Effects/animations (docs/frontend-fx.md rules apply per OS): entry no-ops unless its OS is active, wraps each effect in `safe()`, imports only inside `fx/`, no network, no storage. Deleting `fx/` must leave a working app. |

## Registering an OS (all steps; the contract test checks each)

1. Create `static/os/<name>/` with the files above (`<name>`: `[a-z][a-z0-9]{1,15}`). Every source file starts with a 2–4 line header comment.
2. `os/registry.js`: `import <name>Backgrounds from "./<name>/backgrounds.js";`, add `<name>: Object.freeze({ label: "<Label>", backgrounds: <name>Backgrounds })` to `INFO`, and `"<name>"` to `OSES` (picker order).
3. `os-boot.js`: add `"<name>"` to the literal `OSES` (same order as the registry); optionally list its chrome font in `PRELOAD_FONTS` (only `/static/fonts/*.woff2`).
4. `index.html`: after the existing OS tags add, each as its own tag, `<link rel="stylesheet" href="/static/os/<name>/theme.css">`, `…/chrome.css`, `…/fx/fx.css` (if any), and `<script type="module" src="/static/os/<name>/shell.js">`, `…/fx/fx.js` (if any). Nothing else in `index.html` changes; no OS name may appear outside those tags.
5. Fonts (if new): vendored `.woff2` in `static/fonts/` + `@font-face` in `fonts.css` + OFL text + `fonts/FONTS.md` entry (CSP `font-src 'self'`); refer to them only through `--font-*` tokens.
6. Docs: a section for the OS below; tests: OS-specific checks (e.g. its animations) in a new test file — the generic contract needs no edits.

The OS picker appears in the shell bar as soon as `OSES` has two entries.

## Boot and selection

- `os-boot.js` (classic, linked before any stylesheet): reads `localStorage.getItem("pdash.os")` in try/catch, accepts it only if it is in its literal `OSES`, else `DEFAULT_OS`; sets `data-os` on `<html>`; appends a font preload for that OS. Never writes storage, never throws.
- Invalid, missing or blocked storage ⇒ the default OS. If `os-boot.js` itself fails, `data-os` is absent: neutral layout + default tokens (usable, plain).
- OS picker (`os/os-picker.js`): "OS" drop-down in `[data-slot="os"]`, options = registry labels, checked = active OS; a different pick saves `pdash.os` (`os/storage.js`) and reloads. Hidden when only one OS exists.
- Background picker (`os/background.js`): "Background" drop-down in `[data-slot="background"]` with the active OS's set; applies `body[data-background="<id>"]`, remembered as `pdash.background.<os>`.
- Both pickers use `os/shell-menu.js` (classes `shell-menu-anchor`, `shell-menu-trigger[data-shell-trigger=background|os]`, `shell-menu`, `shell-menu-option[aria-checked]`; neutral styles in `os/shell.css`). Style them in `chrome.css`.

## Scoping rules (CSS)

- Every selector in every CSS file under `os/<name>/` starts with `:root[data-os="<name>"]` followed by a space, `.`, `:`, `[`, `#` or a combinator (e.g. `:root[data-os="aero"] .window`, `:root[data-os="aero"].fx-busy`). One exception: the default OS's token block may also list bare `:root`.
- `@media` blocks are fine (one level); their rules follow the same rule. No other at-rules except `@keyframes`, whose names start with `<name>-` (keyframes are global).
- No `url()`, `@import`, `@font-face`. Outside custom-property declarations: no literal colors (`#…`, `rgb()`, `hsl()`) and `font-family` only via `var()`. `var()` may name contract tokens or this OS's private tokens.
- Specificity: scoped rules are `(0,2,0)` heavier than the same neutral rule, so an OS always wins over `app.css` without `!important`. Keep a state rule (`:hover`, `:active`, media overrides) in the same file as the base rule it overrides, or the base rule may win.
- Reduced motion: every rule with `animation`/`transition` must be listed in a `@media (prefers-reduced-motion: reduce)` rule that sets `animation: none` / `transition: none` for that exact selector. (`app.css` also caps durations globally.)
- Private class names an OS creates (from `shell.js`/`fx`) should carry the OS name or `fx-` (Platinum's `box-shade` predates this and is grandfathered). Functional markup must never use a class only an OS styles.

## Token contract

Exactly the tokens in `docs/frontend.md#theme-tokens` (groups: surfaces, lines, text, accent, states, type, space, shape, elevation, patterns, icons, motion, layout), every one defined by every OS. Values are the OS's to choose (e.g. Aero's `--bevel-raised` can be a soft highlight, `--font-chrome` Catamaran); `app.css`, `os/shell.css` and `/r/`'s `renderer.css` use nothing else. Contrast: every text pair WCAG AA (document the ratios in the OS section below). Icons: the sprite in `index.html` is shared imagery (every OS must draw every symbol; `test_aero_os.py` checks Aero covers them all, `test_bundles_ui.py` that its file types are documents); the fills with classes `ic-accent`, `ic-folder`, `ic-folder-tab`, `ic-folder-shade` follow `--icon-*`; outlines and other hues are fixed. An OS whose look can't come from those fills may replace the *contents* of the sprite's symbols from its `shell.js` (same ids and viewBoxes, shapes built with `createElementNS`, colours from its own CSS classes); every `<use>` then follows, and a reload of another OS gets the original art back (Aero does this).

## Neutral markup an OS styles (hooks)

Stable hooks are listed in `docs/frontend.md#hooks-for-later-layers`. The shell and window parts:

| Part | Markup (neutral) | Notes |
|---|---|---|
| Shell bar | `header.shell-bar[data-shellbar]` > `span.shell-app[data-slot=app]` (icon + "Previews"), `span.shell-slot[data-slot=nav]`, `…[data-slot=background]`, `…[data-slot=os]`, `span.shell-clock[data-slot=clock]` (aria-hidden, empty) | Sticky top bar. Empty slots take no room. The clock is filled by an OS's fx (Platinum: `fx/clock.js`). |
| Desktop | `.desktop` > `nav.desk-icons` > `a.desk-icon[data-nav=feed|trash]` (`svg.icon-lg`, `.desk-icon-label` + `small[data-count]`), `main#main` | `aria-current="page"` on the current section. |
| Window | `section.window.window-<name>[data-window]` > `div.titlebar[data-titlebar]` (`a.titlebar-control.titlebar-close[data-box=close]` only when it works, `h1/h2.titlebar-title`) + `div.window-body` | Neutral close control: 44px hit area with a `×` via `::before`; an OS redraws it (Platinum: a 14px box). Decorations (Platinum's shade box) are added by the OS. |
| Lists | `.finder-header`, `.inset` > `.list-head` (`.cell`, `.is-sorted`), `ul.list` > `li.row` > `a.row-link` (`.cell-name`/`-kind`/`-size`/`-date`) + `button.row-more`; `.statusbar` (`.grow` grip icon) | Hover/focus rows use the accent. |
| Info window | `.info-top`, `.item-preview` (`.preview-toolbar`, `.screen`), `.fields`/`.field`, `.group` + `.group-title`, `.files`/`.file` | |
| Controls | `.button` (`.button-primary` = default action, unstyled by `app.css`; `.button-danger-quiet`), `.link-button`, `.file-action`, `span.popup` > `select.select` + `svg.popup-arrow` | |
| Knowledge map | `a.shell-link[data-nav=knowledge]` (`svg.icon-sm` + `.shell-link-label`, after the nav slot), `.window-kmap`: `.kmap-controls` (`.kmap-search`, `.kmap-view[aria-pressed]`), `.kmap-approvals`, `.kmap-stage[data-mode]` > `.kmap-map.screen` (`svg.kmap-svg` > `g.kmap-node[data-cat=0..7]` with `.kmap-ring`/`.kmap-dot`/`.kmap-shine`/`.kmap-label`, `line.kmap-edge[data-kind=link|tag]`; states `is-recent`, `is-selected`, `is-near`, `is-filtered`, `has-focus`), `.kmap-index` (list by category, `.kmap-swatch[data-cat]`), `aside.kmap-panel` | Each OS defines private `--kmap-c0..7` category colours and fills `[data-cat]`; neutral CSS paints every dot the accent. Platinum: Finder label colours, crisp dots, a still dotted ring for recent notes. Aero: sky map, glossy marbles with a shine, breathing halo for recent notes. |
| Overlays | `.ctx-menu[role=menu][data-window=menu]` (`.ctx-menu-item`, `.ctx-menu-sep`), `dialog.dialog[data-window=dialog]` (`.alert`), `.balloon-help[data-tail=top|bottom]`, `.balloon`/`.version-notice`, `#toast.toast`, `.stage.is-expanded` (full-screen preview, `.stage-close`) | `balloon.js`/`menu.js` position via CSSOM; an OS draws tails/shadows. |

## Isolation and security (docs/security.md C6, C23)

- No network (`fetch`, XHR, `http(s)://`, `/api/`), no HTML sinks, no eval, no cookies/`postMessage`/dynamic `import()`/`sessionStorage` anywhere in `os-boot.js` or `os/**`.
- Storage: exactly `pdash.os` and `pdash.background.<os>`; only `os/storage.js` reads/writes/removes (through `OS_KEY` or a key from `backgroundKey()`, which returns `null` for a non-allowlisted OS), and `os-boot.js` only reads `pdash.os`. Every value is validated against the registry on read and write. Legacy `pdash.background` (B1) / `pdash.desktop` (R5) migrate once to `pdash.background.platinum`.
- CSP unchanged: no inline script/style, `style-src 'self'`, `font-src 'self'`; positioning via CSSOM only.
- Text shown by an OS is fixed strings (labels, hints) — never item data.

## Tests and checks

- `tests/unit/test_os_contract.py` (every OS): allowlists agree (registry, `os-boot.js`, folders on disk); required files; tags in `index.html` (boot first, neutral CSS before OS CSS, one tag per file); exact token contract + scheme + reduced-motion zero; scoping of every selector + `@keyframes` prefix; tokens/literals; reduced motion for every animation/transition; backgrounds ⇔ CSS rules; entry scripts no-op under another OS; imports stay inside the OS folder (shared: inside `os/`); functional code never names an OS or uses an OS-private class; storage keys + Node runtime checks of `storage.js` (migration, validation, blocked storage) and `os-boot.js` (missing/invalid/blocked ⇒ default); assets load with any `fx/` deleted; `/r/` inlines the default OS tokens.
- `tests/unit/test_static_ui.py` (hygiene of all OS-layer JS, neutral CSS tokens-only, parse), `tests/unit/test_fx_isolation.py` (Platinum fx).
- Visual: Playwright screenshots at 390 and 1440 px (Feed root, folder, item, trash, context menu, Background popup) under the real CSP with a stubbed API and a frozen clock; a refactor of neutral code must be pixel-identical for every existing OS.

## Platinum (default)

- `theme.css`: "Platinum 1998", Sage & stone palette (values and contrast: docs/frontend.md#theme-tokens); motion 0ms (the owner wants every state still). Block selector `:root, :root[data-os="platinum"]`.
- `chrome.css`: black-ruled menu bar with a top highlight; white desk-icon labels (accent when current); raised bevel + hard offset shadow on windows; pinstriped title bar (private `--titlebar-stripes`) with a centred title on a window-colour strip; 14px bevelled close/shade boxes; sunken insets/screens; hard shadows on balloons, menus, dialogs, toast; pixel-edged balloon tails; popup end-cap divider; bevelled list heads and etched separators; ringed default button (`margin: 5px` + `--ring-default`); six backgrounds (standard, pinstripe, weave, waves, zen, static). The bar is the neutral one (app name, nav, pickers, clock), so it fits 390px with no OS-specific hiding.
- `shell.js`: a no-op `start()` (the contract requires the file; Platinum adds no DOM). The decorative File / Edit / View / Special menu titles were removed: **no decorative controls, every control must work** (W1 item 3, owner 2026-09-30).
- `fx/`: zoom-open, window shade (also draws the shade box), watch cursor, clock, splash, screensaver (docs/frontend-fx.md).
- Font preload: `pixelify-sans-400.woff2`.

## Aero

"Frutiger Aero" in the Windows Vista / 7 manner (design prototype 10, adapted to the real windows). Light only. Font preloads: `catamaran-400.woff2`, `catamaran-800.woff2`.

- `theme.css`: sky palette — ink `#0b3550` / muted `#3b6580` on frosted white; the Explorer selection is pale (`--color-accent` `#cce8ff`, dark text on it, not white); aqua focus `#0a6fa8`; danger `#c42b1c`; Catamaran for chrome and body (700/800 for chrome); radii 8/22/14px (pill buttons); soft blue blur shadows; `--motion-duration: 240ms`, `--motion-ease: cubic-bezier(0.2, 0.9, 0.3, 1)`.
- `chrome.css`: private tokens for glass, gloss, icon colours, scenery and the **motion set** (below). Glass lives on `::before` layers behind the shell bar and each window (`backdrop-filter` there, never on `.window` itself: that would trap the full-screen preview, a `position: fixed` descendant). Without `backdrop-filter` the layers are still 68–90% opaque white, so the text backing never depends on the blur. Gradient title bar with left-aligned white title; no decorative minimise/maximise (removed: every control must work, W1 item 3, owner 2026-09-30) and the real close control drawn as the wide red caption on the right (50×44px hit area). Glossy pill buttons (`.button-primary` aqua, `.button-danger` red, `.button-danger-quiet` pale red), pill selects, group boxes as glass panels, Win7 tooltips, task-dialog footer, rounded pale-blue menu hover. Backgrounds: Sky (default: sun, rays, bubbles, hills), Aurora (curtains and arcs of light), Ocean (light shafts and bubbles), Dusk (low sun, violet hills), Plain (Vista blue, no scenery).
- `shell.js`: adds the scenery (`.aero-scenery`, fixed at `z-index: -1`, `aria-hidden`), moves `nav.desk-icons` into `[data-slot="nav"]` (Feed/Trash become glass pills; the count text stays for screen readers, the badge shows `data-count-value` with empty alt text), and swaps glossy art into the sprite: every file-type symbol (`i-html` … `i-file`, `i-bundle`, `i-progress`) becomes a **Vista/7 document** (`DOC_ART`: pearl page, folded top-right corner, soft drop shadow, faint shading toward the foot, 1-device-pixel edges via `vector-effect: non-scaling-stroke`) with the type drawn on the page the way the Platinum set does it — HTML a page layout (header bar + columns), SVG a curve with nodes and handles, image a landscape photo, CSV a bar chart, diff red/green lines, Markdown the M↓ mark + lines, code `</>`, video a film frame with a play button, audio a note, PDF a red band with "PDF", JSON braces, text lines, file a blank page with a generic window, progress a checklist + green progress bar, bundle three stacked pages with mixed-type tiles; glyphs are drawn in a 14×17 box and fitted to the page's writing area. Plus manila folders, a glass recycle bin (empty and full) and a warning triangle. Colours: private `--aero-doc-*` / `--aero-c-*` tokens, one `aero-c-<colour>` class per shape (`currentcolor` fill/stroke); gradients are stepped translucent layers since the OS may not use `url()`.
- Phones (< 37.5rem): the bar is one row — orb, Feed, Trash, a picture-tile Background button (its label stays the accessible name), OS; the clock and app name hide. Tap targets 44px.

### Motion (fx/)

One system, all in `chrome.css` tokens: `--aero-dur-press` 90ms, `--aero-dur-fast` 140ms, `--aero-dur-menu` 180ms, `--aero-dur-base` (= `--motion-duration`, 240ms), `--aero-dur-slow` 300ms, `--aero-dur-glint` 300ms; ceremonial `--aero-dur-splash` 700ms, `--aero-dur-screen` 600ms; ambient `--aero-ambient-shimmer` 7s, `--aero-ambient-drift` 17s, `--aero-ambient-rise` 46s, `--aero-ambient-film` 9s; curves `--aero-ease-out` (= `--motion-ease`), `--aero-ease-in`, `--aero-ease-spring` (one small overshoot), `--aero-ease-glide` (sine-like); distances `--aero-open-scale` .94, `--aero-open-rise` 10px, `--aero-close-drop` 12px, `--aero-menu-drop` -6px. Only `transform` and `opacity` animate.

| Effect | How | Timing |
|---|---|---|
| Window open | CSS on `.main > .window`: scale .94→1, rise 10px, fade in | slow, ease-out |
| Close / back | `fx/close.js`: a plain click on `[data-box="close"]` adds `.aero-closing` (fade, drop 12px, scale .98), then sets the link's hash (fallback timer 220ms). Modified clicks pass through | fast, ease-in |
| Hover light | glow layer (`::before`/`::after`) fades in fast, out slow — buttons, bar pills and pickers, list rows (the selection capsule), the red close caption (warm highlight + halo) | in fast, out slow |
| Glint | a light band sweeps once across a glossy button as the pointer arrives (`hover: hover` only) | glint, glide |
| Menus, drop-downs, balloon hints | fade in with a 6px drop | menu, ease-out |
| Dialog | blooms like a window; backdrop fades | slow |
| Toast | rises and fades in (an animation, since it comes from `display: none`); sinks and fades out (transition) | base |
| Badge pop | `fx/badge.js`: when `data-count-value` rises, the badge scales 1→1.3→1 | slow, spring |
| Knowledge map | notes changed this week: their halo ring breathes (opacity .35↔1), paused with `html.aero-paused` | slow × 8, glide |
| Desktop | rays shimmer/sway, bubbles drift or rise, aurora arcs breathe; `fx/ambient.js` pauses them while the tab is hidden (the Aero clock's interval stops too) | ambient |
| Splash | `fx/splash.js`: deep-blue welcome screen, the orb lights up with a bloom, "Previews" rises in, the screen fades out (auto 2.1s or any input; the dismissing input never reaches the page) | splash |
| Screensaver | `fx/screensaver.js`: after 5 min idle the desktop dims and iridescent bubbles float and bounce off the edges (per-bubble size/speed via CSSOM custom properties); `?fxIdleMs=` for testing (values < 1000 ms ignored); timer cleared and overlay removed while the tab is hidden, animations paused via `html.aero-paused` | screen, ambient |

Reduced motion: every animation/transition selector is set to `none` in `fx.css`, every `--aero-dur-*` token becomes 0ms, and `fx.js` runs only the clock (no splash, screensaver, close fade, badge pop or ambient pausing). Dropped as off-theme: a pulsing glow on the dialog's default button (Vista does it, but it would pull the eye to a destructive "Move to trash"), and hover glow on the decorative caption buttons (they do nothing, so they don't react).

### Contrast (measured on rendered pixels, worst background pixel under the text, all five backgrounds)

| Pair | Ratio |
|---|---|
| Ink on the glass bar (app name, pills, pickers, clock) | ≥ 6.96 (12.81 on white) |
| Muted `#3b6580` on window glass (summary, status, field labels) | ≥ 4.85 (6.25 on white) |
| White title on the title-bar gradient | ≥ 5.16 |
| White on the aqua pill (current section, primary button) | ≥ 4.86 |
| White on the Feed badge / Trash badge | 4.64 / 4.97 |
| White on the red confirm button | 4.84 |
| Dark red on the quiet danger button | 6.33 |
| Ink on the pale selection, tooltip, note, menu | ≥ 10.1 |

Aero icons: rules for sprite-shape classes (`.aero-doc-*`, `.aero-c-*`, `.aero-ic-*`) are deliberately unscoped, because `<use>` clones shapes into a shadow tree where a `:root[data-os]` ancestor selector never matches (shapes would render black); `test_aero_icon_css.py` enforces it.

`tests/unit/test_aero_os.py` checks the token pairs, the motion system and the rest of the Aero-specific rules.
