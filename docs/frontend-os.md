# Frontend: OS environments (`static/os/`)

**TL;DR:** The dashboard's look is an **OS**: one folder `static/os/<name>/` (tokens, chrome CSS, a shell script, a background set, optional `fx/`). The functional app is OS-neutral. `os-boot.js` sets `html[data-os="<name>"]` from `pdash.os` before any CSS loads; every OS is linked, every OS rule is scoped to `:root[data-os="<name>"]`, every OS script no-ops unless its name is active. Three OSes ship: Platinum (default), Aero (unit A1) and Neumorph (units N1/N2). Why: ADR 0028. This page is the complete recipe for adding one; `tests/unit/test_os_contract.py` enforces it for every registered OS.

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

## Neumorph

Soft UI (neumorphism, owner request 2026-11-10, backlog §16): every part is moulded from **one** porcelain surface `#e4e9f1` (desktop, windows, wells, keys, menus, notes share it; depth comes only from light/shade pairs). Light only. Font preloads: `nunito-400.woff2`, `nunito-800.woff2`.

- `theme.css`: ink `#26304a`, muted `#566179`; one accent, **iris** `#5146d8` (hover `#4338c4`, soft `#d6dbf6`) for the primary action, current section, selection text, focus ring, checked state and LEDs (picked over blue so it never reads as Aero, over green as Platinum, and over coral/orange so it can't be confused with danger); danger `#b8253a`; `--color-warning-soft` is the surface itself (notes carry an amber LED instead of a yellow fill); Nunito 400/600/800 (rounded terminals match the pillowy shapes); radii 12/14/18px (+ private 16–28px); `--motion-duration: 180ms`, `--focus-ring-width: 3px`.
- **Shadow recipe** (private `--neu-*` tokens in `chrome.css`): one light source top-left; raised = full white `rgb(255 255 255 / 1)` up-left + shade `rgb(163 177 198 / .75)` down-right, blur ≈ 2× offset, plus a **lit rim** (inset 1px white up-left, inset 1px shade down-right) so the up-left edge reads as a highlight, not only the down-right drop (N2 polish 1); sunken = the pair `inset`. Every key state is a **four-layer list** (outer shade, outer light, inner shade, inner light; unused layers are zero-size) so raised ↔ pressed interpolates instead of jumping. Three elevation steps: controls 4px (`--bevel-raised`; xs 2px for small chips), cards/windows 10px (`--shadow-raised`), overlays 20px (`--shadow-overlay`); wells 5px / 8px inset. Faint 145° gradients: convex keys `#edf1f7 → #dde3ec`, concave reversed, slabs `#e8ecf3 → #e0e6ee`. No hard borders, no black rules; separators are engraved grooves (shade line + light line).
- `chrome.css`: the shell bar is a floating raised slab (inset 12/16px from the edges on wider screens) with the **app knob** (a round raised knob with a lit iris LED) and the name; Feed / Trash (moved into the nav slot by `shell.js`), Knowledge map and both pickers are pill keys (current/open = pressed in + accent text; count badges in sunken capsules); the clock is a sunken readout. Windows are 28px raised slabs; the title bar is part of the slab (title in ink 800); the real close control is a round raised knob that presses in (44px hit area). Lists: `.inset` is a sunken well, rows lie flat in it, hover/focus lifts the row into a raised capsule with the title in iris, press sinks it; list heads are small engraved caps; `.row-more` a small round key; status text engraved; the decorative resize grip is hidden. Info window: the preview `.screen` a deep well with the media rounded inside; `.fields` and `.group` embossed panels; files small raised cards (the selected one pressed in, name in iris); "Opens first" a sunken chip. Controls: `.button` convex key → concave on `:active` (shadow flips, 1px down); `.button-primary` an iris key with a soft iris glow; `.button-danger` red key; `.button-danger-quiet` surface key with red text; `.select` a soft key with a round sunken knob holding a CSS chevron (the sprite arrow hides); inputs (`.kmap-search`, code input) sunken pills; `[aria-pressed=true]` stays pressed in + iris. Knowledge map: the N3/N4 showpiece (keys moulded from the surface), see **Knowledge map** below. Overlays (context menu, pickers, dialog over a blurred surface veil, balloon hints with lit/shaded tails, notes with an amber LED, toast pill with an iris LED, full-screen close key) use the top elevation step. `::selection` iris-soft, thin scrollbars.
- Backgrounds (relief on the one surface, gradients only): **Porcelain** (default, a faint convex sheen), **Dunes** (two pairs of long lit/shaded ridges), **Pillows** (a 48px grid of small cushions, lit up-left and shaded down-right), **Rings** (grooves cut in concentric circles around a centre high on the right), **Orb** (one large raised disc of the surface). Alphas stay ≤ .75 light / .32 shade, so no text ever sits on more than a ±3% lightness change.
- `shell.js`: swaps the sprite art (`icons.js`, `safe("sprite", …)`) and moves `nav.desk-icons` into `[data-slot="nav"]`; adds no other DOM (knob, LEDs and relief are CSS).
- `fx/`: the clock always (stops while the tab is hidden); with motion allowed also ghosts, badge pop, splash, screensaver and the knowledge-map effects `fx/kmap.js` (see Motion and Knowledge map).
- Phones (< 37.5rem): one row of 44px keys — knob, Feed, Trash, Knowledge map (icon only; current = pressed + iris rim), Background (a small relief disc; the label stays its accessible name), OS; the clock and app name hide. The Version label aligns with the popup's first line when the switcher wraps.
- **N2 polish** (backlog §16.2): rows lift by cross-fading two pre-rendered layers (`::before` raised capsule, `::after` pressed) — opacity only, no repaint of the row; Map/List is a segmented control (sunken pill track, the active key raised with iris text); count badges are small sunken wells; the list well is deeper at its up-left inner edge; "Opens first" is an embossed chip; menu items (context menu, pickers) rest flat and press in as a capsule with iris text on hover or `:focus-visible`; the ring shows only for keyboard focus and follows the capsule (2px offset), plain `:focus` from opening the menu with the mouse stays flat; the info window's Back is a quiet pill key with an iris chevron on its own row under the title; knowledge-map labels are semibold with a thin surface-coloured halo painted under the glyphs (`paint-order: stroke fill`, 0.26em; the pearl filter moved to the dots, so labels stay crisp and evenly spaced); the sort caret and pin are drawn in the icon set; Orb is a real dome (lit sheen up-left, surface face, darker rim, glow and cast offset).

### Icons (`icons.js`)

One hand, one light: every sprite symbol is redrawn as **moulded porcelain** on a 32-unit grid. Document kinds sit on a **pebble** (26-unit rounded square, r 8) extruded by a helper (`extrude`: a shade copy +0.8 down-right, a light copy up-left, the face, three faint concentric sheens); the mark on it is **embossed** (`emboss`: a light lift up-left, a shade drop down-right, the mark in ink `#34405c` or iris). Objects (folder, trash, caution, pin, app knob, kmap pearls, bundle stack) are themselves pebbles; folder and bins carry an embossed ink edge so they hold their silhouette at list size (folder: iris tab, ink flap edge and handle; bins: ink rim and ribs). Colour language: ink = the structure, iris = the one meaningful accent (bar, sun, play, check, arrow, folder tab), muted strokes only as secondary detail, amber only for caution, the three map pearls in the map palette. Boxes are sized for the tile they show (the tile fills 26 of 32 units): list rows 40px on wider screens (≈ 32px tile, negative block margin keeps the row height), file rows 28px (≈ 23px tile), info head and alerts 88px (≈ 72px tile), pin and sort caret 14px; a two-step CSS `drop-shadow` gives the cast and glow. Shapes carry **bare, unscoped** classes `.neumorph-ic-*` coloured by `--neu-ic-*` tokens: `<use>` clones into a shadow tree where `:root[data-os]` never matches, and the tokens inherit from the `<use>` element (same lesson as Aero; `test_neumorph_icons.py`). Marks that carry meaning reach ≥ 3:1 on the face (ink 8.47, iris 5.35, amber 3.84); muted detail (2.93) never stands alone.

### Motion (`chrome.css` tokens, `fx/fx.css`, `fx/*.js`)

Physical, quiet, one light: things **rise out of** and **sink into** the surface (scale .965 → 1 with a 10px lift, shadow growing with it), never slide or spin. Exits are faster than entrances; press is faster than release; release settles with one small overshoot.

| Token | Value | Used by |
|---|---|---|
| `--neu-dur-press` / `-release` | 70 / 260ms | every key: press in, then release with `--neu-ease-settle` (overshoot ≤ 1.45) |
| `--neu-dur-menu-in` / `-out` | 200 / 120ms | context menu (rises toward its key), pickers, balloon hints |
| `--neu-dur-window-in` / `-out` | 340 / 170ms | window rise on every route, dialog + veil, expanded preview |
| `--neu-dur-toast-in` / `-out` | 280 / 180ms | toast pill |
| `--neu-dur-pop` / `-splash` / `-breathe` | 380 / 560ms / 9s | badge pop, splash, screensaver |
| `--neu-ease-out` / `-in` / `-press` / `-settle` / `-breathe` | cubic-béziers | entrances / exits / press / release / ambient |

- **Keys** (shell keys, buttons, close knob, `…`, file actions, select, map entry buttons, map pearls): rest → hover (−1px, larger shadow) → press (+1px, inset) → release, all on `box-shadow`/`transform` only.
- **Entrances** are CSS animations on the app's own state (`.main > .window`, `.ctx-menu`, `.shell-menu:not([hidden])`, `.dialog[open]` + `::backdrop`, `.toast.is-visible`, `.stage.is-expanded`). **Exits** of `hidden` surfaces use `transition … display allow-discrete` (works through the app's `[hidden]{display:none !important}`); the toast keeps `visibility` for its fade.
- **Ghosts** (`fx/ghost.js`): surfaces the app removes at once (the old window on a route change, a closed context menu or dialog, the full-screen veil) leave an empty `aria-hidden` slab of the same box that sinks away. Ghosts only follow the app: no navigation, no prevented events, no item text (no clone).
- **Badge pop** (`fx/badge.js`), **splash** (`fx/splash.js`: the knob rises, its LED lights, "Previews" surfaces; any input or 1.7s dismisses it, the dismissing input is swallowed; then the bar and window rise in turn), **screensaver** (`fx/screensaver.js`: a breathing dome in three grooved rings; removed while the tab is hidden, `?fxIdleMs` ≥ 1000).
- **Reduced motion**: `fx.js` starts only the clock; every `--neu-dur-*` is 0ms and every animated/transitioned selector is listed with `none` (contract test). Verified: no splash, 0 running animations, instant navigation, no ghosts.

### Knowledge map (N3 + N4, backlog §16.5–16.6)

One physical model, true neumorphism: the map is **moulded from the surface**. Every note is a porcelain **key** raised out of the floor, with its category as a small **LED** in a concave socket; links are **grooves** carved into the floor, tag links rows of **dimples**. Height is the only state language (raised, lifted, flush, pressed); iris light is the only accent and marks what is related to the note in focus.

| Hook / state | Treatment |
|---|---|
| `.kmap-map` | Deep basin (multi-layer inset, `--neu-kmap-basin`) with a smooth floor (no dot grid). Keyboard focus never draws a box: `.kmap-svg` loses its outline and the basin rim lights iris (`--neu-kmap-basin-ring`). |
| `.kmap-ring` | The key: surface-coloured disc (`--neu-kmap-key`), 1px moulded rim, scaled by `--neu-kmap-k` (1.15) via `transform-box: view-box` (the node `g` keeps its own `translate`). Its height is one number, `--neu-kmap-lift`, set by the states; without `fx/` it drives a static CSS drop-shadow pair (shade down-right, light up-left along `--neu-kmap-sx/-sy`). |
| `.kmap-dot` / `.kmap-shine` | Dot = the LED: category colour, scaled down (`--neu-kmap-led-k`). Shine hidden (a matte key has none). |
| hover / `:active` / `is-selected` | Lift 1.8 / flush .16 / the press latched: flush + a 0.75px iris hairline (`--neu-kmap-hairline`, 30%) + iris label. |
| `has-focus` + `is-near` | Neighbours lift (staggered by `--neu-kmap-nd`); unrelated keys sink nearly flush (.22), LED dark (`--neu-kmap-led-off`), label .45. |
| `is-filtered` | Non-matches: nearly flush, LED dark; matches lift with an iris ring round the socket (`--neu-kmap-match`). |
| `is-recent` | The LED glows (`drop-shadow` 3px of its colour); with `fx/` the LED itself breathes (opacity .4 to 1) with its halo. |
| `.kmap-edge` | Groove: 6px floor-dark stroke (`--neu-kmap-groove`), round caps, non-scaling; one lit-lip `drop-shadow` on the whole edge layer (`.kmap-svg g:has(> .kmap-edge)`), never per line. Tag links: dimples (`0.1 var(--neu-kmap-dimple)` = 11px). Near: a faint iris tint without `fx/`. |
| `.kmap-label` | Engraved ink (strong weight, a 0.08em light edge down-right), no plate, just clear of the key. |
| `.kmap-index` | A well; categories with an LED swatch (glass bead in a concave socket, as on the map) and a count well; entries are raised soft keys with the same LED pip, selected = pressed + iris rim/text; "Changed this week" a chip with an iris LED. Phones get the same list. |
| `.kmap-panel` | Raised reading slab; head over an engraved groove; tags convex chips with an iris `#`; links iris over a groove (no default blue), missing = dotted muted groove; quote/code sunken wells; backlinks pill keys. |
| `.kmap-message` | Empty / loading / error: an empty socket above engraved text; "Try again" a soft key. Loading: the socket breathes. |
| `.kmap-approvals` | Control panel slab; title LED (`.group-title::before`): unlit socket = nothing waiting, **amber** = waiting or "can't be checked", **iris** = code entry open, **iris breathing** = a decision in flight (`button:disabled`). Each request is a sunken bay; text full size, never clipped; ID in a well chip; Approve… a convex iris key, Deny… a quiet key with danger text; the code form a raised plate whose input shows six engraved cells (`--neu-kmap-cell`, background gradient only); status a pill (`:empty` stays hidden). |

States share one weight (`:where`), so source order is the priority: unrelated/filtered < neighbour/match < hover < press = selected. Category LEDs on the surface (≥ 3:1, `test_neumorph_kmap.py`): iris `#5a4fd9` 4.85, teal `#1b8379` 3.77, amber `#a8690c` 3.67, rose `#c0446a` 4.03, sky `#2f74c0` 3.93, sage `#4a8650` 3.58, plum `#8a4bb0` 4.64, slate `#5f6c88` 4.32. Every state also differs in height, LED or iris, so none relies on hue alone.

**Moulding** (`fx/kmap.js` + `fx/fx.css`, svg marked `.neumorph-kmap-moulded`): each key gets its own `aria-hidden` decor, all **flat fills in translucent steps** (an OS references nothing, so no gradients, SVG filters, masks or ids): a shade disc and a light disc under the ring (one circle each: a fill plus a wide translucent stroke, darker at the key and lighter beyond; moved by `transform` = throw × lift × direction, so height changes are transitions, never filter changes); a face on it (dome highlight up-left; the LED's socket: a lit lower lip, the dish's floor as fill and wall as stroke) and a glint on the LED. The LED's halo is its own stroke under the bead (`paint-order: stroke`, width `--neu-kmap-halo-w` per key). A key is 11 elements: a state change restyles every part of every key. The ring drops its drop-shadow. **Grooves** lose chrome's layer filter (`filter: none`); kmap.js carves them with plain strokes instead. Under the edge layer it puts one `aria-hidden` group `.neumorph-kmap-carves` holding a copy of every edge (`line.neumorph-kmap-carve[data-kind]`: 6px, round caps, non-scaling, tag copies dimpled like their groove). It has two sub-layers: `.neumorph-kmap-carve-shade`, nudged up-left, and `.neumorph-kmap-carve-light`, nudged down-right. Each nudge is a `transform` of 1/zoom map units, so one screen pixel at any zoom, rewritten on zoom. Only a 1px sliver of each copy shows beside its groove. Copies follow dragged keys and replay the opening draw. Grooves fading back under focus or a filter stay opaque and fade by colour (`--neu-kmap-groove-faded`), so the copies never show through.

**Interaction**:

| Trigger | Motion | Tokens |
|---|---|---|
| First open / back to Map | Keys rise out of the floor in a wave from the centre (`--neu-kmap-d` = distance × 520ms): fade in while every part swells to size and the shadow discs slide out to their height; labels follow; link grooves cut themselves from the nearer end (`stroke-dashoffset`, `--neu-kmap-len`/`-from`), tag dimples fade | `kmap-rise` 560ms, `kmap-draw` 620ms, settle ease |
| Hover (mouse) / press / release | The key lifts / drops flush (press timing) / settles with overshoot | `release`, `press` |
| Focus (hover or select) | A thin iris line with a soft glow is drawn inside each of its grooves, always out of the focused note (link: a beam `g.neumorph-kmap-beam` = a wide faint glow line under the thin line, both drawing; tag: one spark per dimple with a faint iris stroke ring, lit as the light reaches it, `--neu-kmap-t`; the glow is strokes, never a filter on the layer); neighbours lift nearest-first (45ms steps); the rest sinks in one step | `kmap-flow` 900ms (sine), `--neu-kmap-nd` |
| Select | The press latches; a ripple of light and shade spreads through the floor from it (one `aria-hidden` div, removed after) | `kmap-ripple` 900ms |
| Pointer (fine pointer only) | The pointer is a light source: keys within 220px cast their shadow away from it, blended into the room light with distance and centred under a pointer right above it (`--neu-kmap-sx/-sy` on the two discs only, every frame, uneased, written only on change > .04); the selected key ignores it; leaving the map, keys ease back | rAF, passive `pointermove` |
| Recent notes | The LED breathes (`steps(24)`, so idle costs ~24 paints per cycle) | `breathe` / 3 |
| Map → List, note open | Category groups and keys rise in turn; the slab lifts and its parts rise in reading order | `kmap-page` 300ms |
| Approve | Key press; the code plate rises out of the bay; the Approve key stays pressed in while checking, LED breathes | `kmap-page`, `breathe` |

Only `transform`, `opacity` and `stroke-dashoffset` animate; no filter is animated or transitioned. Only keys in play ease (hovered, neighbours, pressed, selected, or just let go `.neumorph-kmap-settling`; the pointer light turns keys every frame, uneased); map-wide changes (focus dim, filters) happen in one step, so 150 notes repaint once, not for 300ms. Paused while the tab is hidden (`html.neumorph-kmap-paused`, the pointer loop stops on leave). Reduced motion: `fx/kmap.js` never starts (the map shows the static CSS look: keys with drop-shadow pairs, flat LEDs, lit-lip grooves), the six `--neu-dur-kmap-*` tokens are 0ms and every animated selector is `none`; every state is still distinct (height, LED, hairline, iris).

**Performance at 150 notes** (~340 grooves). Measured on **headless Chromium with software raster**, so absolute numbers are pessimistic. Scratch harness `kperf2.js`: 3 runs per scene, frame times from rAF, "jank" = time over 16.7ms per run, ±50% run to run. Scenes: pointer sweep / hover in-out ×6 / select-deselect, median frame 16.7ms in each. The first pass in a fresh browser is 2–3x slower than later passes.

| Jank ms per run (sweep / hover / select) | First pass | Warm (second pass) |
|---|---|---|
| Before: layer filters on grooves and channel glow | 2271 / 3476 / 599 | not measured |
| Now: stroke copies, stroked glow | 1810 / 2655 / 439 | 677–733 / 1094–1566 / 389–583 |
| CSS only (`fx/kmap.js` stubbed) | 877–1016 / 1444–1694 / 67–111 | 189 / 245 / 34 |

Idle: no style recalcs. Why it is built this way: a filter on a whole layer re-runs over the map on every repaint, so `fx/` uses no layer filters. Each restyled element costs ~0.04ms here, so keys are 11 elements and the pointer light writes only the two discs. What remains is restyling 150 keys on a focus change plus the transitions of neighbour and settling keys, the cost of the spec's features (owner kept them).

**`fx/kmap.js` isolation**: decoration only. It reads the map's geometry (`.kmap-viewport`, `.kmap-nodes`/`.kmap-edges` children, `getScreenCTM`) and writes only custom properties (`style.setProperty`), its own `neumorph-kmap-*` classes (moulded/opening on the svg, settling on keys just let go, paused on `html`), its own empty `aria-hidden` SVG decor (per-key discs/face/glint, the groove carving copies, one flow layer) and one `aria-hidden` ripple div. No item text, no network, no storage, no HTML sinks, no `url()`, no prevented or stopped events, passive listeners only; it never touches the approvals card (C6, C23, C46). With `fx/` deleted the map is complete and static: keys + LEDs.

### Contrast (WCAG; token pairs and every key-gradient stop, `test_neumorph_os.py`)

| Pair | Ratio |
|---|---|
| Ink on the surface / on the darkest key stop | 10.74 / 9.86 |
| Muted on the surface / lightest / darkest key stop | 5.09 / 5.48 / 4.68 |
| Iris text on the surface / darkest key stop | 5.35 / 4.92 |
| White on the iris key (light / dark stop, flat) | 5.16 / 7.23 / 6.53 |
| White on the red key (light / dark stop) | 4.90 / 7.19 |
| Danger text on the surface / darkest key stop | 5.12 / 4.70 |
| Warning text on the surface | 6.14 |
| Ink on iris-soft (`::selection`) | 9.55 |
| Focus ring (iris) on the surface | 5.35 (≥ 3 needed) |
| Ink / muted / iris on the Orb rim (`#d9e0ea`, darkest background stop) | 9.85 / 4.67 / 4.91 |
| Icon marks on the pebble face: ink / iris / amber (non-text, ≥ 3) | 8.47 / 5.35 / 3.84 |

Every interactive control reads without its shadow: ink or iris text/icons, and selected, current and checked states always add iris text, an iris rim or a lit LED.

`tests/unit/test_neumorph_os.py` checks registration, the one-surface rule, private-token names, contrast, that every hook of the table above is styled, the phone bar, motion and the fx start order, and the Nunito provenance; `tests/unit/test_neumorph_icons.py` runs `icons.js` under Node and checks the icon art (every symbol, unscoped classes, token colours, mark contrast) and the motion rules (reduced-motion zeroing, exit < entrance, press < release, entrances/exits present, ghost and screensaver constraints); `tests/unit/test_neumorph_kmap.py` checks the knowledge map (core contrast, every map/approvals hook styled, no stage outline, the approvals card never hidden/clipped/animated away, keys + LEDs without `fx/`, no dot grid, selected = latched press, state order, keyframe properties, static layer filters only, only keys in play ease, every lit channel draws, `fx/kmap.js` decoration-only rules (flat fills, no `url()`) and reduced-motion coverage).
