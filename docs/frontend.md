# Frontend

**TL;DR:** Vanilla ES modules, no build step, served from an in-memory manifest (`src/preview_dashboard/static/`). The dashboard renders **no HTML from data**: untrusted text goes through `textContent` in `<bdi>`, previews are `<img>`/`<video>`/`<audio>`/sandboxed `<iframe>`s pointing at the **preview origin**. Text kinds are formatted by a page on the preview origin (`/r/`), not by the dashboard. The look is an **OS** (docs/frontend-os.md, ADR 0028): the files here are OS-neutral (shell bar, desktop icons, list window, info window) and every visual value comes from the active OS's `os/<name>/theme.css` (tokens below) plus its `chrome.css`. Default OS: **Platinum 1998** (design prototype 07).

## Structure

| File | Role |
|---|---|
| `index.html` | Shell (OS-neutral): shell bar (`data-shellbar`, slots `data-slot="app|nav|background|os|clock"`), desktop icons Feed / Trash (`data-nav`, count slots `data-count`), `<main>` window area, toast live region, and the **pixel-icon sprite** (`<symbol id="i-…">`, fixed palette: imagery, not theme). No inline script/style (C6). |
| `os-boot.js` | Classic script before the stylesheets: sets `html[data-os]` from `pdash.os` (allowlisted, else the default) and preloads that OS's chrome font (docs/frontend-os.md). |
| `os/` | The OS layer: shared `registry.js`, `storage.js`, `shell.js` + `shell-menu.js` + `background.js` + `os-picker.js` (Background / OS pickers), `shell.css`; one folder per OS (`os/platinum/`: `theme.css` tokens, `chrome.css` signature look, `shell.js`, `backgrounds.js`, `fx/`). The default OS's `theme.css` is also inlined into `/r/` pages, so it references no files. See docs/frontend-os.md. |
| `fonts.css` + `fonts/` | `@font-face` for the vendored Pixelify Sans / Public Sans / Catamaran (Aero) / Nunito (Neumorph) `.woff2` (latin, OFL; provenance + sha256 in `fonts/FONTS.md`, licences `fonts/OFL-*.txt`, not served). Dashboard only. |
| `app.css` | OS-neutral layout + components (structure and a flat token-driven look; each OS adds its signature in `chrome.css`), tokens only (a test forbids literal colors/fonts and any `url()` here). |
| `app.js` | Bootstrap (loads `GET /api/kinds` once, incl. `preview_origin` → `setPreviewOrigin`) + hash router (`#/`, `#/folder/<id>` = the Feed window opened on one folder, `#/folders` redirects to `#/`); each view returns a cleanup that stops its polling. |
| `api.js` | The only network code: same-origin `fetch`, exact CSRF headers on POST, `If-None-Match`, `startPolling` (10 s, paused while the tab is hidden); `itemPath(id, {trashed, rev})`, `itemsPath({…, folder})` (a folder id or `"unfiled"`). |
| `dom.js` | `h()` element builder (refuses `on*`, `style`, `srcdoc` attributes), `untrusted()` (`<bdi>` + `textContent`), `setPreviewOrigin()` / `httpsUrl()` (item URLs must be on the preview origin; fail closed until it is known), `ULID_RE` (single source of truth for id validation), formatting, `toast()`. |
| `feed.js` | Feed and trash as a Finder list window: rows (pinned first, newest first — API order) with pixel kind icon, Kind, Size, Date (trash: "Kept until"), a "…" context-menu button; "Show:" popup (All kinds + optgroups Pictures / Pages / Motion & sound / Code / Data / Other; `progress` is never offered — choosing HTML lists html **and** progress items via one `kind=html,progress` request (owner 2026-09-30, backlog §12.3); a saved choice no longer offered falls back to All kinds); "Load more" (cursor), first-page polling. Folders live inside this one window (backlog §7.1): at `#/` folder rows (Platinum folder icon, name via `untrusted()`, Kind "Folder", item count in the Size column, sorted by name; context menu "Open") come first, then the *unfiled* items (`?folder=unfiled`). **Bundles** (`bundle.js`): `i-bundle` icon, Kind column "Bundle" with a small "N files · <entry kind>" line under it (phones' sub-line: "Bundle (N files), <size>"), context menu "Download bundle (N files)"; the "Show:" filter still matches a bundle by its entry kind (no "Bundles" choice: the API filters by kind only, so a client-side filter would break paging). Opening a folder (`#/folder/<id>`) keeps the window, titles it "Feed ▸ <name>" and lists that folder's items; the close box goes up to `#/`; a **Back** button (see Navigation below), Backspace and Alt+Up go to the Back target. Kind filter, Load more, polling and menus work at both levels; folder rows are not filtered. Trash stays flat. |
| `bundle.js` | The **bundle rule** (backlog §10, owner decision 2026-09-30), pure functions only: `isBundle(item)` = `file_count >= 2` and kind not `html` (an HTML site is one page + its assets and stays HTML); `filesText`, `bundleDetail` ("10 files · Image"). A bundle keeps its real kind for previewing; only its presentation changes. Tested in Node (`tests/unit/test_bundles_ui.py`). |
| `chrome.js` | Window chrome builders: `icon()` (sprite `<use>`, ids from an allowlist), `backButton()` (the Back control, see Navigation), `kindIconId` (by renderer id; `progress` → `i-progress`), `itemIconId` (`i-bundle` for a bundle, else the kind's icon), `fileIconId` (by extension, same mapping the kinds use; unknown → `i-file`), `windowFrame()` (OS-neutral parts only: title, a close control only when `close` is passed — a control that did nothing was a false affordance, W1 item 3 — and the body; no zoom box, W1 item 2; the shade box is Platinum decoration added by its `fx/shade.js`), `popup()` (select + arrow; the OS draws the end cap), `alertWindow()` (not-found / error pages). |
| `desktop.js` | Desktop icon counts (`/api/items?limit=200` per state, "200+" beyond; ETag, 30 s poll + on every route) and the full trash can. |
| `nav.js` | Back navigation (in memory only): `recordRoute(hash)` (called by the router before each render) remembers the previous hash; `itemBack` picks the item's Back target; `folderBack` is always the Feed. No DOM, node-testable. |
| `folders.js` | Data only (backlog §7.1): `loadFolders()` reads `GET /api/folders` and always degrades to "no folders" (404, network error or malformed body → empty list, never a thrown error; entries with a non-ULID id are dropped). Used by `feed.js` for the folder rows and for resolving `#/folder/<id>` (unknown/deleted folder → "Page not found"). Network only via `api.js`. |
| `balloon.js` | Balloon Help hints (W1 item 1): one shared balloon for whichever `[data-hint]` control the owner points at, focuses, or long-presses (mouse: ~500 ms hover; keyboard: on focus; touch: long-press, skipping controls that already own one via `attachContextTrigger`); hides on Escape/pointer leave/blur/scroll. Hint text is a fixed string from `data-hint`, set by builder code, never item data; `aria-describedby` points at the balloon. Delegated on `document`, so the OS layer's shell-bar triggers (Background, OS) get hints too without either file importing the other. |
| `item.js` | Detail as a Get Info window: title bar "<title> Info" (close box = back link), a plain item icon (`itemIconId`: `i-bundle` for a bundle; no button, no context menu — W1 item 5) + title + description, preview (toolbar with file name and Full screen), fields (Kind — a bundle reads "Bundle (N files) · <entry kind>" — Folder — read-only, `item.folder.name` via `untrusted()` or "Unfiled"; backlog §6.3 — Size, Published, Label, Version popup with Delete old versions, trash date), Files group (every file with its own icon by extension — a non-bundle's entry file takes the item's kind icon, so `progress.json` shows `i-progress`; with several files the entry file is tagged "Opens first"; per-file Preview, and Download only for multi-file items — a single file's row would repeat the main Download, W1 item 4), buttons (Move to trash; Pin/Unpin, active items only; ringed default Download all / Restore) with confirm; version switcher reloads the detail with `?rev=<n>` (a pruned version falls back to the latest). |
| `dialog.js` | Native `<dialog>` confirm drawn as an alert (icon, Cancel, default button). |
| `menu.js` | Popup/context menu (R4): opened by right-click, ~500 ms touch press, a row's "…" button, or Menu key/Shift+F10 on a focused trigger; roving-tabindex keyboard nav (arrows/Home/End/Enter/Escape), one menu open at a time, focus always returns to the trigger. Also the shared item actions it offers — `setPinned()` (POST pin/unpin, toast, row order updates via the caller's refresh), `changeItemState()` (the existing trash/restore confirm dialog + POST + toast), `triggerDownload()` — so `feed.js` and `item.js` call one implementation instead of duplicating the network calls. Network only via `api.js`. |
| `expand.js` | Full-screen overlay for previews (CSS overlay, works on iPhone; Escape/Close restore focus). |
| `versions.js` | Version switcher as a "Version:" field row (popup `<select>` of kept revisions, newest first; only when > 1) + "viewing an older version" balloon with Show latest. Labels are numbers and times only. **Delete old versions** (R2, ADR 0030, C43): a quiet-danger `<button>` beside the popup, active items only and only when an older version exists (`olderVersions()`); its confirm dialog says how many and how much ("Delete 4 older versions (380 MB)?" … "This can't be undone. Space is freed within about two hours." — numbers only, no item text), then `POST /api/items/<id>/revisions/prune?expected=<latest>` (a newer version meanwhile → 409, toast "This item changed meanwhile…"); on success the detail reloads on the latest version, so the switcher disappears. |
| `knowledge-map.js` | The **Knowledge map** window (`#/knowledge`, unit M8, C57): Claudia's notes from `GET /api/kb/graph` as a hand-written SVG graph (dots = notes, fill = category slot via `data-cat`, size = connections, ring = changed this week; solid lines = `[[links]]`, dotted = shared tags). Wheel/pinch zoom, drag to pan, drag a dot to move it, tap a dot → side panel; keys `+ - 0` and arrows on the focused map; hover/selection highlights the neighbours; search (name + tags, Enter opens the first match) and a Category popup dim the rest; Map/List toggle. Phones (< 37.5rem) get the **list by category** only, a note covering the list with "Back to the list". Off (404) → "The knowledge map is off…". Read only. |
| `kmap-layout.js` | Pure, node-tested: seeded force layout (categories on a ring, grid-bucket repulsion, springs), `fitTransform`, `zoomAt` (clamped 0.1–6), `neighbours`, `matchesQuery`, `categorySlots` (≤ 8 colour slots). |
| `kmap-note.js` | Note reader: body text → headings, bullets, quotes, fences, paragraphs via `textContent` only (≤ 600 blocks); a resolved `[[link]]` becomes an in-app `<button>` opening that note, an unresolved one a dotted span. |
| `kmap-approvals.js` | "Waiting for your approval" box (`GET /api/claudia/approvals`, 10 s ETag poll): action text, kind, target, state, expiry and the ULID to compare with the phone prompt. No buttons: approving happens on the phone only. Unavailable snapshot → "Nothing is waiting" plus a note to approve nothing until the list can be checked (fail closed). |
| `renderers/` | Renderer registry (`index.js`) + one module per renderer id. |
| `preview-render/` | `renderer.js` + `renderer.css`: the preview-origin text renderer, inlined into `/r/` pages. |
| `vendor/` | Pinned DOMPurify, marked, highlight.js (see `vendor/VENDOR.md`, `CHECKSUMS`). Inlined into `/r/` pages only; **not served by the dashboard** (`vendor/` and `preview-render/` are excluded from its static manifest → 404). |

### Routes

| Hash | View |
|---|---|
| `#/` | Feed (active items) |
| `#/trash` | Trash |
| `#/item/<id>` | Item detail |
| `#/trash/<id>` | Trashed item detail (API `?t=1`, preview URLs carry `?t=1`) |
| `#/folder/<id>` | The Feed window opened on one folder (backlog §7.1): titled "Feed ▸ <name>", that folder's items, up control back to `#/`. An id that doesn't match a current folder shows "Page not found". |
| `#/folders` | Legacy F3 overview; redirects to `#/` (the folders are rows in the root Feed window). |
| `#/knowledge` | Knowledge map (unit M8), opened from the shell bar's **Knowledge map** shortcut (`a.shell-link[data-nav="knowledge"]`, icon `i-kmap`; icon only on phones, the label stays its accessible name). |

The version on screen is view state, not part of the hash: the detail always opens on the latest version.

Ids must match the ULID pattern before any request is made; anything else shows "Page not found".

### Navigation (Back)

The item view and the folder window have a **Back** button (`backButton()` in `chrome.js`, a real `<button>`, label "Back to <place>"; a folder name is rendered via `untrusted()` only). It sets `location.hash` rather than calling `history.back()`, so it can never leave the app. The router records the previous hash in memory (`nav.js`); nothing is persisted.

| View | Origin recorded | Back goes to | Fallback (direct link, reload, unusable origin) |
|---|---|---|---|
| `#/item/<id>` | `#/` or `#/folder/<id>` | that place | the item's folder `#/folder/<folder_id>` if filed (id must be a ULID), else `#/` |
| `#/trash/<id>` | any | `#/trash` | `#/trash` |
| `#/folder/<id>` | ignored | `#/` always | `#/` (any origin, item or folder, is ignored so two views can never bounce between each other) |

If the origin folder differs from the item's own folder, its name is looked up with `loadFolders()` (label "Back to folder" until then). The button sits above the item header (Get Info) and first in the folder window's header, in both OS themes (shared CSS).

## Renderers

`renderers/index.js` mirrors the backend kind registry: `GET /api/kinds` gives each kind's `renderer` id; `renderPreview(ctx)` picks the module (unknown id → `file`, download only). `ctx = {item, file, kind, trashed, capBytes}`; a module returns `{element, actions?}` (`actions` are toolbar buttons, e.g. Full screen).

| Renderer id | Module | How it shows the file |
|---|---|---|
| `image`, `svg` | `image.js`, `svg.js` | `<img src=preview_url>`; tap → full screen, tap again → actual size. SVG never as document/iframe (C31). |
| `video`, `audio` | `video.js`, `audio.js` | Native element, `preload="metadata"`, no autoplay. |
| `html` | `html.js` | `<iframe sandbox="allow-scripts" referrerpolicy="same-origin">` of the entry page; not rendered in the trash (bundle sub-resources aren't served for trashed items). |
| `pdf` | `pdf.js` | "Open PDF" link (new tab, `noopener noreferrer`): the only way a PDF is served (top-level document, C5/C31). |
| `markdown`, `code`, `json`, `csv`, `text`, `diff`, `progress` | `text.js` | `<iframe sandbox="allow-scripts">` of `render_page_url` (`/r/…`). `progress` (ADR 0029) is a tracker drawn on the preview origin by `preview-render/progress.js` (see below); the dashboard never fetches the JSON. Its icon is `i-progress` (`chrome.js` `kindIconId`). |
| `file` / unknown | `file.js` | Note + the item's Download action. |

All frames go through `renderers/frame.js` (`sandbox="allow-scripts"` only; URL must be `https:`).

### Adding a renderer

1. Backend kind first (docs/extending.md): its `renderer` id appears in `/api/kinds`.
2. Add `static/renderers/<id>.js` exporting `default { render(ctx) }`; build DOM with `h()`, untrusted text with `untrusted()`, URLs through `httpsUrl()`. Never an HTML sink.
3. Import and register it in `renderers/index.js`.
4. `tests/unit/test_static_ui.py` checks every registry renderer id is registered and the file passes the sink/eval grep.
5. A new **text** format belongs in `preview-render/renderer.js` instead (and `renderer_page.py` `_SCRIPTS_BY_RENDERER`).

## Text rendering on the preview origin (`/r/`)

`GET /r/{id}/{relpath}` (preview app, docs/api.md; why: ADR 0018) returns an HTML page built by `interfaces/viewer/renderer_page.py`:

- The capped text (`render_cap_bytes`, cut on a UTF-8 boundary) plus `{renderer, filename, extension, truncated, shown_bytes, size}` is embedded in `<script type="application/json" id="pdash-data">` as ASCII JSON with `<`, `>`, `&` escaped (`<`…; U+2028/2029 escaped too), so content can never close the block.
- The renderer code, the default OS's `theme.css` (`os/platinum/theme.css`; its token block also matches bare `:root`) and **only the libraries that renderer needs** are **inlined** (markdown: DOMPurify + marked + highlight.js; code/diff: DOMPurify + highlight.js; json/csv/text: none). Inlined, not `<script src>`: the sandboxed page has an opaque origin, so its sub-resource requests would be cross-site and are (correctly) refused by CORP `same-site` and fetch metadata. The sandbox CSP already allows inline code, so nothing is loosened. Start-up refuses any asset containing `</script`, `<script` + space//`>`, or `</style` (would break inlining).
- `progress` has its own self-contained page: `preview-render/progress.css` + `progress.js` only (no `theme.css`, `renderer.css`, `renderer.js` or vendor code). Owner rule: it looks the same in every OS, so the sheet defines a small neutral light/dark token set (`--p-*`, system fonts, flat, no bevel/glass/pixel face). `progress.js` re-validates schema v1 (ADR 0029: `version == 1`, limits, unique ids, bar refs; the file is untrusted), draws title, note, a segmented "N / M done" meter, the unit list and the "Who runs when" timeline (own horizontal scroll box; bars sharing a phase column stack) with `textContent` only, and shows a fixed "can't be shown" message for anything invalid or truncated.
- Formatting (inside the sandbox): markdown (over 512 Ki chars: plain text instead) → marked (raw HTML shown as text) → DOMPurify (`USE_PROFILES html`, `FORBID_TAGS style form svg math …`, `ALLOWED_URI_REGEXP` https/mailto/relative, never protocol-relative `//host`, links `target=_blank rel="noopener noreferrer"`) and fenced code highlighted; code/diff → `hljs.highlight()` → DOMPurify (`span` + `class` only); JSON → collapsible `<details>` tree via `textContent` (≤ 20 000 values; invalid/truncated JSON → plain text); CSV/TSV → table via `textContent` (≤ 2 000 rows, 200 columns); text → `<pre>`. Any failure → plain text.
- ETag `"<sha256>-t<cap>-r<renderer build>"`; a 304 repeats the 200's `Content-Type`.
- A truncation banner says how much is shown; downloading happens from the dashboard (the sandbox has no downloads/popups).

## Theme tokens

Platinum's palette "Sage & stone" (calm, low saturation, no blue): desktop `--color-bg` #8b9484 with dots #808a79, windows #e2e0dc (shade #c4c2be), text #1c1c1c, accent #5b7262 (hover #4a5e50, soft #dfe5dc, focus ring #3d4f42), danger #9a4540 (hover #7f3733), warning #f7f3dc / #6b5020, success #4f7d5a. Contrast (WCAG): white on accent 5.21, on accent-hover 6.98, on danger 6.37, on danger-hover 8.41, on success 4.76; focus ring on window 6.65 (on white 8.77); text on window 12.93, muted 6.72; warning text on warning-soft 6.73. `--color-accent-soft` (#dfe5dc) is only 4.07 on accent, so text on the highlight uses `--color-accent-contrast` (soft is for the selected-file background, 13.29 with text). Sprite icons in `index.html` use the same muted hues (the accent and folder fills via the `--icon-*` tokens); pixel outlines stay black.

Contract for OSes: every OS's `os/<name>/theme.css` defines **exactly** these custom properties in its `:root[data-os="<name>"]` block (the default OS's block also matches bare `:root`; a dark block under `@media (prefers-color-scheme: dark)` is optional — Platinum is light only and says `color-scheme: light`; `--motion-duration: 0ms` under reduced motion). `tests/unit/test_os_contract.py` checks this list equals each OS's `theme.css`; `tests/unit/test_static_ui.py` checks that `app.css`, `os/shell.css` and `renderer.css` use no other values. An OS's `chrome.css` may add private tokens of its own (docs/frontend-os.md). Fonts: only vendored `.woff2` under `static/fonts/` via `fonts.css` (CSP `font-src 'self'`); `/r/` pages don't load them and fall back to the system stacks in the font tokens.

| Group | Tokens |
|---|---|
| Surfaces | `--color-bg` desktop, `--color-desktop-dot` desktop pattern dots, `--color-window` platinum windows/controls, `--color-window-shade` pressed/sorted header, `--color-surface` white insets (list, preview screen), `--color-surface-sunken` sorted column/wells/code, `--color-media-bg` behind images/video, `--color-overlay` full-screen/dialog backdrop |
| Lines | `--color-border`, `--color-border-strong` window/control edge, `--color-rule` list row lines, `--color-bevel-light`, `--color-bevel-dark`, `--border-width` |
| Text | `--color-text`, `--color-text-muted` |
| Accent | `--color-accent` selection highlight, `--color-accent-hover`, `--color-accent-contrast` text on accent, `--color-accent-soft` selected file background, `--color-focus` focus ring |
| States | `--color-danger`, `--color-danger-hover`, `--color-danger-contrast`, `--color-warning-soft` balloon/notice/toast, `--color-warning-text`, `--color-success` positive state (not yet used by a component) |
| Type | `--font-chrome` pixel face (title bars, menus, buttons, labels), `--font-body`, `--font-mono`, `--font-size-xs`, `--font-size-sm`, `--font-size-base`, `--font-size-lg`, `--font-size-xl`, `--font-size-2xl`, `--font-size-control` (16px selects on touch: no iOS zoom), `--font-weight-regular`, `--font-weight-medium`, `--font-weight-strong`, `--line-height-tight`, `--line-height-body`, `--letter-spacing-heading` |
| Space | `--space-1` … `--space-7` (`--space-1`, `--space-2`, `--space-3`, `--space-4`, `--space-5`, `--space-6`, `--space-7`) |
| Shape | `--radius-sm` popups, `--radius-md` buttons, `--radius-lg` balloons, `--radius-pill` |
| Elevation | `--shadow-raised` window drop shadow, `--shadow-overlay`, `--bevel-raised`, `--bevel-pressed`, `--bevel-sunken`, `--ring-default` default-button ring |
| Patterns | `--desktop-pattern`, `--desktop-pattern-size`, `--desktop-pattern-position` (Platinum's title-bar pinstripes are private to its `chrome.css` since O1) |
| Icons | `--icon-accent`, `--icon-folder`, `--icon-folder-tab`, `--icon-folder-shade`: sprite fills an OS may recolour (symbols carry `class="ic-…"` instead of a fill; Platinum: the accent #5b7262, folder #b4c4b0 / tab #d3dccf / shade #8fa58f) |
| Motion | `--motion-duration`, `--motion-ease` (Platinum: 0ms, no animation; Aero: 240ms, `cubic-bezier(0.2, 0.9, 0.3, 1)`, extended by its private `--aero-dur-*`/`--aero-ease-*` set — docs/frontend-os.md#aero; Neumorph: 180ms, `cubic-bezier(0.3, 0.7, 0.4, 1)`, plus a 90ms press — docs/frontend-os.md#neumorph) |
| Layout | `--desktop-max-width`, `--content-max-width` window width, `--reading-max-width`, `--desk-icons-width`, `--icon-size-sm`, `--icon-size`, `--icon-size-lg`, `--tap-target` (≥ 44px), `--focus-ring-width`, `--topbar-height` menu bar, `--titlebar-height` |

Removed with the card grid: card-min-width and thumb-height.

## Hooks for later layers (R4 context menu, W1 balloon hints — done; R5 cosmetic `fx/`; O1 OS layer)

Stable attributes; restyling must keep them.

| Hook | Where | Meaning |
|---|---|---|
| `li.row[data-item-id][data-pinned][data-state]` | feed/trash rows | item id (ULID), `"true"`/`"false"`, `"active"`/`"trashed"`; the row `<li>` is a flex container holding `a.row-link` and the "…" button |
| `button.row-more[data-row-more]` | feed/trash rows | opens the row's context menu (`menu.js`); also reachable via right-click/long-press on `a.row-link` or Menu key/Shift+F10 while it's focused |
| `[data-context-trigger="true"]` | `a.row-link` (feed/trash rows) | set by `menu.js`'s `attachContextTrigger`: this element already owns a touch long-press for its context menu, so `balloon.js` skips arming its own long-press timer there (hover/keyboard focus hints still work) |
| `[role="menu"][data-window="menu"]` | context menu | `menu.js`'s popup; `[role="menuitem"]` children, `aria-disabled` when unavailable (e.g. no download URL) |
| `[data-hint]`, `#balloon-help` | any actionable control | fixed hint text (never item data) shown by `balloon.js` in the shared `#balloon-help` balloon; the described control gets `aria-describedby="balloon-help"` while it's shown |
| `[data-window]` | windows | `feed` (root and folder level), `trash`, `info` (also `data-item-id`, `data-pinned`, `data-state`), `alert`, `dialog`, `menu` |
| `[data-titlebar]`, `[data-box="close"]` | title bars | title bar of each window; the close control (`a.titlebar-control.titlebar-close`, drawn by the OS — Platinum: a 14px box) only exists when it does something (a back link) — the trash and root Feed windows have none; inside a folder the Feed window has an "up" one |
| `[data-shellbar]`, `[data-slot]` | shell bar (was `data-menubar`, renamed by O1) | slots: `app` (icon + "Previews"), `nav` (empty; an OS may move the desk icons here), `background` / `os` (filled by the shared pickers, `[data-shell-trigger]`), `clock` (empty, aria-hidden; filled by an OS's fx) |
| `html[data-os]`, `body[data-background]` | page | active OS (set by `os-boot.js`; functional code never reads it) and the chosen background id of that OS |
| `[data-nav]`, `[data-count]`, `[data-count-value]`, `[data-trash-icon]` | desktop icons | nav links, count text, raw count, trash can `<use>` |
| `.row-folder[data-folder-id]` | folder rows at the root Feed (`feed.js`) | one per folder, above the item rows |
| `body[data-view]` | page | current route view: `feed`, `trash`, `item`, `folder`, `missing` |

## Security rules (enforced by tests)

- No `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`/`new Function`/`srcdoc`/`DOMParser` in dashboard JS; no storage, cookies, `postMessage`, dynamic `import()`, other origins (`tests/unit/test_static_ui.py`). The OS layer (`os-boot.js`, `os/**`) follows the same rules except for its two storage keys (C23 exception, docs/frontend-os.md). Trusted Types (`require-trusted-types-for 'script'; trusted-types 'none'`) therefore allows no policy at all on the dashboard; DOMPurify is not loaded there.
- Untrusted text (`title`, `description`, `relpath`) only via `untrusted()` / attribute values; overflow clipped in CSS (`line-clamp`, `overflow-wrap: anywhere`, `unicode-bidi: isolate`).
- Frames, images, media, links: URLs from the API only, through `httpsUrl()`, which accepts nothing but the preview origin from `/api/kinds` (C23).
- Frames: `sandbox="allow-scripts"` only.
- POSTs: exactly `Content-Type: application/json`, `X-PDash-CSRF: 1`, body `{}` (`api.js`).
- `menu.js` positions its popup with CSSOM (`root.style.left`/`root.style.top`, JS property assignment), never an HTML `style=` attribute — that's unaffected by the CSP's lack of `style-src 'unsafe-inline'` and doesn't touch `h()`'s ban on a `style` attribute (dom.js). `balloon.js` positions its balloon the same way.
- No headless-browser test yet (no browser in CI); the route/page security is covered by `tests/security/test_renderer_route.py`.
