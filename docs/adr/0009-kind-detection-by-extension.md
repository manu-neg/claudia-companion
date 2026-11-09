# ADR 0009: Content-kind detection by extension only, all-or-nothing confidence

**TL;DR:** The kind registry decides a file's kind (and Content-Type) purely from its extension, never by sniffing bytes. An extension-only kind claims a set of files only if *every* file matches; a mixed-type bundle falls through to the opaque `file` fallback rather than being guessed at.

## Context

`kinds/` is the Registry + Strategy pattern (docs/architecture.md) that
decides two things per published item: which kind it is (for the UI: which
renderer, which preview mode) and what `Content-Type` each of its files
gets. Both decisions are security-relevant: docs/security.md invariant I4
forbids server-side parsing of published content (a classic RCE surface —
image/video/PDF parsers), and C8 requires `Content-Type` to come from a
single, non-client-controlled source with `nosniff` always set. An item can
be a single file or a multi-file bundle (an HTML page plus its assets), and
a publisher may optionally pass an explicit kind hint.

## Decision

- **Extension only, never content sniffing.** `KindRegistry.media_type_for()`
  and every kind's `detect()`/`media_type()` look only at the final
  `/`-segment's extension (`kinds/base.py`'s `extension_of()`), case-folded.
  No kind opens or parses file bytes. This keeps I4 true by construction —
  there's no code path that could be tempted to add "just peek at the
  magic bytes" later.
- **All-or-nothing confidence for extension-only kinds.** A kind like
  `image` or `code` (`SimpleExtensionKind`) returns confidence 100 only if
  *every* file in the item matches its extension set, else 0. A mixed
  bundle (one image, one text file) is therefore claimed by no specific
  kind and falls through to `file` (DOWNLOAD, `application/octet-stream`),
  registered last with a fixed confidence of 1 so it's always the last
  resort. The alternative — partial/proportional confidence, e.g. "60% of
  files are images" — would let an attacker-controlled file count silently
  tip a bundle into a kind with a stronger preview mode (SANDBOXED/MEDIA)
  that renders content the publisher didn't ask for.
- **`html` is the one kind with bundle-aware detection**, because it's the
  one kind that legitimately mixes file types (a page plus its assets): a
  multi-file item is `html` only if it has a root `index.html`; nested or
  missing entry points are not `html`, matching the entry-file rule in
  docs/security.md C5/C7.
- **An explicit hint must be compatible, not just known.** `detect(hint=...)`
  still runs `hint`'s own `detect()` and rejects the publish if it's 0,
  rather than trusting the caller's label. A publisher can request a kind,
  not assign one.
- ~~**Code files are always `text/plain`**, including inside an `html`
  bundle.~~ *Superseded by the amendment below:* a standalone `code` item is
  still always `text/plain`, but members of an `html` bundle are typed by
  `html`'s own closed web-asset map.

## Consequences

- A file named to look like another kind (`payload.html.png`) is typed by
  its real, final extension only — `.png`, an image — never by an earlier
  segment. Renaming can't smuggle a stronger preview mode.
- "Gallery" previews (multiple files that all share one non-`html` kind,
  e.g. several images with no `index.html`) are correctly *detected* as
  that kind today, but the frontend renderer for that kind doesn't yet
  show more than one file — `entry_file()` picks a deterministic first
  file as a placeholder. Building an actual gallery view is future work,
  tracked in docs/architecture.md's "Content kinds" section, not a bug.
- Because `code` files are always inert, an `html` bundle that references
  an external `<script src="app.js">` will not have that script execute
  under `nosniff` — Chrome enforces the declared MIME type for classic
  script loads. HTML bundles that need external, executing JS assets are
  not supported as of unit 3; the interfaces layer (unit 8) or a future
  kind revision would need to special-case bundle-internal script assets
  if that becomes a requirement. Inline `<script>` in the HTML file itself
  still runs (allowed by the SANDBOXED preview CSP's `script-src`).
- Adding a kind never requires touching detection logic elsewhere: a new
  `SimpleExtensionKind` subclass is automatically all-or-nothing, and
  `KindRegistry.detect()`/`media_type_for()` are closed for modification.

## Amendment (unit 3 follow-up): `html` owns media types for its own bundle members

**Context.** The original decision above ("code files are always
`text/plain`... including when such a file is an asset inside an `html`
bundle") broke the core multi-file-HTML-prototype use case: with
`X-Content-Type-Options: nosniff` (docs/security.md C8) always set, a
browser that receives `text/plain` for `style.css` or `app.js` refuses to
apply the stylesheet or run the script at all, so a published HTML bundle
that references external assets renders unstyled and non-interactive.
`application/octet-stream` for every other bundle asset type (images,
fonts, JSON, media) made this worse: `<img>`, `@font-face` and `fetch()`
all fail closed under `nosniff` too.

**Decision.** `HtmlKind` (`kinds/html.py`) now owns the `Content-Type` of
every file in its own bundle via a closed, explicit web-asset map (markup,
stylesheet, script, JSON, images, fonts, common media, plain text/CSV);
anything not in that map -- including `.xml` and `.wasm`, kept opaque on
purpose -- stays `application/octet-stream`. `code`, `image`, and every
other kind's own map is unaffected and still applies when that extension is
a *standalone* item's own kind (e.g. a lone `.css` file published by
itself is still `code`, still `text/plain` -- inert, since nothing will
ever load it as a stylesheet). The distinction is which item's kind is
asked: `application.publish` (the only writer of `ItemFile.media_type`)
looks up the *item's own* kind once and calls `kind.media_type(relpath)`
for every file the item contains, rather than asking the global
`KindRegistry.media_type_for(relpath)` per file -- so the same extension is
typed differently depending on whether it ships inside an `html` bundle or
stands alone.

This is safe because of where item bytes are served from
(docs/security.md C5): every item's bytes, executable-typed or not, come
only from the sandboxed preview origin -- opaque origin, `sandbox
allow-scripts`, `connect-src 'none'`, no cookies -- which *already* lets the
bundle's `index.html` run inline `<script>` (`script-src 'unsafe-inline'
'self'`). `'self'` in that same directive is what makes a same-bundle
`<script src="app.js">` load at all; typing that response as
`text/javascript` instead of `text/plain` grants no new capability over
the inline script the sandbox already allows -- it only makes the
already-permitted script loadable the normal way. Executable types
(`text/html`, `text/javascript`) are therefore only ever emitted by the
`html` kind, and only ever served from that one sandboxed origin.

**Consequences.**
- A multi-file HTML prototype with external `<link rel=stylesheet>`,
  `<script src=...>`, images and fonts now renders and runs as the
  publisher intended; the "external bundle scripts silently don't execute"
  trade-off called out in the Consequences above no longer applies to
  bundle members typed by `html`'s map (it still applies verbatim to a
  standalone `code`-kind file, which stays inert).
- `tests/security/test_kinds.py`'s invariant changes from "only `html`
  emits `text/html`; `code` never emits a scriptable type" to "executable
  types (`text/html`, `text/javascript`) are only ever emitted by the
  `html` kind" -- `code` is unchanged (still always `text/plain`) but is no
  longer the *only* thing proven inert; the html-bundle map is now also
  proven closed (nothing outside the documented list, and `.xml`/`.wasm`/
  unknown extensions still resolve to `application/octet-stream`).
- **Unsupported inside bundles:** ES module scripts (`<script type=module>`)
  and web fonts. The preview origin is opaque (`sandbox allow-scripts`
  without `allow-same-origin`), so module scripts and `@font-face` loads are
  CORS-mode requests from a `null` origin and fail. This is accepted: the
  fix would be CORS headers or `allow-same-origin`, both of which are
  forbidden (docs/security.md C5, C19). Classic scripts, stylesheets and
  images work.
- The closed map is a maintained allowlist, not derived from the other
  kinds' maps, so it can drift from them (e.g. `video`'s `.mov` is
  intentionally *not* in the bundle map -- QuickTime video as a bundle
  asset stays opaque). Any future addition to the bundle map is a
  reviewed, explicit decision, matching this ADR's extension-only,
  never-sniffed, closed-map philosophy.
