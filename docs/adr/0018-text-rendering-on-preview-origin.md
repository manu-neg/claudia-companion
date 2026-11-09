# ADR 0018: Text kinds render on the preview origin, assets inlined (unit 9a)

**TL;DR:** Markdown, code, JSON, CSV, diff and plain text are formatted by an
HTML page served from the **preview** origin (`GET /r/{id}/{relpath}`), framed
by the dashboard in `<iframe sandbox="allow-scripts">`. The page **inlines**
its renderer and vendored libraries instead of loading them from a
`/_r/static/…` route as first planned.

## Context

- Rendering untrusted text as HTML on the dashboard would need DOMPurify and a
  Trusted Types policy there; one sanitizer bug would then run on the origin
  that holds the trash/restore API.
- The orchestrator decision placed rendering on the preview origin with
  vendored JS/CSS served from `/_r/static/…` (`script-src 'self'`).
- A page served with CSP `sandbox allow-scripts` (C5) has an **opaque
  origin**. Its sub-resource requests are cross-site (`Sec-Fetch-Site:
  cross-site`), which CORP `same-site` (C22) and the preview fetch-metadata
  policy (C31) correctly refuse. Opening an exception for them would widen
  both controls for every preview response.

## Decision

- `/r/` returns one self-contained page: the capped text as ASCII JSON in
  `<script type="application/json">` (`<`, `>`, `&`, U+2028/2029 escaped),
  then `theme.css`, `renderer.css`, the renderer and only the libraries that
  renderer needs, as inline `<style>`/`<script>`.
- The sandbox CSP already allows `'unsafe-inline'` (bundle HTML needs it), so
  nothing is loosened. Assets are read once at start-up from a fixed
  allowlist with `static_assets.read_regular_file` (`O_NOFOLLOW` + `fstat`);
  an asset containing `</script`, `<script`+space//`>` or `</style` makes the
  preview app refuse to start.
- The page ETag includes a hash of every inlined asset; 304s carry the same
  headers as the 200.

## Consequences

- The dashboard renders no HTML from data; Trusted Types there never needs a
  policy and DOMPurify is not loaded on the dashboard.
- No `/_r/` route exists; CORP and fetch metadata stay unchanged.
- Each `/r/` page is larger (markdown ≈ 200 KB of inlined libraries), paid
  once per file per ETag; acceptable for a single-owner dashboard.
- A new text format is added in `preview-render/renderer.js` and
  `renderer_page.py` (`_SCRIPTS_BY_RENDERER`), not in the dashboard.
