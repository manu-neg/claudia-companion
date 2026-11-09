# ADR 0012: Fetch-metadata resource isolation, compatible when absent

**TL;DR:** Both viewer apps check `Sec-Fetch-Site/Dest/Mode` as defense in depth. If a browser sends them, they must match what the response is for (SVG only as an image, HTML only in an iframe, top-level documents only for PDFs and downloads); if **no** `Sec-Fetch-*` header is present at all, the request is allowed. HTML-bundle sub-resources get `CORP: cross-origin`, because their sandboxed document has an opaque origin.

## Context

Ambient tailnet authentication (security.md threats) means any page the owner visits can make the browser request dashboard or preview URLs. CSP sandboxing, CORP, `frame-ancestors`, CSRF and "no CORS" already contain that; fetch metadata adds a cheap, central check on *how* each resource is being loaded (the unit 3 review asked for it). Two facts shape the policy:

1. **Absent headers.** Chromium, Firefox and Safari ≥ 16.4 always send them over HTTPS, and an attacker page can't strip them. But older browsers, some native media stacks (range requests for `<video>` on iOS), and non-browser clients (`deploy/check.sh`) may send none.
2. **Opaque origins.** A sandboxed preview document (`sandbox allow-scripts`, no `allow-same-origin`) has an opaque origin. Its own sub-resource requests (`<img src="logo.png">`, `<script src="app.js">`) arrive as `Sec-Fetch-Site: cross-site`, and a `CORP: same-site` response is **blocked** for them by the browser.

## Decision

- **Missing ⇒ allowed; present ⇒ enforced (fail closed).** This is the standard "resource isolation policy". Partial, duplicated, non-ASCII or unknown values are rejected (403).
- **Dashboard app** (`DashboardFetchMetadataMiddleware`): `same-origin` and `none` pass; from any other site only a top-level `GET`/`HEAD` navigation (`dest=document`, `mode=navigate`).
- **Preview app** (`PreviewFetchMetadataMiddleware`, request + response phase, 2xx only): allowed destinations are `document, iframe, image, video, audio, track, script, style, empty` (everything else — `embed`, `object`, workers, `serviceworker`, `font`, … — is refused before any route runs). Per response (`preview_response_allowed`):
  - `document`: downloads (`Content-Disposition: attachment`) and DOCUMENT-mode PDFs, from the dashboard or user-initiated;
  - `iframe`: HTML entry documents, TEXT-mode files, DOCUMENT PDFs, from the dashboard only;
  - `image` (`image/*` incl. SVG) and `video`/`audio` (`video/*`, `audio/*`): from the dashboard, or cross-site only for bundle sub-resources;
  - `script`/`style`/`track`: bundle sub-resources only; `empty`: downloads only.
- Enforcement is central: routes only declare `PreviewHints(preview_mode, bundle_subresource)`; the middleware reads the response's own `Content-Type`/`Content-Disposition`. A denied response is replaced by a generic 403 and the route's body stream aborted.
- **CORP for bundles:** successful responses flagged `bundle_subresource=True` carry `Cross-Origin-Resource-Policy: cross-origin`; everything else `same-site`. This is **not** CORS: nothing becomes readable cross-origin, and CORS-mode loads (fonts, module scripts, `fetch`) stay unsupported in bundles (never "fixed" with CORS or `allow-same-origin`).

## Consequences

- An evil page can't top-level-navigate the owner to a hostile HTML preview, can't `<img>`/`<script>`-load dashboard JSON, and can't open an SVG as a document; modern browsers enforce all of it.
- A browser without fetch metadata gets only the header-based controls (CSP sandbox, CORP, frame-ancestors) — still safe, just without this extra layer.
- ~~A cross-site page that knows a bundle's item id could load that bundle's sub-resources as images/scripts.~~ Closed by the amendment below: sub-resources are bound to their own bundle via `Referer`. Top-level files, SVG items, media and PDFs keep `same-site`.
- Bundle web fonts and ES module scripts don't work (CORS-mode from an opaque origin); use `data:` fonts and classic scripts.

## Amendment (unit 8a review, implemented in unit 8b)

- **Bundle sub-resources are bound to their own bundle.** `CORP: cross-origin` alone would let any page that knows a bundle's id include its scripts/CSS (script-inclusion disclosure: globals, CSS side channels). Now a sub-resource gets `CORP: cross-origin`, and may be loaded `Sec-Fetch-Site: cross-site`, **only** when it carries exactly one `Referer` starting with `<preview origin>/i/<same item id>/` (`hints.bundle_referer_bound`); otherwise `CORP: same-site` and a cross-site request is 403. Bundle pages (2xx SANDBOXED responses) are sent with `Referrer-Policy: same-origin` so their own loads (and CSS `url()` loads) carry that Referer to the preview origin and nowhere else; sub-resources send `Vary: Referer` so a cached copy is never reused with the wrong CORP.
- An attacker can't forge `Referer` from a browser, and the referring bundle page is itself sandboxed hostile-or-not content of that same item — it gains nothing it didn't have.
- **Needs real-browser verification in unit 12** (Chromium, Firefox, Safari): that sandboxed opaque-origin documents send the Referer under `same-origin` policy. If a browser strips it, bundles break (sub-resources 403 / blocked) — they **fail closed**, never open.
- A response with two `Content-Type` or two `Content-Disposition` headers is always denied (403 in the fetch-metadata check, 500 in the header middleware).

## Amendment (revisions, ADR 0019)

- The binding prefix now includes the revision URL segment: `<preview origin>/i/<same item id>/<same revision segment>/`. A page of revision 1 can't pull revision 2's files cross-site (nor `latest` ↔ a number); `PreviewHints.revision` carries the segment and a missing one fails closed.
