# ADR 0005: Separate origin for all item bytes

**TL;DR:** Every byte of published content (HTML, SVG, images, video, PDF, raw, downloads) is served only from a separate preview origin — its own ASGI app on local port 8788 behind `tailscale serve` 8443 — with a strict CSP (sandboxed for everything except PDF), so hostile content can never run as, or read from, the dashboard origin.

## Context

Claude can publish arbitrary content, including HTML and SVG, which the owner then views in-browser. Some of it could be adversarial (e.g. a prompt injection during Claude's research that makes it publish something malicious). If preview content shared an origin with the dashboard, a malicious publish could read the dashboard's DOM, forge trash/restore actions, or exfiltrate other items — defeating the CSRF and identity controls from the inside. Serving only *some* kinds from the preview origin leaves a gap every time a kind is misclassified, so the split is by *route*, not by kind.

## Decision

- **Two ASGI apps:** the dashboard app (local `viewer_port` 8787, serve 443) serves only UI assets and JSON; the preview app (local `preview_port` 8788, serve 8443) serves only item bytes and has no `/api` routes. Config enforces distinct ports and a `preview_origin` of exactly `https://<host>:<port>` that differs from the dashboard origin (`docs/security.md` C3, C5, C17).
- **Preview CSP** on every non-PDF response:
  `sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self' data:; connect-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors <dashboard origin>`.
  The sandbox gives the document an opaque origin; `connect-src 'none'` and `form-action 'none'` stop beacons and phishing form posts.
- **PDF:** also only from the preview origin, but **without** `sandbox` (Chrome refuses to render PDFs under a CSP sandbox), with `default-src 'none'; object-src 'none'`. Its execution surface is the browser's PDF viewer, on an origin that holds nothing.
- **SVG** is only ever referenced via `<img>` (never inlined), `image/svg+xml` only from the preview origin.
- Headers common to the preview app: `nosniff`, `Referrer-Policy: no-referrer`, `CORP: same-site`, `Cache-Control: private`, no cookies, no CORS (C19, C22).

## Consequences

- Hostile HTML/SVG is contained: different origin, opaque sandbox origin, no network egress, no forms, no cookies to steal (there are none anywhere).
- The dashboard's CSP stays strict (`default-src 'self'`) and only allows the preview origin for `img-src`, `media-src`, `frame-src`.
- Two origins mean two header sets and two `tailscale serve` entries to maintain; tests assert the exact CSP per kind (`tests/security/test_preview_headers.py`, unit 8).
- `script-src 'unsafe-inline'` inside the sandbox is deliberate: published HTML must be able to run its own scripts; the sandbox, not the script policy, is the containment.

## Amendment (unit 8a)

- The CSP is chosen **per response, from the file's media type** (`headers.csp_for`), and applied to every preview response including errors; the PDF exception requires both `application/pdf` and the item kind's DOCUMENT mode.
- `worker-src 'none'` was added to the sandbox CSP, and service-worker fetches are refused (security.md C5).
- Successful HTML-bundle sub-resources carry `CORP: cross-origin` instead of `same-site`, because their sandboxed document has an opaque origin (ADR 0012).
- The PDF CSP also carries `form-action 'none'; base-uri 'none'` (unit 8a review).
