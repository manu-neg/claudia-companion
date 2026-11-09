# ADR 0011: Trusted Types on the dashboard, only the `dompurify` policy

**TL;DR:** The dashboard CSP ends with `require-trusted-types-for 'script'; trusted-types dompurify`. Every DOM XSS sink (`innerHTML`, `insertAdjacentHTML`, `document.write`, script URLs) refuses plain strings; the only way to produce a `TrustedHTML` is DOMPurify's own policy. No `default` policy.

## Context

The dashboard renders untrusted text (titles, descriptions, Markdown, highlighted code) that Claude — possibly prompt-injected — published. C23 already says "no `innerHTML` except DOMPurify output", but that is a code-review rule; a single missed call is a DOM XSS on the origin that can trash/restore items (C4 is bypassed from inside the origin). Trusted Types turns the rule into a browser-enforced one (Chromium; other engines ignore the directives and fall back to the code rule).

DOMPurify (≥ 2.x, vendored 3.x in unit 9) supports Trusted Types natively: when `window.trustedTypes` exists it creates a policy named **`dompurify`** at load time, and `DOMPurify.sanitize(dirty, {RETURN_TRUSTED_TYPE: true})` returns a `TrustedHTML` from it.

## Decision

Dashboard CSP (C6, `interfaces/viewer/headers.py::dashboard_csp`) includes:

- `require-trusted-types-for 'script'` — sinks only accept Trusted Types objects.
- `trusted-types dompurify` — the only policy name that may be created.
- **No `default` policy** (a default policy is called implicitly for every string assigned to a sink, which would quietly turn the backstop back off) and **no `'allow-duplicates'`**.
- Also `worker-src 'none'` and `form-action 'none'` (the dashboard has no workers or forms; stricter than the earlier `'self'` wording in C6).

Frontend obligations (unit 9):

- Use the default DOMPurify instance; don't create a second one (a second `createPolicy('dompurify')` throws without `'allow-duplicates'`).
- Assign HTML only as `el.innerHTML = DOMPurify.sanitize(html, {...config, RETURN_TRUSTED_TYPE: true})`.
- `marked` output and `hljs.highlight(...).value` are strings: pass them through DOMPurify before insertion. Never use `hljs.highlightElement`/`highlightAll` (they assign `innerHTML` directly and would throw).
- Everything else uses `textContent` / DOM APIs, which Trusted Types does not restrict.

## Consequences

- A forgotten raw `innerHTML` throws a `TypeError` in Chromium instead of executing attacker markup; a unit-9 static test still guards non-Chromium browsers (C23).
- Some library conveniences (highlight.js auto-highlighting) are unusable; the explicit sanitize-then-assign path is required.
- If a future library needs its own policy, adding its name to `trusted-types` is a deliberate, reviewed CSP change (`tests/security/test_security_headers.py` pins the exact CSP).

## Amendment (9a review, revisions unit): `trusted-types 'none'`

- Since ADR 0018 the dashboard renders no HTML from data and never loads DOMPurify (text is formatted on the preview origin), so no policy is needed at all. The CSP now ends with `require-trusted-types-for 'script'; trusted-types 'none'`: every sink refuses strings and **no** policy can be created. `static/vendor/` is no longer served by the dashboard. The frontend obligations above apply only to the `/r/` renderer page (preview origin), which does not use Trusted Types.
