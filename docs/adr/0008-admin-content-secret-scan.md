# ADR 0008: Content secret scan in the admin process

**TL;DR:** The admin process scans every published byte for well-known secret formats and rejects the publish on a match, because the MCP intake policy can't be enforcing while Claude runs as root.

## Context

MCP intake (ADR 0006) checks *paths*. A prompt-injected Claude running as root can read a secret itself and publish it as inline content, from a renamed copy, or by calling the admin API directly. The admin process is the one choke point every publish crosses, and it runs as a separate, unprivileged service user that Claude cannot modify without root-level tampering.

## Decision

- A pure scanner (`application/secret_scan.py`, no framework imports) runs in the admin publish path over **all** bytes of every file and inline field, streaming with overlap so a match can't hide across chunk boundaries.
- Rules (high-signal, low false-positive): PEM `-----BEGIN … PRIVATE KEY-----` blocks, PGP private-key blocks, AWS access key ids `AKIA[0-9A-Z]{16}`, GitHub tokens `gh[pousr]_…` and `github_pat_…`, Anthropic keys `sk-ant-…`, Slack tokens `xox[baprs]-…`, JSON `"private_key"` keys, and JWTs (three base64url segments starting `eyJ`).
- On match: reject the publish with an error naming the rule only — never echo or log the matched bytes.
- CI uses a separate tool for the repository itself: **gitleaks** (pinned binary, sha256-verified) over full history. Chosen over `detect-secrets` because it scans git history without a baseline file to maintain, and needs no Python dependency in the app's lockfile.

## Consequences

- Closes the cheapest exfiltration paths regardless of how bytes reached the admin API (C15).
- Best-effort: encoded, split, encrypted, or novel-format secrets pass. Documented in `docs/security.md` Known limitations.
- Scanning costs one linear pass per publish (bounded by `max_item_bytes`); acceptable.
- False positives (e.g. publishing docs that contain an example JWT) block the publish; the owner can redact the sample. No bypass flag, by design.

## Amendment (unit 4): port + adapter, labels, performance

- **Location:** a `ContentScanner` port (`ports/scanner.py`) with a streaming
  `ScanSession` (`feed`/`finish`), implemented by `adapters/secret_scan.py`
  (`RegexSecretScanner`, stdlib `re` only). The application depends on the
  port, so rules can be swapped or extended without touching `publish.py`.
  `PublishService` scans every file plus title, description and relpaths;
  `LifecycleService.update` scans edited text.
- **Rules added:** PuTTY keys, AWS `ASIA` (temporary) ids, OpenAI
  `sk-proj-`/`sk-svcacct-`/`sk-admin-`/legacy `sk-`, Google `AIza`, Stripe
  `sk_live_`/`rk_live_`; the generic PEM rule covers OPENSSH/RSA/EC/DSA/PGP.
- **Labels, not ids:** errors carry a neutral label ("GitHub token"), never
  a snake_case id like `github_pat` — an id can equal a token's own prefix,
  which would leak part of the secret's shape back to the publisher.
- **Performance:** one compiled regex per rule, each starting with a literal
  (fast prefix search): ~100-250 MB/s per publish on this host versus ~4 MB/s
  for a single alternation with leading lookbehinds. Linear on adversarial
  input (boundary lookbehind after the literal, possessive/bounded runs).

## Amendment (unit 4 follow-up): sanitized metadata, more rules, explicit limits

- **Sanitized metadata is scanned too.** Title/description are scanned raw
  *and* after the domain sanitizer (the values actually stored/shown). The
  sanitizer strips invisible chars (ZWSP, soft hyphen, U+2060, BOM, CGJ,
  U+180E, bidi controls) and NFC-normalizes (Kelvin sign → `K`), so a token
  hidden from a raw scan by one of those would otherwise be stored intact.
  `publish` reuses the placeholder item built for the manifest precheck;
  `LifecycleService.update` builds the updated item before scanning.
- **Rules added:** GitLab `glpat-`, Hugging Face `hf_`, npm `npm_`, PyPI
  `pypi-AgEI…`, Slack `xapp-` and `hooks.slack.com/services/…` webhooks,
  SendGrid `SG.<22>.<43>`, DigitalOcean `do[por]_v1_`, SSH2
  `---- BEGIN SSH2 ENCRYPTED …` headers, and `private_key` in YAML/TOML/
  single-quoted form (value must be quoted, a block scalar or 16+ base64
  chars, so `private_key = 1` / `${VAR}` templates pass). The PEM rule is
  loosened to `BEGIN[ A-Z0-9]{0,64}PRIVATE KEY` (dashes optional); its run is
  not possessive (its alphabet contains "PRIVATE KEY") but bounded to 64 and
  anchored on a boundary-checked literal, so it stays linear.
- **Window trim keeps lookbehind context:** 2 bytes before the overlap are
  kept and the next pass searches from after them, so a boundary char cut
  off by a trim can't turn a glued look-alike into a false positive.
- **Explicit non-goals (encodings):** UTF-16/32, base64/base32/hex, gzip and
  other compression or encryption, percent-encoding, HTML/XML entities,
  JSON `\uXXXX` escapes, tokens split inside file content, and JWT segments
  longer than 4096/8192 chars are not detected. Decoding would require
  parsing untrusted content server-side (rejected in the threat model) and
  has no natural bound. Listed in `docs/security.md` Known limitations.
