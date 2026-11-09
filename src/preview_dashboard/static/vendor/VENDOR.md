# Vendored frontend libraries

**TL;DR:** Three pinned libraries, copied byte-for-byte from their npm registry tarballs (tarball `sha512` verified against the registry's `dist.integrity`), used only by the preview-origin text renderer (`/r/`, inlined into the sandboxed page). No CDN. `CHECKSUMS` (sha256) is verified by `tests/security/test_vendor_checksums.py` (docs/security.md C13). Vendored files are exempt from the file-header rule (changing them would break the checksums).

| Library | Version | License | Source tarball (npm registry) | Tarball integrity (sha512) |
|---|---|---|---|---|
| DOMPurify | 3.4.16 | MPL-2.0 OR Apache-2.0 | https://registry.npmjs.org/dompurify/-/dompurify-3.4.16.tgz | `sha512-sqo+pNp3qRhCIpbgRi1y8Tgk27Bo2Ry7w0dC1NBeNTdZChWjz9Xb/KOoZbRP/R6pQZ80Qw8YhXw13hWWBbMRnQ==` |
| marked | 18.0.14 | MIT | https://registry.npmjs.org/marked/-/marked-18.0.14.tgz | `sha512-mBHK6FBHuBAlhgRe88w9F0O1AbwwXJUcQibUbC/QcdTbVGAD7aWza+xt3N6oT/jCZx3/OMeS+8rnuiHZcQ9s7A==` |
| highlight.js (common build, `@highlightjs/cdn-assets`) | 11.12.0 | BSD-3-Clause | https://registry.npmjs.org/@highlightjs/cdn-assets/-/cdn-assets-11.12.0.tgz | `sha512-KvOKXODaiFmId9xaq3xc5xCL66wVLUuOngDbO9B/kewbFTqdGbn2nJxNhN3H5R1cgDTVj6R8vH0zgiNDEGjpDw==` |

## Files

| File | Taken from (in tarball) | sha256 |
|---|---|---|
| `dompurify-3.4.16/purify.min.js` | `package/dist/purify.min.js` | `2c90a9b46d6463f26038a29b686e82bc91de01fdac9d5229e7cfe3b360134ea2` |
| `dompurify-3.4.16/LICENSE` | `package/LICENSE` | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `dompurify-3.4.16/LICENSE-MPL` | `package/LICENSE-MPL` | `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85` |
| `marked-18.0.14/marked.umd.js` | `package/lib/marked.umd.js` | `21568877a938d2c4e7d74e27f18e60da96bb73a68809610ca39216e1efebae62` |
| `marked-18.0.14/LICENSE` | `package/LICENSE` | `8e3a3f82f59a60958f56ca08f445647c32a4733dc7ca6c2c46f6eb898471ab9c` |
| `highlightjs-11.12.0/highlight.min.js` | `package/highlight.min.js` | `8ab71eb09c51f501e5e25157d9cff100e46cc29bcbfc744d0b746d451fca7f53` |
| `highlightjs-11.12.0/github.min.css` | `package/styles/github.min.css` | `3a9a5def8b9c311e5ae43abde85c63133185eed4f0d9f67fea4b00a8308cf066` |
| `highlightjs-11.12.0/github-dark.min.css` | `package/styles/github-dark.min.css` | `9f208d022102b1d0c7aebfecd8e42ca7997d5de636649d2b31ea63093d809019` |
| `highlightjs-11.12.0/LICENSE` | `package/LICENSE` | `6c081431591d9df696c82dc598fe1423765b8a299b200ed00b281afd0f64c490` |

## Updating a library

1. `curl -sfO <tarball URL>` for the new pinned version; compare `base64(sha512(tarball))` with `dist.integrity` from `https://registry.npmjs.org/<name>/<version>`.
2. Extract only the files above into a new `<name>-<version>/` directory; delete the old one.
3. Update `renderer_page.py` (`_ASSET_PATHS`), `CHECKSUMS` (`sha256sum */* > CHECKSUMS` from this directory) and this file.
4. Run `uv run pytest tests/security/test_vendor_checksums.py tests/security/test_renderer_route.py` (the renderer refuses to start if a file contains `</script`, `<script` + space/`/`/`>` or `</style`, which would break inlining).
