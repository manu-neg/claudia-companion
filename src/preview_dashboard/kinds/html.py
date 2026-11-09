"""HTML content kind: pages and multi-file bundles, sandboxed on preview.

A bundle may include any asset types (css, js, images, fonts, ...), but its
entry point must be a root `index.html` -- never a nested or ambiguous one --
so the viewer always knows exactly what it is opening in the sandboxed
iframe (docs/security.md C5/C7).

Unlike every other kind, `html` owns the media type of *every* file in its
own bundle (`media_type()` below), via a closed, explicit web-asset map --
not the code/image/... kinds' own maps. `application.publish` (the only
caller that assigns `ItemFile.media_type`) calls the *item's* kind --
`html`, here -- once per bundle member, never `KindRegistry.media_type_for`
per file, so the type a `.css`/`.js`/`.png`/... asset gets depends on
whether it ships inside an `html` bundle or stands alone as its own item.

Why bundle assets may be typed as executable (`text/css`, `text/javascript`)
when the same extension is inert `text/plain` as a standalone `code` item
(docs/security.md C8, ADR 0009 amendment): all item bytes -- HTML included
-- are served only from the sandboxed preview origin (`sandbox allow-scripts;
connect-src 'none'`, no cookies -- docs/security.md C5), which already lets
the bundle's own `index.html` run inline `<script>`. `script-src` there is
`'unsafe-inline' 'self'`, so a same-origin `<script src="app.js">` referencing
another file in the same bundle grants no capability an inline script in
`index.html` didn't already have -- it is not a new execution surface, just
a different way to load the same trusted-as-the-publisher's-own bytes. A
standalone `code` item (no `index.html` alongside it) is never reachable
that way, so it stays inert `text/plain` (`kinds/code.py`).

The map is closed and explicit -- everything not listed falls to
`application/octet-stream`, including `.xml` (avoids handing the browser an
XML/XSLT scripting surface) and `.wasm` (the preview CSP has no
`script-src 'wasm-unsafe-eval'`/`'unsafe-eval'`, so a same-origin `.wasm`
response couldn't be instantiated anyway -- kept opaque rather than relying
on that).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from preview_dashboard.domain.errors import UnsupportedContentError
from preview_dashboard.kinds.base import PreviewMode, extension_of

_ENTRY_FILE = "index.html"

# Closed set of web-asset media types an html bundle member may be served
# as. Nothing outside this map is ever returned by `media_type()` below --
# additions here are a deliberate, reviewed decision (docs/security.md C8).
_BUNDLE_MEDIA_TYPES: Mapping[str, str] = {
    # markup / stylesheet / script -- the core of an HTML bundle.
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".json": "application/json",
    ".map": "application/json",  # source maps: JSON, never executed
    # images
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    # fonts
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    # media
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    # plain text / data
    ".txt": "text/plain",
    ".csv": "text/csv",
    # deliberately kept opaque despite being "web" extensions -- see header.
    ".xml": "application/octet-stream",
    ".wasm": "application/octet-stream",
}


class HtmlKind:
    """HTML pages/bundles, rendered in a sandboxed iframe from the preview origin."""

    name = "html"
    label = "HTML"
    renderer = "html"
    preview_mode = PreviewMode.SANDBOXED
    extensions = frozenset({".html", ".htm"})
    render_capped = False

    def media_type(self, relpath: str) -> str:
        """Return the Content-Type for a file belonging to this html item.

        Looks up the closed `_BUNDLE_MEDIA_TYPES` map only -- never any
        other kind's map, never sniffed. Anything not in the map (including
        every extension deliberately excluded, e.g. `.flac`, `.mov`) is
        `application/octet-stream`, matching the fail-closed default the
        rest of the registry uses for unknown extensions (docs/security.md
        C8).
        """
        return _BUNDLE_MEDIA_TYPES.get(extension_of(relpath), "application/octet-stream")

    def detect(self, relpaths: Sequence[str]) -> int:
        if not relpaths:
            return 0
        if len(relpaths) == 1:
            return 100 if extension_of(relpaths[0]) in self.extensions else 0
        return 100 if _ENTRY_FILE in relpaths else 0

    def entry_file(self, relpaths: Sequence[str]) -> str:
        """Return the file to open.

        Raises:
            UnsupportedContentError: a multi-file bundle has no root
                `index.html` -- callers should only reach this after
                `detect()` confirmed the kind, but the check is repeated
                here so this method is safe to call on its own.
        """
        if len(relpaths) == 1:
            return relpaths[0]
        if _ENTRY_FILE in relpaths:
            return _ENTRY_FILE
        raise UnsupportedContentError("an HTML bundle needs a root index.html")
