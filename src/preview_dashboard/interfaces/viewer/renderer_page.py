"""Builds the preview-origin text renderer page served by `GET /r/{id}/{relpath}`.

TEXT kinds (markdown, code, json, csv, text, diff, progress) are rendered inside the
sandboxed preview origin, never on the dashboard (orchestrator decision,
docs/frontend.md). The page embeds the capped text as escaped JSON in a
`<script type="application/json">` block and **inlines** the renderer's own
code and the vendored libraries it needs. Inlining (instead of `<script
src>`) is deliberate: the sandboxed page has an opaque origin, so its own
sub-resource loads would be cross-site requests that CORP `same-site` and
the fetch-metadata policy (C22, C31) correctly refuse. The sandbox CSP
already allows inline scripts/styles (C5), so nothing is loosened.

All asset bytes are read once at start-up from a fixed allowlist of paths
under the packaged `static/` directory (never a request value, I2, C20).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from preview_dashboard.interfaces.viewer.static_assets import (
    MAX_ASSET_BYTES,
    StaticAssetError,
    read_regular_file,
)

# Fixed allowlist: logical name -> path relative to static/. Nothing else is inlined.
_ASSET_PATHS: Mapping[str, str] = MappingProxyType(
    {
        # The default OS's tokens (its block also matches bare :root): /r/ pages have no data-os.
        "theme.css": "os/platinum/theme.css",
        "renderer.css": "preview-render/renderer.css",
        "renderer.js": "preview-render/renderer.js",
        "purify.js": "vendor/dompurify-3.4.16/purify.min.js",
        "marked.js": "vendor/marked-18.0.14/marked.umd.js",
        "hljs.js": "vendor/highlightjs-11.12.0/highlight.min.js",
        "hljs-light.css": "vendor/highlightjs-11.12.0/github.min.css",
        "hljs-dark.css": "vendor/highlightjs-11.12.0/github-dark.min.css",
        # `progress` pages are OS-neutral (owner rule): own tokens, no theme.css/renderer.css.
        "progress.css": "preview-render/progress.css",
        "progress.js": "preview-render/progress.js",
    }
)

# Which libraries each renderer id needs (renderer.js always comes last).
# JSON, CSV and plain text use DOM APIs only, so they ship no vendor code.
_SCRIPTS_BY_RENDERER: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "markdown": ("purify.js", "marked.js", "hljs.js"),
        "code": ("purify.js", "hljs.js"),
        "diff": ("purify.js", "hljs.js"),
        "json": (),
        "csv": (),
        "text": (),
        "progress": (),  # its own page: see _NEUTRAL_PAGES
    }
)
# Renderers with a self-contained page: (stylesheet, script) replace theme.css, renderer.css
# and renderer.js. No OS tokens reach them, so they look the same in every OS.
_NEUTRAL_PAGES: Mapping[str, tuple[str, str]] = MappingProxyType(
    {"progress": ("progress.css", "progress.js")}
)
_HIGHLIGHTING = frozenset({"markdown", "code", "diff"})
TEXT_RENDERERS = frozenset(_SCRIPTS_BY_RENDERER)

# Inside a raw-text element the HTML tokenizer only ends the element at
# `</script`/`</style`, and `<!--` followed later by `<script` + [space / >]
# switches a script into the "double escaped" state where `</script>` no
# longer closes it. Inlined code must contain neither end-tag nor opener.
_UNSAFE_SCRIPT = re.compile(rb"</script|<script[\s/>]", re.IGNORECASE)
_UNSAFE_STYLE = re.compile(rb"</style", re.IGNORECASE)


def embed_json(payload: object) -> str:
    """Serialize `payload` for a `<script type="application/json">` block.

    ASCII-only JSON (so U+2028/U+2029 and every non-ASCII char become
    `\\uXXXX`), with `<`, `>` and `&` escaped too: the result can never
    contain `</script`, `<!--` or a character that ends the block.
    """
    text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


class RendererPage:
    """Holds the inlined assets and builds renderer pages.

    Attributes:
        version: SHA-256 over every inlined asset, part of each page's ETag
            so a new renderer build invalidates cached pages.
    """

    def __init__(self, assets: Mapping[str, bytes]) -> None:
        missing = set(_ASSET_PATHS) - set(assets)
        if missing:
            raise StaticAssetError(f"renderer assets missing: {sorted(missing)}")
        for name, body in assets.items():
            pattern = _UNSAFE_STYLE if name.endswith(".css") else _UNSAFE_SCRIPT
            if pattern.search(body):
                raise StaticAssetError(f"renderer asset {name} cannot be inlined safely")
            try:
                body.decode("utf-8")
            except UnicodeDecodeError:
                raise StaticAssetError(f"renderer asset {name} is not UTF-8") from None
        self._assets = MappingProxyType(dict(assets))
        digest = hashlib.sha256()
        for name in sorted(self._assets):
            digest.update(name.encode("ascii") + b"\0" + self._assets[name] + b"\0")
        self.version = digest.hexdigest()

    @classmethod
    def load(cls, static_root: Path) -> RendererPage:
        """Read the allowlisted assets from `static_root` (start-up only).

        Raises:
            StaticAssetError: an asset is missing, a symlink, not a regular
                file, not UTF-8, or contains a sequence unsafe to inline.
        """
        assets: dict[str, bytes] = {}
        for name, rel in _ASSET_PATHS.items():
            try:
                assets[name] = read_regular_file(static_root / rel, MAX_ASSET_BYTES)
            except StaticAssetError as exc:
                raise StaticAssetError(f"renderer asset {rel}: {exc}") from None
        return cls(assets)

    def _text(self, name: str) -> str:
        return self._assets[name].decode("utf-8")

    def render(self, *, renderer: str, text: str, meta: Mapping[str, object]) -> bytes:
        """Build the HTML page for one capped text file.

        Args:
            renderer: a `TEXT_RENDERERS` id (unknown ids fall back to `text`).
            text: the (already capped, decoded) file text — untrusted.
            meta: extra JSON-safe fields for the renderer (filename, flags).
        """
        if renderer not in _SCRIPTS_BY_RENDERER:
            renderer = "text"
        data = embed_json({**meta, "renderer": renderer, "text": text})
        neutral = _NEUTRAL_PAGES.get(renderer)
        if neutral:
            styles = [self._text(neutral[0])]
            scripts = [*_SCRIPTS_BY_RENDERER[renderer], neutral[1]]
        else:
            styles = [self._text("theme.css"), self._text("renderer.css")]
            scripts = [*_SCRIPTS_BY_RENDERER[renderer], "renderer.js"]
        if renderer in _HIGHLIGHTING:
            # The vendored themes are kept byte-for-byte (checksums); the
            # light/dark switch is added around them here.
            styles.append(
                "@media (prefers-color-scheme: light) {"
                + self._text("hljs-light.css")
                + "}\n@media (prefers-color-scheme: dark) {"
                + self._text("hljs-dark.css")
                + "}"
            )
        parts = [
            '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n',
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
            '<meta name="color-scheme" content="light dark">\n',
            '<meta name="referrer" content="no-referrer">\n<title>Preview</title>\n',
            *(f"<style>\n{css}\n</style>\n" for css in styles),
            "</head>\n<body>\n",
            f'<script type="application/json" id="pdash-data">{data}</script>\n',
            '<main id="pdash-root" class="r-root"></main>\n',
            *(f"<script>\n{self._text(name)}\n</script>\n" for name in scripts),
            "</body>\n</html>\n",
        ]
        return "".join(parts).encode("utf-8")
