"""Static checks of the dashboard UI files (docs/frontend.md; docs/security.md C6, C23).

Grep-level guards that hold even in browsers without Trusted Types: no
inline scripts/styles/handlers in HTML, no HTML sinks or string-eval in
dashboard JS, untrusted item text only through `untrusted()` (textContent
in `<bdi>`), sandboxed frames only, theme tokens as the single source of
visual values, every served file with the right Content-Type, every
registry renderer id wired up. Syntax is checked with Node when available.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404 - runs only `node --check` on our own files in tests
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import (
    STATIC_MEDIA_TYPES,
    StaticAssets,
    default_static_dir,
)
from preview_dashboard.kinds import default_registry
from tests.viewer_support import make_env, owner_headers

STATIC = default_static_dir()
DOCS = Path(__file__).resolve().parents[2] / "docs"
# Functional dashboard code. vendor/, the preview-origin renderer and the OS
# layer (os-boot.js + os/**, incl. each OS's fx/) are checked separately: the
# OS layer has its own, slightly different rules below, since it's allowed the
# one thing nothing else here is - see docs/frontend-os.md and
# tests/unit/test_os_contract.py / test_fx_isolation.py.
DASHBOARD_JS = sorted(
    p
    for p in STATIC.rglob("*.js")
    if p.parts[len(STATIC.parts)] not in {"vendor", "preview-render", "os", "os-boot.js"}
)
OS_BOOT = STATIC / "os-boot.js"
FX_JS = sorted([*(STATIC / "os").rglob("*.js"), OS_BOOT])
DEFAULT_THEME = STATIC / "os" / "platinum" / "theme.css"
OWN_FILES = sorted(
    p
    for p in STATIC.rglob("*")
    if p.is_file()
    and p.suffix in {".js", ".css", ".html"}
    and p.parts[len(STATIC.parts)] != "vendor"
)
RENDERER_JS = STATIC / "preview-render" / "renderer.js"

FORBIDDEN_JS = [
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"\binsertAdjacentHTML\b",
    r"\bdocument\.write",
    r"\beval\s*\(",
    r"\bnew\s+Function\b",
    r"\bFunction\s*\(",
    r"\bsrcdoc\b",
    r"\bDOMParser\b",
    r"\bcreateContextualFragment\b",
    r"set(?:Timeout|Interval)\s*\(\s*['\"`]",
    r"javascript:",
    r"allow-same-origin",
    r"\blocalStorage\b",
    r"\bsessionStorage\b",
    r"\bdocument\.cookie\b",
    r"\bpostMessage\b",
    r"\bimport\s*\(",
]


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _code(path: Path) -> str:
    """JS source without comments and without dom.js's own attribute denylist line."""
    source = re.sub(r"/\*.*?\*/", "", _text(path), flags=re.S)
    lines = [
        line
        for line in source.splitlines()
        if not line.lstrip().startswith("//") and "const FORBIDDEN_ATTRIBUTE" not in line
    ]
    return "\n".join(lines)


def test_dashboard_js_files_exist() -> None:
    names = {p.relative_to(STATIC).as_posix() for p in DASHBOARD_JS}
    assert {"app.js", "api.js", "feed.js", "item.js", "renderers/index.js"} <= names


@pytest.mark.parametrize("path", DASHBOARD_JS, ids=lambda p: p.name)
def test_no_html_sinks_or_eval_in_dashboard_js(path: Path) -> None:
    source = _code(path)
    for pattern in FORBIDDEN_JS:
        assert not re.search(pattern, source), f"{path.name}: {pattern}"


@pytest.mark.parametrize("path", DASHBOARD_JS, ids=lambda p: p.name)
def test_dashboard_js_contacts_no_other_origin(path: Path) -> None:
    source = _text(path)
    assert not re.search(r"https?://", source), path.name
    assert "fetch(" not in source or path.name == "api.js", path.name


# OS-layer rules (os-boot.js, os/**): the same hygiene as the rest of the
# dashboard, minus the one thing it's allowed that nothing else is -
# localStorage, and only for the documented keys (C23 exception;
# tests/unit/test_os_contract.py checks the keys/allowlists and that only
# os/storage.js and os-boot.js touch it). Everything else FORBIDDEN_JS bans
# stays banned: no HTML sinks, no eval, no cookies/postMessage, no dynamic
# import, no sessionStorage either.
FX_FORBIDDEN_JS = [pattern for pattern in FORBIDDEN_JS if pattern != r"\blocalStorage\b"]


def _rel(path: Path) -> str:
    return path.relative_to(STATIC).as_posix()


@pytest.mark.parametrize("path", FX_JS, ids=_rel)
def test_no_html_sinks_or_eval_in_os_layer_js(path: Path) -> None:
    source = _code(path)
    for pattern in FX_FORBIDDEN_JS:
        assert not re.search(pattern, source), f"{path.name}: {pattern}"


@pytest.mark.parametrize("path", FX_JS, ids=_rel)
def test_os_layer_js_contacts_no_other_origin_or_network(path: Path) -> None:
    """Unlike api.js, the OS layer's fetch ban has no exception: it never talks to the network."""
    source = _text(path)
    assert not re.search(r"https?://", source), path.name
    assert "fetch(" not in source, path.name
    # Every network API, in every OS (os/**, incl. aero) and os-boot.js.
    for api in ("XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon"):
        assert api not in source, f"{path.name}: {api}"


def test_untrusted_item_text_only_via_untrusted_helper() -> None:
    allowed = re.compile(
        r"untrusted\((?:item|file)\.(?:title|description|relpath)\)"
        r"|item\.description \?|if \(item\.description\)"
    )
    for path in DASHBOARD_JS:
        for line in _text(path).splitlines():
            for match in re.finditer(r"item\.(?:title|description)\b", line):
                window = line[max(0, match.start() - 10) : match.end() + 12]
                assert allowed.search(window), f"{path.name}: {line.strip()}"


def test_untrusted_helper_uses_bdi_and_text_content() -> None:
    dom = _text(STATIC / "dom.js")
    assert re.search(r'return h\("bdi", \{[^}]*text: value', dom)
    assert "createTextNode" in dom
    assert "FORBIDDEN_ATTRIBUTE" in dom and "srcdoc" in dom and "style" in dom


def test_item_urls_are_pinned_to_the_preview_origin() -> None:
    """dom.js `httpsUrl` accepts only the preview origin from /api/kinds, failing closed."""
    dom = _code(STATIC / "dom.js")
    assert "let previewOrigin = null;" in dom
    assert "previewOrigin === null) return null;" in dom
    assert "parsed.origin === previewOrigin" in dom
    assert "setPreviewOrigin(data.preview_origin)" in _text(STATIC / "app.js")
    # Every item URL in the UI goes through httpsUrl (never used raw as src/href).
    for path in DASHBOARD_JS:
        for match in re.finditer(r"(?:src|href):\s*([^,}\n]+)", _code(path)):
            value = match.group(1).strip()
            assert "_url" not in value or value.startswith("httpsUrl("), (path.name, value)


def test_frames_are_sandboxed_allow_scripts_only() -> None:
    frames = [p for p in DASHBOARD_JS if '"iframe"' in _text(p)]
    assert [p.name for p in frames] == ["frame.js"]
    assert 'sandbox: "allow-scripts",' in _text(frames[0])


@pytest.mark.parametrize("path", [p for p in OWN_FILES if p.suffix == ".html"], ids=str)
def test_html_has_no_inline_script_style_or_handlers(path: Path) -> None:
    html = _text(path)
    for script in re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.I | re.S):
        attrs, body = script.group(1), script.group(2)
        assert 'src="/static/' in attrs and not body.strip(), script.group(0)
    assert not re.search(r"<style\b", html, re.I)
    assert not re.search(r"\sstyle\s*=", html, re.I)
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)
    assert not re.search(r"javascript:", html, re.I)
    assert not re.search(r"https?://", html)


def test_preview_renderer_inserts_html_only_from_dompurify() -> None:
    source = _text(RENDERER_JS)
    sinks = re.findall(r"\S*\.innerHTML\b.*", source)
    assert sinks == ["target.innerHTML = DOMPurify.sanitize(html, config);"]
    for pattern in (r"\bouterHTML\b", r"insertAdjacentHTML", r"document\.write", r"\beval\s*\(",
                    r"new\s+Function", r"highlightAll", r"highlightElement", r"fetch\(",
                    r"XMLHttpRequest", r"postMessage"):  # fmt: skip
        assert not re.search(pattern, source), pattern
    assert 'FORBID_TAGS: ["style", "form", "svg", "math"' in source
    assert "USE_PROFILES: { html: true }" in source
    assert "ALLOWED_URI_REGEXP: /^(?![\\/\\\\]{2})(?:(?:https|mailto):" in source
    assert 'rel", "noopener noreferrer"' in source and 'target", "_blank"' in source


def test_preview_renderer_caps_markdown_before_parsing() -> None:
    source = _text(RENDERER_JS)
    assert "var MAX_MARKDOWN_CHARS = 512 * 1024;" in source
    body = source.split("function renderMarkdown(root, data) {", 1)[1]
    guard = body.index("data.text.length > MAX_MARKDOWN_CHARS")
    assert guard < body.index("marked.parse(") and guard < body.index("DOMPurify.addHook")
    assert "plain(root, data.text, true);" in body[: body.index("marked.parse(")]


_URI_CASES = {
    "https://a.example/x": True,
    "mailto:x@y.example": True,
    "/rel": True,
    "rel/x.html": True,
    "#frag": True,
    "../up.html": True,
    "//evil.example/x": False,
    "\\\\evil.example": False,
    "/\\evil.example": False,
    "\\/evil.example": False,
    "javascript:alert(1)": False,
    "data:text/html,x": False,
    "http://a.example": False,
}


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_preview_renderer_uri_allowlist_refuses_protocol_relative_urls() -> None:
    source = _text(RENDERER_JS)
    match = re.search(r"ALLOWED_URI_REGEXP: (/.+/i),", source)
    assert match is not None
    node = shutil.which("node")
    assert node is not None
    script = (
        f"const re = {match.group(1)};"
        f"const cases = {json.dumps(_URI_CASES)};"
        "for (const [u, ok] of Object.entries(cases)) if (re.test(u) !== ok) "
        "{ console.error(u); process.exit(1); }"
    )
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own script
        [node, "-e", script], capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stderr


def _tokens(css: str) -> set[str]:
    return set(re.findall(r"var\((--[a-z0-9-]+)\)", css))


def _defined(css: str) -> set[str]:
    return set(re.findall(r"^\s*(--[a-z0-9-]+)\s*:", css, re.M))


def test_layout_css_uses_theme_tokens_only() -> None:
    """OS-neutral CSS uses contract tokens only (per-OS contracts: test_os_contract.py)."""
    theme = _defined(_text(DEFAULT_THEME))
    for name in ("app.css", "os/shell.css", "preview-render/renderer.css"):
        css = _text(STATIC / name)
        assert _tokens(css) <= theme, f"{name}: undefined {_tokens(css) - theme}"
        assert not _defined(css), f"{name} defines its own tokens"
        # No literal colors or font families: those belong in an OS's theme.css.
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", css), name
        assert not re.search(r"font-family:(?!\s*var\()", css), name


FONT_URL = re.compile(r'url\("/static/(fonts/[a-z0-9-]+\.woff2)"\)')


def test_css_loads_nothing_remote() -> None:
    """No @import or url() anywhere, except fonts.css naming vendored /static/fonts/ files."""
    for path in (p for p in OWN_FILES if p.suffix == ".css"):
        css = _text(path)
        assert "@import" not in css, path.name
        if path.name == "fonts.css" and path.parent == STATIC:
            css = FONT_URL.sub("", css)
        assert "url(" not in css, path.name


def test_vendored_fonts_exist_with_their_licences() -> None:
    """fonts.css names only shipped woff2 files; each family ships its OFL text (C6 font-src)."""
    names = FONT_URL.findall(_text(STATIC / "fonts.css"))
    assert names
    for name in names:
        assert (STATIC / name).is_file(), name
    served = StaticAssets.load(STATIC).names()
    assert set(names) <= served
    for family in ("pixelify-sans", "public-sans"):
        licence = STATIC / "fonts" / f"OFL-{family}.txt"
        assert "SIL Open Font License, Version 1.1" in _text(licence)
        assert licence.relative_to(STATIC).as_posix() not in served
    # The default OS's theme.css is inlined into sandboxed /r/ pages: no dashboard assets.
    assert "@font-face" not in _text(DEFAULT_THEME)
    assert '<link rel="stylesheet" href="/static/fonts.css">' in _text(STATIC / "index.html")


def test_icon_sprite_matches_the_icon_allowlist() -> None:
    """Every icon id chrome.js may reference exists in the index.html sprite."""
    ids = set(re.findall(r'<symbol id="(i-[a-z-]+)"', _text(STATIC / "index.html")))
    block = _text(STATIC / "chrome.js").split("const ICONS = new Set([", 1)[1].split("]);")[0]
    allowed = set(re.findall(r'"(i-[a-z-]+)"', block))
    assert allowed == ids


@pytest.mark.parametrize("path", OWN_FILES, ids=lambda p: p.relative_to(STATIC).as_posix())
def test_every_own_static_file_has_a_header_comment(path: Path) -> None:
    head = _text(path).lstrip()
    assert head.startswith("/*") or head.startswith("<!--"), path.name


def test_every_registry_renderer_is_registered_in_the_frontend() -> None:
    index = _text(STATIC / "renderers" / "index.js")
    registered = set(re.findall(r"^import (\w+) from", index, re.M))
    registered |= set(re.findall(r'"(\w+)"', index.split("for (const id of [", 1)[1].split("]")[0]))
    for kind in default_registry().all():
        assert kind.renderer in registered, kind.renderer


def test_every_static_file_is_served_with_its_type() -> None:
    env = make_env()
    client = env.dash_client()
    assets = StaticAssets.load(STATIC)
    assert "renderers/index.js" in assets.names()
    for name in sorted(assets.names()):
        response = client.get(f"/static/{name}", headers=owner_headers())
        assert response.status_code == 200, name
        suffix = Path(name).suffix
        assert response.headers["content-type"] == STATIC_MEDIA_TYPES[suffix], name
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.content == (STATIC / name).read_bytes()
    index = client.get("/", headers=owner_headers())
    assert index.headers["content-type"] == "text/html; charset=utf-8"
    assert index.content == (STATIC / "index.html").read_bytes()
    for unserved in ("vendor/VENDOR.md", "vendor/CHECKSUMS", "vendor/marked-18.0.14/LICENSE"):
        assert client.get(f"/static/{unserved}", headers=owner_headers()).status_code == 404


def test_preview_only_assets_are_not_served_by_the_dashboard() -> None:
    """vendor/ and preview-render/ are inlined into /r/ pages only (ADR 0018, C6)."""
    client = make_env().dash_client()
    names = StaticAssets.load(STATIC).names()
    assert not any(n.startswith(("vendor/", "preview-render/")) for n in names)
    shipped = [
        p.relative_to(STATIC).as_posix()
        for top in ("vendor", "preview-render")
        for p in (STATIC / top).rglob("*")
        if p.is_file() and p.suffix in STATIC_MEDIA_TYPES
    ]
    assert any(n.endswith("purify.min.js") for n in shipped)
    assert "preview-render/renderer.js" in shipped
    for name in shipped:
        response = client.get(f"/static/{name}", headers=owner_headers())
        assert response.status_code == 404, name


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("path", [*DASHBOARD_JS, *FX_JS, RENDERER_JS], ids=_rel)
def test_js_parses(path: Path) -> None:
    node = shutil.which("node")
    assert node is not None
    module = path not in {RENDERER_JS, OS_BOOT}  # both are classic scripts
    args = [node, "--input-type=module", "--check"] if module else [node, "--check", str(path)]
    result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, our own file
        args,
        input=_text(path) if module else None,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


_ORIGIN_SCRIPT = """
const dom = await import(process.argv[1]);
const api = await import(process.argv[2]);
const check = (cond, msg) => { if (!cond) { console.error(msg); process.exit(1); } };
const url = "https://dash.example.ts.net:8443/i/01ARZ3NDEKTSV4RRFFQ69G5FAV/1/index.html";
check(dom.httpsUrl(url) === null, "fails closed before the origin is known");
for (const bad of ["http://dash.example.ts.net:8443", "https://dash.example.ts.net:8443/x",
                   "javascript:alert(1)", "", null]) {
  let threw = false;
  try { dom.setPreviewOrigin(bad); } catch { threw = true; }
  check(threw, "refused origin " + bad);
}
dom.setPreviewOrigin("https://dash.example.ts.net:8443");
check(dom.httpsUrl(url) === url, "preview-origin URL accepted");
for (const other of ["https://dash.example.ts.net/i/x", "https://evil.example:8443/i/x",
                     "https://dash.example.ts.net:8444/i/x", "http://dash.example.ts.net:8443/i/x",
                     "//dash.example.ts.net:8443/i/x", "data:image/png;base64,AA=="]) {
  check(dom.httpsUrl(other) === null, "refused " + other);
}
let changed = false;
try { dom.setPreviewOrigin("https://other.example"); } catch { changed = true; }
check(changed, "origin can't change once set");
const id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
check(api.itemPath(id) === `/api/items/${id}`, "head path");
check(api.itemPath(id, { trashed: true, rev: 3 }) === `/api/items/${id}?t=1&rev=3`, "rev path");
check(api.itemPath(id, { rev: 0 }) === `/api/items/${id}`, "bad rev ignored");
check(api.itemPath(id, { rev: "3" }) === `/api/items/${id}`, "non-integer rev ignored");
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_dom_pins_item_urls_to_the_preview_origin_at_runtime() -> None:
    node = shutil.which("node")
    assert node is not None
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own files
        [
            node,
            "--input-type=module",
            "-e",
            _ORIGIN_SCRIPT,
            (STATIC / "dom.js").as_uri(),
            (STATIC / "api.js").as_uri(),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
