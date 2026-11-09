"""The OS contract (docs/frontend-os.md; ADR 0028; docs/security.md C23 exception).

An OS is a folder under static/os/<name>/ that can be added without touching
functional code. These tests make that promise strict, for every OS the
registry lists: allowlists that agree (registry, os-boot.js, folders on
disk), the files every OS ships and how index.html loads them, the per-OS
token contract, CSS scoping to :root[data-os="<name>"], JS that no-ops under
another OS, isolation from the functional modules both ways, the storage
keys, and a functional app that neither knows nor cares which OS is active.
Runtime checks of os-boot.js and os/storage.js run under Node when present.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404 - runs only our own OS-layer files under node in tests
from dataclasses import dataclass
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.renderer_page import RendererPage
from preview_dashboard.interfaces.viewer.static_assets import StaticAssets, default_static_dir

STATIC = default_static_dir()
OS_DIR = STATIC / "os"
OS_BOOT = STATIC / "os-boot.js"
REGISTRY = OS_DIR / "registry.js"
STORAGE = OS_DIR / "storage.js"
INDEX = STATIC / "index.html"
DOCS = Path(__file__).resolve().parents[2] / "docs"
FUNCTIONAL_JS = sorted(
    p
    for p in STATIC.rglob("*.js")
    if p.parts[len(STATIC.parts)] not in {"vendor", "preview-render", "os", "os-boot.js"}
)
NEUTRAL_CSS = [STATIC / "app.css", OS_DIR / "shell.css"]
REQUIRED_OS_FILES = ("theme.css", "chrome.css", "shell.js", "backgrounds.js")
IMPORT_FROM = re.compile(r'import\s+(?:[^;]+?)\s+from\s+"([^"]+)"')
LITERAL_COLOR = re.compile(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(")


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _code(path: Path) -> str:
    """JS without block or line comments (so prose can't satisfy or trip a check)."""
    source = re.sub(r"/\*.*?\*/", "", _text(path), flags=re.S)
    return "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//"))


def _registry_oses() -> list[str]:
    match = re.search(r"export const OSES = Object\.freeze\(\[([^\]]*)\]\);", _text(REGISTRY))
    assert match is not None
    return re.findall(r'"([a-z][a-z0-9-]*)"', match.group(1))


def _registry_default() -> str:
    match = re.search(r'export const DEFAULT_OS = "([a-z0-9-]+)";', _text(REGISTRY))
    assert match is not None
    return match.group(1)


OSES = _registry_oses()
DEFAULT_OS = _registry_default()


# --- a tiny CSS reader: enough to see every selector, at-rule and declaration ---


@dataclass
class Rule:
    """One style rule (selectors + declarations) and the at-rules wrapping it."""

    selectors: list[str]
    body: str
    media: str | None


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _blocks(css: str) -> list[tuple[str, str]]:
    """Top-level `(prelude, inner)` pairs, braces matched (quoted strings respected)."""
    out: list[tuple[str, str]] = []
    depth, start, prelude_start, quote = 0, 0, 0, ""
    for i, ch in enumerate(css):
        if quote:
            if ch == quote and css[i - 1] != "\\":
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                out.append((css[prelude_start:start].strip(), css[start + 1 : i]))
                prelude_start = i + 1
    assert depth == 0, "unbalanced braces"
    return out


def _split_selectors(prelude: str) -> list[str]:
    parts, depth, cur = [], 0, ""
    for ch in prelude:
        depth += ch == "("
        depth -= ch == ")"
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    parts.append(cur.strip())
    return [p for p in parts if p]


@dataclass
class Sheet:
    rules: list[Rule]
    keyframes: list[str]
    at_rules: list[str]


def _parse(css: str) -> Sheet:
    sheet = Sheet([], [], [])
    for prelude, inner in _blocks(_strip_css_comments(css)):
        if prelude.startswith("@keyframes"):
            sheet.keyframes.append(prelude.split()[1])
        elif prelude.startswith("@media"):
            for sub_prelude, sub_inner in _blocks(inner):
                assert not sub_prelude.startswith("@"), f"nested at-rule {sub_prelude}"
                sheet.rules.append(Rule(_split_selectors(sub_prelude), sub_inner, prelude))
        elif prelude.startswith("@"):
            sheet.at_rules.append(prelude)
        else:
            sheet.rules.append(Rule(_split_selectors(prelude), inner, None))
    return sheet


def _declared_tokens(css: str) -> set[str]:
    return set(re.findall(r"(?:^|[;{\s])(--[a-z0-9-]+)\s*:", _strip_css_comments(css)))


def _used_tokens(css: str) -> set[str]:
    return set(re.findall(r"var\((--[a-z0-9-]+)", css))


def _contract_tokens() -> set[str]:
    section = _text(DOCS / "frontend.md").split("## Theme tokens", 1)[1].split("\n## ", 1)[0]
    return set(re.findall(r"`(--[a-z0-9-]+)`", section))


def _os_css(os: str) -> list[Path]:
    return sorted((OS_DIR / os).rglob("*.css"))


def _os_js(os: str) -> list[Path]:
    return sorted((OS_DIR / os).rglob("*.js"))


def _scope(os: str) -> str:
    return f':root[data-os="{os}"]'


# --- allowlists: registry, os-boot.js and the folders on disk agree ---


def test_registry_boot_and_disk_list_the_same_oses() -> None:
    assert OSES, "no OS registered"
    assert len(OSES) == len(set(OSES))
    assert DEFAULT_OS in OSES
    boot = _code(OS_BOOT)
    boot_list = re.search(r"var OSES = \[([^\]]*)\];", boot)
    assert boot_list is not None
    assert re.findall(r'"([a-z0-9-]+)"', boot_list.group(1)) == OSES
    assert f'var DEFAULT_OS = "{DEFAULT_OS}";' in boot
    on_disk = sorted(p.name for p in OS_DIR.iterdir() if p.is_dir())
    assert on_disk == sorted(OSES), "every OS folder must be registered, and vice versa"
    registry = _code(REGISTRY)
    for os in OSES:
        entry = rf'^\s*{re.escape(os)}: Object\.freeze\(\{{ label: "[^"]+", '
        assert re.search(entry, registry, re.M), os
        assert f'from "./{os}/backgrounds.js";' in registry


def test_os_names_are_safe_identifiers() -> None:
    for os in OSES:
        assert re.fullmatch(r"[a-z][a-z0-9]{1,15}", os), os


# --- files and loading ---


@pytest.mark.parametrize("os", OSES)
def test_every_os_ships_the_required_files(os: str) -> None:
    for name in REQUIRED_OS_FILES:
        assert (OS_DIR / os / name).is_file(), f"{os}/{name}"
    fx = OS_DIR / os / "fx"
    if fx.exists():
        assert (fx / "fx.js").is_file() and (fx / "fx.css").is_file(), f"{os}/fx"


def _links(html: str) -> list[str]:
    return re.findall(r'<link rel="stylesheet" href="([^"]+)">', html)


def _module_scripts(html: str) -> list[str]:
    return re.findall(r'<script type="module" src="([^"]+)"></script>', html)


def test_index_html_boots_the_os_before_any_stylesheet() -> None:
    html = _text(INDEX)
    boot = html.index('<script src="/static/os-boot.js"></script>')
    assert boot < html.index('<link rel="stylesheet"'), "os-boot.js must run before CSS"
    assert html.count("os-boot.js") == 1
    # Neutral CSS first, then every OS: an OS rule never loses to a neutral one on order.
    links = _links(html)
    assert links[:3] == ["/static/fonts.css", "/static/app.css", "/static/os/shell.css"]


@pytest.mark.parametrize("os", OSES)
def test_index_html_loads_every_file_of_every_os_as_its_own_tag(os: str) -> None:
    html = _text(INDEX)
    links, scripts = _links(html), _module_scripts(html)
    expected_css = [f"/static/os/{os}/theme.css", f"/static/os/{os}/chrome.css"]
    expected_js = [f"/static/os/{os}/shell.js"]
    if (OS_DIR / os / "fx").exists():
        expected_css.append(f"/static/os/{os}/fx/fx.css")
        expected_js.append(f"/static/os/{os}/fx/fx.js")
    assert [x for x in links if x.startswith(f"/static/os/{os}/")] == expected_css
    assert [x for x in scripts if x.startswith(f"/static/os/{os}/")] == expected_js
    assert "/static/os/shell.js" in scripts


def test_index_html_references_nothing_under_os_but_registered_oses_and_shared_files() -> None:
    for ref in [*_links(_text(INDEX)), *_module_scripts(_text(INDEX))]:
        if ref.startswith("/static/os/"):
            rest = ref.removeprefix("/static/os/")
            assert rest in {"shell.css", "shell.js"} or rest.split("/", 1)[0] in OSES, ref
            assert (STATIC / ref.removeprefix("/static/")).is_file(), ref


# --- token contract per OS ---


@pytest.mark.parametrize("os", OSES)
def test_os_theme_defines_exactly_the_contract_tokens(os: str) -> None:
    theme = _text(OS_DIR / os / "theme.css")
    assert _declared_tokens(theme) == _contract_tokens()
    assert "@font-face" not in theme and "url(" not in theme and "@import" not in theme


@pytest.mark.parametrize("os", OSES)
def test_os_theme_declares_its_scheme_and_zeroes_motion_for_reduced_motion(os: str) -> None:
    theme = _text(OS_DIR / os / "theme.css")
    assert re.search(r"color-scheme: (?:light|dark|light dark);", theme)
    reduced = [
        r for r in _parse(theme).rules if r.media and "prefers-reduced-motion: reduce" in r.media
    ]
    assert any(re.search(r"--motion-duration:\s*0ms;", r.body) for r in reduced), os


def test_neutral_css_uses_contract_tokens_only_and_never_names_an_os() -> None:
    contract = _contract_tokens()
    for path in NEUTRAL_CSS:
        css = _text(path)
        assert _used_tokens(css) <= contract, f"{path.name}: {_used_tokens(css) - contract}"
        assert not _declared_tokens(css), path.name
        assert not LITERAL_COLOR.search(_strip_css_comments(css)), path.name
        assert "data-os" not in css, f"{path.name} must not depend on the active OS"


# --- scoping: every OS rule applies only under its own OS ---


def _scoped(selector: str, os: str) -> bool:
    scope = _scope(os)
    return selector == scope or (selector.startswith(scope) and selector[len(scope)] in " .:[#>+~")


@pytest.mark.parametrize("os", OSES)
def test_every_os_css_rule_is_scoped_to_its_os(os: str) -> None:
    for path in _os_css(os):
        sheet = _parse(_text(path))
        assert not sheet.at_rules, f"{path}: {sheet.at_rules}"  # no @import/@font-face/...
        for rule in sheet.rules:
            for selector in rule.selectors:
                # The default OS's token block (and its reduced-motion twin) also matches bare
                # :root: the fallback when no OS applies, and the /r/ pages' tokens.
                if os == DEFAULT_OS and path.name == "theme.css" and selector == ":root":
                    assert _scope(os) in rule.selectors
                    continue
                # Sprite-shape classes must stay unscoped: <use> shadow trees never match an
                # ancestor selector. They are OS-prefixed, so they cannot leak into another OS.
                if re.fullmatch(rf"\.{os}-(?:doc|c|ic)-[a-z-]+", selector):
                    continue
                assert _scoped(selector, os), f"{path.relative_to(STATIC)}: {selector}"
        for name in sheet.keyframes:
            assert name.startswith(f"{os}-"), f"{path.name}: @keyframes {name} needs the OS prefix"


@pytest.mark.parametrize("os", OSES)
def test_os_css_uses_contract_or_its_own_private_tokens_and_no_literal_values(os: str) -> None:
    """Chrome/fx CSS: var() refs are contract tokens or tokens this OS declares itself;
    literal colors and font families only inside custom-property declarations."""
    private: set[str] = set()
    for path in _os_css(os):
        if path.name != "theme.css":
            private |= _declared_tokens(_text(path))
    assert not private & _contract_tokens(), "an OS may not redefine contract tokens in chrome"
    allowed = _contract_tokens() | private
    for path in _os_css(os):
        css = _text(path)
        assert _used_tokens(css) <= allowed, f"{path.name}: {_used_tokens(css) - allowed}"
        assert "url(" not in css and "@import" not in css, path.name
        if path.name == "theme.css":
            continue
        for rule in _parse(css).rules:
            for decl in (d.strip() for d in rule.body.split(";")):
                if decl.startswith("--"):
                    continue
                assert not LITERAL_COLOR.search(decl), f"{path.name}: {decl}"
                assert not re.match(r"font-family:(?!\s*var\()", decl), f"{path.name}: {decl}"


@pytest.mark.parametrize("os", OSES)
def test_every_os_animation_and_transition_is_neutralised_under_reduced_motion(os: str) -> None:
    for path in _os_css(os):
        rules = _parse(_text(path)).rules
        neutral: set[str] = set()
        for rule in rules:
            reduced = rule.media is not None and "prefers-reduced-motion: reduce" in rule.media
            if reduced and re.search(r"(animation|transition):\s*none", rule.body):
                neutral |= set(rule.selectors)
        for rule in rules:
            if rule.media and "prefers-reduced-motion" in rule.media:
                continue
            if re.search(r"(?:^|;)\s*(animation|transition)(?:-name)?:\s*(?!none)", rule.body):
                for selector in rule.selectors:
                    assert selector in neutral, f"{path.name}: {selector} keeps moving"


@pytest.mark.parametrize("os", OSES)
def test_backgrounds_match_their_css_rules(os: str) -> None:
    source = _code(OS_DIR / os / "backgrounds.js")
    ids = re.findall(r'\{ id: "([^"]+)", label: "[^"]+" \}', source)
    assert ids and len(ids) == len(set(ids))
    for bg in ids:
        assert re.fullmatch(r"[a-z][a-z0-9-]{0,31}", bg), bg
    chrome = _text(OS_DIR / os / "chrome.css")
    painted = re.findall(rf'{re.escape(_scope(os))} body\[data-background="([^"]+)"\]', chrome)
    assert sorted(set(painted)) == sorted(ids)


# --- JS: OS modules no-op under another OS; isolation both ways ---


@pytest.mark.parametrize("os", OSES)
def test_os_entry_scripts_do_nothing_under_another_os(os: str) -> None:
    entries = [OS_DIR / os / "shell.js"]
    if (OS_DIR / os / "fx").exists():
        entries.append(OS_DIR / os / "fx" / "fx.js")
    for path in entries:
        body = _code(path)
        assert f'const OS = "{os}";' in body, path
        start = body.split("function start() {", 1)[1]
        assert start.lstrip().startswith("if (document.documentElement.dataset.os !== OS) return;")


def _resolve(path: Path, target: str) -> Path:
    return (path.parent / target).resolve()


@pytest.mark.parametrize("os", OSES)
def test_os_modules_import_only_inside_their_own_folder(os: str) -> None:
    root = (OS_DIR / os).resolve()
    for path in _os_js(os):
        for target in IMPORT_FROM.findall(_text(path)):
            assert target.startswith("./") or target.startswith("../"), (path, target)
            assert _resolve(path, target).is_relative_to(root), f"{path.name} imports {target}"


def test_shared_os_modules_import_only_inside_os() -> None:
    root = OS_DIR.resolve()
    for path in sorted(OS_DIR.glob("*.js")):
        for target in IMPORT_FROM.findall(_text(path)):
            assert target.startswith("./"), (path.name, target)
            assert _resolve(path, target).is_relative_to(root), f"{path.name} imports {target}"
            if "/" in target.removeprefix("./"):
                # The registry is the only shared module that reaches into an OS folder.
                assert path == REGISTRY and target.endswith("/backgrounds.js"), (path, target)


def test_os_boot_is_a_classic_script_that_imports_nothing() -> None:
    boot = _code(OS_BOOT)
    assert "import " not in boot and "export " not in boot
    assert boot.lstrip().startswith("(function () {")


def test_functional_code_never_imports_or_names_an_os() -> None:
    names = re.compile(r"\b(" + "|".join(map(re.escape, OSES)) + r")\b", re.I)
    for path in FUNCTIONAL_JS:
        source = _text(path)  # comments too: functional code is OS-agnostic in prose as well
        assert not names.search(source), f"{path.name} names an OS"
        assert "dataset.os" not in source and "data-os" not in source, path.name
        for target in IMPORT_FROM.findall(source):
            assert "os/" not in target and "os-boot" not in target, (path.name, target)
    html = re.sub(r"<(?:link|script)\b[^>]*>", "", _text(INDEX))
    assert not names.search(html), "index.html names an OS outside its link/script tags"


def _class_tokens(text: str) -> set[str]:
    found: set[str] = set()
    for match in re.finditer(r'class(?:Name)?\s*[:=]\s*(?:"([^"]*)"|`([^`]*)`)', text):
        value = re.sub(r"\$\{[^}]*\}", " ", match.group(1) or match.group(2) or "")
        found |= set(value.split())
    return found


def _css_classes(css: str) -> set[str]:
    classes: set[str] = set()
    for rule in _parse(css).rules:
        for selector in rule.selectors:
            classes |= set(re.findall(r"\.([a-zA-Z][\w-]*)", selector))
    return classes


def test_functional_markup_uses_no_os_private_classes() -> None:
    """Classes only an OS styles (e.g. Platinum's menu titles, shade box, fx classes) are
    created by that OS's own modules, never by functional JS or index.html."""
    # Semantic roles the functional markup sets that neutral CSS leaves unstyled on purpose (each
    # OS draws them): the default action button.
    neutral = {"button-primary"}.union(*(_css_classes(_text(p)) for p in NEUTRAL_CSS))
    private: set[str] = set()
    for os in OSES:
        for path in _os_css(os):
            private |= _css_classes(_text(path)) - neutral
    assert private, "expected at least one OS-private class"
    used = set().union(*(_class_tokens(_text(p)) for p in [*FUNCTIONAL_JS, INDEX]))
    assert not used & private, f"functional markup uses OS-private classes: {used & private}"


def test_app_css_and_chrome_js_carry_no_platinum_decoration() -> None:
    """Regression guard for the split: the decorations moved out of neutral files."""
    app = _text(STATIC / "app.css")
    for gone in ("menubar", ".box", "titlebar-stripes", "bevel-raised", "bevel-pressed",
                 "bevel-sunken", "shadow-raised", "shadow-overlay", "ring-default"):  # fmt: skip
        assert gone not in app, gone
    chrome = _code(STATIC / "chrome.js")
    assert "box-shade" not in chrome and "box-close" not in chrome


# --- storage: exactly pdash.os + pdash.background.<os>, through two files ---


def test_only_storage_js_and_os_boot_touch_storage() -> None:
    for path in sorted(OS_DIR.rglob("*.js")):
        source = _code(path)
        if path != STORAGE:
            assert "localStorage" not in source and "sessionStorage" not in source, path.name
    assert "sessionStorage" not in _code(STORAGE)
    boot = _code(OS_BOOT)
    assert re.findall(r"localStorage\.\w+\(([^)]*)\)", boot) == ['"pdash.os"']
    assert "localStorage.getItem" in boot and "setItem" not in boot and "removeItem" not in boot


def test_storage_keys_are_the_documented_constants() -> None:
    body = _code(STORAGE)
    assert 'export const OS_KEY = "pdash.os";' in body
    assert 'const BACKGROUND_PREFIX = "pdash.background.";' in body
    assert 'const LEGACY_KEYS = Object.freeze(["pdash.background", "pdash.desktop"]);' in body
    assert "return OSES.includes(os) ? BACKGROUND_PREFIX + os : null;" in body
    # Every Storage call uses a key variable, never a literal or other data.
    for call in re.finditer(r"localStorage\.(?:get|set|remove)Item\(([^,)]+)", body):
        assert call.group(1).strip() in {"OS_KEY", "key", "legacyKey"}, call.group(0)
    for assign in re.findall(r"const key = ([^;]+);", body):
        assert assign.startswith("backgroundKey("), assign


def _node() -> str:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    return node


_STORAGE_SCRIPT = """
const storage = await import(process.argv[1]);
globalThis.document = { documentElement: { dataset: {} } };
function run(store, fn) {
  globalThis.localStorage = {
    getItem: (k) => (Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: (k) => { delete store[k]; },
  };
  const value = fn();
  return { value, store: { ...store } };
}
const load = () => storage.loadBackground("platinum");
const out = {
  fromB1: run({ "pdash.background": "waves" }, load),
  fromR5: run({ "pdash.desktop": "zen" }, load),
  b1Wins: run({ "pdash.background": "weave", "pdash.desktop": "zen" }, load),
  junk: run({ "pdash.background": "<img onerror=x>", "pdash.desktop": "nope" }, load),
  keepsNew: run({ "pdash.background.platinum": "static", "pdash.desktop": "waves" }, load),
  invalidNew: run({ "pdash.background.platinum": "__proto__" }, load),
  none: run({}, load),
  saveOk: run({}, () => storage.saveBackground("platinum", "weave")),
  saveBadValue: run({}, () => storage.saveBackground("platinum", "x;y")),
  saveBadOs: run({}, () => storage.saveBackground("__proto__", "weave")),
  saveOs: run({}, () => storage.saveOs("platinum")),
  saveOsBad: run({}, () => storage.saveOs("<b>")),
  keyBad: run({}, () => [storage.backgroundKey("constructor"), storage.backgroundKey("")]),
};
const blocked = () => { throw new Error("blocked"); };
globalThis.localStorage = { getItem: blocked, setItem: blocked, removeItem: blocked };
out.blocked = { value: storage.loadBackground("platinum"), saved: storage.saveOs("platinum") };
console.log(JSON.stringify(out));
"""


def test_storage_migrates_validates_and_survives_blocked_storage() -> None:
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own module
        [_node(), "--input-type=module", "-e", _STORAGE_SCRIPT, STORAGE.as_uri()],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["fromB1"] == {"value": "waves", "store": {"pdash.background.platinum": "waves"}}
    assert out["fromR5"] == {"value": "zen", "store": {"pdash.background.platinum": "zen"}}
    assert out["b1Wins"] == {"value": "weave", "store": {"pdash.background.platinum": "weave"}}
    assert out["junk"] == {"value": "standard", "store": {}}
    # An existing per-OS value wins; the legacy keys are still removed (C23).
    assert out["keepsNew"] == {"value": "static", "store": {"pdash.background.platinum": "static"}}
    assert out["invalidNew"]["value"] == "standard"
    assert out["none"] == {"value": "standard", "store": {}}
    assert out["saveOk"]["store"] == {"pdash.background.platinum": "weave"}
    assert out["saveBadValue"]["store"] == {} and out["saveBadOs"]["store"] == {}
    assert out["saveOs"] == {"value": True, "store": {"pdash.os": "platinum"}}
    assert out["saveOsBad"] == {"value": False, "store": {}}
    assert out["keyBad"]["value"] == [None, None]
    assert out["blocked"] == {"value": "standard", "saved": False}


_BOOT_SCRIPT = """
const fs = require("fs");
const source = fs.readFileSync(process.argv[1], "utf8");
function boot(storage) {
  const attrs = {};
  const head = [];
  const window = { localStorage: storage };
  const document = {
    documentElement: { setAttribute: (k, v) => { attrs[k] = v; } },
    head: { appendChild: (el) => head.push(el) },
    createElement: () => ({}),
  };
  new Function("window", "document", source)(window, document);
  return { os: attrs["data-os"] ?? null, preloads: head.map((l) => [l.rel, l.as, l.href]) };
}
const stored = (v) => ({ getItem: (k) => (k === "pdash.os" ? v : null) });
console.log(JSON.stringify({
  missing: boot(stored(null)),
  valid: boot(stored(process.argv[2])),
  junk: boot(stored("<img src=x onerror=alert(1)>")),
  proto: boot(stored("__proto__")),
  blocked: boot({ getItem() { throw new Error("blocked"); } }),
}));
"""


def test_os_boot_falls_back_to_the_default_for_missing_invalid_or_blocked_values() -> None:
    last = OSES[-1]
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own script
        [_node(), "-e", _BOOT_SCRIPT, str(OS_BOOT), last],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    assert out["valid"]["os"] == last
    for case in ("missing", "junk", "proto", "blocked"):
        assert out[case]["os"] == DEFAULT_OS, case
    for case in out.values():
        for rel, kind, href in case["preloads"]:
            assert rel == "preload" and kind == "font"
            assert re.fullmatch(r"/static/fonts/[a-z0-9-]+\.woff2", href), href
            assert (STATIC / href.removeprefix("/static/")).is_file(), href


# --- the functional app works whatever the OS layer does ---


def test_dashboard_assets_load_with_any_os_folder_or_fx_deleted(tmp_path: Path) -> None:
    """Deleting an OS's fx/ (or a whole non-default OS layer file set) never touches the
    functional files the dashboard serves."""
    full = StaticAssets.load(STATIC)
    for os in OSES:
        copy = tmp_path / os / "static"
        shutil.copytree(STATIC, copy, ignore=shutil.ignore_patterns("fx"))
        assets = StaticAssets.load(copy)
        functional = {n for n in full.names() if not n.startswith("os/")} | {"os-boot.js"}
        for name in functional:
            assert assets.get(name) is not None, name
            assert assets.get(name).body == full.get(name).body  # type: ignore[union-attr]
        assert not any(n.startswith(f"os/{os}/fx/") for n in assets.names())


def test_preview_pages_inline_the_default_os_tokens() -> None:
    """/r/ pages have no data-os: they get the default OS's theme, whose block matches :root."""
    page = RendererPage.load(STATIC)
    theme = page._assets["theme.css"].decode("utf-8")
    assert theme == _text(OS_DIR / DEFAULT_OS / "theme.css")
    first = _parse(theme).rules[0]
    assert ":root" in first.selectors and _scope(DEFAULT_OS) in first.selectors


# --- F-A1: forbidden browser APIs and background timers across every OS ---

FORBIDDEN_JS = {
    "location navigation": re.compile(r"\blocation\.(?:href|assign|replace)\b"),
    "window.open": re.compile(r"\bwindow\.open\b"),
    'setAttribute("style"': re.compile(r"""setAttribute\(\s*["']style["']"""),
    "on<event> assignment": re.compile(r"\.on[a-z]+\s*=(?!=)"),
    "location.hash write": re.compile(r"\blocation\.hash\s*=(?!=)"),
}
HASH_WRITERS = {Path("aero/fx/close.js")}  # the one sanctioned navigation, see docs/frontend-os.md


def _all_os_js() -> list[Path]:
    return sorted(OS_DIR.rglob("*.js"))


def test_os_layer_never_navigates_opens_windows_or_uses_inline_handlers_or_styles() -> None:
    for path in _all_os_js():
        source = _code(path)
        rel = path.relative_to(OS_DIR)
        for label, pattern in FORBIDDEN_JS.items():
            if label == "location.hash write" and rel in HASH_WRITERS:
                assert pattern.search(source), f"{rel} no longer writes location.hash; update test"
                continue
            assert not pattern.search(source), f"{rel}: {label}"


# Platinum's fx predates this rule and is deliberately unchanged (F-A1: "Aero at least").
VISIBILITY_EXEMPT = {"platinum"}


def test_every_new_os_fx_module_with_a_long_timer_handles_visibilitychange() -> None:
    """Recurring or idle-length timers must stop while the tab is hidden (battery)."""
    for path in _all_os_js():
        rel = path.relative_to(OS_DIR)
        if "fx" not in rel.parts or rel.parts[0] in VISIBILITY_EXEMPT:
            continue
        source = _code(path)
        if "setInterval(" in source or "idleThreshold" in source:
            assert "visibilitychange" in source, rel
            assert "document.hidden" in source, rel


def test_aero_screensaver_and_clock_stop_their_timers_while_hidden() -> None:
    saver = _code(OS_DIR / "aero" / "fx" / "screensaver.js")
    hidden = saver.split("function onVisibility() {", 1)[1].split("} else {", 1)[0]
    assert "clearTimeout(timer)" in hidden and "overlay.remove()" in hidden
    clock = _code(OS_DIR / "aero" / "fx" / "clock.js")
    assert "const stop = () => {\n    clearInterval(interval);" in clock
    assert "document.hidden ? stop() : start()" in clock
    assert "tick();" in clock.split("const start = () => {", 1)[1].split("};", 1)[0]


@pytest.mark.parametrize("os", OSES)
def test_fx_idle_override_ignores_values_under_one_second(os: str) -> None:
    path = OS_DIR / os / "fx" / "screensaver.js"
    if not path.exists():
        pytest.skip("no screensaver")
    source = _code(path)
    assert "const MIN_IDLE_MS = 1000;" in source
    assert "n >= MIN_IDLE_MS" in source


def test_no_decorative_controls_return() -> None:
    """Owner rule 2026-09-30: every control must work; no fake caption buttons or menu titles."""
    banned = (
        "aero-caption",
        "menubar-title",
        "menubar-wide",
        "data-menu",
        "dataset.menu",
        "MENU_TITLES",
    )
    for path in [*OS_DIR.rglob("*.js"), *OS_DIR.rglob("*.css"), INDEX, STATIC / "app.css"]:
        text = _text(path)
        for word in banned:
            assert word not in text, f"{path.name}: {word}"
