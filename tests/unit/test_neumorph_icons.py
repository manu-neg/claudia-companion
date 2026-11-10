"""Neumorph icons and motion (docs/frontend-os.md#neumorph "Icons" / "Motion"; backlog §16.2).

Icons: icons.js redraws every shared sprite symbol (run under Node against a stub DOM); every
art class it emits has a rule in chrome.css, and those rules are bare class selectors, because
<use> clones shapes into a shadow tree where a :root[data-os] ancestor never matches (the same
lesson as test_aero_icon_css.py); the colours come from declared --neu-ic-* tokens.
Motion: every duration token is zeroed under reduced motion; exits are faster than entrances;
the ghost layer only follows the app (no navigation, no prevented events, no item text); the
screensaver stops while hidden.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404 - runs only our own OS-layer module under node in tests
from pathlib import Path

import pytest

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
NEU = STATIC / "os" / "neumorph"
ICONS = NEU / "icons.js"
CHROME = NEU / "chrome.css"
FX = NEU / "fx"


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _css(path: Path) -> str:
    return re.sub(r"/\*.*?\*/", "", _text(path), flags=re.S)


def _selectors(css: str) -> list[str]:
    found: list[str] = []
    for prelude in re.findall(r"([^{}]+)\{", css):
        found += [p.strip() for p in prelude.split(",") if p.strip()]
    return found


def _decl(css: str, name: str) -> str:
    match = re.search(rf"(?<![\w-]){re.escape(name)}:\s*([^;]+);", css)
    assert match is not None, name
    return match.group(1).strip()


_SPRITE_SCRIPT = """
const icons = await import(process.argv[1]);
const symbols = {};
const ids = JSON.parse(process.argv[2]);
const sprite = {
  namespaceURI: "svg-ns",
  setAttribute() {},
  querySelector(sel) {
    const id = /symbol\\[id="([^"]+)"\\]/.exec(sel)[1];
    if (!ids.includes(id)) return null;
    return { replaceChildren: (...nodes) => { symbols[id] = nodes; } };
  },
};
globalThis.document = {
  querySelector: (sel) => (sel === "svg.sprite" ? sprite : null),
  createElementNS(ns, tag) {
    const attrs = {};
    return { ns, tag, attrs, setAttribute: (k, v) => { attrs[k] = v; } };
  },
};
icons.swapSprite();
console.log(JSON.stringify(Object.fromEntries(Object.entries(symbols).map(
  ([id, nodes]) => [id, nodes.map((n) => ({ ns: n.ns, tag: n.tag, attrs: n.attrs }))]))));
"""


def _symbol_ids() -> list[str]:
    return re.findall(r'<symbol id="([a-z-]+)"', _text(STATIC / "index.html"))


@pytest.fixture(scope="module")
def art() -> dict[str, list[dict[str, object]]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    ids = json.dumps(_symbol_ids())
    result = subprocess.run(  # noqa: S603 - fixed node binary, our own module
        [node, "--input-type=module", "-e", _SPRITE_SCRIPT, ICONS.as_uri(), ids],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    out: dict[str, list[dict[str, object]]] = json.loads(result.stdout)
    return out


def _classes(art: dict[str, list[dict[str, object]]]) -> set[str]:
    classes: set[str] = set()
    for nodes in art.values():
        for n in nodes:
            attrs = n["attrs"]
            assert isinstance(attrs, dict)
            classes |= set(str(attrs.get("class", "")).split())
    return classes


# --- icons ---


Art = dict[str, list[dict[str, object]]]
SHAPES = {"path", "rect", "circle", "ellipse"}


def test_every_shared_symbol_is_redrawn_with_svg_shapes(art: Art) -> None:
    ids = _symbol_ids()
    assert ids and set(ids) <= set(art), set(ids) - set(art)
    for symbol, nodes in art.items():
        assert nodes, symbol
        for n in nodes:
            assert n["ns"] == "svg-ns" and n["tag"] in SHAPES, (symbol, n)
            attrs = n["attrs"]
            assert isinstance(attrs, dict)
            assert str(attrs.get("class", "")).startswith("neumorph-ic-"), (symbol, attrs)
            assert "style" not in attrs and not any(k.startswith("on") for k in attrs), attrs


def test_every_art_class_has_a_bare_unscoped_rule(art: dict[str, list[dict[str, object]]]) -> None:
    selectors = _selectors(_css(CHROME))
    classes = _classes(art)
    assert len(classes) > 20
    for cls in sorted(classes):
        hits = [s for s in selectors if re.search(rf"\.{cls}(?![\w-])", s)]
        assert hits, f"art class without a rule: {cls}"
        for sel in hits:
            assert re.fullmatch(rf"\.{cls}", sel), f"scoped icon-art selector: {sel}"


def test_icon_art_colours_come_from_declared_tokens() -> None:
    css = _css(CHROME)
    art_rules = re.findall(r"(\.neumorph-ic-[^{]*)\{([^}]*)\}", css)
    assert art_rules
    for _, body in art_rules:
        for token in re.findall(r"var\((--[a-z0-9-]+)\)", body):
            assert re.search(rf"(?<![\w-]){re.escape(token)}:", css), token
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(", body), body


def test_icons_module_uses_the_sprite_namespace_and_no_urls() -> None:
    source = _text(ICONS)
    assert "sprite.namespaceURI" in source and "createElementNS(ns," in source
    assert "url(" not in source and not re.search(r"https?://", source)
    shell = _text(NEU / "shell.js")
    assert 'import { swapSprite } from "./icons.js";' in shell
    assert 'safe("sprite", swapSprite)' in shell


def _luminance(hex_colour: str) -> float:
    channels = [int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_the_meaningful_icon_marks_meet_non_text_contrast() -> None:
    # WCAG 1.4.11: the marks that say what an icon is (ink, iris, warn) reach 3:1 on the pebble
    # face; muted strokes only ever accompany one of them.
    chrome = _css(CHROME)
    face = _decl(chrome, "--neu-ic-face")
    for mark in ("--neu-ic-ink", "--neu-ic-iris", "--neu-ic-warn"):
        assert _ratio(_decl(chrome, mark), face) >= 3, mark


# --- motion ---


def test_every_duration_token_is_zeroed_under_reduced_motion() -> None:
    chrome, fx = _css(CHROME), _css(FX / "fx.css")
    tokens = set(re.findall(r"(--neu-dur-[a-z-]+):", chrome))
    reduced = fx.split("@media (prefers-reduced-motion: reduce)", 1)[1]
    # instant is already 0; breathe only drives animations that are set to none.
    for token in tokens - {"--neu-dur-instant", "--neu-dur-breathe"}:
        assert re.search(rf"{re.escape(token)}: 0ms;", reduced), token
    assert _decl(chrome, "--neu-dur") == "var(--motion-duration)"


def _ms(value: str) -> float:
    return float(value[:-2]) if value.endswith("ms") else float(value[:-1]) * 1000


def test_exits_are_faster_than_entrances_and_press_is_quicker_than_release() -> None:
    chrome = _css(CHROME)
    d = {
        f"{name}-{phase}": _ms(_decl(chrome, f"--neu-dur-{name}-{phase}"))
        for name in ("menu", "window", "toast")
        for phase in ("in", "out")
    }
    d["press"] = _ms(_decl(chrome, "--neu-dur-press"))
    d["release"] = _ms(_decl(chrome, "--neu-dur-release"))
    for name in ("menu", "window", "toast"):
        assert d[f"{name}-out"] < d[f"{name}-in"], name
    assert d["press"] < d["release"]
    # One small overshoot at most: the settle curve's peak stays modest.
    settle = [float(x) for x in re.findall(r"[\d.]+", _decl(chrome, "--neu-ease-settle"))]
    assert 1 < settle[1] <= 1.6 and settle[3] == 1


def test_every_surface_that_appears_has_an_entrance_and_an_exit() -> None:
    fx = _css(FX / "fx.css")
    entrances = (
        ".main > .window",
        ".ctx-menu",
        ".shell-menu:not([hidden])",
        ".balloon-help:not([hidden])",
        ".dialog[open]",
        ".dialog[open]::backdrop",
        ".toast.is-visible",
        ".stage.is-expanded",
    )
    for entrance in entrances:
        rule = rf'neumorph"\] {re.escape(entrance)} \{{[^}}]*animation: neumorph-'
        assert re.search(rule, fx), entrance
    for ghost in ("window", "menu", "dialog", "veil"):
        assert re.search(rf"\.neumorph-ghost-{ghost} \{{[^}}]*animation: neumorph-", fx), ghost
    exit_rule = r"display var\(--neu-dur-menu-out\) allow-discrete"
    for hidden in (".shell-menu", ".balloon-help"):
        assert re.search(rf'neumorph"\] {re.escape(hidden)} \{{[^}}]*{exit_rule}', fx), hidden
    assert "visibility var(--neu-dur-toast-out)" in fx


def test_ghosts_only_follow_the_app() -> None:
    source = _text(FX / "ghost.js")
    code = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    banned = ["preventDefault", "stopPropagation", "location.hash"]
    banned += ["textContent", "innerHTML", "cloneNode"]
    for name in banned:
        assert name not in code, name
    assert 'setAttribute("aria-hidden", "true")' in code and "style.setProperty(" in code


def test_screensaver_and_clock_stop_while_hidden() -> None:
    saver = _text(FX / "screensaver.js")
    hidden = saver.split("function onVisibility() {", 1)[1].split("} else {", 1)[0]
    assert "clearTimeout(timer)" in hidden and "overlay.remove()" in hidden
    assert "const MIN_IDLE_MS = 1000;" in saver
