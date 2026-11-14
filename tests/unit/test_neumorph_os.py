"""Neumorph-specific checks (docs/frontend-os.md#neumorph); the generic OS contract lives in
test_os_contract.py and already covers scoping, the token list and the reduced-motion list.

Here: Neumorph is registered third with Porcelain first and four relief backgrounds (gradients
only); the one-surface rule (desktop, windows and insets share one colour); the token and key
gradient colour pairs pass WCAG AA and the focus ring >= 3:1; private tokens are --neu-* (plus the
map's --kmap-c0..7); every neutral hook of the docs table gets a rule; motion animates only
transform/opacity/box-shadow and is timed by tokens; fx runs only the clock under reduced motion;
Nunito is vendored with its licence and documented. Icons and motion: test_neumorph_icons.py.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
NEU = STATIC / "os" / "neumorph"
THEME = NEU / "theme.css"
CHROME = NEU / "chrome.css"
FX_CSS = NEU / "fx" / "fx.css"
FX_JS = NEU / "fx" / "fx.js"
FONTS = STATIC / "fonts"
SCOPE = ':root[data-os="neumorph"]'


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _css(path: Path) -> str:
    return re.sub(r"/\*.*?\*/", "", _text(path), flags=re.S)


def _decl(css: str, name: str) -> str:
    match = re.search(rf"(?<![\w-]){re.escape(name)}:\s*([^;]+);", css)
    assert match is not None, name
    return match.group(1).strip()


def _lum(hex_color: str) -> float:
    rgb = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _stops(gradient: str) -> list[str]:
    return re.findall(r"#[0-9a-fA-F]{6}", gradient)


# --- registration and backgrounds ---


def test_neumorph_is_registered_third_with_porcelain_first() -> None:
    registry = _text(STATIC / "os" / "registry.js")
    entry = 'neumorph: Object.freeze({ label: "Neumorph", backgrounds: neumorphBackgrounds })'
    assert entry in registry
    assert 'export const OSES = Object.freeze(["platinum", "aero", "neumorph"]);' in registry
    ids = re.findall(r'id: "([a-z-]+)"', _text(NEU / "backgrounds.js"))
    assert ids[0] == "porcelain" and len(ids) >= 5


def test_relief_backgrounds_are_gradients_on_the_surface_colour() -> None:
    chrome = _css(CHROME)
    for bg in re.findall(r'id: "([a-z-]+)"', _text(NEU / "backgrounds.js")):
        body = chrome.split(f'{SCOPE} body[data-background="{bg}"]', 1)[1].split("}", 1)[0]
        assert "background-color: var(--color-bg);" in body, bg
        assert "gradient(" in body or "var(--desktop-pattern)" in body, bg


def test_neumorph_references_nothing_outside_the_dashboard() -> None:
    for path in NEU.rglob("*"):
        if path.is_file():
            source = _text(path)
            assert "url(" not in source and "@import" not in source, path.name
            assert not re.search(r"https?://", source), path.name


# --- one surface, private tokens ---


def test_one_surface_colour_for_desktop_windows_and_insets() -> None:
    theme = _css(THEME)
    surface = _decl(theme, "--color-surface")
    for name in ("--color-bg", "--color-window", "--color-warning-soft"):
        assert _decl(theme, name) == surface, name


def test_private_tokens_are_namespaced() -> None:
    declared = set(re.findall(r"(?:^|[;{\s])(--[a-z0-9-]+)\s*:", _css(CHROME) + _css(FX_CSS)))
    kmap = {f"--kmap-c{i}" for i in range(8)}
    assert kmap <= declared
    assert all(t.startswith("--neu-") for t in declared - kmap), declared - kmap


# --- contrast ---


def test_token_text_pairs_pass_wcag_aa() -> None:
    theme = _css(THEME)
    tok = {name: _decl(theme, name) for name in re.findall(r"(--color-[a-z-]+):", theme)}
    tok = {k: v for k, v in tok.items() if v.startswith("#")}
    pairs = [
        ("--color-text", "--color-surface"),
        ("--color-text", "--color-surface-sunken"),
        ("--color-text-muted", "--color-surface"),
        ("--color-text-muted", "--color-surface-sunken"),
        ("--color-accent", "--color-surface"),
        ("--color-accent-contrast", "--color-accent"),
        ("--color-accent-contrast", "--color-accent-hover"),
        ("--color-text", "--color-accent-soft"),
        ("--color-danger", "--color-surface"),
        ("--color-danger-contrast", "--color-danger"),
        ("--color-danger-contrast", "--color-danger-hover"),
        ("--color-warning-text", "--color-warning-soft"),
        ("--color-success", "--color-surface"),
    ]
    for fg, bg in pairs:
        assert _ratio(tok[fg], tok[bg]) >= 4.5, (fg, bg, round(_ratio(tok[fg], tok[bg]), 2))
    assert _ratio(tok["--color-focus"], tok["--color-surface"]) >= 3


def test_text_stays_aa_across_every_key_gradient() -> None:
    theme, chrome = _css(THEME), _css(CHROME)
    ink, muted = _decl(theme, "--color-text"), _decl(theme, "--color-text-muted")
    accent, danger = _decl(theme, "--color-accent"), _decl(theme, "--color-danger")
    white = _decl(theme, "--color-accent-contrast")
    for name in ("--neu-convex", "--neu-concave", "--neu-slab"):
        for stop in _stops(_decl(chrome, name)):
            for fg in (ink, muted, accent, danger):
                assert _ratio(fg, stop) >= 4.5, (name, fg, stop)
    for name in ("--neu-accent-convex", "--neu-accent-concave", "--neu-danger-convex"):
        for stop in _stops(_decl(chrome, name)):
            assert _ratio(white, stop) >= 4.5, (name, stop)


# --- coverage: every neutral hook gets a deliberate treatment ---

HOOKS = (
    ".shell-bar", ".shell-app", ".shell-clock", ".shell-link", ".shell-menu-trigger", ".shell-menu",
    ".shell-menu-option", ".desk-icon", ".window", ".titlebar", ".titlebar-title",
    ".titlebar-close",
    ".finder-header", ".inset", ".list-head", ".row", ".row-link", ".row-more", ".statusbar",
    ".info-top", ".screen", ".fields", ".group", ".group-title", ".file", ".file-entry", ".button",
    ".button-primary", ".button-danger", ".button-danger-quiet", ".link-button", ".file-action",
    ".select", ".popup", ".popup-arrow", ".kmap-search", ".kmap-view", ".kmap-map", ".kmap-edge",
    ".kmap-dot", ".kmap-node", ".kmap-index", ".kmap-panel", ".kmap-approvals", ".kmap-swatch",
    ".ctx-menu", ".ctx-menu-item", ".ctx-menu-sep", ".dialog", ".balloon", ".version-notice",
    ".balloon-help", ".toast", ".stage", ".stage-close", "::selection", ":focus-visible",
)  # fmt: skip


def test_every_neutral_hook_is_styled() -> None:
    chrome = _css(CHROME)
    for hook in HOOKS:
        assert re.search(rf"{re.escape(SCOPE)}[^{{]*{re.escape(hook)}(?![\w-])", chrome), hook
    for tail in ("top", "bottom"):
        assert f'.balloon-help[data-tail="{tail}"]' in chrome
    for cat in range(8):
        assert f'.kmap-node[data-cat="{cat}"] .kmap-dot' in chrome
    for state in ("is-recent", "is-selected", "is-near"):
        assert state in chrome, state


def test_phone_bar_keeps_44px_targets_and_hides_the_clock() -> None:
    phone = _css(CHROME).split("@media (max-width: 37.49rem)", 1)[1]
    assert "min-height: var(--tap-target);" in phone
    assert re.search(r"\.shell-clock \{\s*display: none;", phone)


# --- motion ---


def _motion(css: str) -> list[str]:
    return re.findall(r"(?:^|[;{\s])((?:animation|transition)(?:-duration)?:[^;}]+)", css)


def test_motion_is_quiet_physical_and_token_timed() -> None:
    theme, chrome = _css(THEME), _css(CHROME)
    assert _decl(theme, "--motion-duration") == "180ms"
    assert _decl(theme, "--motion-ease").startswith("cubic-bezier(")
    for decl in _motion(chrome + _css(FX_CSS)):
        value = decl.split(":", 1)[1].strip()
        if value == "none":
            continue
        assert not re.findall(r"(?<![\w.-])(\d*\.?\d+m?s)\b", value), decl
        assert "var(--" in value, decl
        if decl.startswith("transition:"):
            props = {part.split()[0] for part in value.split(",")}
            # display/visibility only hold a hiding surface on screen while it fades
            # (discrete, nothing visibly interpolates); everything that moves is one of three.
            assert props <= {"box-shadow", "transform", "opacity", "display", "visibility"}, decl
    assert "@keyframes" not in chrome


def test_fx_runs_the_clock_and_kmap_moulding_always_and_the_rest_only_with_motion() -> None:
    body = _text(FX_JS)
    effects = re.findall(r"safe\(\"(\w+)\"", body)
    assert effects == ["clock", "kmap", "ghosts", "badges", "splash", "screensaver"]
    head, tail = body.split("if (REDUCE_MOTION) return;", 1)
    assert 'safe("clock"' in head and 'safe("clock"' not in tail
    # The knowledge map's moulding is structure: it runs too, told to leave its motion out.
    assert 'safe("kmap", () => initKmap(!REDUCE_MOTION))' in head
    clock = _text(NEU / "fx" / "clock.js")
    assert "visibilitychange" in clock and "document.hidden ? stop() : start()" in clock


# --- fonts ---


def test_nunito_is_vendored_with_its_licence_and_documented() -> None:
    table = _text(FONTS / "FONTS.md")
    fonts_css = _text(STATIC / "fonts.css")
    for weight in (400, 600, 800):
        name = f"nunito-{weight}.woff2"
        digest = hashlib.sha256((FONTS / name).read_bytes()).hexdigest()
        assert f"`{name}`" in table and digest in table, name
        assert f'url("/static/fonts/{name}")' in fonts_css
    assert "SIL Open Font License" in _text(FONTS / "OFL-nunito.txt")
    assert _decl(_css(THEME), "--font-chrome").startswith('"Nunito"')
