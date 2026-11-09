"""Aero-specific checks (docs/frontend-os.md#aero); the generic OS contract lives in
test_os_contract.py and already covers Aero's scoping, tokens and reduced-motion list.

Here: Aero is registered with its background set; one shared motion system (every animation
and transition is timed by the --aero-*/--motion-* tokens, UI timings stay <= 300ms, only
transform/opacity move, every duration token zeroes under reduced motion, fx.js skips the
moving effects there); no network or url() anywhere in the OS; the sprite art covers every
shared symbol; the vendored Catamaran fonts match FONTS.md; and the token colour pairs pass
WCAG AA.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
AERO = STATIC / "os" / "aero"
CHROME = AERO / "chrome.css"
FX_CSS = AERO / "fx" / "fx.css"
FX_JS = AERO / "fx" / "fx.js"
THEME = AERO / "theme.css"
FONTS = STATIC / "fonts"


def _text(path: Path) -> str:
    return path.read_text("utf-8")


def _css(path: Path) -> str:
    return re.sub(r"/\*.*?\*/", "", _text(path), flags=re.S)


def _decl(css: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}:\s*([^;]+);", css)
    assert match is not None, name
    return match.group(1).strip()


# --- registration ---


def test_aero_is_registered_with_sky_first_and_four_more_backgrounds() -> None:
    registry = _text(STATIC / "os" / "registry.js")
    assert 'aero: Object.freeze({ label: "Aero", backgrounds: aeroBackgrounds })' in registry
    ids = re.findall(r'id: "([a-z-]+)"', _text(AERO / "backgrounds.js"))
    assert ids[0] == "sky" and len(ids) >= 5


# --- one motion system ---

DURATION_TOKENS = re.compile(r"(--aero-dur-[a-z]+):\s*([^;]+);")
UI_DURATIONS = ("--aero-dur-press", "--aero-dur-fast", "--aero-dur-menu", "--aero-dur-slow",
                "--aero-dur-glint")  # fmt: skip


def _ms(value: str) -> float:
    match = re.fullmatch(r"([\d.]+)(ms|s)", value.strip())
    assert match is not None, value
    return float(match.group(1)) * (1 if match.group(2) == "ms" else 1000)


def test_ui_motion_is_short_and_soft() -> None:
    chrome = _css(CHROME)
    for name in UI_DURATIONS:
        assert _ms(_decl(chrome, name)) <= 300, name
    theme = _css(THEME)
    assert _ms(_decl(theme, "--motion-duration")) <= 300
    # A decelerating (ease-out) curve, never linear or stepped, for UI motion.
    assert _decl(theme, "--motion-ease").startswith("cubic-bezier(")
    assert "steps(" not in chrome + _css(FX_CSS)


def test_every_duration_token_is_zeroed_under_reduced_motion() -> None:
    declared = {
        name for name, value in DURATION_TOKENS.findall(_css(CHROME)) if "var(" not in value
    }
    reduced = _css(FX_CSS).split("@media (prefers-reduced-motion: reduce)", 1)[1]
    zeroed = {name for name, value in DURATION_TOKENS.findall(reduced) if value.strip() == "0ms"}
    assert declared and declared <= zeroed, declared - zeroed


def _motion_declarations(css: str) -> list[str]:
    return re.findall(r"(?:^|[;{\s])((?:animation|transition)(?:-duration|-delay)?:[^;}]+)", css)


def test_animations_and_transitions_are_timed_only_by_motion_tokens() -> None:
    for path in (CHROME, FX_CSS):
        for decl in _motion_declarations(_css(path)):
            if decl.split(":", 1)[1].strip() in {"none", "visibility 0s"}:
                continue
            # "0s" is the instant visibility flip of the toast; everything else is a token.
            literal = re.findall(r"(?<![\w.-])(\d*\.?\d+m?s)\b", decl)
            assert set(literal) <= {"0s"}, f"{path.name}: {decl}"
            assert "var(--" in decl, f"{path.name}: {decl}"


def test_only_transform_and_opacity_move() -> None:
    css = _css(FX_CSS) + _css(CHROME)
    for name, body in re.findall(r"@keyframes\s+([\w-]+)\s*\{((?:[^{}]*\{[^}]*\})*[^{}]*)\}", css):
        props = set(re.findall(r"([a-z-]+)\s*:", body))
        assert props <= {"opacity", "transform"}, f"{name}: {props}"
    for decl in _motion_declarations(css):
        if decl.startswith("transition:"):
            props = {part.split()[0] for part in decl.split(":", 1)[1].split(",")}
            assert props <= {"opacity", "transform", "visibility", "none"}, decl


def test_fx_skips_moving_effects_under_reduced_motion() -> None:
    body = _text(FX_JS)
    start = body.split("function start() {", 1)[1]
    guard = start.index("if (REDUCE_MOTION) return;")
    for effect in ("initClose", "initBadges", "initAmbient", "initSplash", "initScreensaver"):
        assert start.index(effect) > guard, effect
    assert start.index("initClock") < guard  # the clock isn't motion


def test_close_fade_only_delays_plain_clicks_on_the_close_control() -> None:
    source = _text(AERO / "fx" / "close.js")
    assert "event.metaKey || event.ctrlKey || event.shiftKey || event.altKey" in source
    assert "event.button !== 0" in source and "event.defaultPrevented" in source
    assert "location.hash = hash;" in source and "setTimeout(go, FALLBACK_MS)" in source


# --- no network, no external references ---


def test_aero_references_nothing_outside_the_dashboard() -> None:
    for path in AERO.rglob("*"):
        if path.is_file():
            source = _text(path)
            assert "url(" not in source and "@import" not in source, path.name
            assert not re.search(r"https?://", source), path.name
    shell = _text(AERO / "shell.js")
    assert "sprite.namespaceURI" in shell and "createElementNS(ns," in shell


def test_sprite_art_covers_every_shared_symbol() -> None:
    symbols = set(re.findall(r'<symbol id="([a-z-]+)"', _text(STATIC / "index.html")))
    shell = _text(AERO / "shell.js")
    art = set(re.findall(r'^\s*"(i-[a-z-]+)":', shell, re.M)) | set(
        re.findall(r'ART\["(i-[a-z-]+)"\] =', shell)
    )
    assert symbols and symbols <= art, symbols - art


# --- fonts ---


def test_catamaran_is_vendored_with_its_licence_and_documented() -> None:
    table = _text(FONTS / "FONTS.md")
    fonts_css = _text(STATIC / "fonts.css")
    for weight in (400, 700, 800):
        name = f"catamaran-{weight}.woff2"
        digest = hashlib.sha256((FONTS / name).read_bytes()).hexdigest()
        assert f"`{name}`" in table and digest in table, name
        assert f'url("/static/fonts/{name}")' in fonts_css
    assert "SIL Open Font License" in _text(FONTS / "OFL-catamaran.txt")
    assert _decl(_css(THEME), "--font-chrome").startswith('"Catamaran"')


# --- contrast of the token pairs (rendered-pixel checks are in the hand-off report) ---


def _lum(hex_color: str) -> float:
    rgb = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_token_text_pairs_pass_wcag_aa() -> None:
    theme = _css(THEME)
    tok = {name: _decl(theme, name) for name in re.findall(r"(--color-[a-z-]+):", theme)}
    pairs = [
        ("--color-text", "--color-window"),
        ("--color-text", "--color-surface"),
        ("--color-text-muted", "--color-surface"),
        ("--color-text-muted", "--color-surface-sunken"),
        ("--color-text-muted", "--color-window"),
        ("--color-accent-contrast", "--color-accent"),
        ("--color-accent-contrast", "--color-accent-hover"),
        ("--color-danger-contrast", "--color-danger"),
        ("--color-danger-contrast", "--color-danger-hover"),
        ("--color-danger", "--color-surface"),
        ("--color-focus", "--color-surface"),
        ("--color-warning-text", "--color-warning-soft"),
        ("--color-text", "--color-warning-soft"),
    ]
    for fg, bg in pairs:
        assert _ratio(tok[fg], tok[bg]) >= 4.5, (fg, bg, round(_ratio(tok[fg], tok[bg]), 2))


def test_hidden_tab_freezes_the_screensaver_bubbles_and_the_timers_stop() -> None:
    """F-A1: ambient.js toggles html.aero-paused; the screensaver's bubbles obey it too, and
    the screensaver/clock stop their timers on visibilitychange."""
    css = _css(FX_CSS)
    rule = re.search(r':root\[data-os="aero"\]\.aero-paused \.aero-screensaver \*\s*{([^}]*)}', css)
    assert rule is not None and "animation-play-state: paused" in rule.group(1)
    saver = _text(AERO / "fx" / "screensaver.js")
    assert 'addEventListener("visibilitychange", onVisibility)' in saver
    assert "n >= MIN_IDLE_MS" in saver
    clock = _text(AERO / "fx" / "clock.js")
    assert 'addEventListener("visibilitychange"' in clock and "clearInterval" in clock
