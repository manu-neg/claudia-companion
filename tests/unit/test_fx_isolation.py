"""Isolation guarantees for Platinum's cosmetic layer (backlog "R5 - Cosmetic
layer", moved to static/os/platinum/fx/ by O1; docs/frontend-fx.md,
docs/frontend-os.md).

The whole point of the fx layer is that it's optional: the functional
dashboard must work identically whether this directory exists, is deleted,
or throws. These tests check the boundary from the Python/static-analysis
side (import graph, network/storage surface, script-tag independence, and
that the static-asset loader is happy with fx/ entirely missing). The
matching real-browser proof (delete fx/, make it throw, load the app in
Chromium) is Playwright-only and documented in the hand-off report; it
can't run here because there's no browser in CI (docs/frontend.md). The
shared OS layer (registry, storage, pickers) is covered by
tests/unit/test_os_contract.py.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from preview_dashboard.interfaces.viewer.static_assets import StaticAssets, default_static_dir

STATIC = default_static_dir()
FX = STATIC / "os" / "platinum" / "fx"
FX_JS = sorted(FX.rglob("*.js"))
# Every registered OS's fx/ folder (F-A1: the boundary checks are not Platinum-only).
ALL_FX_JS = sorted((STATIC / "os").glob("*/fx/*.js"))
FX_CSS = FX / "fx.css"
FUNCTIONAL_JS = sorted(
    p
    for p in STATIC.rglob("*.js")
    if p.parts[len(STATIC.parts)] not in {"vendor", "preview-render", "os", "os-boot.js"}
)

IMPORT_FROM = re.compile(r'import\s+(?:[^;]+?)\s+from\s+"([^"]+)"')


def _imports(path: Path) -> list[str]:
    return IMPORT_FROM.findall(path.read_text("utf-8"))


def _code(path: Path) -> str:
    """Source with block comments stripped, so a comment mentioning e.g. "localStorage"
    can't be confused with code that uses it."""
    return re.sub(r"/\*.*?\*/", "", path.read_text("utf-8"), flags=re.S)


def test_fx_has_the_expected_modules() -> None:
    names = {p.relative_to(FX).as_posix() for p in FX_JS}
    assert {"fx.js", "zoom.js", "shade.js", "clock.js", "cursor.js", "splash.js",
            "screensaver.js"} <= names  # fmt: skip


def test_fx_modules_never_import_functional_modules() -> None:
    """fx/*.js may only import each other (relative, staying inside fx/)."""
    for path in ALL_FX_JS:
        for target in _imports(path):
            assert target.startswith("./"), f"{path.name}: non-relative import {target}"
            assert ".." not in target, f"{path.name}: escapes fx/ via {target}"


def test_functional_modules_never_import_fx() -> None:
    """The converse: app.js/api.js/feed.js/... never reach into fx/ (or anywhere in os/)."""
    for path in FUNCTIONAL_JS:
        for target in _imports(path):
            assert "fx/" not in target, f"{path.name}: imports fx via {target}"
            assert "os/" not in target, f"{path.name}: imports the OS layer via {target}"


def test_fx_never_touches_the_network() -> None:
    for path in ALL_FX_JS:
        source = _code(path)
        assert "fetch(" not in source, path.name
        assert "XMLHttpRequest" not in source, path.name
        assert not re.search(r"https?://", source), path.name
        assert "/api/" not in source, path.name


def test_fx_never_touches_storage() -> None:
    """Since O1 the background picker and its storage live in the shared OS layer
    (os/background.js, os/storage.js - test_os_contract.py); fx stores nothing."""
    for path in ALL_FX_JS:
        source = _code(path)
        assert "localStorage" not in source and "sessionStorage" not in source, path.name


def test_fx_only_runs_under_its_own_os() -> None:
    body = _code(FX / "fx.js")
    assert 'const OS = "platinum";' in body
    start = body.split("function start() {", 1)[1]
    assert start.lstrip().startswith("if (document.documentElement.dataset.os !== OS) return;")


def test_fx_reduced_motion_disables_only_the_animated_effects() -> None:
    """backlog §4: reduced motion turns off animation, not the whole layer.

    The clock, window shade and the watch cursor stay unconditional; only the
    startup splash and the idle screensaver are skipped. Zoom-open still runs
    (zoom.js), its actual animation is removed on the CSS side instead (see
    the fx.css assertion below).
    """
    body = (FX / "fx.js").read_text("utf-8")
    assert 'matchMedia("(prefers-reduced-motion: reduce)").matches' in body
    start = body.split("function start() {", 1)[1].split("\n}", 1)[0]
    always, gated = start.split("if (!REDUCE_MOTION) {", 1)
    for name in ("zoom", "shade", "clock", "cursor"):
        assert f'safe("{name}"' in always, name
        assert f'safe("{name}"' not in gated, name
    for name in ("splash", "screensaver"):
        assert f'safe("{name}"' in gated, name
        assert f'safe("{name}"' not in always, name


def test_fx_css_removes_animation_under_reduced_motion() -> None:
    """The CSS-side half of the same split: zoom-open and the screensaver's
    drift are the only animations fx.css defines, and both are neutralized."""
    css = FX_CSS.read_text("utf-8")
    block = css.split("@media (prefers-reduced-motion: reduce) {", 1)[1]
    assert ".fx-zoom-in" in block
    assert ".fx-screensaver-pattern" in block
    assert "animation: none;" in block


def test_fx_wraps_every_effect_so_one_failure_cant_take_down_another() -> None:
    body = (FX / "fx.js").read_text("utf-8")
    inits = re.findall(r'safe\("([a-z-]+)", init\w+\)', body)
    assert set(inits) == {"splash", "zoom", "shade", "clock", "cursor", "screensaver"}
    assert "try {" in body and "} catch (err) {" in body


def test_shade_box_is_drawn_by_the_effect_that_gives_it_meaning() -> None:
    """O1: the decorative shade square moved out of chrome.js (functional) into fx/shade.js,
    so deleting fx/ removes the square together with the behaviour behind it."""
    shade = _code(FX / "shade.js")
    assert 'box.className = "box box-shade";' in shade
    assert 'box.setAttribute("aria-hidden", "true");' in shade
    assert "tabIndex" not in shade  # pointer-only hint, never focusable (F-W2)
    assert "box-shade" not in (STATIC / "chrome.js").read_text("utf-8")


def test_dismissing_input_cannot_reach_what_is_underneath() -> None:
    """S2 F1: a dismissing pointerdown/tap must not let its synthesized click land on
    whatever's now underneath, and a dismissing keydown (e.g. Enter) must not also
    activate a focused control. Both splash.js and screensaver.js swallow exactly one
    following click (capture phase, with a timeout fallback) and prevent+stop the
    dismissing keydown itself."""
    for name in ("splash.js", "screensaver.js"):
        body = _code(FX / name)
        assert re.search(r'addEventListener\("click",\s*swallowNextClick,\s*true\)', body), name
        assert "CLICK_SWALLOW_MS" in body, name
        assert "event.preventDefault();" in body, name
        assert "event.stopPropagation();" in body, name
        # The click swallow itself must be capture-phase so it runs before the
        # newly-exposed target's own click handlers.
        swallow_fn = body.split("const swallowNextClick = (event) => {", 1)[1].split("};", 1)[0]
        assert "event.preventDefault();" in swallow_fn
        assert "event.stopPropagation();" in swallow_fn


def test_overlays_that_only_dismiss_keep_default_pointer_events() -> None:
    """splash/screensaver must stay clickable to dismiss (backlog: not pointer-events: none)."""
    css = FX_CSS.read_text("utf-8")
    for selector in (".fx-splash", ".fx-screensaver"):
        block = re.search(re.escape(selector) + r"\s*{([^}]*)}", css)
        assert block is not None, selector
        assert "pointer-events" not in block.group(1), selector


def test_fx_css_defines_no_url_or_remote_assets() -> None:
    css = FX_CSS.read_text("utf-8")
    assert "url(" not in css
    assert "@import" not in css


def test_index_html_loads_app_and_fx_as_two_independent_module_scripts() -> None:
    """Separate <script type=module> tags: a throw or 404 in one can't block the other."""
    html = (STATIC / "index.html").read_text("utf-8")
    scripts = re.findall(r'<script type="module" src="([^"]+)"></script>', html)
    assert "/static/app.js" in scripts
    assert "/static/os/platinum/fx/fx.js" in scripts
    assert len(scripts) == len(set(scripts))


def test_static_assets_load_fine_with_fx_entirely_deleted(tmp_path: Path) -> None:
    """The proof for 'app still works with os/platinum/fx/ deleted': the manifest loader (and
    thus the whole dashboard) doesn't need fx/ to exist at all."""
    copy = tmp_path / "static"
    shutil.copytree(STATIC, copy, ignore=shutil.ignore_patterns("fx"))
    assert not (copy / "os" / "platinum" / "fx").exists()
    assets = StaticAssets.load(copy)
    names = assets.names()
    assert "index.html" in names
    assert "app.js" in names
    assert not any(n.startswith("os/platinum/fx/") for n in names)
    # Every functional file that was on disk made it into the manifest untouched.
    full = StaticAssets.load(STATIC)
    # ignore_patterns("fx") drops every OS's fx/ folder, not just Platinum's.
    functional_names = {n for n in full.names() if not re.match(r"os/[^/]+/fx/", n)}
    assert names == functional_names
    for name in functional_names:
        assert assets.get(name).body == full.get(name).body  # type: ignore[union-attr]
