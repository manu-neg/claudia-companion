"""Neumorph knowledge map (N3, docs/frontend-os.md#neumorph "Knowledge map").

Checks: the eight category cores are >= 3:1 on the porcelain and distinct; every map hook and
state (stage, pearls, channels, labels, index, note slab, approvals incl. the F-CL6 code form) has
a rule; the stage never shows a box outline; the approvals card is never hidden or animated away
(C46 independent view); the map keyframes only move transform / opacity / stroke-dashoffset;
fx/kmap.js is decoration only (no network, storage, HTML or text sinks, no prevented events,
passive listeners, CSSOM writes, aria-hidden decor, pauses while hidden) and runs only with
motion allowed.
"""

from __future__ import annotations

import re
from itertools import combinations
from pathlib import Path

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
NEU = STATIC / "os" / "neumorph"
SCOPE = ':root[data-os="neumorph"]'


def _css(path: Path) -> str:
    return re.sub(r"/\*.*?\*/", "", path.read_text("utf-8"), flags=re.S)


def _code(path: Path) -> str:
    source = path.read_text("utf-8")
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", source, flags=re.S))


CHROME = _css(NEU / "chrome.css")
FX = _css(NEU / "fx" / "fx.css")
KMAP_JS = _code(NEU / "fx" / "kmap.js")


def _lum(hex_color: str) -> float:
    rgb = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(a: str, b: str) -> float:
    hi, lo = sorted((_lum(a), _lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _rules(css: str) -> list[tuple[str, str]]:
    """(selector list, body) of every plain rule, media blocks flattened."""
    flat = re.sub(r"@media[^{]*\{((?:[^{}]*\{[^{}]*\})*)\s*\}", r"\1", css)
    flat = re.sub(r"@keyframes[^{]*\{(?:[^{}]*\{[^{}]*\})*\s*\}", "", flat)
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", flat)]


def test_category_cores_are_distinct_and_at_least_3_to_1_on_the_porcelain() -> None:
    theme = _css(NEU / "theme.css")
    match = re.search(r"--color-surface:\s*(#[0-9a-f]{6})", theme)
    assert match
    surface = match.group(1)
    cores = re.findall(r"--kmap-c[0-7]:\s*(#[0-9a-f]{6});", CHROME)
    assert len(cores) == 8 and len(set(cores)) == 8
    for core in cores:
        assert _ratio(core, surface) >= 3, (core, round(_ratio(core, surface), 2))
    # Distinguishable from each other, not only from the floor.
    for a, b in combinations(cores, 2):
        gap = sum(abs(int(a[i : i + 2], 16) - int(b[i : i + 2], 16)) for i in (1, 3, 5))
        assert gap > 60, (a, b)


MAP_HOOKS = (
    ".kmap-map", ".kmap-svg", ".kmap-message", ".kmap-edge", '.kmap-edge[data-kind="tag"]',
    ".kmap-edge.is-near", ".kmap-edge.is-filtered", ".kmap-node", ".kmap-ring", ".kmap-dot",
    ".kmap-shine", ".kmap-label", ".kmap-node.is-recent", ".kmap-node.is-selected",
    ".kmap-node.is-filtered", ".kmap-svg.has-focus", ".kmap-swatch", ".kmap-index",
    ".kmap-section-title", ".kmap-count", ".kmap-entries", ".kmap-entry-button",
    ".kmap-entry.is-selected", ".kmap-new", ".kmap-panel", ".kmap-panel-hint", ".kmap-panel-nav",
    ".kmap-note-title", ".kmap-note-meta", ".kmap-tags", ".kmap-tag", ".kmap-heading",
    ".kmap-list", ".kmap-quote", ".kmap-code", ".kmap-link", ".kmap-link.is-missing",
    ".kmap-backlinks", ".kmap-backlinks-title", ".kmap-backlink-list", ".kmap-statusbar",
    ".kmap-zooms", ".kmap-zoom", ".kmap-views", ".kmap-view", ".kmap-search",
)  # fmt: skip

APPROVAL_HOOKS = (
    ".kmap-approvals", ".kmap-approval-list", ".kmap-approval", ".kmap-approval-text",
    ".kmap-approval-id", ".kmap-approvals-none", ".kmap-approvals-note", ".kmap-approval-actions",
    ".kmap-approval-code", ".kmap-code-row", ".kmap-code-input", ".kmap-approval-status",
)  # fmt: skip


def test_every_map_and_approvals_hook_and_state_has_a_neumorph_rule() -> None:
    selectors = " ".join(sel for sel, _ in _rules(CHROME))
    for hook in (*MAP_HOOKS, *APPROVAL_HOOKS):
        assert re.search(rf"{re.escape(hook)}(?![\w-])", selectors), hook
    for cat in range(8):
        assert f'.kmap-node[data-cat="{cat}"] .kmap-dot' in selectors
        assert f'.kmap-swatch[data-cat="{cat}"]' in selectors
    # The approvals LED has a state for: waiting / can't be checked, and code entry open.
    led = " .group-title::before"
    assert f".kmap-approvals:has(.kmap-approval){led}" in selectors
    assert ".kmap-approvals:has(.kmap-approvals-none + .kmap-approvals-note)" in selectors
    assert f".kmap-approvals:has(.kmap-approval-code:not([hidden])){led}" in selectors
    # The empty status line stays hidden (Neumorph gives it a display of its own).
    empty = rf"{re.escape(SCOPE)} \.kmap-approval-status:empty \{{\s*display: none;"
    assert re.search(empty, CHROME)


def test_the_map_never_shows_a_box_outline_and_focus_lights_the_basin_rim() -> None:
    rules = dict(_rules(CHROME))
    focus = f"{SCOPE} .kmap-svg:focus,\n{SCOPE} .kmap-svg:focus-visible"
    assert "outline: none" in rules[focus]
    ring = rules[f"{SCOPE} .kmap-map:has(> .kmap-svg:focus-visible)"]
    assert "var(--neu-kmap-basin-ring)" in ring
    assert re.search(r"--neu-kmap-basin-ring:\s*inset 0 0 0 3px var\(--color-focus\);", CHROME)


def test_the_approvals_card_is_never_hidden_clipped_or_animated_away() -> None:
    hiding = re.compile(
        r"display:\s*none|visibility:\s*hidden|opacity:\s*0(?:[;\s]|$)|clip|overflow:\s*hidden"
        r"|text-overflow|line-clamp|pointer-events:\s*none"
    )
    for css in (CHROME, FX):
        for selector, body in _rules(css):
            if "approval" not in selector:
                continue
            if selector.endswith(".kmap-approval-status:empty"):
                continue
            assert not hiding.search(body), selector
    # Only the code plate's entrance and the busy LED move; never the text or the keys.
    animated = [
        sel
        for sel, body in _rules(FX)
        if "approval" in sel and re.search(r"animation:\s*neumorph-", body)
    ]
    assert sorted(animated) == sorted(
        [
            f"{SCOPE} .kmap-approval-code:not([hidden])",
            f"{SCOPE} .kmap-approvals:has(.kmap-approval button:disabled) .group-title::before",
        ]
    )
    assert "approval" not in KMAP_JS


def test_map_keyframes_only_move_transform_opacity_and_dashoffset() -> None:
    blocks = re.findall(r"@keyframes (neumorph-kmap-[\w-]+) \{((?:[^{}]*\{[^{}]*\})*)\s*\}", FX)
    assert {name for name, _ in blocks} >= {
        "neumorph-kmap-rise", "neumorph-kmap-socket", "neumorph-kmap-draw", "neumorph-kmap-trickle",
        "neumorph-kmap-seat", "neumorph-kmap-ripple", "neumorph-kmap-breathe", "neumorph-kmap-page",
        "neumorph-kmap-lift",
    }  # fmt: skip
    for name, body in blocks:
        props = set(re.findall(r"([a-z-]+)\s*:", body))
        allowed = {
            "transform", "opacity", "stroke-dashoffset", "stroke-dasharray",
            "animation-timing-function",
        }  # fmt: skip
        assert props <= allowed, name
        # dasharray is held (the same in every frame), never interpolated.
        held = set(re.findall(r"stroke-dasharray:\s*([^;]+);", body))
        assert len(held) <= 1, name


def test_channel_light_lip_is_one_filter_on_the_layer_not_one_per_line() -> None:
    rules = dict(_rules(CHROME))
    assert "filter: var(--neu-kmap-lip)" in rules[f"{SCOPE} .kmap-svg g:has(> .kmap-edge)"]
    assert "filter" not in rules[f"{SCOPE} .kmap-edge"]


def test_kmap_fx_is_decoration_only() -> None:
    banned = [
        "fetch(", "XMLHttpRequest", "/api/", "http://", "https://", "localStorage",
        "sessionStorage", "document.cookie", "innerHTML", "outerHTML", "insertAdjacent",
        "textContent", "innerText",
        "preventDefault", "stopPropagation", "location", "eval(", "import(", "postMessage",
        "setAttribute(\"style\"", "cloneNode",
    ]  # fmt: skip
    for name in banned:
        assert name not in KMAP_JS, name
    # Styles only through CSSOM custom properties.
    assert "style.setProperty(" in KMAP_JS
    assert not re.search(r"\.style\.(?!setProperty|removeProperty)[a-zA-Z]+", KMAP_JS)
    # Every listener it adds to the map is passive; it never blocks a gesture.
    adds = re.findall(r"svg\.addEventListener\(([^)]*)\)", KMAP_JS)
    assert adds and all("passive: true" in a for a in adds)
    # Its own decor is empty and hidden from assistive tech.
    assert KMAP_JS.count('setAttribute("aria-hidden", "true")') == 2
    # Frames only on demand, none while the tab is hidden.
    assert "requestAnimationFrame" in KMAP_JS and "setInterval(" not in KMAP_JS
    assert "visibilitychange" in KMAP_JS and "document.hidden" in KMAP_JS


def test_kmap_fx_runs_only_with_motion_allowed() -> None:
    body = (NEU / "fx" / "fx.js").read_text("utf-8")
    head, tail = body.split("if (REDUCE_MOTION) return;", 1)
    # The effect is only started after the reduced-motion early return.
    assert 'safe("kmap", initKmap)' in tail
    assert 'safe("kmap"' not in head
    reduced = FX.split("@media (prefers-reduced-motion: reduce)", 1)[1]
    for token in re.findall(r"(--neu-dur-kmap-[a-z]+):", CHROME):
        assert f"{token}: 0ms;" in reduced, token
    assert ".neumorph-kmap-light {\n    display: none;" in reduced
