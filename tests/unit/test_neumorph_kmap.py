"""Neumorph knowledge map (N3 + N4 + N4b, docs/frontend-os.md#neumorph "Knowledge map").

Checks: the eight category LEDs are >= 3:1 on the porcelain and distinct; every map hook and
state (stage, keys, LEDs, grooves, labels, index, note slab, approvals incl. the F-CL6 code form)
has a rule; the stage never shows a box outline; the approvals card is never hidden or animated
away (C46 independent view); keys are moulded from the surface (no dot grid, no plates, no
shine) and read as keys + LEDs in a dish without fx/; each key has ONE shadow (the ring's soft
pair; no shadow discs); selected is the press, latched; the map keyframes only move transform /
opacity / stroke-dashoffset, and filter only in the eased height of a key in play; the groove
carving lies inside the groove; every lit channel draws; fx/kmap.js is decoration only, in
flat fills (no url(): no network, storage, HTML or text sinks, no prevented events, passive
listeners, CSSOM writes, aria-hidden decor, pauses while hidden, skips selected keys in the
pointer light) and moulds the map under reduced motion too, with its motion left out.
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
    flat = re.sub(r"@property[^{]*\{[^{}]*\}", "", flat)
    return [(m.group(1).strip(), m.group(2)) for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", flat)]


def _rule(css: str, selector: str) -> str:
    bodies = [body for sel, body in _rules(css) if sel == selector]
    assert bodies, selector
    return "".join(bodies)


def test_category_leds_are_distinct_and_at_least_3_to_1_on_the_porcelain() -> None:
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
    ".kmap-node.is-filtered", ".kmap-node.is-near", ".kmap-node:active", ".kmap-node:hover",
    ".kmap-svg.has-focus", ".kmap-swatch", ".kmap-index",
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


def test_the_map_is_moulded_from_the_surface_and_reads_as_keys_without_fx() -> None:
    # The floor is one smooth well: no dot grid, no dimple texture.
    basin = _rule(CHROME, f"{SCOPE} .kmap-map")
    assert "background-image" not in basin and "gradient" not in basin
    assert "--neu-kmap-dimples" not in CHROME
    # Without fx/: the ring is a surface-coloured key with a CSS drop-shadow pair; the dot a
    # small flat LED of the category colour; N3's shine is gone; labels have no plate.
    ring = _rule(CHROME, f"{SCOPE} .kmap-ring")
    assert "fill: var(--neu-kmap-key)" in ring and ring.count("drop-shadow(") == 2
    assert "var(--neu-kmap-shade)" in ring and "var(--neu-kmap-light)" in ring
    dot = _rule(CHROME, f"{SCOPE} .kmap-dot")
    assert "var(--neu-kmap-cat" in dot and "var(--neu-kmap-led-k)" in dot
    # Never a bare dot: the LED sits in a dish (its own wide stroke, painted under it).
    assert "stroke: var(--neu-kmap-dish)" in dot and "paint-order: stroke" in dot
    assert "display: none" in _rule(CHROME, f"{SCOPE} .kmap-shine")
    label = _rule(CHROME, f"{SCOPE} .kmap-label")
    assert "stroke: none" in label and "filter: var(--neu-kmap-engrave)" in label
    assert "--neu-kmap-label-plate" not in CHROME


def test_selected_is_the_press_latched_and_states_rank_in_source_order() -> None:
    lift = re.compile(r"--neu-kmap-lift:\s*var\((--neu-kmap-lift-[a-z]+)\)")
    order = [(sel, m.group(1)) for sel, body in _rules(CHROME) if (m := lift.search(body))]
    levels = [level for _, level in order]
    assert levels == [
        "--neu-kmap-lift-low",  # unrelated under focus, non-matches
        "--neu-kmap-lift-up",  # neighbours, matches
        "--neu-kmap-lift-up",  # hover
        "--neu-kmap-lift-flush",  # press and selected: one rule, the same height
    ]
    press = order[-1][0]
    assert ".kmap-node:active" in press and ".kmap-node.is-selected" in press
    # Every state selector weighs the same (:where), so the order above is the priority.
    assert all(f"{SCOPE} :where(" in sel for sel, _ in order)
    # Selected carries only a hairline iris border.
    assert re.search(r"--neu-kmap-hairline:\s*rgb\(81 70 216 / 0\.3\);", CHROME)
    hairline = _rule(CHROME, f"{SCOPE} :where(.kmap-node.is-selected) .kmap-ring")
    assert "var(--neu-kmap-hairline)" in hairline and "stroke-width: 0.75px" in hairline


def test_map_keyframes_only_move_transform_opacity_dashoffset_and_custom_properties() -> None:
    blocks = re.findall(r"@keyframes (neumorph-kmap-[\w-]+) \{((?:[^{}]*\{[^{}]*\})*)\s*\}", FX)
    heights = {"neumorph-kmap-raise", "neumorph-kmap-press", "neumorph-kmap-settle"}
    assert {name for name, _ in blocks} >= {
        "neumorph-kmap-rise", "neumorph-kmap-swell", "neumorph-kmap-draw", "neumorph-kmap-ripple",
        "neumorph-kmap-breathe", "neumorph-kmap-spark", "neumorph-kmap-page",
        "neumorph-kmap-lift", *heights,
    }  # fmt: skip
    for name, body in blocks:
        props = set(re.findall(r"([a-z-]+)\s*:", body))
        allowed = {
            "transform", "opacity", "stroke-dashoffset", "stroke-dasharray",
            "animation-timing-function",
        }  # fmt: skip
        if name in heights:
            # A key in play eases its one shadow from the height it had: the ring's pair only.
            assert props == {"filter"} and body.count("drop-shadow(") == 2, name
            assert "var(--neu-kmap-was)" in body and "to {" not in body, name
            continue
        assert props <= allowed, name
        # dasharray is held (the same in every frame), never interpolated.
        held = set(re.findall(r"stroke-dasharray:\s*([^;]+);", body))
        assert len(held) <= 1, name


def test_filters_are_static_one_pass_on_layers_never_per_line_or_animated() -> None:
    chrome, fx = dict(_rules(CHROME)), dict(_rules(FX))
    layer = f"{SCOPE} .kmap-svg g:has(> .kmap-edge)"
    assert "filter: var(--neu-kmap-lip)" in chrome[layer]
    # fx/ drops the layer filter: the carving is plain stroke copies over the edge layer, a shade
    # layer and a light layer nudged one screen pixel (1/zoom) apart, narrower than the groove
    # so both stay inside it (one channel, never parallel lines).
    moulded = fx[f"{SCOPE} .kmap-svg.neumorph-kmap-moulded g:has(> .kmap-edge)"]
    assert "filter: none" in moulded
    carve = fx[f"{SCOPE} .neumorph-kmap-carve"]
    assert "vector-effect: non-scaling-stroke" in carve and "var(--neu-kmap-carve-w)" in carve
    carve_w = re.search(r"--neu-kmap-carve-w:\s*(\d+)px;", FX)
    groove_w = re.search(r"--neu-kmap-groove-w:\s*(\d+)px;", CHROME)
    assert carve_w and groove_w and int(groove_w.group(1)) - int(carve_w.group(1)) >= 2
    tag_carve = fx[f'{SCOPE} .neumorph-kmap-carve[data-kind="tag"]']
    assert "stroke-dasharray: 0.1 var(--neu-kmap-dimple)" in tag_carve
    assert "viewport.insertBefore(carves, flows)" in KMAP_JS and "(1 / k)" in KMAP_JS
    assert "filter" not in chrome[f"{SCOPE} .kmap-edge"]
    # One key, one shadow: the ring keeps chrome's soft pair; no shadow discs anywhere.
    assert f"{SCOPE} .kmap-svg.neumorph-kmap-moulded .kmap-ring" not in fx
    for name in ("neumorph-kmap-shade", "neumorph-kmap-glow", "--neu-kmap-disc"):
        assert name not in FX and name not in KMAP_JS and name not in CHROME, name
    for css in (CHROME, FX):
        for selector, body in _rules(css):
            if ".kmap" in selector or "neumorph-kmap" in selector:
                assert not re.search(r"transition[^;]*filter", body), selector


def test_only_keys_in_play_ease_so_a_focus_change_repaints_the_map_once() -> None:
    eased = {
        m.group(1): sel
        for sel, body in _rules(FX)
        if (m := re.search(r"animation:\s*(neumorph-kmap-(?:raise|press|settle)) ", body))
    }
    assert set(eased) == {"neumorph-kmap-raise", "neumorph-kmap-press", "neumorph-kmap-settle"}
    states = {
        "neumorph-kmap-settle": ("neumorph-kmap-settling",),
        "neumorph-kmap-raise": (":hover", ".is-near"),
        "neumorph-kmap-press": (":active", ".is-selected"),
    }
    for name, wanted in states.items():
        sel = eased[name]
        assert sel.startswith(f"{SCOPE} :where(") and sel.endswith(") .kmap-ring"), sel
        for state in wanted:
            assert state in sel, (name, state)
    # Same weight, so source order is the priority: settle < raise < press.
    order = [sel for sel, _ in _rules(FX)]
    assert order.index(eased["neumorph-kmap-settle"]) < order.index(eased["neumorph-kmap-raise"])
    assert order.index(eased["neumorph-kmap-raise"]) < order.index(eased["neumorph-kmap-press"])
    # A let-go key eases from the height it left (kmap.js writes it).
    assert '"--neu-kmap-left"' in KMAP_JS and "LEFT_FLUSH" in KMAP_JS
    # The pointer light turns only the ring (not the whole key), frame by frame, uneased.
    assert "neumorph-kmap-lit" not in FX and 'n.ring.style.setProperty("--neu-kmap-sx"' in KMAP_JS
    # Map-wide changes (edges, nodes, labels) don't fade.
    for selector, body in _rules(CHROME):
        if re.search(r"\.kmap-(edge|node|label)\s*$", selector):
            assert "transition" not in body, selector


def test_every_lit_channel_draws_out_of_the_focused_note() -> None:
    rules = dict(_rules(FX))
    draw = rules[f"{SCOPE} .neumorph-kmap-flow"]
    assert "animation: neumorph-kmap-draw var(--neu-dur-kmap-flow)" in draw
    # Tag channels: one iris spark per dimple, each lit as the light reaches it.
    spark = rules[f"{SCOPE} .neumorph-kmap-spark"]
    assert "animation: neumorph-kmap-spark" in spark
    assert "animation-delay: calc(var(--neu-dur-kmap-flow) * var(--neu-kmap-t))" in spark
    assert "DIMPLE_PX = 11;" in KMAP_JS and re.search(r"--neu-kmap-dimple:\s*11px;", CHROME)
    # The light starts at the focused note's end of the groove.
    assert "edge.dataset.source === focus" in KMAP_JS


def test_kmap_fx_is_decoration_only() -> None:
    banned = [
        "fetch(", "XMLHttpRequest", "/api/", "http://", "https://", "localStorage",
        "sessionStorage", "document.cookie", "innerHTML", "outerHTML", "insertAdjacent",
        "textContent", "innerText", "createTextNode",
        "preventDefault", "stopPropagation", "location", "eval(", "import(", "postMessage",
        "setAttribute(\"style\"", "cloneNode", ".title", "dataset.title",
    ]  # fmt: skip
    for name in banned:
        assert name not in KMAP_JS, name
    # Even the SVG namespace is read from the map (svg.namespaceURI), not written out.
    assert re.findall(r"https?:", KMAP_JS) == []
    # Styles only through CSSOM.
    assert "style.setProperty(" in KMAP_JS
    assert not re.search(r"\.style\.(?!setProperty|removeProperty)[a-zA-Z]+", KMAP_JS)
    # Every listener it adds to the map is passive; it never blocks a gesture.
    adds = re.findall(r"svg\.addEventListener\(([^)]*)\)", KMAP_JS)
    assert adds and all("passive: true" in a for a in adds)
    # Its own decor is empty and hidden from assistive tech: every SVG part goes through decor()
    # (one aria-hidden), the ripple div is the other; one flow layer.
    assert KMAP_JS.count('setAttribute("aria-hidden", "true")') == 2
    assert KMAP_JS.count('decor("g", FLOWS)') == 1
    assert KMAP_JS.count("document.createElement(") == 1
    # Flat fills only: no paint servers, filters, masks or ids of its own (an OS may not url()).
    assert "url(" not in KMAP_JS and '"id"' not in KMAP_JS
    for tag in ("defs", "filter", "mask", "Gradient", "pattern"):
        assert f'"{tag}' not in KMAP_JS, tag
    # Frames only on demand, none while the tab is hidden.
    assert "requestAnimationFrame" in KMAP_JS and "setInterval(" not in KMAP_JS
    assert "visibilitychange" in KMAP_JS and "document.hidden" in KMAP_JS
    # The pointer light leaves a latched (selected) key alone.
    assert 'classList.contains("is-selected")' in KMAP_JS


def test_kmap_fx_moulds_under_reduced_motion_with_its_motion_left_out() -> None:
    body = (NEU / "fx" / "fx.js").read_text("utf-8")
    head, tail = body.split("if (REDUCE_MOTION) return;", 1)
    # The moulding is structure, not motion: started before the reduced-motion return, told
    # whether motion is allowed, so a key is never a bare dot.
    assert 'safe("kmap", () => initKmap(!REDUCE_MOTION))' in head
    assert 'safe("kmap"' not in tail
    assert "export function initKmap(motion = true)" in KMAP_JS
    # Without motion: no opening wave, no ripple, no pointer light.
    assert "if (!motion) return;" in KMAP_JS
    assert "if (motion) ripple(chosen);" in KMAP_JS
    assert 'if (motion) svg.addEventListener("pointermove"' in KMAP_JS
    reduced = FX.split("@media (prefers-reduced-motion: reduce)", 1)[1]
    for token in re.findall(r"(--neu-dur-kmap-[a-z]+):", CHROME):
        assert f"{token}: 0ms;" in reduced, token
    for selector in (
        ".neumorph-kmap-flow,", ".neumorph-kmap-spark,",
        ".kmap-svg.neumorph-kmap-opening .kmap-node", ".neumorph-kmap-ripple",
    ):  # fmt: skip
        assert selector in reduced, selector
