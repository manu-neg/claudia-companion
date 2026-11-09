"""Static guard for Aero's sprite-shape CSS: shapes are cloned into <use> shadow trees, so
their rules must match with no ancestor/:root selector, and every art class must be styled.
"""

from __future__ import annotations

import re

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

AERO = default_static_dir() / "os" / "aero"
CLASS_RE = re.compile(r"aero-(?:doc|c|ic)-[a-z]+(?:-[a-z]+)*")


def _art_classes() -> set[str]:
    js = (AERO / "shell.js").read_text("utf-8")
    classes = set(CLASS_RE.findall(js))
    # Colour classes are built as `aero-c-${colour}` from f()/s() arguments and the bundle list.
    colours = re.findall(r'\b[fs]\((?:"[^"]*"|`[^`]*`),\s*"([a-z]+)"', js)
    colours += re.findall(r'\[[\d.]+, [\d.]+, "([a-z]+)"\]', js)
    classes |= {f"aero-c-{c}" for c in colours}
    return classes


def _selectors() -> list[str]:
    css_files = [*AERO.glob("*.css"), *(AERO / "fx").glob("*.css")]
    found: list[str] = []
    for path in css_files:
        css = re.sub(r"/\*.*?\*/", "", path.read_text("utf-8"), flags=re.S)
        for prelude in re.findall(r"([^{}]+)\{", css):
            found += [p.strip() for p in prelude.split(",") if p.strip()]
    return found


def test_art_classes_found() -> None:
    assert len(_art_classes()) > 30


def test_every_art_class_has_an_unscoped_rule() -> None:
    selectors = _selectors()
    unstyled = []
    for cls in sorted(_art_classes()):
        hits = [s for s in selectors if re.search(rf"\.{cls}(?![\w-])", s)]
        if not hits:
            unstyled.append(cls)
        for sel in hits:
            # A bare class (optionally with pseudo-classes) survives the <use> shadow tree.
            assert re.fullmatch(rf"\.{cls}(?::[\w-]+)*", sel), f"scoped icon-art selector: {sel}"
    assert not unstyled, f"art classes without a rule: {unstyled}"
