"""Structural checks for W1 (owner UI feedback round 6): balloon hints,
zoom-box removal, a close box only where it works, the single-file download row, the
kind-icon-as-plain-icon + visible Pin button, and body-level backgrounds.

`balloon.js` manipulates real DOM (`document`), so - like `menu.js` - it can't run
standalone under plain Node (no jsdom dependency in this repo). These tests pin the
contract at the source level, the same style as `test_context_menu.py`.
"""

from __future__ import annotations

import re

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
BALLOON = (STATIC / "balloon.js").read_text("utf-8")
CHROME = (STATIC / "chrome.js").read_text("utf-8")
ITEM = (STATIC / "item.js").read_text("utf-8")
FEED = (STATIC / "feed.js").read_text("utf-8")
MENU = (STATIC / "menu.js").read_text("utf-8")
EXPAND = (STATIC / "expand.js").read_text("utf-8")
APP_JS = (STATIC / "app.js").read_text("utf-8")
APP_CSS = (STATIC / "app.css").read_text("utf-8")
INDEX_HTML = (STATIC / "index.html").read_text("utf-8")
FX_DESKTOP = (STATIC / "os" / "background.js").read_text("utf-8")
SHELL_MENU = (STATIC / "os" / "shell-menu.js").read_text("utf-8")
FX_SHADE = (STATIC / "os" / "platinum" / "fx" / "shade.js").read_text("utf-8")
OS_CHROME_CSS = (STATIC / "os" / "platinum" / "chrome.css").read_text("utf-8")


# --- balloon.js itself ---


def test_balloon_exports_init_and_is_wired_from_app_js() -> None:
    assert "export function initBalloonHints(" in BALLOON
    assert 'from "./balloon.js"' in APP_JS
    assert "initBalloonHints();" in APP_JS


def test_balloon_hover_delay_and_keyboard_focus_show_immediately() -> None:
    assert "const HOVER_DELAY_MS = 500;" in BALLOON
    body = BALLOON.split("function onPointerOver(event) {", 1)[1].split("\n}", 1)[0]
    assert "HOVER_DELAY_MS" in body
    focus_body = BALLOON.split("function onFocusIn(event) {", 1)[1].split("\n}", 1)[0]
    assert "setTimeout" not in focus_body
    assert "show(target)" in focus_body


def test_balloon_reads_hint_from_data_hint_never_item_data() -> None:
    assert "target.dataset.hint" in BALLOON
    assert "item." not in BALLOON and "file." not in BALLOON


def test_balloon_sets_aria_describedby_to_its_own_id_and_clears_it_on_hide() -> None:
    assert 'const BALLOON_ID = "balloon-help";' in BALLOON
    show_body = BALLOON.split("function show(target) {", 1)[1].split("\n}", 1)[0]
    assert 'target.setAttribute("aria-describedby", BALLOON_ID);' in show_body
    hide_body = BALLOON.split("function hide() {", 1)[1].split("\n}", 1)[0]
    assert 'current.removeAttribute("aria-describedby");' in hide_body


def test_balloon_hides_on_escape_pointer_leave_blur_and_scroll() -> None:
    assert '"Escape"' in BALLOON
    keydown_body = BALLOON.split("function onKeydown(event) {", 1)[1].split("\n}", 1)[0]
    assert "hide()" in keydown_body
    out_body = BALLOON.split("function onPointerOut(event) {", 1)[1].split("\n}", 1)[0]
    assert "hide()" in out_body
    focusout_body = BALLOON.split("function onFocusOut(event) {", 1)[1].split("\n}", 1)[0]
    assert "hide()" in focusout_body
    scroll_body = BALLOON.split("function onScroll() {", 1)[1].split("\n}", 1)[0]
    assert "hide()" in scroll_body
    assert 'addEventListener("scroll", onScroll, true)' in BALLOON


def test_balloon_touch_long_press_skips_elements_that_own_a_context_menu() -> None:
    assert "const LONG_PRESS_MS = 500;" in BALLOON
    down_body = BALLOON.split("function onPointerDown(event) {", 1)[1].split("\n}", 1)[0]
    assert 'event.pointerType !== "touch") return;' in down_body
    assert "ownsLongPress(target)) return;" in down_body
    assert "target.closest('[data-context-trigger=\"true\"]')" in BALLOON


def test_balloon_swallows_the_click_after_a_fired_long_press() -> None:
    assert "FIRED_LONG_PRESS_RESET_MS" in BALLOON
    assert 'addEventListener("click", onClickCapture, true)' in BALLOON
    body = BALLOON.split("function onClickCapture(event) {", 1)[1].split("\n}", 1)[0]
    assert "event.preventDefault();" in body
    assert "event.stopPropagation();" in body


def test_balloon_positions_via_cssom_not_a_style_attribute() -> None:
    assert "balloon.style.left" in BALLOON and "balloon.style.top" in BALLOON
    assert "style:" not in BALLOON  # never an h() `style` prop (dom.js refuses it anyway)


# --- F-W1 review fixes ---


def test_balloon_show_hides_a_different_or_disconnected_previous_target() -> None:
    # First substantive check in show(): switching straight to a new target,
    # or finding the old one already removed from the DOM (e.g. a
    # re-rendered Pin button), both clear the previous control's
    # aria-describedby before anything else runs.
    show_body = BALLOON.split("function show(target) {", 1)[1].split("\n}", 1)[0]
    guard = "if (current && (current !== target || !current.isConnected)) hide();"
    assert guard in show_body
    assert show_body.index(guard) < show_body.index("const text = target.dataset.hint;")


def test_balloon_hides_on_hashchange() -> None:
    # hashchange fires on `window` and doesn't bubble; a `document` listener
    # never runs (F-W2 fix of the F-W1 mistake).
    assert 'window.addEventListener("hashchange", hide)' in BALLOON
    assert 'document.addEventListener("hashchange", hide)' not in BALLOON


# --- F-W2 review fixes ---


def test_balloon_hides_on_any_click_but_a_swallowed_long_press_click_keeps_it() -> None:
    # After the owner activates a control its hint is done (e.g. Pin
    # re-renders), so a plain click hides the balloon. A long-press's own
    # click is still swallowed (preventDefault/stopPropagation, no
    # activation) and must NOT also hide the balloon it just opened.
    body = BALLOON.split("function onClickCapture(event) {", 1)[1].split("\n}", 1)[0]
    swallow_branch, rest = body.split("return;\n  }", 1)
    assert "clearFiredLongPress();" in swallow_branch
    assert "event.preventDefault();" in swallow_branch
    assert "event.stopPropagation();" in swallow_branch
    assert "hide();" not in swallow_branch
    assert "hide();" in rest


def test_balloon_hints_initialized_before_load_kinds_in_start() -> None:
    # F-W2: hints must work even on the "can't reach its server" page, so
    # initBalloonHints() runs before the loadKinds() call that can throw.
    start_body = APP_JS.split("async function start() {", 1)[1].split("\nstart();", 1)[0]
    assert start_body.index("initBalloonHints();") < start_body.index("await loadKinds();")


def test_menu_marks_its_context_trigger_elements_for_balloon_to_skip() -> None:
    body = MENU.split("export function attachContextTrigger(", 1)[1]
    assert 'el.dataset.contextTrigger = "true";' in body.split("\n  let timer", 1)[0]


# --- every listed control has a fixed hint (backlog #6 item 1's enumeration) ---


def test_every_specified_control_carries_a_fixed_data_hint() -> None:
    assert 'dataset: { box: "close", hint: close.hint }' in CHROME
    assert 'const SHADE_HINT = "Shade: collapse this window to its title bar.";' in FX_SHADE
    assert "box.dataset.hint = SHADE_HINT;" in FX_SHADE
    assert 'hint: trashed ? "Close: back to the trash." : "Close: back to the feed."' in ITEM
    assert "Download: save this file." in ITEM
    assert "Download all: save every file as one .zip." in ITEM
    assert "Move to trash: you can restore it until it's deleted for good." in ITEM
    assert "Restore: move this item back to the feed." in ITEM
    assert "Pin: keep this item at the top of the feed." in ITEM
    assert "Unpin: let it sort by date again." in ITEM
    assert "Preview: show this file in the window above." in ITEM
    assert "Download: save just this file." in ITEM
    assert "Try again: retry loading this item." in ITEM
    assert 'hint: "Show: filter the list to one kind."' in FEED
    assert "More actions: pin, download, or move to trash." in FEED
    assert "More actions: download or restore." in FEED
    assert "Load more: show the next ${PAGE_SIZE} items." in FEED
    assert "Show new items: refresh the list with what's new." in FEED
    assert "Try again: retry loading the list." in FEED
    assert 'dataset: { hint: "Close: return to the normal view." }' in EXPAND
    assert "dataset: { hint: `${label}: fill the screen with this preview.` }" in EXPAND
    assert 'data-hint="Feed: everything currently published."' in INDEX_HTML
    assert 'data-hint="Trash: items waiting to be deleted for good."' in INDEX_HTML
    assert 'hint: "Background: choose a background pattern.",' in FX_DESKTOP
    assert "trigger.dataset.hint = hint;" in SHELL_MENU


def test_balloon_help_css_uses_theme_tokens_only() -> None:
    section = APP_CSS.split("/* --- Balloon Help hints", 1)[1].split("\n/* --- buttons", 1)[0]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", section)
    assert "position: fixed;" in section
    assert "pointer-events: none;" in section


# --- item 2: zoom box removed ---


def test_zoom_box_is_removed_from_chrome_and_css() -> None:
    assert "box-zoom" not in CHROME
    assert "box-zoom" not in APP_CSS
    assert "box-zoom" not in OS_CHROME_CSS


# --- item 3: close box only when it does something ---


def test_close_box_is_only_rendered_when_close_is_provided() -> None:
    body = CHROME.split("export function windowFrame(", 1)[1]
    close_box_expr = body.split("const closeBox = close\n", 1)[1].split(";\n", 1)[0]
    assert close_box_expr.strip().startswith("?")
    assert close_box_expr.rstrip().endswith(": null")


def test_close_box_only_inside_a_folder_as_the_up_control() -> None:
    """Root feed and trash have no close box; a folder level gets one ("up", backlog §7.1)."""
    body = FEED.split("const frame = windowFrame(", 1)[1].split(");", 1)[0]
    assert 'close: folder ? { href: "#/"' in body and ": null" in body


# --- item 4: single-file item drops the file row's Download ---


def test_single_file_item_drops_the_file_rows_download() -> None:
    body = ITEM.split("function renderFiles(item) {", 1)[1].split("\n  function renderAll", 1)[0]
    assert "const showFileDownload = files.length > 1;" in body
    assert "showFileDownload && download" in body


# --- item 5: plain kind icon + visible Pin/Unpin button; feed-row menu unchanged ---


def test_kind_icon_is_plain_with_no_button_or_context_menu() -> None:
    head_body = ITEM.split("function renderHead(item) {", 1)[1].split("\n  // Each revision", 1)[0]
    assert "info-icon-trigger" not in head_body
    assert "attachContextTrigger" not in head_body
    assert 'head.append(\n      icon(itemIconId(item, kind), "icon-lg"),' in ITEM


def test_pin_button_is_visible_only_for_active_items() -> None:
    active_marker = "} else {\n      append(buttonsSlot, ["
    active_body = ITEM.split(active_marker, 1)[1].split("\n    }\n  }", 1)[0]
    assert 'text: pinned ? "Unpin" : "Pin"' in active_body
    trashed_marker = "if (trashed) {\n      append(buttonsSlot, ["
    trashed_body = ITEM.split(trashed_marker, 1)[1].split("]);\n    } else", 1)[0]
    assert '"Pin"' not in trashed_body and '"Unpin"' not in trashed_body


def test_feed_row_menu_entries_are_unchanged_by_w1() -> None:
    body = FEED.split("function rowMenuEntries(", 1)[1].split("\nfunction row(", 1)[0]
    assert '"Open"' in body and '"Pin"' in body and '"Unpin"' in body
    assert '"Move to trash"' in body and '"Restore"' in body


# --- item 6: backgrounds cover the viewport (body-level, not .desktop) ---


def test_desktop_pictures_apply_to_body_not_the_desktop_column() -> None:
    assert "applyBackground(document.body, os, loadBackground(os));" in FX_DESKTOP
    assert "applyBackground(document.body, os, id);" in FX_DESKTOP
    assert "function applyBackground(target, os, id) {" in FX_DESKTOP
    assert ".desktop[data-background=" not in OS_CHROME_CSS
    for picture in ("standard", "pinstripe", "weave", "waves", "zen", "static"):
        assert f':root[data-os="platinum"] body[data-background="{picture}"]' in OS_CHROME_CSS
