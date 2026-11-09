"""Structural checks for the R4 item context menu (docs/frontend.md, backlog R4).

`menu.js` opens/manipulates real DOM (`document`), so it can't run standalone
under plain Node the way `dom.js`'s pure helpers can (no jsdom dependency in
this repo). These tests instead pin the contract at the source level: one
menu open at a time, roving-tabindex keyboard nav, touch-only long-press,
focus restoration, and that `feed.js`/`item.js` wire the right entries
through the shared `menu.js` actions. Generic sink/eval/origin/header/token
checks for `menu.js` itself already run in `test_static_ui.py` (it globs all
of `static/`), so they are not repeated here.
"""

from __future__ import annotations

import re

from preview_dashboard.interfaces.viewer.static_assets import default_static_dir

STATIC = default_static_dir()
MENU = (STATIC / "menu.js").read_text("utf-8")
FEED = (STATIC / "feed.js").read_text("utf-8")
ITEM = (STATIC / "item.js").read_text("utf-8")
APP_CSS = (STATIC / "app.css").read_text("utf-8")


def test_menu_exports_the_expected_public_api() -> None:
    for name in (
        "openMenu",
        "closeMenu",
        "attachContextTrigger",
        "triggerDownload",
        "setPinned",
        "changeItemState",
    ):
        assert re.search(rf"export (?:async )?function {name}\(", MENU), name


def test_only_one_menu_is_open_at_a_time() -> None:
    body = MENU.split("export function openMenu(", 1)[1]
    assert body.split(") {", 1)[1].lstrip().startswith("closeMenu();")


def test_keyboard_navigation_covers_the_required_keys() -> None:
    # Menu key / Shift+F10 opens it; arrows/Home/End move; Enter activates (native <div> click
    # via Space/Enter is browser-default for a focused element with a click handler); Escape and
    # Tab close it; focus always returns to the trigger (restoreFocus).
    assert '"ContextMenu"' in MENU and 'event.shiftKey && event.key === "F10"' in MENU
    for key in ("ArrowDown", "ArrowUp", "Home", "End", "Escape", "Tab"):
        assert f'"{key}"' in MENU, key
    assert "restoreFocus" in MENU
    assert 'role: "menuitem"' in MENU and 'tabindex: "-1"' in MENU


def test_long_press_is_touch_only_and_about_500ms() -> None:
    assert "LONG_PRESS_MS = 500;" in MENU
    assert 'event.pointerType !== "touch") return;' in MENU
    # A long press must swallow the row link's own click afterwards, not also navigate.
    assert "firedLongPress" in MENU


def test_fired_long_press_is_reset_on_the_next_pointerdown_and_a_timeout() -> None:
    """S2 F1: touch browsers often send no click after a long-press, so relying on
    click alone to clear `firedLongPress` would swallow the row's next real tap too.
    The next pointerdown (any pointer type, not just touch) and a short timeout must
    both clear it as well."""
    assert "FIRED_LONG_PRESS_RESET_MS" in MENU
    body = MENU.split('el.addEventListener("pointerdown", (event) => {', 1)[1].split("});", 1)[0]
    assert "clearFiredLongPress();" in body
    # The reset must happen before the touch-only early return, so it covers every pointer type.
    touch_guard = 'event.pointerType !== "touch") return;'
    assert body.index("clearFiredLongPress();") < body.index(touch_guard)
    timer_body = MENU.split("timer = setTimeout(() => {", 1)[1].split("}, LONG_PRESS_MS);", 1)[0]
    assert "setTimeout(clearFiredLongPress, FIRED_LONG_PRESS_RESET_MS);" in timer_body


def test_contextmenu_event_is_prevented_before_opening() -> None:
    body = MENU.split('addEventListener("contextmenu"', 1)[1].split("});", 1)[0]
    assert "event.preventDefault();" in body


def test_menu_actions_only_call_the_network_through_api_js() -> None:
    assert 'from "./api.js"' in MENU
    assert "fetch(" not in MENU
    assert "XMLHttpRequest" not in MENU


def test_trash_and_restore_keep_the_confirm_dialog() -> None:
    assert 'from "./dialog.js"' in MENU
    body = MENU.split("export async function changeItemState(", 1)[1]
    assert body.index("confirmAction(") < body.index("apiPost(")


def test_pin_endpoint_matches_docs_api_and_toasts_the_result() -> None:
    assert '`/api/items/${encodeURIComponent(item.id)}/${pinned ? "pin" : "unpin"}`' in MENU
    assert 'toast(pinned ? "Pinned" : "Unpinned");' in MENU
    assert "err.status === 409" in MENU  # trashed items can't be pinned (ADR 0020)


def test_feed_rows_get_a_more_button_and_a_context_trigger() -> None:
    assert 'class: "row-more"' in FEED and 'rowMore: "",' in FEED
    assert "attachContextTrigger(link," in FEED
    assert "openMenu({ anchor: more, entries: rowMenuEntries" in FEED


def test_row_menu_entries_match_the_backlog_order() -> None:
    body = FEED.split("function rowMenuEntries(", 1)[1].split("\nfunction row(", 1)[0]
    order = [
        m.start() for m in re.finditer(r'"Open"|Pin.*?Unpin|"Move to trash"|"Restore"|"sep"', body)
    ]
    assert order == sorted(order)  # Open, then Pin/Unpin, Download, a separator, then trash/restore
    assert '"Pin"' in body and '"Unpin"' in body
    assert '"Move to trash"' in body and '"Restore"' in body
    assert "danger: true" in body  # Move to trash is the destructive entry


def test_row_menu_entries_use_a_busy_guard_like_item_js() -> None:
    """S2 F1 (optional): entries are built fresh from `item` at open time (already true -
    rowMenuEntries takes the live `item`) and a row with a request in flight disables the
    entries that would fire another one, mirroring item.js's `state.busy` guard."""
    body = FEED.split("function rowMenuEntries(", 1)[1].split("\nfunction row(", 1)[0]
    assert "busyRowIds" in body
    assert "disabled: busy" in body
    assert body.count("disabled: busy") == 3  # Pin/Unpin, Restore, Move to trash


def test_row_menu_refresh_reorders_the_list_on_pin_and_trash_changes() -> None:
    body = FEED.split("function rowMenuEntries(", 1)[1]
    assert "if (await setPinned(item, !item.pinned)) refresh();" in body
    assert "if (await changeItemState(item, false)) refresh();" in body
    assert "if (await changeItemState(item, true)) refresh();" in body
    # row() is called with `reload` as its refresh callback.
    page = FEED.split("function showPage(", 1)[1].split("\n", 3)[2]
    assert "row(item, ctx, trashed, reload)" in page


def test_get_info_icon_is_a_plain_icon_with_no_context_menu() -> None:
    """W1 item 5: the kind icon lost its button/context-menu wrapper; Pin/Unpin is now a
    visible button instead (togglePinned is still there, just wired to a <button>, not a menu)."""
    assert "info-icon-trigger" not in ITEM
    assert "attachContextTrigger" not in ITEM
    assert "infoMenuEntries" not in ITEM
    assert "togglePinned" in ITEM


def test_item_view_has_pin_download_and_trash_restore_buttons() -> None:
    assert 'text: pinned ? "Unpin" : "Pin"' in ITEM
    assert '"Move to trash"' in ITEM and '"Restore"' in ITEM


def test_ctx_menu_styles_use_theme_tokens_only() -> None:
    section = APP_CSS.split("/* --- context menu", 1)[1].split("\n/* --- Finder", 1)[0]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(", section)
    assert 'role="menu"' not in section  # selectors are class-based; role lives in menu.js markup
