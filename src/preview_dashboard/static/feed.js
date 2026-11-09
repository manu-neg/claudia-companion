/*
  Feed and trash views as a Finder-style list window: one row per item (pinned first, then
  newest, as the API orders them) with a pixel kind icon (a bundle: the bundle icon and "Bundle"
  kind, bundle.js), a "Show:" popup grouped by kind family (no "progress" choice: HTML lists
  html + progress items, backlog §12.3), cursor paging ("Load more") and ETag polling of the
  first page.
  Folders (backlog §7.1, unit F4) live inside this same window rather than a separate one:
  `#/` shows folder rows (name, sorted; "Folder" kind; item count) ahead of the *unfiled* items
  (`?folder=unfiled`); opening a folder (click/Enter/"Open") reuses the very same window at
  `#/folder/<id>`, titled "Feed ▸ <folder name>", with a Back button (nav.js; also Backspace/Alt+Up)
  and the close box (up to the root). Trash stays flat and never shows folder rows or an up control.
  All item/folder text is untrusted → textContent inside <bdi> (dom.js), never HTML.
*/
import { apiGet, itemsPath, startPolling } from "./api.js";
import { bundleDetail, filesText, isBundle } from "./bundle.js";
import { alertWindow, backButton, icon, itemIconId, popup, windowFrame } from "./chrome.js";
import { append, clear, dayOnly, formatBytes, h, httpsUrl, timeEl, untrusted } from "./dom.js";
import { attachContextTrigger, changeItemState, openMenu, setPinned, triggerDownload } from "./menu.js";
import { loadFolders } from "./folders.js";
import { folderBack } from "./nav.js";

const PAGE_SIZE = 30;

// The "Show:" popup groups kinds into families (design brief); unlisted kinds go to Other.
const KIND_GROUPS = [
  ["Pictures", ["image", "svg"]],
  ["Pages", ["html", "pdf", "markdown"]],
  ["Motion & sound", ["video", "audio"]],
  ["Code", ["code", "diff"]],
  ["Data", ["json", "csv"]],
  ["Other", ["text", "file"]],
];

// Kinds the popup never offers (owner decision 2026-09-30, backlog §12.3): a progress page is
// listed under HTML instead, so choosing HTML asks the API for both (`kind=html,progress`).
const HIDDEN_KINDS = new Set(["progress"]);
const KIND_ALSO = new Map([["html", ["progress"]]]);

/** The kinds one Show choice lists: the choice itself plus any kinds folded into it. */
function filterKinds(name) {
  return name ? [name, ...(KIND_ALSO.get(name) || [])] : [];
}

/** The kinds the Show popup offers (the registry minus hidden ones). */
function offeredKinds(ctx) {
  return ctx.kindList.filter((kind) => !HIDDEN_KINDS.has(kind.name));
}

// The kind filter survives navigating to an item and back, keyed per view: "active", "trashed",
// or "folder:<id>" (one entry per folder visited, so switching folders doesn't share a filter).
const filterByView = new Map();
const currentFilter = (viewKey) => filterByView.get(viewKey) || "";

// Row ids with a pin/trash/restore request in flight, so a double tap on the same row's menu
// can't fire two overlapping requests (same idea as item.js's single-item `state.busy`).
const busyRowIds = new Set();

function itemHref(item, trashed) {
  const id = encodeURIComponent(item.id);
  return trashed ? `#/trash/${id}` : `#/item/${id}`;
}

function sizeText(item) {
  const size = formatBytes(item.total_size);
  return item.file_count > 1 ? `${item.file_count} files, ${size}` : size;
}

// The row context menu: Open, Pin/Unpin (active only), Download, then Move to trash/Restore.
// `refresh` re-fetches the current page so a pin/unpin or trash/restore reorders the list.
// Built fresh from `item` every time the menu opens, so labels/disabled state always reflect
// the row's current data; a busy row (a request already in flight for it) disables the entries
// that would fire another one, same idea as item.js's `state.busy`.
function rowMenuEntries(item, trashed, refresh) {
  const busy = busyRowIds.has(item.id);
  async function runRowAction(action) {
    if (busyRowIds.has(item.id)) return;
    busyRowIds.add(item.id);
    try {
      await action();
    } finally {
      busyRowIds.delete(item.id);
    }
  }
  const download = httpsUrl(item.download_url);
  const entries = [{ label: "Open", action: () => { location.hash = itemHref(item, trashed); } }];
  if (!trashed) {
    entries.push({
      label: item.pinned ? "Unpin" : "Pin",
      disabled: busy,
      action: () =>
        runRowAction(async () => {
          if (await setPinned(item, !item.pinned)) refresh();
        }),
    });
  }
  // A bundle names itself here (backlog §10): the menu is often opened without seeing the Kind column.
  let downloadLabel = item.file_count > 1 ? "Download all" : "Download";
  if (isBundle(item)) downloadLabel = `Download bundle (${item.file_count} files)`;
  entries.push({
    label: downloadLabel,
    action: () => triggerDownload(download),
    disabled: !download,
  });
  entries.push("sep");
  entries.push(
    trashed
      ? {
          label: "Restore",
          disabled: busy,
          action: () =>
            runRowAction(async () => {
              if (await changeItemState(item, false)) refresh();
            }),
        }
      : {
          label: "Move to trash",
          danger: true,
          disabled: busy,
          action: () =>
            runRowAction(async () => {
              if (await changeItemState(item, true)) refresh();
            }),
        },
  );
  return entries;
}

function itemsLabel(count) {
  return count === 1 ? "1 item" : `${count} items`;
}

// A folder row at the root of the Feed window: name (sorted, untrusted), a fixed "Folder" kind,
// its item count in the Size column, no date. Only "Open" in its context menu - there is nothing
// else to do with a folder row itself (pin/trash/download are per-item actions).
function folderRowEntries(folder) {
  return [{ label: "Open", action: () => { location.hash = `#/folder/${encodeURIComponent(folder.id)}`; } }];
}

function folderRow(folder) {
  const link = h(
    "a",
    { class: "row-link", href: `#/folder/${encodeURIComponent(folder.id)}` },
    h(
      "span",
      { class: "cell cell-name" },
      icon("i-folder", "icon"),
      h(
        "span",
        { class: "row-text" },
        h("span", { class: "row-title" }, untrusted(folder.name)),
        h("span", { class: "row-sub", text: itemsLabel(folder.count) }),
      ),
    ),
    h("span", { class: "cell cell-kind", text: "Folder" }),
    h("span", { class: "cell cell-size", text: itemsLabel(folder.count) }),
    h("span", { class: "cell cell-date" }),
  );
  attachContextTrigger(link, () => folderRowEntries(folder));
  // No "…" button: the end column is padding on the link (app.css `.row-folder .row-link`), so the
  // hover highlight spans the whole row instead of stopping short of a blank spacer.
  return h("li", { class: "row row-folder", dataset: { folderId: folder.id } }, link);
}

function row(item, ctx, trashed, refresh) {
  const kind = ctx.kinds.get(item.kind) || null;
  const entryKindLabel = kind ? kind.label : String(item.kind ?? "");
  // A bundle (bundle.js) shows as "Bundle" with "N files · <entry kind>" under it; it still
  // previews as its entry kind, so only these labels and the icon change.
  const bundle = isBundle(item);
  const kindLabel = bundle ? "Bundle" : entryKindLabel;
  const kindCell = bundle
    ? h("span", { class: "cell cell-kind" }, "Bundle", h("small", { class: "kind-detail", text: bundleDetail(item, entryKindLabel) }))
    : h("span", { class: "cell cell-kind", text: kindLabel });
  // Phones (one sub-line, no Kind column): short enough for 390px; the entry kind is in Get Info.
  const subText = bundle ? `Bundle (${filesText(item.file_count)}), ${formatBytes(item.total_size)}` : `${kindLabel}, ${sizeText(item)}`;
  const pinned = Boolean(item.pinned) && !trashed;
  const date = trashed
    ? h("span", { text: item.purge_at ? dayOnly(item.purge_at) : "" })
    : timeEl(item.created_at);
  const link = h(
    "a",
    { class: "row-link", href: itemHref(item, trashed) },
    h(
      "span",
      { class: "cell cell-name" },
      icon(itemIconId(item, kind), "icon"),
      h(
        "span",
        { class: "row-text" },
        h("span", { class: "row-title" }, untrusted(item.title)),
        h("span", { class: "row-sub", text: subText }),
      ),
      pinned ? h("span", { class: "row-pin" }, icon("i-pin", "pin"), h("span", { class: "sr-only", text: "Pinned" })) : null,
    ),
    kindCell,
    h("span", { class: "cell cell-size", text: formatBytes(item.total_size) }),
    h("span", { class: "cell cell-date" }, date),
  );
  const more = h("button", {
    type: "button",
    class: "row-more",
    "aria-label": "More actions",
    "aria-haspopup": "menu",
    dataset: {
      rowMore: "",
      hint: trashed ? "More actions: download or restore." : "More actions: pin, download, or move to trash.",
    },
  }, "…");
  more.addEventListener("click", (event) => {
    event.stopPropagation();
    openMenu({ anchor: more, entries: rowMenuEntries(item, trashed, refresh) });
  });
  attachContextTrigger(link, () => rowMenuEntries(item, trashed, refresh), { anchor: more });
  return h(
    "li",
    {
      class: `row${pinned ? " is-pinned" : ""}`,
      dataset: { itemId: item.id, pinned: String(pinned), state: trashed ? "trashed" : "active" },
    },
    link,
    more,
  );
}

function kindSelect(ctx, viewKey, onChange) {
  const offered = offeredKinds(ctx);
  const known = new Map(offered.map((kind) => [kind.name, kind]));
  const grouped = new Set();
  const groups = [];
  for (const [label, names] of KIND_GROUPS) {
    const kinds = names.map((name) => known.get(name)).filter(Boolean);
    kinds.forEach((kind) => grouped.add(kind.name));
    groups.push([label, kinds]);
  }
  const rest = offered.filter((kind) => !grouped.has(kind.name));
  if (rest.length) groups[groups.length - 1][1].push(...rest);
  const active = currentFilter(viewKey);
  const option = (kind) => h("option", { value: kind.name, selected: kind.name === active, text: kind.label });
  const select = h(
    "select",
    {
      id: `show-${viewKey}`,
      class: "select",
      dataset: { hint: "Show: filter the list to one kind." },
      on: { change: (event) => onChange(event.currentTarget.value) },
    },
    h("option", { value: "", selected: !active, text: "All kinds" }),
    groups.filter(([, kinds]) => kinds.length).map(([label, kinds]) => h("optgroup", { label }, kinds.map(option))),
  );
  return h("div", { class: "show-menu" }, h("label", { for: select.id, text: "Show:" }), popup(select));
}

function emptyState(trashed, filtered) {
  if (filtered) return h("p", { class: "empty", text: "Nothing of this kind here. Choose All kinds to see everything." });
  if (trashed) return h("p", { class: "empty", text: "The trash is empty." });
  return h("p", { class: "empty", text: "Nothing published yet. Items appear here as soon as Claude publishes them." });
}

function columnHeads(trashed) {
  // Visual column titles only: each row link already reads name, kind, size and date in order.
  // The trailing spacer mirrors row-more's box (same shared width rules in app.css) so the "…"
  // column doesn't narrow row-link's grid and throw the cells out of line with the headers.
  return h(
    "div",
    { class: "list-head", "aria-hidden": "true" },
    h(
      "span",
      { class: "list-head-cells" },
      h("span", { class: "cell cell-name", text: "Name" }),
      h("span", { class: "cell cell-kind", text: "Kind" }),
      h("span", { class: "cell cell-size", text: "Size" }),
      h("span", { class: "cell cell-date is-sorted" }, trashed ? "Kept until" : "Date", icon("i-sort", "sort-dir")),
    ),
    h("span", { class: "list-head-spacer" }),
  );
}

function renderPageNotFound(main) {
  clear(main);
  main.appendChild(
    alertWindow({
      title: "Page not found",
      body: "This address doesn't match anything in the dashboard.",
      actions: [h("a", { class: "button button-primary", href: "#/", text: "Go to the feed" })],
    }),
  );
}

function isTextEntry(el) {
  return Boolean(el) && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);
}

/**
 * Render the feed (`trashed` false) or the trash into `main`. Returns a cleanup function.
 * `folderId`: a ULID naming the folder to open (backlog §7.1, unit F4) - looked up in
 * `GET /api/folders` first (same window shows "Loading…" meanwhile); an id that doesn't match a
 * current folder shows "Page not found", same as any other bad route. Only ever combined with
 * `trashed: false` - the trash stays flat and never takes a folder.
 * With no `folderId` and `trashed: false`, this is the root Feed: folder rows (sorted by name)
 * ahead of the *unfiled* items (`?folder=unfiled`).
 * @param ctx {kinds: Map, kindList: Array, capBytes: number}
 */
export function renderFeed(main, ctx, { trashed = false, folderId = null } = {}) {
  if (trashed || !folderId) return renderList(main, ctx, { trashed, folder: null });
  const state = { disposed: false, stop: null };
  clear(main);
  main.appendChild(h("p", { class: "loading", text: "Loading…" }));
  loadFolders().then(({ folders }) => {
    if (state.disposed) return;
    const folder = folders.find((candidate) => candidate.id === folderId) || null;
    if (!folder) {
      renderPageNotFound(main);
      return;
    }
    state.stop = renderList(main, ctx, { trashed: false, folder });
  });
  return () => {
    state.disposed = true;
    if (state.stop) state.stop();
  };
}

/**
 * The actual Finder list window, once a folder (if any) is resolved. `folder`: `{id, name}` for
 * `#/folder/<id>`, or `null` for the root Feed or the trash.
 */
function renderList(main, ctx, { trashed, folder }) {
  const viewKey = folder ? `folder:${folder.id}` : trashed ? "trashed" : "active";
  // A saved choice the popup no longer offers (e.g. a stale "progress") falls back to All kinds.
  if (currentFilter(viewKey) && !offeredKinds(ctx).some((kind) => kind.name === currentFilter(viewKey))) {
    filterByView.delete(viewKey);
  }
  const atRoot = !trashed && !folder; // folder rows + the up control only make sense there
  const state = { cursor: null, pages: 0, etag: null, loading: false, disposed: false };
  const folderList = atRoot ? h("ul", { class: "list", "aria-label": "Folders" }) : null;
  const list = h("ul", { class: "list", "aria-label": trashed ? "Trashed items" : "Items" });
  const status = h("div", { class: "list-status", "aria-live": "polite" });
  const summary = h("p", { class: "finder-summary" });
  const showing = h("span", { class: "statusbar-text" });
  const more = h("button", {
    type: "button",
    class: "button load-more",
    text: "Load more",
    hidden: true,
    dataset: { hint: `Load more: show the next ${PAGE_SIZE} items.` },
  });
  const fresh = h("button", {
    type: "button",
    class: "button fresh",
    text: "Show new items",
    hidden: true,
    dataset: { hint: "Show new items: refresh the list with what's new." },
  });
  const windowName = trashed ? "trash" : "feed";
  const windowTitle = folder ? [`Feed ▸ `, untrusted(folder.name)] : trashed ? "Trash" : "Feed";
  const frame = windowFrame({
    name: windowName,
    title: windowTitle,
    className: "window-finder",
    close: folder ? { href: "#/", label: "Up, back to Feed", hint: "Up: back to the feed." } : null,
  });
  // Where Back leads (nav.js): always the Feed, so two views can't bounce.
  const back = folder ? folderBack() : null;
  const kindName = () => ctx.kinds.get(currentFilter(viewKey))?.label || currentFilter(viewKey);

  append(frame.body, [
    h("div", { class: "finder-header" }, back ? backButton(back) : null, summary, kindSelect(ctx, viewKey, (name) => {
      filterByView.set(viewKey, name);
      reload();
    })),
    trashed
      ? h("p", { class: "balloon", text: "Items in the trash are deleted for good on the date shown. Restore one to keep it." })
      : null,
    fresh,
    h("div", { class: "inset" }, columnHeads(trashed), folderList, list, status),
    h("div", { class: "statusbar" }, showing, more, icon("i-grow", "grow")),
  ]);
  clear(main);
  main.appendChild(frame.root);

  const pageQuery = (cursor) =>
    itemsPath({
      state: trashed ? "trashed" : "active",
      kind: filterKinds(currentFilter(viewKey)),
      folder: trashed ? undefined : folder ? folder.id : "unfiled",
      cursor,
      limit: PAGE_SIZE,
    });

  function describe() {
    const rows = list.querySelectorAll(".row");
    const pinned = list.querySelectorAll(".row.is-pinned").length;
    const count = rows.length === 1 ? "1 item" : `${rows.length} items`;
    summary.textContent = state.cursor ? `${count} shown, more below` : pinned ? `${count}, ${pinned} pinned` : count;
    showing.textContent = currentFilter(viewKey) ? `Showing ${kindName()} only` : "Showing all kinds";
  }

  // Folder rows aren't paginated and don't take the kind filter (backlog §7.1: "folder rows
  // stay visible at root"); refreshed alongside the item list so counts stay current.
  async function loadFolderRows() {
    if (!folderList) return;
    const { folders } = await loadFolders();
    if (state.disposed) return;
    clear(folderList);
    const sorted = [...folders].sort((a, b) => a.name.localeCompare(b.name));
    for (const candidate of sorted) folderList.appendChild(folderRow(candidate));
  }

  function showPage(data, { replace }) {
    if (replace) clear(list);
    for (const item of data.items) list.appendChild(row(item, ctx, trashed, reload));
    state.cursor = data.next_cursor;
    more.hidden = !state.cursor;
    clear(status);
    if (!list.childElementCount && !folderList?.childElementCount) {
      status.appendChild(emptyState(trashed, Boolean(currentFilter(viewKey))));
    }
    describe();
  }

  function showError() {
    clear(status);
    status.appendChild(
      h(
        "p",
        { class: "error" },
        "Couldn't load items. ",
        h("button", {
          type: "button",
          class: "link-button",
          text: "Try again",
          dataset: { hint: "Try again: retry loading the list." },
          on: { click: reload },
        }),
      ),
    );
  }

  async function reload() {
    state.loading = true;
    fresh.hidden = true;
    try {
      const [result] = await Promise.all([apiGet(pageQuery(null)), loadFolderRows()]);
      if (state.disposed) return;
      state.etag = result.etag;
      state.pages = 1;
      showPage(result.data, { replace: true });
    } catch {
      if (!state.disposed) showError();
    } finally {
      state.loading = false;
    }
  }

  more.addEventListener("click", async () => {
    if (state.loading || !state.cursor) return;
    state.loading = true;
    more.disabled = true;
    try {
      const result = await apiGet(pageQuery(state.cursor));
      if (state.disposed) return;
      state.pages += 1;
      showPage(result.data, { replace: false });
    } catch {
      if (!state.disposed) showError();
    } finally {
      state.loading = false;
      more.disabled = false;
    }
  });
  fresh.addEventListener("click", reload);

  // Poll the first page (and the folder rows, at root); replace it silently unless the owner
  // already paged further.
  const stop = startPolling(async () => {
    if (state.loading || state.disposed) return;
    const result = await apiGet(pageQuery(null), { etag: state.etag });
    await loadFolderRows();
    if (result.status === 304 || state.disposed) return;
    state.etag = result.etag;
    if (state.pages <= 1) showPage(result.data, { replace: true });
    else fresh.hidden = false;
  });

  // Backspace / Alt+Up ("where natural", backlog §7.1) walk back up to the root, but never
  // while the owner is typing/selecting in a control (the "Show:" popup, e.g.).
  function onKeydown(event) {
    // Leave the key to whoever already handled it, to browser shortcuts, and to an open menu.
    if (event.defaultPrevented || event.ctrlKey || event.metaKey) return;
    if (document.querySelector(".ctx-menu")) return;
    if (isTextEntry(document.activeElement)) return;
    if (event.key === "Backspace" || (event.altKey && event.key === "ArrowUp")) {
      event.preventDefault();
      location.hash = back.href;
    }
  }
  if (folder) document.addEventListener("keydown", onKeydown);

  reload();
  return () => {
    state.disposed = true;
    stop();
    if (folder) document.removeEventListener("keydown", onKeydown);
  };
}
