/*
  Item detail view as a "Get Info" window: preview (via the renderer registry), fields (kind,
  size, dates, version popup + Delete old versions), files group, Download and Trash/Restore
  behind a confirm dialog.
  Polls the item with its ETag so a change made elsewhere (a new version, a trash) shows up.
  Untrusted text (title, description, filenames) → textContent in <bdi> only.
*/
import { ApiError, apiGet, itemPath, startPolling } from "./api.js";
import { filesText, isBundle } from "./bundle.js";
import { alertWindow, backButton, fileIconId, icon, itemIconId, kindIconId, windowFrame } from "./chrome.js";
import { absoluteTime, append, clear, dayOnly, formatBytes, h, httpsUrl, timeEl, toast, untrusted } from "./dom.js";
import { changeItemState, setPinned } from "./menu.js";
import { loadFolders } from "./folders.js";
import { itemBack, previousHash } from "./nav.js";
import { perFilePreview, renderPreview } from "./renderers/index.js";
import { deleteOldVersions, olderVersionNotice, versionSwitcher } from "./versions.js";

function notFound(main, trashed) {
  clear(main);
  main.appendChild(
    alertWindow({
      title: "Item not found",
      body: trashed
        ? "It may have been restored or deleted for good."
        : "It may have been moved to the trash, or the link is wrong.",
      actions: [
        h("a", { class: "button button-primary", href: trashed ? "#/trash" : "#/", text: trashed ? "Back to trash" : "Back to feed" }),
      ],
    }),
  );
}

function entryFile(item) {
  const files = Array.isArray(item.files) ? item.files : [];
  return files.find((f) => f.relpath === item.entry_file) || files[0] || null;
}

// "Image", or for a bundle (bundle.js) "Bundle (10 files) · Image": it previews as its entry kind.
function kindText(item, kind) {
  const label = kind ? kind.label : String(item.kind ?? "");
  return isBundle(item) ? `Bundle (${filesText(item.file_count)}) · ${label}` : label;
}

// Per-file icon: by extension (same mapping the kinds use), except a non-bundle's entry file,
// which is the item's own kind (e.g. `progress.json` is a Progress file, not plain JSON).
function fileIcon(item, file, kind, kindList) {
  if (file.relpath === item.entry_file && !isBundle(item) && kind) return kindIconId(kind);
  return fileIconId(file.relpath, kindList);
}

function field(label, ...value) {
  return h("div", { class: "field" }, h("dt", { text: label }), h("dd", {}, value));
}

/**
 * Render item `id` into `main`. `trashed` selects the trash variant (`?t=1` URLs).
 * Returns a cleanup function.
 */
export function renderItem(main, ctx, { id, trashed = false }) {
  // `rev`: the revision number on screen, or null to follow the latest one.
  const state = { etag: null, item: null, selected: null, disposed: false, busy: false, rev: null };
  const frame = windowFrame({
    name: "info",
    title: "Info",
    close: {
      href: trashed ? "#/trash" : "#/",
      label: trashed ? "Close, back to Trash" : "Close, back to Feed",
      hint: trashed ? "Close: back to the trash." : "Close: back to the feed.",
    },
  });
  frame.root.dataset.state = trashed ? "trashed" : "active";
  frame.root.dataset.itemId = id;
  // Recorded by the router before this view rendered: where the owner came from (nav.js).
  const origin = previousHash();
  const navSlot = h("div", { class: "info-nav" });
  const head = h("header", { class: "info-top" });
  const noticeSlot = h("div", { class: "info-notice" });
  const previewSlot = h("section", { class: "item-preview", "aria-label": "Preview" });
  const fieldsSlot = h("dl", { class: "fields" });
  const filesSlot = h("section", { class: "group item-files", "aria-labelledby": `files-${id}` });
  const buttonsSlot = h("div", { class: "buttons item-actions" });
  frame.body.classList.add("info-body");
  frame.body.append(navSlot, head, noticeSlot, previewSlot, fieldsSlot, filesSlot, buttonsSlot);
  clear(main);
  main.appendChild(frame.root);

  function kindOf(item) {
    return ctx.kinds.get(item.kind) || null;
  }

  function renderPreviewFor(item, file, extraActions = []) {
    clear(previewSlot);
    if (!file) {
      previewSlot.appendChild(h("p", { class: "preview-empty", text: "This item has no files." }));
      return;
    }
    const { element, actions } = renderPreview({ item, file, kind: kindOf(item), trashed, capBytes: ctx.capBytes });
    const label = h("p", { class: "preview-label" }, untrusted(file.relpath));
    const toolbar = h("div", { class: "preview-toolbar" }, label, h("div", { class: "preview-actions" }, extraActions, actions));
    previewSlot.append(toolbar, h("div", { class: "screen" }, element));
  }

  // Shared with the row context menu (menu.js): same confirm dialog, POST and toast.
  async function changeState(action) {
    if (state.busy || !state.item) return;
    const toTrash = action === "trash";
    state.busy = true;
    const ok = await changeItemState(state.item, toTrash);
    state.busy = false;
    if (ok && !state.disposed) location.hash = toTrash ? "#/" : `#/item/${encodeURIComponent(id)}`;
  }

  async function togglePinned() {
    if (state.busy || !state.item || trashed) return;
    state.busy = true;
    const ok = await setPinned(state.item, !state.item.pinned);
    state.busy = false;
    if (ok && !state.disposed) load();
  }

  // After a prune only the latest version exists: follow it and refresh the switcher.
  async function pruneOldVersions() {
    if (state.busy || !state.item || trashed) return;
    state.busy = true;
    const ok = await deleteOldVersions(state.item);
    state.busy = false;
    if (state.disposed) return;
    if (ok && state.rev !== null) showRevision(null);
    else load();
  }

  // A real Back button: it sets the hash, so it stays inside the app. Names the place it
  // goes to; a folder name is untrusted, so it only ever reaches the DOM as text.
  let backKey = null;
  async function renderBack(item) {
    const back = itemBack({ trashed, folder: item.folder || null, origin });
    const key = `${back.href}|${back.text}|${back.name ?? ""}`;
    if (key === backKey) return;
    backKey = key;
    const show = (shown) => {
      clear(navSlot);
      navSlot.appendChild(backButton(shown));
    };
    show(back);
    if (!back.folderId) return;
    // Came from a folder other than the item's own (e.g. it was moved): look its name up.
    const { folders } = await loadFolders();
    const found = folders.find((candidate) => candidate.id === back.folderId);
    if (found && !state.disposed && backKey === key) show({ href: back.href, text: "Back to", name: found.name });
  }

  function renderHead(item) {
    renderBack(item);
    const kind = kindOf(item);
    const pinned = Boolean(item.pinned) && !trashed;
    frame.root.dataset.pinned = String(pinned);

    clear(frame.title);
    frame.title.append(untrusted(item.title), " Info");

    clear(head);
    // Plain icon (W1 item 5): no button, no context menu - actions live in buttonsSlot below.
    head.append(
      icon(itemIconId(item, kind), "icon-lg"),
      h(
        "div",
        { class: "info-heading" },
        h("h2", { class: "item-title" }, untrusted(item.title)),
        item.description ? h("p", { class: "item-desc" }, untrusted(item.description)) : null,
      ),
    );

    clear(noticeSlot);
    const notice = olderVersionNotice(item, () => showRevision(null));
    if (notice) noticeSlot.appendChild(notice);

    clear(fieldsSlot);
    const size = formatBytes(item.total_size);
    // Read-only (backlog §6.3): the viewer only reads folders, it never assigns one here.
    // "Unfiled" is a fixed string (never item data); the folder's actual name goes via untrusted().
    append(fieldsSlot, [
      field("Kind:", kindText(item, kind)),
      field("Folder:", item.folder ? untrusted(item.folder.name) : "Unfiled"),
      field("Size:", item.file_count > 1 ? `${size} in ${item.file_count} files` : size),
      field("Published:", `${absoluteTime(item.created_at)} (`, timeEl(item.created_at), ")"),
      pinned ? field("Label:", h("span", { class: "label-dot", "aria-hidden": "true" }), "Pinned") : null,
      trashed && item.purge_at ? field("Deleted on:", h("span", { class: "warning-text", text: `${dayOnly(item.purge_at)}, for good` })) : null,
    ]);
    // Delete old versions: active items only (the server refuses trashed ones, C43).
    const switcher = versionSwitcher(
      item,
      (number, isLatest) => showRevision(isLatest ? null : number),
      trashed ? null : pruneOldVersions,
    );
    if (switcher) fieldsSlot.appendChild(switcher);

    clear(buttonsSlot);
    const download = httpsUrl(item.download_url);
    const downloadLink = download
      ? h("a", {
          class: `button${trashed ? "" : " button-primary"}`,
          href: download,
          rel: "noopener noreferrer",
          text: item.file_count > 1 ? "Download all (.zip)" : "Download",
          dataset: {
            hint: item.file_count > 1 ? "Download all: save every file as one .zip." : "Download: save this file.",
          },
        })
      : null;
    if (trashed) {
      append(buttonsSlot, [
        downloadLink,
        h("button", {
          type: "button",
          class: "button button-primary",
          text: "Restore",
          dataset: { hint: "Restore: move this item back to the feed." },
          on: { click: () => changeState("restore") },
        }),
      ]);
    } else {
      append(buttonsSlot, [
        h("button", {
          type: "button",
          class: "button button-danger-quiet",
          text: "Move to trash",
          dataset: { hint: "Move to trash: you can restore it until it's deleted for good." },
          on: { click: () => changeState("trash") },
        }),
        h("button", {
          type: "button",
          class: "button",
          text: pinned ? "Unpin" : "Pin",
          dataset: { hint: pinned ? "Unpin: let it sort by date again." : "Pin: keep this item at the top of the feed." },
          on: { click: togglePinned },
        }),
        downloadLink,
      ]);
    }
  }

  // Each revision has its own files and URLs: reload the detail for it (the server's `?rev=`).
  function showRevision(rev) {
    if (state.disposed || state.rev === rev) return;
    state.rev = rev;
    state.etag = null;
    state.selected = null;
    load();
  }

  function path() {
    return itemPath(id, { trashed, rev: state.rev });
  }

  function renderFiles(item) {
    clear(filesSlot);
    const files = Array.isArray(item.files) ? item.files : [];
    const previewable = perFilePreview(kindOf(item)) && files.length > 1;
    filesSlot.appendChild(h("h3", { class: "group-title", id: `files-${id}`, text: files.length === 1 ? "File" : `Files (${files.length})` }));
    const list = h("ul", { class: "files" });
    // A single-file item's row would repeat the main Download button (same file): drop it
    // there and keep it only when there's something to tell files apart (W1 item 4).
    const showFileDownload = files.length > 1;
    for (const file of files) {
      const download = httpsUrl(file.download_url);
      // Only mark a selection when there is something to choose between.
      const isSelected = previewable && state.selected === file.relpath;
      list.appendChild(
        h(
          "li",
          { class: `file${isSelected ? " is-selected" : ""}` },
          icon(fileIcon(item, file, kindOf(item), ctx.kindList), "icon-sm"),
          h("span", { class: "file-name" }, untrusted(file.relpath)),
          // The entry file (what the preview opens first) is marked once there are several.
          files.length > 1 && file.relpath === item.entry_file
            ? h("span", { class: "file-entry", text: "Opens first" })
            : null,
          h("span", { class: "file-meta", text: formatBytes(file.size) }),
          h(
            "span",
            { class: "file-actions" },
            previewable
              ? h("button", {
                  type: "button",
                  class: "file-action",
                  "aria-pressed": String(isSelected),
                  text: "Preview",
                  dataset: { hint: "Preview: show this file in the window above." },
                  on: {
                    click: () => {
                      state.selected = file.relpath;
                      renderPreviewFor(item, file);
                      renderFiles(item);
                      previewSlot.scrollIntoView({ block: "start" });
                    },
                  },
                })
              : null,
            showFileDownload && download
              ? h("a", {
                  class: "file-action",
                  href: download,
                  rel: "noopener noreferrer",
                  text: "Download",
                  dataset: { hint: "Download: save just this file." },
                })
              : null,
          ),
        ),
      );
    }
    filesSlot.appendChild(list);
  }

  function renderAll(item) {
    state.item = item;
    const files = Array.isArray(item.files) ? item.files : [];
    const selected = files.find((f) => f.relpath === state.selected) || entryFile(item);
    state.selected = selected ? selected.relpath : null;
    renderHead(item);
    renderPreviewFor(item, selected);
    renderFiles(item);
  }

  async function load() {
    const rev = state.rev;
    try {
      const result = await apiGet(path());
      if (state.disposed || rev !== state.rev) return;
      state.etag = result.etag;
      renderAll(result.data);
    } catch (err) {
      if (state.disposed || rev !== state.rev) return;
      if (err instanceof ApiError && err.status === 404 && rev !== null) {
        // That version was pruned meanwhile: fall back to the latest one.
        toast("That version is no longer kept. Showing the latest.");
        showRevision(null);
      } else if (err instanceof ApiError && (err.status === 404 || err.status === 400)) notFound(main, trashed);
      else {
        clear(head);
        head.appendChild(
          h(
            "p",
            { class: "error" },
            "Couldn't load this item. ",
            h("button", {
              type: "button",
              class: "link-button",
              text: "Try again",
              dataset: { hint: "Try again: retry loading this item." },
              on: { click: load },
            }),
          ),
        );
      }
    }
  }

  const stop = startPolling(async () => {
    if (!state.item || state.disposed) return;
    let result;
    const rev = state.rev;
    try {
      result = await apiGet(path(), { etag: state.etag });
    } catch (err) {
      if (rev !== state.rev) return;
      if (err instanceof ApiError && err.status === 404 && !state.disposed && rev !== null) {
        showRevision(null); // the version on screen was pruned
      } else if (err instanceof ApiError && err.status === 404 && !state.disposed) {
        // Trashed, restored or purged elsewhere.
        notFound(main, trashed);
        stop();
      }
      return;
    }
    if (result.status === 304 || state.disposed || rev !== state.rev) return;
    state.etag = result.etag;
    const before = state.item;
    const next = result.data;
    const sameFiles = JSON.stringify(before.files) === JSON.stringify(next.files);
    // Keep the playing video / scrolled frame when only metadata changed.
    state.item = next;
    renderHead(next);
    renderFiles(next);
    if (!sameFiles) renderAll(next);
  });

  load();
  return () => {
    state.disposed = true;
    stop();
  };
}
