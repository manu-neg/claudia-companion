/*
  Dashboard bootstrap + hash router: #/ (feed, incl. folder rows), #/trash, #/item/<id>,
  #/trash/<id> (trashed item), #/folder/<id> (backlog §7.1, unit F4 - the same Feed window,
  filtered to one folder; feed.js resolves the id and does the "Page not found" fallback) and
  #/folders (redirected to #/ - F3's separate folder overview window is gone) and #/knowledge
  (the knowledge map, opened from the shell bar's shortcut).
  Loads the kind registry once (GET /api/kinds, the single source of truth), then renders views;
  each view returns a cleanup function that stops its polling when the route changes.
  Also keeps the desktop icons (Feed / Trash counts) current.
*/
import { apiGet } from "./api.js";
import { initBalloonHints } from "./balloon.js";
import { alertWindow } from "./chrome.js";
import { refreshCounts, startCountPolling } from "./desktop.js";
import { clear, h, setPreviewOrigin, ULID_RE } from "./dom.js";
import { renderFeed } from "./feed.js";
import { renderItem } from "./item.js";
import { renderKnowledgeMap } from "./knowledge-map.js";
import { recordRoute } from "./nav.js";

const ctx = { kinds: new Map(), kindList: [], capBytes: 0 };
let cleanup = null;

function parseRoute(hash) {
  const path = hash.replace(/^#/, "") || "/";
  if (path === "/" || path === "/folders") return { view: "feed" };
  if (path === "/trash") return { view: "trash" };
  if (path === "/knowledge") return { view: "knowledge" };
  const item = /^\/(item|trash)\/([^/]+)$/.exec(path);
  if (item && ULID_RE.test(item[2])) return { view: "item", id: item[2], trashed: item[1] === "trash" };
  const folder = /^\/folder\/([^/]+)$/.exec(path);
  if (folder && ULID_RE.test(folder[1])) return { view: "folder", id: folder[1] };
  return { view: "missing" };
}

// A folder is the Feed window filtered to one folder (backlog §7.1): the Feed desktop icon
// shows as current there too.
function markNav(route) {
  const section =
    route.view === "knowledge"
      ? "knowledge"
      : route.view === "trash" || (route.view === "item" && route.trashed)
        ? "trash"
        : route.view === "feed" || route.view === "folder" || (route.view === "item" && !route.trashed)
          ? "feed"
          : null;
  for (const link of document.querySelectorAll("[data-nav]")) {
    if (link.dataset.nav === section) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
}

function renderMissing(main) {
  clear(main);
  main.appendChild(
    alertWindow({
      title: "Page not found",
      body: "This address doesn't match anything in the dashboard.",
      actions: [h("a", { class: "button button-primary", href: "#/", text: "Go to the feed" })],
    }),
  );
}

function route() {
  const main = document.getElementById("main");
  // #/folders (F3's overview window) no longer exists - fix the address bar quietly, without
  // a hashchange round trip, then fall through and render the same thing parseRoute already
  // mapped it to (the root Feed).
  if (location.hash === "#/folders") history.replaceState(null, "", "#/");
  recordRoute(location.hash); // before the views render: they read the origin (Back control)
  if (cleanup) cleanup();
  cleanup = null;
  const current = parseRoute(location.hash);
  markNav(current);
  if (current.view === "feed") cleanup = renderFeed(main, ctx, { trashed: false });
  else if (current.view === "trash") cleanup = renderFeed(main, ctx, { trashed: true });
  else if (current.view === "item") cleanup = renderItem(main, ctx, current);
  else if (current.view === "folder") cleanup = renderFeed(main, ctx, { trashed: false, folderId: current.id });
  else if (current.view === "knowledge") cleanup = renderKnowledgeMap(main);
  else renderMissing(main);
  document.body.dataset.view = current.view;
  document.title =
    current.view === "trash" ? "Trash – Previews" : current.view === "knowledge" ? "Knowledge map – Previews" : "Previews";
  refreshCounts();
  window.scrollTo(0, 0);
  // Move focus for screen readers without scrolling past the header.
  main.focus({ preventScroll: true });
}

async function loadKinds() {
  const { data } = await apiGet("/api/kinds");
  ctx.kindList = Array.isArray(data.kinds) ? data.kinds : [];
  ctx.kinds = new Map(ctx.kindList.map((kind) => [kind.name, kind]));
  ctx.capBytes = Number(data.render_cap_bytes) || 0;
  // Throws on anything but a bare https origin: the UI then shows the "can't reach" page.
  setPreviewOrigin(data.preview_origin);
}

async function start() {
  // Wired first so hints still work on the "can't reach its server" page
  // (e.g. the OS layer's Background trigger's hint) even if loadKinds() below fails (F-W2).
  initBalloonHints();
  const main = document.getElementById("main");
  try {
    await loadKinds();
  } catch {
    clear(main);
    main.appendChild(
      alertWindow({
        title: "The dashboard can't reach its server",
        body: "Check that the viewer service is running, then reload this page.",
      }),
    );
    return;
  }
  window.addEventListener("hashchange", route);
  route();
  startCountPolling();
}

start();
