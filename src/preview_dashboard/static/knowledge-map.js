/*
  Knowledge map window (#/knowledge; docs/frontend.md, security.md C57): Claudia's notes as a live
  graph built from GET /api/kb/graph on every open - dots = notes (colour = category, size =
  connections, a ring = changed this week), lines = [[links]] and shared tags; zoom/pan/drag, tap a
  dot to read the note in the side panel (tap it again to close it), search, category filter,
  neighbour highlight. Phones (and the List view) get the notes listed by category. Read only; note
  text is untrusted and only ever becomes text nodes (kmap-note.js). Also shows the
  pending-approvals box (kmap-approvals.js).
*/
import { ApiError, apiGet } from "./api.js";
import { icon, popup, svgElement, windowFrame } from "./chrome.js";
import { append, clear, dayOnly, h, untrusted } from "./dom.js";
import { approvalsPanel } from "./kmap-approvals.js";
import {
  categorySlots,
  fitTransform,
  layoutGraph,
  matchesQuery,
  neighbours,
  nodeRadius,
  zoomAt,
} from "./kmap-layout.js";
import { noteBlocks } from "./kmap-note.js";

const NOTE_ID_RE = /^[0-9a-f]{32}$/;
const MAP_SIZE = 1000;
const LABEL_PX = 11;
const DRAG_SLOP = 4;
const ZOOM_STEP = 1.3;
// Phones read the list (the plan: "list by category on phones"); same breakpoint as app.css.
const PHONE = "(max-width: 37.49rem)";

function categoryName(name) {
  const text = String(name).replace(/-/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function notesText(count) {
  return count === 1 ? "1 note" : `${count} notes`;
}

/** Keep only well-formed nodes/edges (the API is trusted for shape, but never blindly). */
function cleanGraph(data) {
  const nodes = (Array.isArray(data?.nodes) ? data.nodes : []).filter(
    (n) => n && NOTE_ID_RE.test(n.id) && typeof n.title === "string" && typeof n.category === "string",
  );
  const known = new Set(nodes.map((n) => n.id));
  const edges = (Array.isArray(data?.edges) ? data.edges : []).filter(
    (e) => e && known.has(e.source) && known.has(e.target),
  );
  return {
    nodes,
    edges,
    skipped: Number(data?.skipped) || 0,
    truncated: data?.truncated === true,
  };
}

/**
 * What a tap on the map (a press that didn't move) does: "open" the pressed note, "close" when
 * it is the note already open (a second tap deselects, owner 2026-11-14) or on the bare floor
 * while one is open, else null. Pure, so the toggle is tested under node.
 */
export function pressAction(pressed, selected) {
  if (pressed) return pressed === selected ? "close" : "open";
  return selected ? "close" : null;
}

/** @param main the window area; returns the cleanup function (stops polling and listeners). */
export function renderKnowledgeMap(main) {
  const phone = window.matchMedia(PHONE);
  const state = {
    disposed: false,
    graph: null,
    slots: new Map(),
    near: new Map(),
    positions: new Map(),
    elements: new Map(), // id -> {g, edges: [line, ...]}
    view: { x: 0, y: 0, k: 1 },
    fitted: false,
    selected: null,
    hovered: null,
    query: "",
    category: "",
    mode: "map",
    noteRequest: 0,
  };

  const frame = windowFrame({ name: "kmap", title: "Knowledge map", className: "window-kmap" });
  const summary = h("p", { class: "finder-summary", text: "Loading…" });
  const search = h("input", {
    type: "search",
    id: "kmap-search",
    class: "kmap-search",
    placeholder: "Find a note",
    autocomplete: "off",
    spellcheck: "false",
    maxlength: "80",
    dataset: { hint: "Search: dim every note whose name and tags don't match. Enter opens the first match." },
  });
  const categorySelect = h("select", {
    id: "kmap-category",
    class: "select",
    dataset: { hint: "Category: show one category's notes only." },
  });
  const views = h(
    "div",
    { class: "kmap-views", role: "group", "aria-label": "View" },
    viewButton("map", "Map", "Map: notes as connected dots."),
    viewButton("list", "List", "List: notes by category."),
  );
  const approvals = approvalsPanel();

  const svg = svgElement("svg", { class: "kmap-svg", role: "img", tabindex: "0", "aria-label": "Map of the notes" });
  const viewport = svgElement("g", { class: "kmap-viewport" });
  const edgeLayer = svgElement("g", { class: "kmap-edges" });
  const nodeLayer = svgElement("g", { class: "kmap-nodes" });
  if (svg) {
    viewport.append(edgeLayer, nodeLayer);
    svg.appendChild(viewport);
  }
  const mapMessage = h("div", { class: "kmap-message", "aria-live": "polite" });
  const mapPane = h("div", { class: "kmap-map screen" }, svg, mapMessage);
  const index = h("div", { class: "kmap-index inset", "aria-label": "Notes by category" });
  const panel = h("aside", { class: "kmap-panel", "aria-label": "Note", "aria-live": "polite" });
  const stage = h("div", { class: "kmap-stage", dataset: { mode: "map" } }, mapPane, index, panel);
  const status = h("span", { class: "statusbar-text" });
  const zoomOut = h("button", { type: "button", class: "button kmap-zoom", text: "−", "aria-label": "Zoom out", dataset: { hint: "Zoom out." } });
  const zoomIn = h("button", { type: "button", class: "button kmap-zoom", text: "+", "aria-label": "Zoom in", dataset: { hint: "Zoom in." } });
  const fit = h("button", { type: "button", class: "button kmap-zoom", text: "Fit", dataset: { hint: "Fit: show the whole map." } });
  const reload = h("button", {
    type: "button",
    class: "button",
    text: "Reload",
    dataset: { hint: "Reload: rebuild the map from the notes as they are now." },
  });

  append(frame.body, [
    h(
      "div",
      { class: "finder-header kmap-header" },
      summary,
      h(
        "div",
        { class: "kmap-controls" },
        h("label", { class: "sr-only", for: "kmap-search", text: "Find a note" }),
        search,
        h("label", { class: "sr-only", for: "kmap-category", text: "Category" }),
        popup(categorySelect),
        views,
      ),
    ),
    approvals.root,
    stage,
    h("div", { class: "statusbar kmap-statusbar" }, status, h("span", { class: "kmap-zooms" }, zoomOut, zoomIn, fit), reload, icon("i-grow", "grow")),
  ]);
  clear(main);
  main.appendChild(frame.root);
  showPanelHint();

  function viewButton(mode, label, hint) {
    return h("button", {
      type: "button",
      class: "button kmap-view",
      text: label,
      "aria-pressed": mode === "map" ? "true" : "false",
      dataset: { view: mode, hint },
      on: { click: () => setMode(mode) },
    });
  }

  function setMode(mode) {
    state.mode = mode;
    stage.dataset.mode = mode;
    for (const button of views.querySelectorAll(".kmap-view")) {
      button.setAttribute("aria-pressed", String(button.dataset.view === mode));
    }
    if (mode === "map") fitOnce();
  }

  // --- loading ----------------------------------------------------------------------------

  async function load() {
    summary.textContent = "Loading…";
    setMessage("Drawing the map…");
    try {
      const { data } = await apiGet("/api/kb/graph");
      if (state.disposed) return;
      state.graph = cleanGraph(data);
    } catch (err) {
      if (state.disposed) return;
      state.graph = null;
      showUnavailable(err instanceof ApiError && err.status === 404);
      return;
    }
    draw();
  }

  function showUnavailable(off) {
    clear(edgeLayer);
    clear(nodeLayer);
    clear(index);
    summary.textContent = off ? "Off" : "Not loaded";
    status.textContent = "";
    if (off) {
      setMessage("The knowledge map is off: no knowledge base is set up for the dashboard yet.");
      index.appendChild(h("p", { class: "empty", text: "The knowledge map is off: no knowledge base is set up for the dashboard yet." }));
      return;
    }
    const retry = () => h("button", { type: "button", class: "link-button", text: "Try again", on: { click: load } });
    setMessage("Couldn't load the map. ", retry());
    index.appendChild(h("p", { class: "error" }, "Couldn't load the notes. ", retry()));
  }

  function setMessage(...children) {
    clear(mapMessage);
    append(mapMessage, children);
    mapMessage.hidden = children.length === 0;
  }

  // --- drawing ----------------------------------------------------------------------------

  function draw() {
    const { nodes, edges } = state.graph;
    state.slots = categorySlots(nodes.map((n) => n.category));
    state.near = neighbours(edges);
    state.positions = layoutGraph(nodes, edges, { size: MAP_SIZE });
    state.elements = new Map();
    fillCategories();
    drawSvg();
    drawIndex();
    state.fitted = false;
    if (!nodes.length) {
      setMessage("No notes yet. They appear here as soon as Claudia writes them.");
    } else {
      setMessage();
      fitOnce();
    }
    if (state.selected && !state.positions.has(state.selected)) closeNote();
    applyFilter();
    highlight();
  }

  function fillCategories() {
    const previous = state.category;
    clear(categorySelect);
    categorySelect.appendChild(h("option", { value: "", text: "All categories" }));
    for (const name of state.slots.keys()) {
      categorySelect.appendChild(h("option", { value: name, text: categoryName(name) }));
    }
    state.category = state.slots.has(previous) ? previous : "";
    categorySelect.value = state.category;
  }

  function drawSvg() {
    if (!svg) return;
    clear(edgeLayer);
    clear(nodeLayer);
    const { nodes, edges } = state.graph;
    svg.setAttribute("aria-label", `Map of ${notesText(nodes.length)}. Use the List view to read them one by one.`);
    for (const node of nodes) state.elements.set(node.id, { g: null, edges: [] });
    for (const edge of edges) {
      const a = state.positions.get(edge.source);
      const b = state.positions.get(edge.target);
      const line = svgElement("line", {
        class: "kmap-edge",
        "data-kind": edge.kind === "tag" ? "tag" : "link",
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
      });
      line.dataset.source = edge.source;
      line.dataset.target = edge.target;
      state.elements.get(edge.source).edges.push(line);
      state.elements.get(edge.target).edges.push(line);
      edgeLayer.appendChild(line);
    }
    // Label the best-connected fifth of the notes; the rest get labels when zoomed in.
    const degrees = nodes.map((n) => Number(n.degree) || 0).sort((x, y) => y - x);
    const hubFloor = Math.max(1, degrees[Math.floor(degrees.length / 5)] ?? 1);
    for (const node of nodes) {
      const { x, y } = state.positions.get(node.id);
      const r = nodeRadius(node.degree);
      const g = svgElement("g", {
        class: "kmap-node",
        transform: `translate(${x} ${y})`,
        "data-cat": String(state.slots.get(node.category) ?? 0),
      });
      g.dataset.id = node.id;
      if (node.recent) g.classList.add("is-recent");
      if ((Number(node.degree) || 0) >= hubFloor || nodes.length <= 12) g.classList.add("is-hub");
      g.append(
        svgElement("circle", { class: "kmap-ring", r: r + 4 }),
        svgElement("circle", { class: "kmap-dot", r }),
        svgElement("ellipse", { class: "kmap-shine", cx: -r * 0.3, cy: -r * 0.38, rx: r * 0.5, ry: r * 0.32 }),
      );
      const label = svgElement("text", { class: "kmap-label", y: r + LABEL_PX + 2 });
      label.textContent = node.title;
      g.appendChild(label);
      state.elements.get(node.id).g = g;
      nodeLayer.appendChild(g);
    }
  }

  function drawIndex() {
    clear(index);
    const { nodes } = state.graph;
    if (!nodes.length) {
      index.appendChild(h("p", { class: "empty", text: "No notes yet. They appear here as soon as Claudia writes them." }));
      return;
    }
    for (const name of state.slots.keys()) {
      const members = nodes.filter((n) => n.category === name).sort((a, b) => a.title.localeCompare(b.title));
      const section = h(
        "section",
        { class: "kmap-section", dataset: { category: name } },
        h(
          "h3",
          { class: "kmap-section-title" },
          h("span", { class: "kmap-swatch", dataset: { cat: String(state.slots.get(name)) }, "aria-hidden": "true" }),
          categoryName(name),
          h("small", { class: "kmap-count", text: notesText(members.length) }),
        ),
        h(
          "ul",
          { class: "kmap-entries" },
          members.map((node) =>
            h(
              "li",
              { class: "kmap-entry", dataset: { id: node.id } },
              h(
                "button",
                { type: "button", class: "kmap-entry-button", on: { click: () => openNote(node.id, { centre: true }) } },
                h("span", { class: "kmap-entry-title" }, untrusted(node.title)),
                node.recent ? h("span", { class: "kmap-new", text: "Changed this week" }) : null,
              ),
            ),
          ),
        ),
      );
      index.appendChild(section);
    }
    if (state.graph.truncated) {
      index.appendChild(h("p", { class: "balloon", text: "The knowledge base is larger than the map can show; some notes are left out." }));
    }
  }

  // --- view transform ---------------------------------------------------------------------

  function applyView() {
    if (!svg) return;
    const { x, y, k } = state.view;
    viewport.setAttribute("transform", `translate(${x} ${y}) scale(${k})`);
    // Labels keep their on-screen size whatever the zoom (CSSOM, not a style attribute: CSP).
    nodeLayer.style.fontSize = `${LABEL_PX / k}px`;
    svg.classList.toggle("is-zoomed", k >= 1.6);
    updateStatus();
  }

  function size() {
    const rect = svg ? svg.getBoundingClientRect() : { width: 0, height: 0 };
    return { width: rect.width, height: rect.height };
  }

  function fitOnce() {
    if (state.fitted || !state.graph || !state.graph.nodes.length) return;
    const { width, height } = size();
    if (width <= 0 || height <= 0) return; // hidden (phone / List view): fit when shown
    state.view = fitTransform(state.positions, width, height);
    state.fitted = true;
    applyView();
  }

  function fitAll() {
    state.fitted = false;
    fitOnce();
  }

  function zoomBy(factor) {
    const { width, height } = size();
    state.view = zoomAt(state.view, factor, width / 2, height / 2);
    applyView();
  }

  function centreOn(id) {
    const point = state.positions.get(id);
    const { width, height } = size();
    if (!point || width <= 0) return;
    const k = Math.max(state.view.k, 1);
    state.view = { x: width / 2 - point.x * k, y: height / 2 - point.y * k, k };
    applyView();
  }

  function updateStatus() {
    if (!state.graph) return;
    const shown = state.graph.nodes.filter(visible).length;
    const total = state.graph.nodes.length;
    const zoom = state.mode === "map" && !phone.matches ? ` Zoom ${Math.round(state.view.k * 100)}%.` : "";
    status.textContent = `${shown === total ? notesText(total) : `${shown} of ${notesText(total)}`} shown.${zoom}`;
  }

  // --- filter and highlight -----------------------------------------------------------------

  function visible(node) {
    return (!state.category || node.category === state.category) && matchesQuery(node, state.query);
  }

  function applyFilter() {
    if (!state.graph) return;
    const { nodes } = state.graph;
    const shownIds = new Set(nodes.filter(visible).map((n) => n.id));
    const shown = shownIds.size;
    for (const node of nodes) {
      state.elements.get(node.id)?.g?.classList.toggle("is-filtered", !shownIds.has(node.id));
    }
    for (const entry of index.querySelectorAll(".kmap-entry")) entry.hidden = !shownIds.has(entry.dataset.id);
    for (const section of index.querySelectorAll(".kmap-section")) {
      section.hidden = !section.querySelector(".kmap-entry:not([hidden])");
    }
    for (const line of edgeLayer.childNodes) {
      line.classList.toggle("is-filtered", !(shownIds.has(line.dataset.source) && shownIds.has(line.dataset.target)));
    }
    const categories = new Set(nodes.map((n) => n.category)).size;
    summary.textContent =
      shown === nodes.length
        ? `${notesText(nodes.length)} in ${categories === 1 ? "1 category" : `${categories} categories`}`
        : `${shown} of ${notesText(nodes.length)} match`;
    if (state.graph.skipped) summary.textContent += `, ${state.graph.skipped} files skipped`;
    updateStatus();
  }

  /** Dim everything but the focused note (selected, else hovered) and its neighbours. */
  function highlight() {
    const focus = state.selected || state.hovered;
    svg?.classList.toggle("has-focus", Boolean(focus));
    const near = focus ? state.near.get(focus) || new Set() : new Set();
    for (const [id, { g, edges }] of state.elements) {
      if (!g) continue;
      g.classList.toggle("is-selected", id === state.selected);
      g.classList.toggle("is-near", Boolean(focus) && (id === focus || near.has(id)));
      for (const line of edges) {
        line.classList.toggle("is-near", Boolean(focus) && (line.dataset.source === focus || line.dataset.target === focus));
      }
    }
    for (const entry of index.querySelectorAll(".kmap-entry")) {
      entry.classList.toggle("is-selected", entry.dataset.id === state.selected);
    }
  }

  // --- the note panel -----------------------------------------------------------------------

  function showPanelHint() {
    clear(panel);
    stage.classList.remove("is-reading");
    panel.appendChild(h("p", { class: "kmap-panel-hint", text: "Choose a note to read it here. Its links open the notes they name." }));
  }

  function closeNote() {
    state.selected = null;
    state.noteRequest += 1;
    showPanelHint();
    highlight();
  }

  async function openNote(id, { centre = false } = {}) {
    if (!NOTE_ID_RE.test(id)) return;
    state.selected = id;
    const request = (state.noteRequest += 1);
    highlight();
    if (centre && state.mode === "map") centreOn(id);
    stage.classList.add("is-reading");
    clear(panel);
    panel.appendChild(h("p", { class: "loading", text: "Opening the note…" }));
    try {
      const { data } = await apiGet(`/api/kb/notes/${id}`);
      if (state.disposed || request !== state.noteRequest) return;
      showNote(data);
    } catch (err) {
      if (state.disposed || request !== state.noteRequest) return;
      clear(panel);
      panel.appendChild(panelBack());
      const gone = err instanceof ApiError && err.status === 404;
      panel.appendChild(
        h(
          "p",
          { class: "error" },
          gone ? "This note has moved or gone since the map was drawn. " : "Couldn't open the note. ",
          h("button", { type: "button", class: "link-button", text: gone ? "Reload the map" : "Try again", on: { click: gone ? load : () => openNote(id) } }),
        ),
      );
    }
  }

  // Phones show "Back to the list" (the note covers the list there), wider screens "Close note".
  function panelBack() {
    return h(
      "div",
      { class: "kmap-panel-nav" },
      h("button", {
        type: "button",
        class: "button back-button kmap-back-to-list",
        text: "Back to the list",
        dataset: { hint: "Back to the list of notes." },
        on: { click: closeNote },
      }),
      h("button", {
        type: "button",
        class: "button kmap-close-note",
        text: "Close note",
        dataset: { hint: "Close note: clear the selection." },
        on: { click: closeNote },
      }),
    );
  }

  function showNote(note) {
    clear(panel);
    const slot = String(state.slots.get(note.category) ?? 0);
    const tags = Array.isArray(note.tags) ? note.tags.filter((t) => typeof t === "string") : [];
    const backlinks = Array.isArray(note.backlinks) ? note.backlinks.filter((b) => b && NOTE_ID_RE.test(b.id)) : [];
    append(panel, [
      panelBack(),
      h(
        "header",
        { class: "kmap-note-head" },
        h("h2", { class: "kmap-note-title" }, untrusted(note.title)),
        h(
          "p",
          { class: "kmap-note-meta" },
          h("span", { class: "kmap-swatch", dataset: { cat: slot }, "aria-hidden": "true" }),
          `${categoryName(note.category)}, updated ${dayOnly(note.updated) || "on an unknown date"}`,
        ),
        tags.length ? h("ul", { class: "kmap-tags", "aria-label": "Tags" }, tags.map((tag) => h("li", { class: "kmap-tag" }, untrusted(tag)))) : null,
      ),
      h("div", { class: "kmap-note-body" }, noteBlocks(note.body, note.links, (target) => openNote(target, { centre: true }))),
      backlinks.length
        ? h(
            "section",
            { class: "kmap-backlinks", "aria-labelledby": "kmap-backlinks-title" },
            h("h3", { class: "kmap-backlinks-title", id: "kmap-backlinks-title", text: "Linked from" }),
            h(
              "ul",
              { class: "kmap-backlink-list" },
              backlinks.map((b) =>
                h("li", {}, h("button", { type: "button", class: "kmap-link", on: { click: () => openNote(b.id, { centre: true }) } }, untrusted(b.title))),
              ),
            ),
          )
        : null,
    ]);
  }

  // --- pointer, wheel and keys on the map -----------------------------------------------------

  const pointers = new Map();
  let gesture = null;

  function local(event) {
    const rect = svg.getBoundingClientRect();
    return { x: event.clientX - rect.left, y: event.clientY - rect.top };
  }

  function nodeIdAt(target) {
    const g = target instanceof Element ? target.closest(".kmap-node") : null;
    return g && NOTE_ID_RE.test(g.dataset.id || "") ? g.dataset.id : null;
  }

  function moveNode(id, dx, dy) {
    const point = state.positions.get(id);
    point.x += dx;
    point.y += dy;
    const { g, edges } = state.elements.get(id);
    g.setAttribute("transform", `translate(${point.x} ${point.y})`);
    for (const line of edges) {
      const end = line.dataset.source === id ? "1" : "2";
      line.setAttribute(`x${end}`, point.x);
      line.setAttribute(`y${end}`, point.y);
    }
  }

  function onPointerDown(event) {
    if (!state.graph || event.button > 0) return;
    svg.setPointerCapture(event.pointerId);
    pointers.set(event.pointerId, local(event));
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      gesture = { kind: "pinch", distance: Math.hypot(a.x - b.x, a.y - b.y), moved: true };
      return;
    }
    const start = local(event);
    gesture = { kind: "press", node: nodeIdAt(event.target), start, last: start, moved: false };
  }

  function onPointerMove(event) {
    if (!pointers.has(event.pointerId)) {
      if (event.pointerType === "mouse") hover(nodeIdAt(event.target));
      return;
    }
    const point = local(event);
    pointers.set(event.pointerId, point);
    if (!gesture) return;
    if (gesture.kind === "pinch" && pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const distance = Math.hypot(a.x - b.x, a.y - b.y);
      if (gesture.distance > 0) {
        state.view = zoomAt(state.view, distance / gesture.distance, (a.x + b.x) / 2, (a.y + b.y) / 2);
        applyView();
      }
      gesture.distance = distance;
      return;
    }
    if (gesture.kind !== "press") return;
    if (!gesture.moved && Math.hypot(point.x - gesture.start.x, point.y - gesture.start.y) < DRAG_SLOP) return;
    gesture.moved = true;
    const dx = point.x - gesture.last.x;
    const dy = point.y - gesture.last.y;
    gesture.last = point;
    if (gesture.node) {
      moveNode(gesture.node, dx / state.view.k, dy / state.view.k);
    } else {
      state.view = { ...state.view, x: state.view.x + dx, y: state.view.y + dy };
      applyView();
    }
  }

  function onPointerUp(event) {
    if (!pointers.delete(event.pointerId)) return;
    const done = gesture;
    if (pointers.size === 0) gesture = null;
    if (!done || done.kind !== "press" || done.moved) return;
    const action = pressAction(done.node, state.selected);
    if (action === "open") openNote(done.node);
    else if (action === "close") closeNote();
  }

  function hover(id) {
    if (id === state.hovered) return;
    state.hovered = id;
    highlight();
  }

  function onWheel(event) {
    if (!state.graph) return;
    event.preventDefault();
    const { x, y } = local(event);
    state.view = zoomAt(state.view, Math.exp(-event.deltaY * 0.0015), x, y);
    applyView();
  }

  function onKey(event) {
    const pan = 60;
    const moves = { ArrowLeft: [pan, 0], ArrowRight: [-pan, 0], ArrowUp: [0, pan], ArrowDown: [0, -pan] };
    if (event.key === "+" || event.key === "=") zoomBy(ZOOM_STEP);
    else if (event.key === "-") zoomBy(1 / ZOOM_STEP);
    else if (event.key === "0") fitAll();
    else if (event.key === "Escape" && state.selected) closeNote();
    else if (moves[event.key]) {
      const [dx, dy] = moves[event.key];
      state.view = { ...state.view, x: state.view.x + dx, y: state.view.y + dy };
      applyView();
    } else return;
    event.preventDefault();
  }

  if (svg) {
    svg.addEventListener("pointerdown", onPointerDown);
    svg.addEventListener("pointermove", onPointerMove);
    svg.addEventListener("pointerup", onPointerUp);
    svg.addEventListener("pointercancel", onPointerUp);
    svg.addEventListener("pointerleave", () => hover(null));
    svg.addEventListener("wheel", onWheel, { passive: false });
    svg.addEventListener("keydown", onKey);
  }

  // --- controls -------------------------------------------------------------------------------

  search.addEventListener("input", () => {
    state.query = search.value;
    applyFilter();
  });
  search.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || !state.graph) return;
    event.preventDefault();
    const first = state.graph.nodes.filter(visible).sort((a, b) => a.title.localeCompare(b.title))[0];
    if (first) openNote(first.id, { centre: true });
  });
  categorySelect.addEventListener("change", () => {
    state.category = categorySelect.value;
    applyFilter();
  });
  zoomIn.addEventListener("click", () => zoomBy(ZOOM_STEP));
  zoomOut.addEventListener("click", () => zoomBy(1 / ZOOM_STEP));
  fit.addEventListener("click", fitAll);
  reload.addEventListener("click", load);

  const onResize = () => {
    if (!phone.matches && state.mode === "map") fitOnce();
  };
  window.addEventListener("resize", onResize);

  load();
  return () => {
    state.disposed = true;
    approvals.stop();
    window.removeEventListener("resize", onResize);
  };
}
