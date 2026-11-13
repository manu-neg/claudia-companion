/*
  Knowledge-map moulding and motion for Neumorph (docs/frontend-os.md#neumorph "Knowledge map"):
  dresses every note as a porcelain key (shadow discs, a face with dome and socket, a glint on
  the LED), draws iris light along the focused note's grooves out of it, ripples
  the floor on select, plays the opening wave and makes the pointer a light source. Reads only
  the map's neutral hooks and geometry; writes CSS custom properties (CSSOM), OS-prefixed classes
  and its own empty aria-hidden decor. No text, no item data, no prevented events; the approvals
  card is untouched.
*/

const MOULDED = "neumorph-kmap-moulded";
const OPENING = "neumorph-kmap-opening";
const PAUSED = "neumorph-kmap-paused";
const RIPPLE = "neumorph-kmap-ripple";
const FLOWS = "neumorph-kmap-flows";
const SETTLING = "neumorph-kmap-settling"; // just let go: it eases back to rest

const WAVE_MS = 520; // the outermost key starts this long after the centre one
const OPEN_MS = 1500; // wave + rise + label fade, then the opening class goes
const RIPPLE_CLEAR_MS = 1100; // a little over --neu-dur-kmap-ripple, in case animationend never fires
const STAGGER_MS = 45; // neighbours of a focused note lift one after another...
const STAGGER_STEPS = 8; // ...for at most this many steps
const REACH_PX = 220; // keys within this distance of the pointer feel its light
const SWING = 1.6; // how far a key's shadow swings away from a pointer right next to it
const OVERHEAD_PX = 48; // closer than this the light is above the key: its shadow centres
const EPSILON = 0.04; // smaller changes are not written (no restyle for nothing)
const SETTLE_MS = 420; // a let-go key keeps its easing this long (> --neu-dur-release)
const DIMPLE_PX = 11; // tag dimple pitch, = --neu-kmap-dimple (chrome.css)
const SPARK_PX = 1.5; // radius of a lit dimple, on screen

// A key's proportions over the layout radius r (knowledge-map.js draws the ring at r + 4), as
// fractions of the key: the mockup's socket 1/2, halo .44, LED .3. Few elements per key on
// purpose: a state change restyles every part of every key, so each part is one circle. A shadow
// disc is a fill plus a wide translucent stroke: darker at the key's edge, lighter beyond (a
// stepped soft edge, since an OS references no gradients). The socket's wall is its stroke.
const KEY_PAD = 4;
const DISC = { r: 1.0, edge: 0.36 };
const DOME = { r: 0.8, at: -0.1 };
const SOCKET = { r: 0.465, wall: 0.07, lip: 0.04 };
const HALO = 0.44;
const LED = 0.3;
const GLINT = { r: 0.085, at: -0.075 };

// The SVG namespace, taken from the map itself (watchMap sets it before building anything).
let svgNs = "";

/** Our own decor: empty, hidden from assistive tech, never a hit target of its own. */
function decor(tag, className, attrs = {}) {
  const el = document.createElementNS(svgNs, tag);
  el.setAttribute("class", className);
  for (const [name, value] of Object.entries(attrs)) el.setAttribute(name, String(value));
  el.setAttribute("aria-hidden", "true");
  return el;
}

/** A circle of radius r (in keys) at (at, at) keys from the node's origin, stroke w keys. */
function disc(className, key, r, at = 0, w = 0) {
  const attrs = { r: (r * key).toFixed(2) };
  if (at) {
    attrs.cx = (at * key).toFixed(2);
    attrs.cy = (at * key).toFixed(2);
  }
  if (w) attrs["stroke-width"] = (w * key).toFixed(2);
  return decor("circle", className, attrs);
}

/** Position of a node group (its translate), in map units. */
function nodePoint(g) {
  const list = g.transform && g.transform.baseVal;
  if (!list || list.numberOfItems === 0) return { x: 0, y: 0 };
  const m = list.getItem(0).matrix;
  return { x: m.e, y: m.f };
}

function lineEnds(line) {
  const n = (name) => Number(line.getAttribute(name)) || 0;
  return { x1: n("x1"), y1: n("y1"), x2: n("x2"), y2: n("y2") };
}

function lineLength(line) {
  const { x1, y1, x2, y2 } = lineEnds(line);
  return Math.hypot(x2 - x1, y2 - y1);
}

/** Watch one knowledge-map window; returns its stop function. */
function watchMap(svg, finePointer) {
  const map = svg.closest(".kmap-map");
  const stage = svg.closest(".kmap-stage");
  const viewport = svg.querySelector(".kmap-viewport");
  const nodeLayer = svg.querySelector(".kmap-nodes");
  const edgeLayer = svg.querySelector(".kmap-edges");
  if (!map || !viewport || !nodeLayer || !edgeLayer) return () => {};
  svgNs = svg.namespaceURI;

  const nodes = new Map(); // g -> { id, x, y, sx, sy, lit }
  const byId = new Map(); // note id -> g
  const dressed = new WeakSet();
  const settling = new Map(); // g -> when it was let go
  let settleTimer = 0;
  let focus = null;
  let selected = null;
  let hovered = null;
  let flowing = []; // the lit channels: { edge, out, el }
  let openTimer = 0;
  let pending = false;
  let frame = 0;
  let pointer = null;
  let zoom = 0;

  const flows = decor("g", FLOWS);
  viewport.insertBefore(flows, nodeLayer);

  // The grooves' carving: a copy of every groove in a shade layer nudged up-left and a light
  // layer nudged down-right, under the edge layer, so only a 1px sliver of each shows. Plain
  // strokes, no filter: a layer filter re-runs over the whole map on every repaint.
  const carveShade = decor("g", "neumorph-kmap-carve-shade");
  const carveLight = decor("g", "neumorph-kmap-carve-light");
  const carves = decor("g", "neumorph-kmap-carves");
  carves.append(carveShade, carveLight);
  edgeLayer.parentNode.insertBefore(carves, edgeLayer);
  let carved = []; // [edge, shade copy, light copy]

  function carve() {
    carveShade.replaceChildren();
    carveLight.replaceChildren();
    carved = [];
    for (const edge of edgeLayer.querySelectorAll(".kmap-edge")) {
      const kind = edge.dataset.kind === "tag" ? "tag" : "link";
      const copies = [decor("line", "neumorph-kmap-carve", { "data-kind": kind }), decor("line", "neumorph-kmap-carve", { "data-kind": kind })];
      carveShade.appendChild(copies[0]);
      carveLight.appendChild(copies[1]);
      carved.push([edge, ...copies]);
    }
    trace();
  }

  // Copy each groove's ends onto its carving (drawn, or a key dragged).
  function trace() {
    for (const [edge, ...copies] of carved) {
      for (const name of ["x1", "y1", "x2", "y2"]) {
        const value = edge.getAttribute(name);
        for (const copy of copies) if (copy.getAttribute(name) !== value) copy.setAttribute(name, value);
      }
    }
  }

  // Map units -> screen pixels (the viewport's zoom); grooves and channel light keep their
  // screen width (non-scaling strokes), so their dashes and the carving are in pixels.
  function scale() {
    const ctm = viewport.getCTM();
    return ctm ? Math.hypot(ctm.a, ctm.b) || 1 : 1;
  }

  // The grooves' carving is one screen pixel at any zoom. Returns whether the zoom changed (a pan
  // doesn't: nothing measured in screen pixels needs redoing).
  function rescaleGroove() {
    const k = scale();
    if (Math.abs(k - zoom) < 1e-3) return false;
    zoom = k;
    const px = (1 / k).toFixed(4);
    carveShade.setAttribute("transform", `translate(-${px} -${px})`);
    carveLight.setAttribute("transform", `translate(${px} ${px})`);
    return true;
  }

  // A key: two shadow discs under the ring; on it a face (dome, lip, socket) under the LED and a
  // glint on the LED. The LED's halo is its own stroke (fx.css), as wide as --neu-kmap-halo-w.
  // Returns the discs (the pointer light turns only them).
  function dress(g) {
    const ring = g.querySelector(".kmap-ring");
    const dot = g.querySelector(".kmap-dot");
    if (dressed.has(g)) return [...g.querySelectorAll(".neumorph-kmap-shade, .neumorph-kmap-glow")];
    const r = dot ? Number(dot.getAttribute("r")) : 0;
    if (!ring || !(r > 0)) return [];
    dressed.add(g);
    const key = r + KEY_PAD;
    g.style.setProperty("--neu-kmap-led-k", ((LED * key) / r).toFixed(3));
    g.style.setProperty("--neu-kmap-halo-w", `${(2 * r * (HALO / LED - 1)).toFixed(2)}px`);
    const discs = [disc("neumorph-kmap-shade", key, DISC.r, 0, DISC.edge), disc("neumorph-kmap-glow", key, DISC.r, 0, DISC.edge)];
    for (const d of discs) g.insertBefore(d, ring);
    const face = decor("g", "neumorph-kmap-face");
    face.append(
      disc("neumorph-kmap-dome", key, DOME.r, DOME.at),
      disc("neumorph-kmap-lip", key, SOCKET.r + SOCKET.wall / 2, SOCKET.lip),
      disc("neumorph-kmap-socket", key, SOCKET.r, 0, SOCKET.wall),
    );
    g.insertBefore(face, dot);
    g.insertBefore(disc("neumorph-kmap-glint", key, GLINT.r, GLINT.at), dot.nextSibling);
    return discs;
  }

  function setLine(line, from, delay) {
    line.style.setProperty("--neu-kmap-len", String(Math.ceil(lineLength(line) * scale()) + 2));
    line.style.setProperty("--neu-kmap-from", String(from));
    if (delay !== undefined) line.style.setProperty("--neu-kmap-d", `${delay}ms`);
  }

  // The opening draw's dash is in screen pixels: measure every groove and carving again at the
  // current zoom before it replays.
  function remeasure() {
    const k = scale();
    for (const lines of carved) {
      for (const el of lines) el.style.setProperty("--neu-kmap-len", String(Math.ceil(lineLength(el) * k) + 2));
    }
  }

  function open() {
    if (svg.classList.contains(OPENING)) {
      svg.classList.remove(OPENING);
      void svg.getBoundingClientRect(); // restart the wave from its first frame
    }
    svg.classList.add(OPENING);
    clearTimeout(openTimer);
    openTimer = setTimeout(() => svg.classList.remove(OPENING), OPEN_MS);
  }

  // The map was (re)drawn: dress every key, note its place and its place in the wave.
  function prime() {
    nodes.clear();
    byId.clear();
    settling.clear();
    focus = null;
    selected = null;
    clearFlows();
    carve();
    rescaleGroove();
    const groups = [...nodeLayer.querySelectorAll(".kmap-node")];
    if (!groups.length) return;
    let cx = 0;
    let cy = 0;
    for (const g of groups) {
      const discs = dress(g);
      const p = nodePoint(g);
      nodes.set(g, { id: g.dataset.id, x: p.x, y: p.y, sx: 1, sy: 1, lit: false, discs });
      byId.set(g.dataset.id, g);
      cx += p.x / groups.length;
      cy += p.y / groups.length;
    }
    svg.classList.add(MOULDED);
    let far = 1;
    for (const n of nodes.values()) far = Math.max(far, Math.hypot(n.x - cx, n.y - cy));
    const delays = new Map();
    for (const [g, n] of nodes) {
      const delay = Math.round((Math.hypot(n.x - cx, n.y - cy) / far) * WAVE_MS);
      delays.set(n.id, delay);
      g.style.setProperty("--neu-kmap-d", `${delay}ms`);
    }
    // A groove cuts itself from its end nearer the centre, starting as that key rises.
    for (const [line, ...copies] of carved) {
      const a = delays.get(line.dataset.source) ?? 0;
      const b = delays.get(line.dataset.target) ?? 0;
      for (const el of [line, ...copies]) setLine(el, a <= b ? 1 : -1, Math.min(a, b));
    }
    open();
  }

  function ripple(g) {
    const ring = g.querySelector(".kmap-ring");
    if (!ring) return;
    const box = map.getBoundingClientRect();
    const at = ring.getBoundingClientRect();
    const el = document.createElement("div");
    el.className = RIPPLE;
    el.setAttribute("aria-hidden", "true");
    el.style.setProperty("--neu-kmap-rx", `${Math.round(at.left + at.width / 2 - box.left)}px`);
    el.style.setProperty("--neu-kmap-ry", `${Math.round(at.top + at.height / 2 - box.top)}px`);
    map.insertBefore(el, svg);
    let gone = false;
    const remove = () => {
      if (gone) return;
      gone = true;
      el.remove();
    };
    el.addEventListener("animationend", remove, { once: true });
    setTimeout(remove, RIPPLE_CLEAR_MS);
  }

  // --- channel light: an iris line inside each of the focused note's grooves, drawn out of it ---

  function clearFlows() {
    flows.replaceChildren();
    flowing = [];
  }

  // Lay a lit channel along its groove from the focused note's end. A link is one line (a
  // non-scaling stroke, so its dash is in screen pixels). A tag link is one spark per dimple, at
  // the dimples' own places (the groove's dashes start at its first end), each lit as the light
  // reaches it. Placed again (zoom, drag), a channel is already lit: it no longer animates.
  function place(flow) {
    const { x1, y1, x2, y2 } = lineEnds(flow.edge);
    const k = scale();
    const screen = Math.hypot(x2 - x1, y2 - y1) * k;
    if (flow.placed) flow.el.classList.add("neumorph-kmap-steady");
    flow.placed = true;
    if (flow.kind === "link") {
      const [ax, ay, bx, by] = flow.out ? [x1, y1, x2, y2] : [x2, y2, x1, y1];
      for (const line of flow.el.children) {
        line.setAttribute("x1", ax);
        line.setAttribute("y1", ay);
        line.setAttribute("x2", bx);
        line.setAttribute("y2", by);
        line.style.setProperty("--neu-kmap-len", String(Math.ceil(screen) + 2));
      }
      return;
    }
    flow.el.replaceChildren();
    if (!(screen > 0)) return;
    const r = (SPARK_PX / k).toFixed(3);
    for (let s = 0; s <= screen; s += DIMPLE_PX) {
      const f = s / screen;
      const spark = decor("circle", "neumorph-kmap-spark", {
        cx: (x1 + (x2 - x1) * f).toFixed(2),
        cy: (y1 + (y2 - y1) * f).toFixed(2),
        r,
      });
      spark.style.setProperty("--neu-kmap-t", (flow.out ? f : 1 - f).toFixed(3));
      flow.el.appendChild(spark);
    }
  }

  function drawFlows() {
    clearFlows();
    if (!focus) return;
    for (const edge of edgeLayer.querySelectorAll(".kmap-edge.is-near")) {
      if (edge.classList.contains("is-filtered")) continue;
      const kind = edge.dataset.kind === "tag" ? "tag" : "link";
      // A link's light is a beam: a wide faint glow line under the thin line (strokes, not a
      // filter on the layer, which would re-run over the map on every frame of the draw).
      const el = kind === "tag" ? decor("g", "neumorph-kmap-sparks") : decor("g", "neumorph-kmap-beam");
      if (kind === "link") el.append(decor("line", "neumorph-kmap-flow neumorph-kmap-flow-glow"), decor("line", "neumorph-kmap-flow"));
      const flow = { edge, kind, out: edge.dataset.source === focus, el, placed: false };
      place(flow);
      flows.appendChild(el);
      flowing.push(flow);
    }
  }

  // A key leaves a state that eased (hover, neighbour, selected): it eases back too, while the
  // rest of the map changes in one step (fx.css lists who may ease).
  function letGo(g) {
    if (!g || !g.isConnected) return;
    g.classList.add(SETTLING);
    settling.set(g, performance.now());
    if (!settleTimer) settleTimer = setTimeout(sweepSettled, SETTLE_MS);
  }

  function sweepSettled() {
    settleTimer = 0;
    const now = performance.now();
    for (const [g, at] of settling) {
      if (now - at < SETTLE_MS) continue;
      g.classList.remove(SETTLING);
      settling.delete(g);
    }
    if (settling.size) settleTimer = setTimeout(sweepSettled, SETTLE_MS);
  }

  function neighboursOf(id) {
    return flowing.map((f) => (f.out ? f.edge.dataset.target : f.edge.dataset.source)).filter((other) => other !== id);
  }

  // The note in focus changed (selection or hover): light leaves it along its grooves, its
  // neighbours lift nearest first, and a new selection ripples through the floor.
  function refocus() {
    pending = false;
    const chosen = nodeLayer.querySelector(".kmap-node.is-selected");
    const chosenId = chosen ? chosen.dataset.id : null;
    const next = chosenId || (svg.classList.contains("has-focus") ? hovered : null);
    if (chosen && chosenId !== selected) {
      ripple(chosen);
      settle(chosen, true); // a latched key ignores the pointer light
    }
    if (selected && selected !== chosenId) letGo(byId.get(selected));
    selected = chosenId;
    if (next === focus) return;
    if (focus) {
      letGo(byId.get(focus));
      for (const id of neighboursOf(focus)) letGo(byId.get(id));
    }
    focus = next;
    drawFlows();
    if (!focus) return;
    const centre = byId.get(focus);
    const at = centre ? nodes.get(centre) : null;
    if (!at) return;
    centre.style.setProperty("--neu-kmap-nd", "0ms");
    const near = new Set(neighboursOf(focus));
    const ranked = [];
    for (const [g, n] of nodes) {
      if (near.has(n.id)) ranked.push([Math.hypot(n.x - at.x, n.y - at.y), g]);
    }
    ranked.sort((p, q) => p[0] - q[0]);
    ranked.forEach(([, g], i) => g.style.setProperty("--neu-kmap-nd", `${Math.min(i, STAGGER_STEPS) * STAGGER_MS}ms`));
  }

  function onMutations(records) {
    let drawn = false;
    let moved = false;
    let dragged = false;
    for (const record of records) {
      if (record.type === "childList" && (record.target === nodeLayer || record.target === edgeLayer)) drawn = true;
      else if (record.type === "attributes" && record.attributeName === "transform") {
        if (record.target === viewport) {
          // A pure pan moves everything together: the channels stay as they are.
          if (rescaleGroove()) moved = true;
          continue;
        }
        const n = nodes.get(record.target);
        if (n) {
          Object.assign(n, nodePoint(record.target)); // a dragged key
          moved = true;
          dragged = true;
        }
      }
    }
    if (drawn) prime();
    else if (moved) {
      if (dragged) trace();
      for (const flow of flowing) place(flow);
    }
    if (!pending) {
      pending = true;
      queueMicrotask(refocus);
    }
  }

  const observer = new MutationObserver(onMutations);
  observer.observe(svg, { subtree: true, childList: true, attributes: true, attributeFilter: ["class", "transform"] });

  // Back from List: the map pane is shown again, so the keys rise again.
  const modeObserver = new MutationObserver(() => {
    if (stage && stage.dataset.mode === "map" && nodes.size) {
      rescaleGroove();
      remeasure();
      open();
    }
  });
  if (stage) modeObserver.observe(stage, { attributes: true, attributeFilter: ["data-mode"] });

  // --- the pointer light (fine pointers only): within reach, a key casts its shadow away from
  // the pointer, blended into the room light (up-left) with distance so nothing snaps ---

  // Written on the two discs, not the node: only they restyle (a node write restyles the whole
  // key, ~15x the cost on a 150-note map).
  function turn(g, n, sx, sy) {
    if (Math.abs(sx - n.sx) < EPSILON && Math.abs(sy - n.sy) < EPSILON) return;
    n.sx = sx;
    n.sy = sy;
    for (const d of n.discs) {
      if (sx === 1 && sy === 1) {
        d.style.removeProperty("--neu-kmap-sx");
        d.style.removeProperty("--neu-kmap-sy");
      } else {
        d.style.setProperty("--neu-kmap-sx", sx.toFixed(3));
        d.style.setProperty("--neu-kmap-sy", sy.toFixed(3));
      }
    }
  }

  // Back to the room light. Leaving reach needs no easing (the light already fades to nothing
  // with distance); the pointer leaving the map or the key latching does: it eases back.
  function settle(g, ease) {
    const n = nodes.get(g);
    if (!n) return;
    if (n.lit) {
      n.lit = false;
      if (ease) letGo(g);
    }
    turn(g, n, 1, 1);
  }

  // Follows the pointer frame by frame without transitions (an eased key restyles every frame,
  // which on 150 notes costs more than the turn itself).
  function paint() {
    frame = 0;
    const m = pointer ? viewport.getScreenCTM() : null;
    for (const [g, n] of nodes) {
      if (!m || g.classList.contains("is-selected")) {
        settle(g, true);
        continue;
      }
      const dx = m.a * n.x + m.c * n.y + m.e - pointer.x;
      const dy = m.b * n.x + m.d * n.y + m.f - pointer.y;
      const d = Math.hypot(dx, dy) || 1;
      const w = Math.max(0, 1 - d / REACH_PX);
      if (w === 0) {
        settle(g, false);
        continue;
      }
      n.lit = true;
      const lean = SWING * w * Math.min(1, d / OVERHEAD_PX);
      turn(g, n, 1 - w + (dx / d) * lean, 1 - w + (dy / d) * lean);
    }
  }

  function schedule() {
    if (!frame && !document.hidden) frame = requestAnimationFrame(paint);
  }

  function onMove(event) {
    if (event.pointerType !== "mouse" && !finePointer.matches) return;
    pointer = { x: event.clientX, y: event.clientY };
    schedule();
  }

  function onOver(event) {
    const g = event.target instanceof Element ? event.target.closest(".kmap-node") : null;
    const id = g ? g.dataset.id || null : null;
    if (hovered && hovered !== id) letGo(byId.get(hovered)); // its hover lift eases down
    hovered = id;
  }

  function onLeave() {
    pointer = null;
    if (hovered) letGo(byId.get(hovered));
    hovered = null;
    schedule();
  }

  svg.addEventListener("pointermove", onMove, { passive: true });
  svg.addEventListener("pointerover", onOver, { passive: true });
  svg.addEventListener("pointerleave", onLeave, { passive: true });

  if (nodeLayer.querySelector(".kmap-node")) prime();

  return () => {
    observer.disconnect();
    modeObserver.disconnect();
    clearTimeout(openTimer);
    clearTimeout(settleTimer);
    if (frame) cancelAnimationFrame(frame);
    svg.removeEventListener("pointermove", onMove);
    svg.removeEventListener("pointerover", onOver);
    svg.removeEventListener("pointerleave", onLeave);
  };
}

export function initKmap() {
  const main = document.getElementById("main");
  if (!main) return;
  const finePointer = matchMedia("(pointer: fine)");
  let current = null;
  let stop = () => {};

  // The map window is rebuilt on every visit to #/knowledge: follow whichever one is shown.
  function follow() {
    const svg = main.querySelector(".window-kmap .kmap-svg");
    if (svg === current) return;
    stop();
    current = svg;
    stop = svg ? watchMap(svg, finePointer) : () => {};
  }

  // Hidden tab: the recent LEDs stop breathing and the pointer light stops (no frames).
  function onVisibility() {
    document.documentElement.classList.toggle(PAUSED, document.hidden);
  }

  new MutationObserver(follow).observe(main, { childList: true });
  document.addEventListener("visibilitychange", onVisibility);
  onVisibility();
  follow();
}
