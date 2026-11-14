/*
  Knowledge-map moulding and motion for Neumorph (docs/frontend-os.md#neumorph "Knowledge map"):
  dresses every note as the approved mockup's porcelain key (convex face, gradient rim, concave
  socket, blurred LED halo, lit LED glass, painted by one shared aria-hidden <defs>; its one soft
  shadow is chrome's), carves the grooves, draws iris light along the focused note's grooves out
  of it, ripples the floor on select, plays the opening wave and makes the pointer a light source
  that turns each nearby key's shadow. Reads only the map's neutral hooks and geometry; writes CSS
  custom properties (CSSOM), OS-prefixed classes and its own empty aria-hidden decor. No text, no
  item data, no prevented events; the approvals card is untouched.
*/

const MOULDED = "neumorph-kmap-moulded";
const OPENING = "neumorph-kmap-opening";
const PAUSED = "neumorph-kmap-paused";
const RIPPLE = "neumorph-kmap-ripple";
const FLOWS = "neumorph-kmap-flows";
const SETTLING = "neumorph-kmap-settling"; // just let go: it eases back to rest
// The height a let-go key eases down (or up) from: a raised key or the latched (selected) one.
const LEFT_UP = "var(--neu-kmap-lift-up)";
const LEFT_FLUSH = "var(--neu-kmap-lift-flush)";

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

// A key's face is the approved mockup's key, drawn at the mockup's own size (a 21-unit key) and
// scaled to each key (knowledge-map.js draws the ring at r + 4), so its gradients, rim, blur and
// inset shading keep the mockup's proportions on every key at every zoom. The LED is the map's
// own dot, sized to the mockup's 6.3. The key's shadow is no part of the face: it is the ring's
// soft drop-shadow pair (chrome.css), so a key is one key with one shadow.
const KEY_PAD = 4;
const FACE = { key: 21, rim: 20.4, rimW: 1.2, socket: 10.5, halo: 8.8, led: 6.3 };

// The mockup's paint servers, its values copied as they are: the convex key, the gradient rim,
// the concave socket and its inset shading (shade up-left, light down-right, inside the shape),
// the LED's blurred halo and the light on the LED's glass. One of each in one aria-hidden <defs>,
// shared by every key (a filter per key janked N4). Ids are namespaced; nothing else is
// referenced (an OS loads nothing: only these in-document fragments).
const PAINT = [
  ["linearGradient", { id: "neumorph-kmap-convex", x1: 0, y1: 0, x2: 1, y2: 1 }, [
    ["stop", { offset: 0, "stop-color": "#eff3f8" }],
    ["stop", { offset: 1, "stop-color": "#dce2eb" }],
  ]],
  ["linearGradient", { id: "neumorph-kmap-concave", x1: 0, y1: 0, x2: 1, y2: 1 }, [
    ["stop", { offset: 0, "stop-color": "#d9dfe8" }],
    ["stop", { offset: 1, "stop-color": "#ebeff5" }],
  ]],
  ["linearGradient", { id: "neumorph-kmap-rim", x1: 0, y1: 0, x2: 1, y2: 1 }, [
    ["stop", { offset: 0, "stop-color": "#ffffff", "stop-opacity": 0.95 }],
    ["stop", { offset: 0.5, "stop-color": "#ffffff", "stop-opacity": 0 }],
    ["stop", { offset: 1, "stop-color": "#96a4bc", "stop-opacity": 0.35 }],
  ]],
  ["radialGradient", { id: "neumorph-kmap-ledlight", cx: 0.36, cy: 0.34, r: 0.7 }, [
    ["stop", { offset: 0, "stop-color": "#ffffff", "stop-opacity": 0.5 }],
    ["stop", { offset: 0.45, "stop-color": "#ffffff", "stop-opacity": 0 }],
    ["stop", { offset: 1, "stop-color": "#000000", "stop-opacity": 0.22 }],
  ]],
  ["filter", { id: "neumorph-kmap-inset", x: "-30%", y: "-30%", width: "160%", height: "160%", "color-interpolation-filters": "sRGB" }, [
    ["feComponentTransfer", { in: "SourceAlpha", result: "inv" }, [["feFuncA", { type: "table", tableValues: "1 0" }]]],
    ["feOffset", { in: "inv", dx: 1.6, dy: 1.6, result: "o1" }],
    ["feGaussianBlur", { in: "o1", stdDeviation: 1.3, result: "b1" }],
    ["feFlood", { "flood-color": "#8a99b2", "flood-opacity": 0.85 }],
    ["feComposite", { operator: "in", in2: "b1" }],
    ["feComposite", { operator: "in", in2: "SourceAlpha", result: "shade" }],
    ["feOffset", { in: "inv", dx: -1.4, dy: -1.4, result: "o2" }],
    ["feGaussianBlur", { in: "o2", stdDeviation: 1.2, result: "b2" }],
    ["feFlood", { "flood-color": "#ffffff", "flood-opacity": 1 }],
    ["feComposite", { operator: "in", in2: "b2" }],
    ["feComposite", { operator: "in", in2: "SourceAlpha", result: "light" }],
    ["feMerge", {}, [["feMergeNode", { in: "SourceGraphic" }], ["feMergeNode", { in: "shade" }], ["feMergeNode", { in: "light" }]]],
  ]],
  ["filter", { id: "neumorph-kmap-bloom", x: "-100%", y: "-100%", width: "300%", height: "300%" }, [
    ["feGaussianBlur", { stdDeviation: 2.2 }],
  ]],
];

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

/** One part of the paint-server tree (inside the hidden <defs>, so no aria of its own). */
function paint([tag, attrs, children = []]) {
  const el = document.createElementNS(svgNs, tag);
  for (const [name, value] of Object.entries(attrs)) el.setAttribute(name, String(value));
  for (const child of children) el.appendChild(paint(child));
  return el;
}

/** The map's one <defs> of paint servers, first in the svg; reused if it is already there. */
function paintServers(svg) {
  const found = svg.querySelector(":scope > .neumorph-kmap-paint");
  if (found) return found;
  const defs = decor("defs", "neumorph-kmap-paint");
  for (const server of PAINT) defs.appendChild(paint(server));
  svg.insertBefore(defs, svg.firstChild);
  return defs;
}

/** A face part: a mockup circle of radius r (mockup units), painted by attributes. */
function part(className, r, attrs = {}) {
  return decor("circle", className, { r, ...attrs });
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

/**
 * Watch one knowledge-map window; returns its stop function. With `motion` false (reduced
 * motion) the keys are still dressed and the grooves carved (structure, not motion); the
 * opening wave, the ripple and the pointer light stay off, and fx.css stills the rest.
 */
function watchMap(svg, finePointer, motion) {
  const map = svg.closest(".kmap-map");
  const stage = svg.closest(".kmap-stage");
  const viewport = svg.querySelector(".kmap-viewport");
  const nodeLayer = svg.querySelector(".kmap-nodes");
  const edgeLayer = svg.querySelector(".kmap-edges");
  if (!map || !viewport || !nodeLayer || !edgeLayer) return () => {};
  svgNs = svg.namespaceURI;
  const defs = paintServers(svg);

  const nodes = new Map(); // g -> { id, x, y, sx, sy, ring }
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

  // The grooves' carving: a narrower copy of every groove in a faint shade layer nudged up-left
  // and a faint light layer nudged down-right, over the edge layer (under the channel light), so
  // both stay inside their groove: its upper wall in shade, its lower wall lit, one channel.
  // Plain strokes, no filter: a layer filter re-runs over the whole map on every repaint.
  const carveShade = decor("g", "neumorph-kmap-carve-shade");
  const carveLight = decor("g", "neumorph-kmap-carve-light");
  const carves = decor("g", "neumorph-kmap-carves");
  carves.append(carveShade, carveLight);
  viewport.insertBefore(carves, flows);
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

  // A key, element for element as the mockup: over the ring (the key's shadow) a face of the
  // convex key, its gradient rim, the concave socket with its inset shading and the LED's blurred
  // halo; the map's dot is the LED; over it the light on its glass. Paint is set as attributes
  // (fx.css only restyles states). Returns the ring (which the pointer light turns), or null for
  // a key it can't dress.
  function dress(g) {
    const ring = g.querySelector(".kmap-ring");
    const dot = g.querySelector(".kmap-dot");
    if (dressed.has(g)) return ring;
    const r = dot ? Number(dot.getAttribute("r")) : 0;
    if (!ring || !(r > 0)) return null;
    dressed.add(g);
    const key = r + KEY_PAD;
    const unit = (key / FACE.key).toFixed(4);
    g.style.setProperty("--neu-kmap-led-k", ((FACE.led * key) / (FACE.key * r)).toFixed(4));
    const face = decor("g", "neumorph-kmap-face");
    face.style.setProperty("--neu-kmap-u", unit);
    face.append(
      part("neumorph-kmap-key", FACE.key, { fill: "url(#neumorph-kmap-convex)" }),
      part("neumorph-kmap-rim", FACE.rim, { fill: "none", stroke: "url(#neumorph-kmap-rim)", "stroke-width": FACE.rimW }),
      part("neumorph-kmap-socket", FACE.socket, { fill: "url(#neumorph-kmap-concave)", filter: "url(#neumorph-kmap-inset)" }),
      part("neumorph-kmap-halo", FACE.halo, { filter: "url(#neumorph-kmap-bloom)" }),
    );
    const glass = part("neumorph-kmap-glass", FACE.led, { fill: "url(#neumorph-kmap-ledlight)" });
    glass.style.setProperty("--neu-kmap-u", unit);
    g.insertBefore(face, dot);
    g.insertBefore(glass, dot.nextSibling);
    return ring;
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
    if (!motion) return; // reduced motion: the keys are simply there
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
      const ring = dress(g);
      const p = nodePoint(g);
      nodes.set(g, { id: g.dataset.id, x: p.x, y: p.y, sx: 1, sy: 1, ring });
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

  // A key leaves a state that eased (hover, neighbour, selected): it eases back too, from the
  // height it left, while the rest of the map changes in one step (fx.css lists who may ease).
  function letGo(g, left = LEFT_UP) {
    if (!g || !g.isConnected) return;
    g.style.setProperty("--neu-kmap-left", left);
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
      if (motion) ripple(chosen);
      settle(chosen); // a latched key ignores the pointer light
    }
    const was = selected;
    if (selected && selected !== chosenId) letGo(byId.get(selected), LEFT_FLUSH);
    selected = chosenId;
    if (next === focus) return;
    if (focus) {
      if (focus !== was) letGo(byId.get(focus));
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

  // Written on the ring (the only part that casts the shadow), not the node: only it restyles (a
  // node write restyles the whole key, several times the cost on a 150-note map).
  function turn(n, sx, sy) {
    if (!n.ring || (Math.abs(sx - n.sx) < EPSILON && Math.abs(sy - n.sy) < EPSILON)) return;
    n.sx = sx;
    n.sy = sy;
    if (sx === 1 && sy === 1) {
      n.ring.style.removeProperty("--neu-kmap-sx");
      n.ring.style.removeProperty("--neu-kmap-sy");
    } else {
      n.ring.style.setProperty("--neu-kmap-sx", sx.toFixed(3));
      n.ring.style.setProperty("--neu-kmap-sy", sy.toFixed(3));
    }
  }

  // Back to the room light, in one step: the light already fades to nothing with distance, and
  // a key that latches eases down anyway (its press).
  function settle(g) {
    const n = nodes.get(g);
    if (n) turn(n, 1, 1);
  }

  // Follows the pointer frame by frame without transitions (an eased key restyles every frame,
  // which on 150 notes costs more than the turn itself).
  function paintPointer() {
    frame = 0;
    const m = pointer ? viewport.getScreenCTM() : null;
    for (const [g, n] of nodes) {
      if (!m || g.classList.contains("is-selected")) {
        settle(g);
        continue;
      }
      const dx = m.a * n.x + m.c * n.y + m.e - pointer.x;
      const dy = m.b * n.x + m.d * n.y + m.f - pointer.y;
      const d = Math.hypot(dx, dy) || 1;
      const w = Math.max(0, 1 - d / REACH_PX);
      if (w === 0) {
        settle(g);
        continue;
      }
      const lean = SWING * w * Math.min(1, d / OVERHEAD_PX);
      turn(n, 1 - w + (dx / d) * lean, 1 - w + (dy / d) * lean);
    }
  }

  function schedule() {
    if (!frame && !document.hidden) frame = requestAnimationFrame(paintPointer);
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

  if (motion) svg.addEventListener("pointermove", onMove, { passive: true });
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
    defs.remove(); // its ids leave the document with the map they belong to
  };
}

/**
 * Mould every knowledge map shown. `motion` false (reduced motion): the same keys and grooves,
 * nothing that moves on its own (fx.js starts this in both cases; a key is never a bare dot).
 */
export function initKmap(motion = true) {
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
    stop = svg ? watchMap(svg, finePointer, motion) : () => {};
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
