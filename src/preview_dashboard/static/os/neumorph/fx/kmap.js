/*
  Knowledge-map motion for Neumorph (docs/frontend-os.md#neumorph "Knowledge map"): the opening
  wave, the iris flow along a focused note's channels, the ripple through the basin and the
  pointer light (pearls near the pointer lean their highlight toward it). Reads only the map's
  neutral hooks; writes CSS custom properties (CSSOM), two OS-prefixed classes and its own empty
  aria-hidden decor. No text, no item data, no prevented events; the approvals card is untouched.
*/

const OPENING = "neumorph-kmap-opening";
const LIT = "neumorph-kmap-lit";
const PAUSED = "neumorph-kmap-paused";
const LIGHT = "neumorph-kmap-light";
const RIPPLE = "neumorph-kmap-ripple";

const WAVE_MS = 520; // the outermost pearl starts this long after the centre one
const OPEN_MS = 1500; // wave + rise + label fade, then the opening class goes
const RIPPLE_CLEAR_MS = 1100; // a little over --neu-dur-kmap-ripple, in case animationend never fires
const STAGGER_MS = 45; // neighbours of a focused note rise one after another...
const STAGGER_STEPS = 8; // ...for at most this many steps
const REACH_PX = 190; // pearls within this distance of the pointer feel its light
const NEAR_PX = 46; // inside this, a pearl's highlight follows the pointer one to one
const LEAN_EPSILON = 0.03; // smaller changes are not written (no restyle for nothing)

/** Position of a node group (its translate), in map units. */
function nodePoint(g) {
  const list = g.transform && g.transform.baseVal;
  if (!list || list.numberOfItems === 0) return { x: 0, y: 0 };
  const m = list.getItem(0).matrix;
  return { x: m.e, y: m.f };
}

function lineLength(line) {
  const n = (name) => Number(line.getAttribute(name)) || 0;
  return Math.hypot(n("x2") - n("x1"), n("y2") - n("y1"));
}

/** Watch one knowledge-map window; returns its stop function. */
function watchMap(svg, finePointer) {
  const map = svg.closest(".kmap-map");
  const stage = svg.closest(".kmap-stage");
  const viewport = svg.querySelector(".kmap-viewport");
  const nodeLayer = svg.querySelector(".kmap-nodes");
  const edgeLayer = svg.querySelector(".kmap-edges");
  if (!map || !viewport || !nodeLayer || !edgeLayer) return () => {};

  const nodes = new Map(); // g -> { id, x, y, lx, ly, glint }
  let focus = null;
  let selected = null;
  let hovered = null;
  let openTimer = 0;
  let pending = false;
  let frame = 0;
  let pointer = null;

  const light = document.createElement("div");
  light.className = LIGHT;
  light.setAttribute("aria-hidden", "true");
  map.insertBefore(light, map.firstChild);

  // Non-scaling strokes dash in screen pixels: a line's dash length is its length on screen.
  function strokeScale(line) {
    const ctm = viewport.getCTM();
    const scales = getComputedStyle(line).vectorEffect === "non-scaling-stroke";
    return ctm && scales ? Math.hypot(ctm.a, ctm.b) : 1;
  }

  function setLine(line, from, delay) {
    line.style.setProperty("--neu-kmap-len", String(Math.ceil(lineLength(line) * strokeScale(line)) + 2));
    line.style.setProperty("--neu-kmap-from", String(from));
    if (delay !== undefined) line.style.setProperty("--neu-kmap-d", `${delay}ms`);
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

  // The map was (re)drawn: note every pearl's place and give each its place in the wave.
  function prime() {
    nodes.clear();
    focus = null;
    selected = null;
    const groups = [...nodeLayer.querySelectorAll(".kmap-node")];
    if (!groups.length) return;
    let cx = 0;
    let cy = 0;
    for (const g of groups) {
      const p = nodePoint(g);
      nodes.set(g, { id: g.dataset.id, x: p.x, y: p.y, lx: 0, ly: 0, glint: 0 });
      cx += p.x / groups.length;
      cy += p.y / groups.length;
    }
    let far = 1;
    for (const n of nodes.values()) far = Math.max(far, Math.hypot(n.x - cx, n.y - cy));
    const delays = new Map();
    for (const [g, n] of nodes) {
      const delay = Math.round((Math.hypot(n.x - cx, n.y - cy) / far) * WAVE_MS);
      delays.set(n.id, delay);
      g.style.setProperty("--neu-kmap-d", `${delay}ms`);
    }
    // A channel draws from its end nearer the centre, starting as that pearl rises.
    for (const line of edgeLayer.querySelectorAll(".kmap-edge")) {
      const a = delays.get(line.dataset.source) ?? 0;
      const b = delays.get(line.dataset.target) ?? 0;
      setLine(line, a <= b ? 1 : -1, Math.min(a, b));
    }
    open();
  }

  function ripple(g) {
    const dot = g.querySelector(".kmap-dot");
    if (!dot) return;
    const box = map.getBoundingClientRect();
    const at = dot.getBoundingClientRect();
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

  // The note in focus changed (selection or hover): light leaves it along its channels, its
  // neighbours rise nearest first, and a new selection ripples through the basin.
  function refocus() {
    pending = false;
    const chosen = nodeLayer.querySelector(".kmap-node.is-selected");
    const chosenId = chosen ? chosen.dataset.id : null;
    const next = chosenId || (svg.classList.contains("has-focus") ? hovered : null);
    if (chosen && chosenId !== selected) ripple(chosen);
    selected = chosenId;
    if (next === focus) return;
    focus = next;
    if (!focus) return;
    const centre = [...nodes.values()].find((n) => n.id === focus);
    const near = [];
    for (const line of edgeLayer.querySelectorAll(".kmap-edge.is-near")) {
      const out = line.dataset.source === focus;
      setLine(line, out ? 1 : -1);
      near.push(out ? line.dataset.target : line.dataset.source);
    }
    if (!centre) return;
    const ranked = [];
    for (const [g, n] of nodes) {
      if (near.includes(n.id)) ranked.push([Math.hypot(n.x - centre.x, n.y - centre.y), g]);
    }
    ranked.sort((p, q) => p[0] - q[0]);
    ranked.forEach(([, g], i) => g.style.setProperty("--neu-kmap-nd", `${Math.min(i, STAGGER_STEPS) * STAGGER_MS}ms`));
  }

  function onMutations(records) {
    let drawn = false;
    for (const record of records) {
      if (record.type === "childList" && record.target === nodeLayer) drawn = true;
      else if (record.type === "attributes" && record.attributeName === "transform") {
        const n = nodes.get(record.target);
        if (n) Object.assign(n, nodePoint(record.target)); // a dragged pearl
      }
    }
    if (drawn) prime();
    if (!pending) {
      pending = true;
      queueMicrotask(refocus);
    }
  }

  const observer = new MutationObserver(onMutations);
  observer.observe(svg, { subtree: true, childList: true, attributes: true, attributeFilter: ["class", "transform"] });

  // Back from List: the map pane is shown again, so the pearls rise again.
  const modeObserver = new MutationObserver(() => {
    if (stage && stage.dataset.mode === "map" && nodes.size) open();
  });
  if (stage) modeObserver.observe(stage, { attributes: true, attributeFilter: ["data-mode"] });

  // --- the pointer light (fine pointers only) ---

  function lean(g, n, lx, ly, glint) {
    if (Math.abs(lx - n.lx) < LEAN_EPSILON && Math.abs(ly - n.ly) < LEAN_EPSILON && Math.abs(glint - n.glint) < LEAN_EPSILON) return;
    n.lx = lx;
    n.ly = ly;
    n.glint = glint;
    if (lx === 0 && ly === 0 && glint === 0) {
      g.style.removeProperty("--neu-kmap-lx");
      g.style.removeProperty("--neu-kmap-ly");
      g.style.removeProperty("--neu-kmap-glint");
      return;
    }
    g.style.setProperty("--neu-kmap-lx", lx.toFixed(3));
    g.style.setProperty("--neu-kmap-ly", ly.toFixed(3));
    g.style.setProperty("--neu-kmap-glint", glint.toFixed(3));
  }

  function paint() {
    frame = 0;
    if (!pointer) return;
    const box = map.getBoundingClientRect();
    light.style.setProperty("--neu-kmap-x", `${Math.round(pointer.x - box.left)}px`);
    light.style.setProperty("--neu-kmap-y", `${Math.round(pointer.y - box.top)}px`);
    const m = viewport.getScreenCTM();
    if (!m) return;
    for (const [g, n] of nodes) {
      const dx = pointer.x - (m.a * n.x + m.c * n.y + m.e);
      const dy = pointer.y - (m.b * n.x + m.d * n.y + m.f);
      const d = Math.hypot(dx, dy);
      if (d >= REACH_PX) {
        lean(g, n, 0, 0, 0);
        continue;
      }
      // Close by, the highlight follows the pointer one to one; further out it eases back to
      // the room light (weight falls smoothly to zero at REACH_PX).
      const t = 1 - d / REACH_PX;
      const weight = t * t * (3 - 2 * t);
      const pull = Math.min(1, d / NEAR_PX) / Math.max(d, 1);
      lean(g, n, dx * pull * weight, dy * pull * weight, weight);
    }
  }

  function schedule() {
    if (!frame && !document.hidden) frame = requestAnimationFrame(paint);
  }

  function onMove(event) {
    if (event.pointerType !== "mouse" && !finePointer.matches) return;
    pointer = { x: event.clientX, y: event.clientY };
    light.classList.add(LIT);
    schedule();
  }

  function onOver(event) {
    const g = event.target instanceof Element ? event.target.closest(".kmap-node") : null;
    hovered = g ? g.dataset.id || null : null;
  }

  function onLeave() {
    pointer = null;
    hovered = null;
    light.classList.remove(LIT);
    for (const [g, n] of nodes) lean(g, n, 0, 0, 0);
  }

  svg.addEventListener("pointermove", onMove, { passive: true });
  svg.addEventListener("pointerover", onOver, { passive: true });
  svg.addEventListener("pointerleave", onLeave, { passive: true });

  if (nodeLayer.querySelector(".kmap-node")) prime();

  return () => {
    observer.disconnect();
    modeObserver.disconnect();
    clearTimeout(openTimer);
    if (frame) cancelAnimationFrame(frame);
    svg.removeEventListener("pointermove", onMove);
    svg.removeEventListener("pointerover", onOver);
    svg.removeEventListener("pointerleave", onLeave);
    light.remove();
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

  // Hidden tab: the recent notes stop breathing and the pointer light stops (no frames).
  function onVisibility() {
    document.documentElement.classList.toggle(PAUSED, document.hidden);
  }

  new MutationObserver(follow).observe(main, { childList: true });
  document.addEventListener("visibilitychange", onVisibility);
  onVisibility();
  follow();
}
