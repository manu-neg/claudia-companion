/*
  Knowledge map geometry, pure functions only (no DOM, node-testable): a seeded force layout that
  pulls each category into its own cluster, node radius by connection count, the zoom/pan
  transform that fits the map, a label-collision nudge, neighbour sets and the search match. Deterministic: the same notes
  always land in the same places, so the map looks the same every time it opens.
*/

const MIN_RADIUS = 4;
const MAX_RADIUS = 14;

/** Dot radius in map units: grows with the square root of the connection count. */
export function nodeRadius(degree) {
  const d = Number.isFinite(degree) && degree > 0 ? degree : 0;
  return Math.min(MAX_RADIUS, MIN_RADIUS + 2 * Math.sqrt(d));
}

// FNV-1a over a string: the layout seed (stable per set of notes).
function hash(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// mulberry32: a tiny seeded PRNG (Math.random would move the map on every open).
function random(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Lay the map out in a `size` x `size` square. `nodes`: [{id, category, degree}], `edges`:
 * [{source, target, kind}] (`tag` edges pull more softly than `link` ones). Returns a Map
 * id -> {x, y}. Repulsion is only computed between dots in neighbouring grid cells, so the
 * cost stays near-linear up to the API's 2000 notes.
 */
export function layoutGraph(nodes, edges, { size = 1000, iterations = null } = {}) {
  const positions = new Map();
  if (!Array.isArray(nodes) || nodes.length === 0) return positions;
  const ids = nodes.map((n) => n.id);
  const rand = random(hash(ids.slice().sort().join("|")));
  const categories = [...new Set(nodes.map((n) => n.category))].sort();
  const centre = size / 2;
  const ring = categories.length > 1 ? size * 0.3 : 0;
  const anchors = new Map(
    categories.map((name, i) => {
      const angle = (2 * Math.PI * i) / categories.length - Math.PI / 2;
      return [name, { x: centre + ring * Math.cos(angle), y: centre + ring * Math.sin(angle) }];
    }),
  );
  const ideal = Math.max(18, Math.min(60, size / Math.sqrt(nodes.length + 1) / 1.6));
  const points = nodes.map((n) => {
    const anchor = anchors.get(n.category);
    return { id: n.id, x: anchor.x + (rand() - 0.5) * ideal * 4, y: anchor.y + (rand() - 0.5) * ideal * 4, dx: 0, dy: 0, anchor };
  });
  const index = new Map(points.map((p, i) => [p.id, i]));
  const springs = (Array.isArray(edges) ? edges : [])
    .filter((e) => index.has(e.source) && index.has(e.target) && e.source !== e.target)
    .map((e) => [index.get(e.source), index.get(e.target), e.kind === "tag" ? 0.35 : 1]);
  const steps = iterations ?? Math.max(60, Math.min(300, Math.round(60000 / (nodes.length + 100))));
  const cell = ideal * 2;
  let temperature = ideal * 2;

  for (let step = 0; step < steps; step += 1) {
    for (const p of points) {
      p.dx = 0;
      p.dy = 0;
    }
    const grid = new Map();
    points.forEach((p, i) => {
      const key = `${Math.floor(p.x / cell)},${Math.floor(p.y / cell)}`;
      if (!grid.has(key)) grid.set(key, []);
      grid.get(key).push(i);
    });
    points.forEach((p, i) => {
      const gx = Math.floor(p.x / cell);
      const gy = Math.floor(p.y / cell);
      for (let ox = -1; ox <= 1; ox += 1) {
        for (let oy = -1; oy <= 1; oy += 1) {
          for (const j of grid.get(`${gx + ox},${gy + oy}`) || []) {
            if (j <= i) continue;
            const q = points[j];
            let vx = p.x - q.x;
            let vy = p.y - q.y;
            let dist = Math.hypot(vx, vy);
            if (dist < 0.01) {
              vx = rand() - 0.5;
              vy = rand() - 0.5;
              dist = 0.01;
            }
            if (dist > cell) continue;
            const force = (ideal * ideal) / dist;
            const fx = (vx / dist) * force;
            const fy = (vy / dist) * force;
            p.dx += fx;
            p.dy += fy;
            q.dx -= fx;
            q.dy -= fy;
          }
        }
      }
    });
    for (const [a, b, weight] of springs) {
      const p = points[a];
      const q = points[b];
      const vx = p.x - q.x;
      const vy = p.y - q.y;
      const dist = Math.max(0.01, Math.hypot(vx, vy));
      const force = ((dist * dist) / ideal) * weight;
      const fx = (vx / dist) * force;
      const fy = (vy / dist) * force;
      p.dx -= fx;
      p.dy -= fy;
      q.dx += fx;
      q.dy += fy;
    }
    for (const p of points) {
      // Gravity toward the category's anchor: the clusters.
      p.dx += (p.anchor.x - p.x) * 0.06 * ideal * 0.1;
      p.dy += (p.anchor.y - p.y) * 0.06 * ideal * 0.1;
      const len = Math.hypot(p.dx, p.dy);
      if (len > 0) {
        const move = Math.min(len, temperature);
        p.x += (p.dx / len) * move;
        p.y += (p.dy / len) * move;
      }
    }
    temperature = Math.max(0.5, temperature * 0.97);
  }
  nudgeLabels(points, nodes);
  for (const p of points) positions.set(p.id, { x: p.x, y: p.y });
  return positions;
}

const LABEL_HEIGHT = 13;
const LABEL_CHAR_WIDTH = 6.5;
const LABEL_MAX_CHARS = 28;
const NUDGE_PASSES = 12;
const NUDGE_LIMIT = 36;

/**
 * Small collision nudge after the force layout: where two labels (centred under their dots)
 * would overlap, push the two dots apart vertically, at most NUDGE_LIMIT units from where the
 * layout put them. Deterministic: sorted by label top then id, fixed number of passes.
 */
export function nudgeLabels(points, nodes) {
  const info = new Map(nodes.map((n) => [n.id, n]));
  const items = points.map((p) => {
    const node = info.get(p.id) || {};
    const chars = Math.min(LABEL_MAX_CHARS, String(node.title || "").length);
    return { p, home: p.y, half: (chars * LABEL_CHAR_WIDTH) / 2, drop: nodeRadius(node.degree) + 2 };
  });
  for (let pass = 0; pass < NUDGE_PASSES; pass += 1) {
    items.sort((a, b) => a.p.y + a.drop - (b.p.y + b.drop) || (a.p.id < b.p.id ? -1 : 1));
    let moved = false;
    for (let i = 0; i < items.length; i += 1) {
      const a = items[i];
      for (let j = i + 1; j < items.length; j += 1) {
        const b = items[j];
        const overlapY = a.p.y + a.drop + LABEL_HEIGHT - (b.p.y + b.drop);
        if (overlapY <= 0) break; // sorted by top: nothing further down can overlap a
        if (Math.abs(a.p.x - b.p.x) >= a.half + b.half) continue;
        const push = overlapY / 2 + 0.5;
        const up = clamp(a.p.y - push, a.home - NUDGE_LIMIT, a.home + NUDGE_LIMIT);
        const down = clamp(b.p.y + push, b.home - NUDGE_LIMIT, b.home + NUDGE_LIMIT);
        if (up !== a.p.y || down !== b.p.y) moved = true;
        a.p.y = up;
        b.p.y = down;
      }
    }
    if (!moved) break;
  }
}

/**
 * The transform `{x, y, k}` (screen = map * k + offset) that fits every position into a
 * `width` x `height` view with `pad` pixels to spare; zoom clamped to [minK, maxK].
 */
export function fitTransform(positions, width, height, { pad = 32, minK = 0.1, maxK = 2.5 } = {}) {
  const list = [...positions.values()];
  if (!list.length || width <= 0 || height <= 0) return { x: 0, y: 0, k: 1 };
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const { x, y } of list) {
    minX = Math.min(minX, x);
    minY = Math.min(minY, y);
    maxX = Math.max(maxX, x);
    maxY = Math.max(maxY, y);
  }
  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);
  const k = clamp(Math.min((width - 2 * pad) / spanX, (height - 2 * pad) / spanY), minK, maxK);
  return { x: width / 2 - ((minX + maxX) / 2) * k, y: height / 2 - ((minY + maxY) / 2) * k, k };
}

/** Zoom by `factor` around the screen point (px, py), keeping that point still. */
export function zoomAt(view, factor, px, py, { minK = 0.1, maxK = 6 } = {}) {
  const k = clamp(view.k * factor, minK, maxK);
  const ratio = k / view.k;
  return { x: px - (px - view.x) * ratio, y: py - (py - view.y) * ratio, k };
}

export function clamp(value, low, high) {
  return Math.min(high, Math.max(low, value));
}

/** Map id -> Set of neighbour ids (both directions). */
export function neighbours(edges) {
  const map = new Map();
  for (const { source, target } of Array.isArray(edges) ? edges : []) {
    if (!map.has(source)) map.set(source, new Set());
    if (!map.has(target)) map.set(target, new Set());
    map.get(source).add(target);
    map.get(target).add(source);
  }
  return map;
}

/** Search: every word of `query` appears in the title or a tag (case-insensitive). */
export function matchesQuery(node, query) {
  const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return true;
  const haystack = [node.title, ...(Array.isArray(node.tags) ? node.tags : [])].join(" ").toLowerCase();
  return words.every((word) => haystack.includes(word));
}

/** Category colour slot 0..7 per category name, in name order (the same every time). */
export function categorySlots(categories) {
  const names = [...new Set(categories)].sort();
  return new Map(names.map((name, i) => [name, i % 8]));
}
