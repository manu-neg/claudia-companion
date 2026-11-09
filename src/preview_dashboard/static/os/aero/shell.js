/*
  Aero shell (docs/frontend-os.md#aero): the OS-only decorative DOM this OS adds - the desktop
  scenery (sun, rays, bubbles, hills; CSS-painted), the Feed/Trash icons moved into the glass
  shell bar, and Aero art (Vista/7 document icons for every file type, glossy folder/bin/alert)
  swapped into the sprite. Decorative only (aria-hidden, no behaviour). Does nothing unless
  html[data-os] is "aero"; no functional imports, no network, no storage.
*/

const OS = "aero";

// --- scenery: fixed, behind everything (z-index -1), painted by chrome.css per background ---

const SCENERY_PARTS = [
  "aero-sun",
  "aero-ray aero-ray-1",
  "aero-ray aero-ray-2",
  "aero-ray aero-ray-3",
  "aero-bubble aero-bubble-1",
  "aero-bubble aero-bubble-2",
  "aero-bubble aero-bubble-3",
  "aero-bubble aero-bubble-4",
  "aero-bubble aero-bubble-5",
  "aero-bubble aero-bubble-6",
  "aero-hill aero-hill-back",
  "aero-hill aero-hill-front",
];

function addScenery() {
  if (document.querySelector(".aero-scenery")) return;
  const scenery = document.createElement("div");
  scenery.className = "aero-scenery";
  scenery.setAttribute("aria-hidden", "true");
  for (const className of SCENERY_PARTS) {
    const part = document.createElement("span");
    part.className = className;
    scenery.appendChild(part);
  }
  document.body.prepend(scenery);
}

// --- shell bar: Feed / Trash become glass pills next to the orb (functional code finds them
// by their [data-nav] hooks at use time, wherever they sit) ---

function moveDeskIcons() {
  const icons = document.querySelector(".desktop > .desk-icons");
  const slot = document.querySelector('[data-shellbar] [data-slot="nav"]');
  if (icons && slot) slot.appendChild(icons);
}

// --- icons: glossy Aero art replaces the shared sprite's pixel art in place (same symbol ids
// and viewBoxes, so every <use> updates). Shapes only; colours come from chrome.css classes. ---

// Vista / 7 document icons: a pearl page with a folded top-right corner, a soft drop shadow and a
// faint shading toward the foot; the file type is drawn on the page the way the 1998 set does it.
// Edges are 1 device pixel at every size (non-scaling stroke, chrome.css); page edges sit on
// half units so they land on whole pixels at 32px, the list size.
const f = (d, colour) => ["path", { d, class: `aero-doc-f aero-c-${colour}` }];
const s = (d, colour, width) => ["path", { d, class: `aero-doc-s aero-c-${colour}`, "stroke-width": width }];

function pageShapes(x, y, w, h, fold, tone = "") {
  const r = x + w;
  const b = y + h;
  const outline = `M${x} ${y}H${r - fold}L${r} ${y + fold}V${b}H${x}z`;
  const shadow = `M${x + 1} ${y + 1.2}H${r - fold + 1}L${r + 1} ${y + fold + 1.2}V${b + 1.2}H${x + 1}z`;
  const shadeFrom = (top) => `M${x} ${top}H${r}V${b}H${x}z`;
  const foldPath = `M${r - fold} ${y}V${y + fold - 1}a1 1 0 0 0 1 1H${r}z`;
  return {
    under: [
      ["path", { d: shadow, class: "aero-doc-shadow" }],
      ["path", { d: outline, class: `aero-doc-page${tone}` }],
      ["path", { d: shadeFrom(y + h * 0.45), class: "aero-doc-shade" }],
      ["path", { d: shadeFrom(y + h * 0.75), class: "aero-doc-shade" }],
      ["path", { d: `M${x + 0.8} ${y + 0.8}V${b - 0.8}`, class: "aero-doc-gleam" }],
    ],
    over: [
      ["path", { d: `M${r - fold} ${y + fold}H${r}l-${fold * 0.2} ${fold * 0.2}H${r - fold + 1}z`, class: "aero-doc-crease" }],
      ["path", { d: foldPath, class: "aero-doc-fold" }],
      ["path", { d: outline, class: "aero-doc-edge" }],
      ["path", { d: foldPath, class: "aero-doc-edge" }],
    ],
  };
}

const PAGE = pageShapes(5.5, 1.5, 21, 29, 6.5);

// Glyphs are drawn in a 14 x 17 box (x 9-23, y 10-27) and stretched onto the page's 16 x 19
// writing area, so they stay as large as the page allows at 16px.
const GLYPH_FIT = "matrix(1.14 0 0 1.12 -2.24 -2.22)";
const fit = ([tag, attrs]) => [tag, { ...attrs, transform: attrs.transform ? `${GLYPH_FIT} ${attrs.transform}` : GLYPH_FIT }];

/** A document icon with `glyph` shapes drawn on the page (under the fold and the edge). */
function doc(...glyph) {
  return { shapes: [...PAGE.under, ...glyph.map(fit), ...PAGE.over] };
}

// Text-like rows: [y, length] pairs from the page's left margin.
const rows = (colour, height, list) => f(list.map(([y, len]) => `M9 ${y}h${len}v${height}H9z`).join(""), colour);

const DOC_ART = {
  "i-html": doc(
    f("M9 10h14v3.2H9z", "blue"),
    f("M9 10h14v1.3H9z", "shine"),
    f("M9 14.6h4.1v11H9zM14 14.6h4v11h-4zM18.9 14.6H23v11h-4.1z", "paleblue"),
    f("M14 14.6h4v3.2h-4z", "blue"),
    f("M9.7 19.4h2.7v1H9.7zM9.7 21.6h2.1v1H9.7zM14.7 19.4h2.6v1h-2.6zM14.7 21.6h2v1h-2zM19.6 19.4h2.7v1h-2.7zM19.6 21.6h2.1v1h-2.1z", "slate"),
  ),
  "i-svg": doc(
    s("M10 24 12.5 13.5M22 12l-2.5 10.5", "slate", 0.8),
    s("M10 24C12.5 13.5 19.5 22.5 22 12", "orange", 2),
    ["circle", { cx: 12.5, cy: 13.5, r: 1.2, class: "aero-doc-f aero-c-blue" }],
    ["circle", { cx: 19.5, cy: 22.5, r: 1.2, class: "aero-doc-f aero-c-blue" }],
    ["rect", { x: 8.6, y: 22.6, width: 2.8, height: 2.8, class: "aero-doc-node" }],
    ["rect", { x: 20.6, y: 10.6, width: 2.8, height: 2.8, class: "aero-doc-node" }],
  ),
  "i-image": doc(
    f("M9 10h14v16H9z", "skytop"),
    f("M9 15h14v11H9z", "sky"),
    ["circle", { cx: 19.6, cy: 14, r: 2, class: "aero-doc-f aero-c-sun" }],
    f("M9 21.5c3-3.2 6.2-3.6 9-1.6 2 1.4 3.6 1.2 5-.2V26H9z", "hill"),
    f("M9 23.4c4.5-2.4 9.5-2.6 14-.4V26H9z", "grass"),
    ["rect", { x: 9, y: 10, width: 14, height: 16, class: "aero-doc-frame" }],
  ),
  "i-csv": doc(
    s("M9 14.5h14M9 18.5h14M9 22.5h14", "mist", 0.8),
    f("M9.3 19.5h2.8v6.5H9.3zM13.1 15h2.8v11h-2.8zM16.9 17.5h2.8V26h-2.8zM20.7 12h2.8v14h-2.8z", "green"),
    f("M9.3 19.5h1.2v6.5H9.3zM13.1 15h1.2v11h-1.2zM16.9 17.5h1.2V26h-1.2zM20.7 12h1.2v14h-1.2z", "shine"),
    f("M9 26h14.5v1.1H9z", "slate"),
  ),
  "i-diff": doc(
    f("M9 10.5h14v2.8H9zM9 17.1h14v2.8H9z", "pink"),
    f("M9 13.8h14v2.8H9zM9 20.4h14v2.8H9zM9 23.7h14v2.8H9z", "mint"),
    f("M9 10.5h2.3v2.8H9zM9 17.1h2.3v2.8H9z", "red"),
    f("M9 13.8h2.3v2.8H9zM9 20.4h2.3v2.8H9zM9 23.7h2.3v2.8H9z", "green"),
    f("M12.5 11.4h7v1h-7zM12.5 18h9v1h-9z", "redink"),
    f("M12.5 14.7h9.5v1h-9.5zM12.5 21.3h7.5v1h-7.5zM12.5 24.6h5.5v1h-5.5z", "greenink"),
  ),
  "i-markdown": doc(
    ["rect", { x: 9, y: 10, width: 14, height: 7, rx: 1.4, class: "aero-doc-f aero-c-navy" }],
    s("M11 15.2v-3.4l1.9 2.2 1.9-2.2v3.4M19.3 11.6v3.6M17.6 13.6l1.7 1.7 1.7-1.7", "white", 1.2),
    rows("slate", 1.1, [[19.2, 14], [21.6, 11.5], [24, 13]]),
  ),
  "i-code": doc(
    s("M12.8 12.5 9.2 17l3.6 4.5M19.2 12.5l3.6 4.5-3.6 4.5", "teal", 2),
    s("M17.4 11.4 14.6 22.6", "slate", 1.4),
    rows("mist", 1.1, [[25, 7]]),
  ),
  "i-video": doc(
    ["rect", { x: 8.5, y: 10.5, width: 15, height: 15, rx: 1, class: "aero-doc-f aero-c-film" }],
    f("M9.3 11.3h1.6v1.4H9.3zM12 11.3h1.6v1.4H12zM14.7 11.3h1.6v1.4h-1.6zM17.4 11.3H19v1.4h-1.6zM20.1 11.3h1.6v1.4h-1.6zM9.3 23.3h1.6v1.4H9.3zM12 23.3h1.6v1.4H12zM14.7 23.3h1.6v1.4h-1.6zM17.4 23.3H19v1.4h-1.6zM20.1 23.3h1.6v1.4h-1.6z", "white"),
    f("M8.5 13.5h15v9h-15z", "purple"),
    f("M8.5 13.5h15v3.6h-15z", "shine"),
    f("M14 15.2v5.6l4.8-2.8z", "white"),
  ),
  "i-audio": doc(
    s("M14 22V13.4l7.9-2.1V20", "purple", 1.4),
    f("M14 13.4l7.9-2.1v2.6L14 16z", "purple"),
    ["ellipse", { cx: 12, cy: 22.4, rx: 2.4, ry: 1.8, transform: "rotate(-20 12 22.4)", class: "aero-doc-f aero-c-purple" }],
    ["ellipse", { cx: 19.9, cy: 20.4, rx: 2.4, ry: 1.8, transform: "rotate(-20 19.9 20.4)", class: "aero-doc-f aero-c-purple" }],
    ["ellipse", { cx: 11.4, cy: 21.8, rx: 0.9, ry: 0.5, transform: "rotate(-20 11.4 21.8)", class: "aero-doc-f aero-c-shine" }],
    ["ellipse", { cx: 19.3, cy: 19.8, rx: 0.9, ry: 0.5, transform: "rotate(-20 19.3 19.8)", class: "aero-doc-f aero-c-shine" }],
  ),
  "i-pdf": doc(
    rows("slate", 1.1, [[10.5, 9], [12.8, 13], [15.1, 11]]),
    f("M6.8 18.5h18.4v8H6.8z", "red"),
    f("M6.8 18.5h18.4v3.3H6.8z", "shine"),
    s("M10 25v-4.6h2a1.35 1.35 0 0 1 0 2.7h-2M14.7 25v-4.6h1.3a2 2.3 0 0 1 0 4.6zM19.7 25v-4.6h2.8M19.7 22.6h2.2", "white", 1.1),
  ),
  "i-json": doc(
    s("M12.8 10.5c-2 0-2.3 1-2.3 2.7v2.4c0 1.3-.7 2-2 2.3 1.3.3 2 1 2 2.3v2.4c0 1.7.3 2.7 2.3 2.7", "navy", 1.7),
    s("M19.2 10.5c2 0 2.3 1 2.3 2.7v2.4c0 1.3.7 2 2 2.3-1.3.3-2 1-2 2.3v2.4c0 1.7-.3 2.7-2.3 2.7", "navy", 1.7),
    f("M13.8 13.8h4.4v1.4h-4.4zM13.8 17.1h3.2v1.4h-3.2zM13.8 20.4h4.4v1.4h-4.4z", "green"),
  ),
  "i-text": doc(rows("slate", 1.1, [[10.5, 13], [12.9, 10], [15.3, 12.5], [17.7, 8], [20.1, 13], [22.5, 11], [24.9, 9]])),
  "i-file": doc(
    ["rect", { x: 10, y: 13, width: 12, height: 10, rx: 1, class: "aero-doc-f aero-c-mist" }],
    f("M10 14a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v2H10z", "steel"),
    ["rect", { x: 10, y: 13, width: 12, height: 10, rx: 1, class: "aero-doc-s aero-c-steel", "stroke-width": 0.8 }],
    f("M11.5 18h9v1h-9zM11.5 20h6v1h-6z", "white"),
  ),
  "i-progress": doc(
    ["rect", { x: 9, y: 10.2, width: 3.6, height: 3.6, rx: 0.8, class: "aero-doc-f aero-c-green" }],
    ["rect", { x: 9, y: 15.4, width: 3.6, height: 3.6, rx: 0.8, class: "aero-doc-f aero-c-green" }],
    ["rect", { x: 9.4, y: 20.9, width: 2.8, height: 2.8, rx: 0.6, class: "aero-doc-box" }],
    s("M9.9 12.1l1 1 1.1-1.9M9.9 17.3l1 1 1.1-1.9", "white", 0.9),
    f("M14 11.5h9v1.1h-9zM14 16.7h7.5v1.1H14zM14 21.8h8.5v1.1H14z", "slate"),
    ["rect", { x: 9, y: 24.6, width: 14, height: 2.9, rx: 1.2, class: "aero-doc-trough" }],
    ["rect", { x: 9, y: 24.6, width: 9.5, height: 2.9, rx: 1.2, class: "aero-doc-f aero-c-green" }],
    f("M9.6 24.9h8.3v1.1H9.6z", "shine"),
  ),
};

// A bundle: three pages stacked back to front, the front one tiled with mixed file types.
const BUNDLE_BACK = pageShapes(12.5, 1.5, 15, 21, 4.5, " aero-doc-page-back");
const BUNDLE_MID = pageShapes(9, 5, 15, 21.5, 4.5, " aero-doc-page-mid");
const BUNDLE_FRONT = pageShapes(5.5, 8.5, 16, 22, 5);
DOC_ART["i-bundle"] = {
  shapes: [
    ...BUNDLE_BACK.under, ...BUNDLE_BACK.over,
    ...BUNDLE_MID.under, ...BUNDLE_MID.over,
    ...BUNDLE_FRONT.under,
    ...[[7.6, 14.2, "blue"], [13.8, 14.2, "orange"], [7.6, 20.4, "green"], [13.8, 20.4, "purple"]].flatMap(([x, y, colour]) => [
      ["rect", { x, y, width: 5.4, height: 5.4, rx: 1, class: `aero-doc-f aero-c-${colour}` }],
      f(`M${x} ${y + 1}a1 1 0 0 1 1-1h3.4a1 1 0 0 1 1 1v1.3H${x}z`, "shine"),
    ]),
    f("M7.6 27.2h8v1.1h-8z", "slate"),
    ...BUNDLE_FRONT.over,
  ],
};

const ART = {
  ...DOC_ART,
  "i-folder": {
    shapes: [
      ["path", { d: "M3 8a2 2 0 0 1 2-2h7l3 3h12a2 2 0 0 1 2 2v15a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z", class: "ic-folder-shade" }],
      ["path", { d: "M6 10h20v8H6z", class: "ic-folder-tab" }],
      ["path", { d: "M2.5 15a2 2 0 0 1 2-2h23a2 2 0 0 1 2 2l-1 10a2 2 0 0 1-2 2H5.5a2 2 0 0 1-2-2z", class: "ic-folder" }],
      ["path", { d: "M3.2 14.2c.3-.8 1-1.2 1.8-1.2h22c.8 0 1.5.4 1.8 1.2L28.5 19c-8 1.6-17 1.6-25 0z", class: "aero-ic-shine" }],
    ],
  },
  "i-trash": {
    shapes: [
      ["path", { d: "M8 10.5h16l-1.5 16.6a2 2 0 0 1-2 1.9h-9a2 2 0 0 1-2-1.9z", class: "aero-ic-bin" }],
      ["path", { d: "M12.5 13v13M16 13v13M19.5 13v13", class: "aero-ic-bin-rib" }],
      ["path", { d: "M9.5 11h3.5l-.8 16H10.9z", class: "aero-ic-shine" }],
      ["rect", { x: 6, y: 7.5, width: 20, height: 3.5, rx: 1.5, class: "aero-ic-bin-rim" }],
    ],
  },
  "i-caution": {
    shapes: [
      ["path", { d: "M14.3 4.8a2 2 0 0 1 3.4 0l11 19.4A2 2 0 0 1 27 27H5a2 2 0 0 1-1.7-2.8z", class: "aero-ic-warn" }],
      ["path", { d: "M14.6 6.2c.6-1 2.2-1 2.8 0l6 10.6c-5 1.4-10 1.4-14.8 0z", class: "aero-ic-shine" }],
      ["path", { d: "M16 11v8", class: "aero-ic-warn-mark" }],
      ["circle", { cx: 16, cy: 23, r: 1.6, class: "aero-ic-warn-dot" }],
    ],
  },
  "i-app": {
    shapes: [
      ["circle", { cx: 8, cy: 8, r: 7, class: "aero-ic-orb" }],
      ["ellipse", { cx: 8, cy: 5, rx: 4.6, ry: 2.8, class: "aero-ic-shine" }],
      ["path", { d: "M6.2 4.8v6.4L11.4 8z", class: "aero-ic-glyph" }],
    ],
  },
  "i-pin": {
    shapes: [
      ["path", { d: "M6 8.5h1v4.5H6z", class: "aero-ic-needle" }],
      ["circle", { cx: 6.5, cy: 5, r: 4.2, class: "aero-ic-pin" }],
      ["circle", { cx: 5.2, cy: 3.6, r: 1.5, class: "aero-ic-glint" }],
    ],
  },
  "i-sort": { shapes: [["path", { d: "M1.5 1.5 4.5 4.5 7.5 1.5", class: "aero-ic-chevron" }]] },
  "i-popup": { shapes: [["path", { d: "M1 4.5h7L4.5 8.5z", class: "aero-ic-arrow" }]] },
  "i-grow": {
    shapes: [
      ["path", {
        d: "M12.5 3.5h1.5v1.5h-1.5zM9.5 6.5h1.5v1.5H9.5zM12.5 6.5h1.5v1.5h-1.5zM6.5 9.5h1.5v1.5H6.5zM9.5 9.5h1.5v1.5H9.5zM12.5 9.5h1.5v1.5h-1.5zM3.5 12.5h1.5v1.5H3.5zM6.5 12.5h1.5v1.5H6.5zM9.5 12.5h1.5v1.5H9.5zM12.5 12.5h1.5v1.5h-1.5z",
        class: "aero-ic-grip",
      }],
    ],
  },
};
// The full trash can: the bin plus crumpled paper above the rim.
ART["i-trash-full"] = {
  shapes: [
    ["path", { d: "M9.5 8 11 3.5l3.5 2 2.5-3 2.8 3.2 2.8-1.6L24 8z", class: "aero-ic-paper" }],
    ...ART["i-trash"].shapes,
  ],
};

// The knowledge map shortcut: three glossy marbles joined by fine lines.
ART["i-kmap"] = {
  shapes: [
    s("M4 5.5 12 4M4 5.5 8.5 12M12 4 8.5 12", "slate", 1.1),
    ["circle", { cx: 4, cy: 5.5, r: 3, class: "aero-doc-f aero-c-blue" }],
    ["circle", { cx: 12, cy: 4, r: 2.6, class: "aero-doc-f aero-c-orange" }],
    ["circle", { cx: 8.5, cy: 12, r: 3, class: "aero-doc-f aero-c-green" }],
    ["ellipse", { cx: 3.3, cy: 4.3, rx: 1.7, ry: 1, class: "aero-ic-shine" }],
    ["ellipse", { cx: 11.4, cy: 3, rx: 1.4, ry: 0.8, class: "aero-ic-shine" }],
    ["ellipse", { cx: 7.8, cy: 10.8, rx: 1.7, ry: 1, class: "aero-ic-shine" }],
  ],
};

function swapSprite() {
  const sprite = document.querySelector("svg.sprite");
  if (!sprite) return;
  // The SVG namespace is read from the sprite (OS-layer JS holds no URL literals).
  const ns = sprite.namespaceURI;
  for (const [id, art] of Object.entries(ART)) {
    const symbol = sprite.querySelector(`symbol[id="${id}"]`);
    if (!symbol) continue;
    const nodes = art.shapes.map(([tag, attrs]) => {
      const node = document.createElementNS(ns, tag);
      for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
      return node;
    });
    symbol.replaceChildren(...nodes);
  }
  sprite.setAttribute("shape-rendering", "geometricPrecision");
}

/** Run `fn`; a thrown error is logged and swallowed so the other parts still apply. */
function safe(name, fn) {
  try {
    fn();
  } catch (err) {
    console.error(`aero shell: ${name} failed`, err);
  }
}

function start() {
  if (document.documentElement.dataset.os !== OS) return;
  safe("sprite", swapSprite);
  safe("scenery", addScenery);
  safe("desk icons", moveDeskIcons);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
