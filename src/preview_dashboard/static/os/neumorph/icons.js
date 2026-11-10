/*
  Neumorph icon set (docs/frontend-os.md#neumorph, "Icons"): replaces the contents of every shared
  sprite symbol (same ids and viewBoxes, createElementNS only) with raised soft-UI art - pebbles of
  the porcelain surface, lit up-left and shaded down-right, each carrying a small embossed glyph in
  ink and iris. Shapes only; colours come from the unscoped neumorph-ic-* classes in chrome.css.
*/

// --- building blocks -------------------------------------------------------------------------

const C = (name) => `neumorph-ic-${name}`;

// A copy's offset goes outside the shape's own transform (e.g. a rotated ellipse keeps its tilt).
const moved = (attrs, offset) => {
  const transform = [offset, attrs.transform].filter(Boolean).join(" ");
  return transform ? { transform } : {};
};

/**
 * An extruded shape (any SVG element): a shade copy down-right and a light copy up-left frame the
 * face, then two smaller translucent sheens step the face lighter toward the top-left. `centre`
 * is the point the sheens shrink toward; `face` lets a pebble take another fill (the pin, LEDs).
 */
function extrude([tag, attrs], [cx, cy], { depth = 0.8, face = "face", sheen = true } = {}) {
  const at = (cls, offset) => [tag, { ...attrs, class: C(cls), ...moved(attrs, offset) }];
  const shrink = (k, dx) => `translate(${dx} ${dx}) translate(${cx} ${cy}) scale(${k}) translate(${-cx} ${-cy})`;
  return [
    at("shade", `translate(${depth} ${depth})`),
    at("light", `translate(${-depth * 0.75} ${-depth * 0.75})`),
    at(face),
    ...(sheen ? [at("sheen", shrink(0.86, -0.6)), at("sheen", shrink(0.68, -1.2)), at("sheen", shrink(0.5, -1.8))] : []),
  ];
}

/**
 * An embossed glyph part: a shade copy below-right and a light copy above-left under the ink, so
 * the glyph stands a hair proud of its pebble. A `width` makes it a stroke, else it is a fill.
 */
function emboss(tag, attrs, colour, width) {
  const stroke = width !== undefined;
  const extra = stroke ? { "stroke-width": width } : {};
  const part = (cls, offset) => [tag, { ...attrs, ...extra, class: C(cls), ...moved(attrs, offset) }];
  return [
    part(stroke ? "drop-s" : "drop", "translate(0.55 0.55)"),
    part(stroke ? "lift-s" : "lift", "translate(-0.45 -0.45)"),
    part(stroke ? `${colour}-s` : colour),
  ];
}

const path = (d) => ["path", { d }];
const ink = (d) => emboss("path", { d }, "ink");
const iris = (d) => emboss("path", { d }, "iris");
const inkLine = (d, w = 1.8) => emboss("path", { d }, "ink", w);
const irisLine = (d, w = 1.8) => emboss("path", { d }, "iris", w);
const mutedLine = (d, w = 1) => emboss("path", { d }, "muted", w);
const bar = (x, y, w, h, colour = "ink") => emboss("rect", { x, y, width: w, height: h, rx: Math.min(w, h) / 2 }, colour);
const dot = (cx, cy, r, colour = "ink") => emboss("circle", { cx, cy, r }, colour);

// The document pebble: a rounded square of the surface (26 units, radius 8 of a 32 viewBox),
// leaving room around it for the light/shade copies; the CSS cast shadow may spill outside.
const TILE = extrude(["rect", { x: 3, y: 3, width: 26, height: 26, rx: 8 }], [16, 16]);
const pebble = (...glyph) => ({ shapes: [...TILE, ...glyph.flat()] });

// --- file types: one glyph each, drawn on the pebble's 9..23 writing area ----------------------

const ART = {
  "i-html": pebble(
    inkLine("M10.5 10h11a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-11a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z", 1.6),
    iris("M10.5 9.2h11a2.8 2.8 0 0 1 2.8 2.8v1.6H7.7V12a2.8 2.8 0 0 1 2.8-2.8z"),
    bar(11, 16.3, 7, 1.7),
    bar(11, 19.2, 10, 1.7),
  ),
  "i-svg": pebble(
    mutedLine("M9.5 22 12.4 13.2M22.5 10l-2.9 8.8"),
    irisLine("M9.5 22C12.4 8.5 19.6 23.5 22.5 10", 2),
    dot(12.4, 13.2, 1.3, "muted"),
    dot(19.6, 18.8, 1.3, "muted"),
    emboss("rect", { x: 7.9, y: 20.4, width: 3.2, height: 3.2, rx: 0.9 }, "ink"),
    emboss("rect", { x: 20.9, y: 8.4, width: 3.2, height: 3.2, rx: 0.9 }, "ink"),
  ),
  "i-image": pebble(
    inkLine("M10.5 9.5h11a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-11a2 2 0 0 1-2-2v-9a2 2 0 0 1 2-2z", 1.6),
    ink("M9.4 21.6 13.4 16.6l3.3 3.5 2.2-2.2 3.8 3.7z"),
    dot(19.4, 13.2, 1.9, "iris"),
  ),
  "i-csv": pebble(
    bar(9.6, 16.5, 3, 6.7),
    bar(14.5, 11.5, 3, 11.7, "iris"),
    bar(19.4, 14.2, 3, 9),
    bar(8.6, 23.9, 14.8, 1.4, "muted"),
  ),
  "i-diff": pebble(irisLine("M16 8.8v7M12.5 12.3h7", 2.2), inkLine("M12.5 20.6h7", 2.2), bar(10, 23.6, 12, 1.3, "muted")),
  "i-markdown": pebble(
    inkLine("M8.6 20.5V11.6l3.6 4.3 3.6-4.3v8.9", 1.9),
    irisLine("M20.6 11.6v8.4M17.8 17.4l2.8 3 2.8-3", 1.9),
  ),
  "i-code": pebble(inkLine("M12.4 11.4 8.4 16l4 4.6M19.6 11.4l4 4.6-4 4.6", 2), irisLine("M17.5 10.2 14.5 21.8", 1.8)),
  "i-video": pebble(
    inkLine("M16 8.6a7.4 7.4 0 1 1 0 14.8 7.4 7.4 0 0 1 0-14.8z", 1.6),
    emboss("path", { d: "M14.3 12.6v6.8l5.6-3.4z", "stroke-linejoin": "round" }, "iris"),
  ),
  "i-audio": pebble(
    inkLine("M13 21V12l9-2v9", 1.7),
    iris("M13 11.6 22 9.6v2.6l-9 2z"),
    emboss("ellipse", { cx: 11.1, cy: 21.2, rx: 2.4, ry: 1.85, transform: "rotate(-20 11.1 21.2)" }, "ink"),
    emboss("ellipse", { cx: 20.1, cy: 19.2, rx: 2.4, ry: 1.85, transform: "rotate(-20 20.1 19.2)" }, "ink"),
  ),
  "i-pdf": pebble(
    bar(9, 9.4, 9, 1.6),
    bar(9, 12.4, 14, 1.6, "muted"),
    emboss("rect", { x: 7.8, y: 16, width: 16.4, height: 7.4, rx: 2.2 }, "iris"),
    [["path", { d: "M10.4 21.8v-4.2h1.8a1.25 1.25 0 0 1 0 2.5h-1.8M14.6 21.8v-4.2h1.2a1.9 2.1 0 0 1 0 4.2zM19.2 21.8v-4.2h2.6M19.2 19.6h2", "stroke-width": 1.15, class: C("white-s") }]],
  ),
  "i-json": pebble(
    inkLine("M12.6 9c-2 0-2.3 1-2.3 2.6v2.3c0 1.3-.7 1.9-2 2.1 1.3.2 2 .8 2 2.1v2.3c0 1.6.3 2.6 2.3 2.6", 1.7),
    inkLine("M19.4 9c2 0 2.3 1 2.3 2.6v2.3c0 1.3.7 1.9 2 2.1-1.3.2-2 .8-2 2.1v2.3c0 1.6-.3 2.6-2.3 2.6", 1.7),
    dot(13.9, 16, 1.15, "iris"),
    dot(16, 16, 1.15, "iris"),
    dot(18.1, 16, 1.15, "iris"),
  ),
  "i-text": pebble(bar(9, 9.6, 10, 2.2, "iris"), bar(9, 13.6, 14, 1.6), bar(9, 16.6, 11.5, 1.6), bar(9, 19.6, 14, 1.6), bar(9, 22.6, 8, 1.6)),
  "i-file": pebble(inkLine("M11.5 9.3H18l3.8 3.8v9.6h-10.3z", 1.6), mutedLine("M18 9.6v3.5h3.5", 1.2)),
  "i-progress": pebble(
    [["circle", { cx: 16, cy: 16, r: 7, "stroke-width": 2.6, class: C("track-s") }]],
    irisLine("M16 9a7 7 0 1 1-7 7", 2.6),
    inkLine("M13.2 16.2l1.9 1.9 3.7-3.9", 1.6),
  ),
};

// A bundle: three pebbles stacked back to front; the front one carries a 2 x 2 tile grid.
const small = (x, y) => extrude(["rect", { x, y, width: 18, height: 18, rx: 5.5 }], [x + 9, y + 9], { depth: 0.7 });
ART["i-bundle"] = {
  shapes: [
    ...small(11, 3),
    ...small(7.5, 7),
    ...small(4, 11),
    ...emboss("rect", { x: 7.4, y: 14.4, width: 4.8, height: 4.8, rx: 1.4 }, "iris"),
    ...emboss("rect", { x: 13.8, y: 14.4, width: 4.8, height: 4.8, rx: 1.4 }, "muted"),
    ...emboss("rect", { x: 7.4, y: 20.8, width: 4.8, height: 4.8, rx: 1.4 }, "muted"),
    ...emboss("rect", { x: 13.8, y: 20.8, width: 4.8, height: 4.8, rx: 1.4 }, "ink"),
  ],
};

// A soft raised folder: the back panel with its iris tab (the one accent) behind a pillowy front
// flap; the flap's edge is drawn in embossed ink like every file glyph, so the silhouette holds
// at list size, and an ink handle sits on it.
ART["i-folder"] = {
  shapes: [
    ...extrude(path("M4 9a3 3 0 0 1 3-3h5.4a2 2 0 0 1 1.4.6L16.4 9H25a3 3 0 0 1 3 3v12a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3z"), [16, 16], {
      face: "back",
      sheen: false,
    }),
    ...iris("M4.4 13.4V9.2a3 3 0 0 1 3-3h4.9a2 2 0 0 1 1.4.6l2.9 2.9v4.7z"),
    ...extrude(["rect", { x: 3.4, y: 12.6, width: 25.2, height: 15, rx: 3.8 }], [16, 20]),
    ...inkLine("M7.2 13.3h17.6a3 3 0 0 1 3 3v7.6a3 3 0 0 1-3 3H7.2a3 3 0 0 1-3-3v-7.6a3 3 0 0 1 3-3z", 1.6),
    ...bar(12.4, 17.4, 7.2, 2),
  ],
};

// The bin: a pebble lid with a knob over a tapered pebble body; body edge and ribs in embossed ink
// (as the folder) so it reads at list size.
const BODY = "M8.4 12h15.2l-1.3 13.6a2.6 2.6 0 0 1-2.6 2.4h-7.4a2.6 2.6 0 0 1-2.6-2.4z";
const BIN_BODY = [
  ...extrude(path(BODY), [16, 19]),
  ...inkLine("M9.2 12.6l1.2 12.9a2 2 0 0 0 2 1.8h7.2a2 2 0 0 0 2-1.8l1.2-12.9", 1.5),
  ...["M12.9 15.4v8.8", "M16 15.4v8.8", "M19.1 15.4v8.8"].flatMap((d) => inkLine(d, 1.5)),
];
const BIN = [
  ...BIN_BODY,
  ...extrude(["rect", { x: 13, y: 5.2, width: 6, height: 3.4, rx: 1.7 }], [16, 6.9], { depth: 0.6, sheen: false }),
  ...extrude(["rect", { x: 6.6, y: 7.8, width: 18.8, height: 3.6, rx: 1.8 }], [16, 9.6], { depth: 0.7 }),
  ...inkLine("M8.4 9.6h15.2", 1.5),
];
ART["i-trash"] = { shapes: BIN };
// Full: two crumpled paper pebbles peek over the lid, which sits a little askew on them.
ART["i-trash-full"] = {
  shapes: [
    ...extrude(path("M8 7.6 9.2 4.2l3-1.2 2.4 1.6.4 2.9-1.6 2.3-3.2.4z"), [11.4, 6.4], { depth: 0.6, face: "paper", sheen: false }),
    ...extrude(path("M17 5.6l1.6-2.9 2.8-.3 1.9 2.2-.5 2.9-2.6 1.4-2.6-.9z"), [20, 5.6], { depth: 0.6, face: "paper", sheen: false }),
    ["path", { d: "M10.2 5.2 12 6.6l1.2-1.4M18.8 4.6l1.5 1.6", "stroke-width": 0.6, class: C("track-s") }],
    ...BIN_BODY,
    ...extrude(["rect", { x: 6.6, y: 8.6, width: 18.8, height: 3.6, rx: 1.8, transform: "rotate(-4 16 10.4)" }], [16, 10.4], {
      depth: 0.7,
    }),
    ...emboss("path", { d: "M8.4 10.4h15.2", transform: "rotate(-4 16 10.4)" }, "ink", 1.5),
  ],
};

// Warning: a rounded raised triangle with an amber mark.
ART["i-caution"] = {
  shapes: [
    ...extrude(
      path("M16 4.6c.8 0 1.5.4 1.9 1.1l9.7 17.3c.8 1.5-.2 3.3-1.9 3.3H6.3c-1.7 0-2.7-1.8-1.9-3.3l9.7-17.3c.4-.7 1.1-1.1 1.9-1.1z"),
      [16, 18],
    ),
    ...emboss("path", { d: "M16 11.6v6.6" }, "warn", 2.6),
    ...emboss("circle", { cx: 16, cy: 22.2, r: 1.55 }, "warn"),
  ],
};

// The app mark: a round knob with a lit iris LED (the shell bar draws its own; this is the art).
ART["i-app"] = {
  shapes: [
    ...extrude(["circle", { cx: 8, cy: 8, r: 6 }], [8, 8], { depth: 0.5 }),
    ["circle", { cx: 8, cy: 8, r: 2.2, class: C("iris") }],
    ["circle", { cx: 7.3, cy: 7.3, r: 0.7, class: C("shine") }],
  ],
};

// Pinned: an iris pushpin pebble on a short muted needle (13 x 13).
ART["i-pin"] = {
  shapes: [
    ["path", { d: "M6.5 8.4v3.6", "stroke-width": 1.3, class: C("muted-s") }],
    ...extrude(["circle", { cx: 6.5, cy: 5.2, r: 3.7 }], [6.5, 5.2], { depth: 0.6, face: "iris", sheen: false }),
    ["circle", { cx: 5.3, cy: 4, r: 1.1, class: C("shine") }],
  ],
};

// Small chevrons: the sorted column's direction and the drop-down arrows, on-palette.
ART["i-sort"] = { shapes: [["path", { d: "M1.6 1.4 4.5 4.4l2.9-3", "stroke-width": 1.6, class: C("iris-s") }]] };
ART["i-popup"] = { shapes: [["path", { d: "M1.8 4.4 4.5 1.8l2.7 2.6M1.8 7.6l2.7 2.6 2.7-2.6", "stroke-width": 1.4, class: C("muted-s") }]] };

// The knowledge map shortcut: three category pearls joined by engraved lines.
ART["i-kmap"] = {
  shapes: [
    ["path", { d: "M4 5.6 12 4.2 8.4 12z", "stroke-width": 1.1, class: C("muted-s") }],
    ...[
      [4, 5.6, 2.7, "pearl-iris"],
      [12, 4.2, 2.4, "pearl-amber"],
      [8.4, 12, 2.7, "pearl-teal"],
    ].flatMap(([cx, cy, r, face]) => [
      ...extrude(["circle", { cx, cy, r }], [cx, cy], { depth: 0.45, face, sheen: false }),
      ["circle", { cx: cx - r * 0.35, cy: cy - r * 0.35, r: r * 0.32, class: C("shine") }],
    ]),
  ],
};

// The resize grip (hidden in this OS; drawn so every symbol is covered): engraved diagonals.
ART["i-grow"] = {
  shapes: ["M13 5 5 13", "M13 9 9 13"].flatMap((d) => [
    ["path", { d, "stroke-width": 1.2, class: C("groove-s") }],
    ["path", { d, "stroke-width": 0.8, class: C("lift-s"), transform: "translate(0.7 0.7)" }],
  ]),
};

/** Swap every sprite symbol's contents for the Neumorph art (same ids and viewBoxes). */
export function swapSprite() {
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
