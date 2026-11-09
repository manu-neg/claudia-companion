/*
  Renderer registry (mirrors the backend kind registry): one module per renderer id from
  GET /api/kinds. `renderPreview` picks the module for a kind's renderer; unknown ids fall back
  to the download-only renderer. Adding a renderer: docs/frontend.md#adding-a-renderer.
*/
import audio from "./audio.js";
import file from "./file.js";
import html from "./html.js";
import image from "./image.js";
import pdf from "./pdf.js";
import svg from "./svg.js";
import text from "./text.js";
import video from "./video.js";

const registry = new Map();

/** Register `module` ({render(ctx) → {element, actions?}}) under renderer `id`. */
export function register(id, module) {
  if (registry.has(id)) throw new Error(`renderer ${id} already registered`);
  registry.set(id, module);
}

for (const [id, module] of Object.entries({ image, svg, video, audio, html, pdf, file })) {
  register(id, module);
}
// Every TEXT renderer is the same sandboxed /r/ frame; the preview origin does the formatting
// (`progress` too: its tracker is drawn by preview-render/progress.js, never on the dashboard).
for (const id of ["markdown", "code", "json", "csv", "text", "diff", "progress"]) register(id, text);

/**
 * Render the preview of one file.
 * @param ctx {item, file, kind, trashed, capBytes}
 * @returns {{element: Node, actions: Node[]}}
 */
export function renderPreview(ctx) {
  const module = (ctx.kind && registry.get(ctx.kind.renderer)) || file;
  const result = module.render(ctx);
  return { element: result.element, actions: result.actions || [] };
}

/** True if individual files of this kind can be previewed on their own. */
export function perFilePreview(kind) {
  return Boolean(kind) && kind.renderer !== "html" && kind.renderer !== "file" && registry.has(kind.renderer);
}
