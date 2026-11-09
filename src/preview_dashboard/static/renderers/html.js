/*
  HTML bundle renderer: the entry page in a sandboxed iframe on the preview origin.
  referrerpolicy="same-origin" matches ADR 0012 (the bundle's own loads carry its Referer).
  Trashed bundles are not rendered (their sub-resources are not served; backlog 8b note).
*/
import { h } from "../dom.js";
import { frameStage } from "./frame.js";

export default {
  render(ctx) {
    if (ctx.trashed) {
      return {
        element: h("div", { class: "preview-empty" }, h("p", { text: "Restore this page to preview it again. You can still download it." })),
      };
    }
    return frameStage(ctx.file.preview_url, {
      title: `Page preview: ${ctx.file.relpath}`,
      referrerPolicy: "same-origin",
      className: "stage-page",
    });
  },
};
