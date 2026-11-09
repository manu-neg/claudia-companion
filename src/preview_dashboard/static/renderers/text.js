/*
  Text renderer for every TEXT kind (markdown, code, json, csv, text, diff): frames the
  preview-origin /r/ page, which formats the text inside its sandbox. The dashboard itself never
  turns untrusted text into HTML (orchestrator decision, docs/frontend.md).
*/
import { frameStage } from "./frame.js";
import { h } from "../dom.js";

export default {
  render(ctx) {
    if (!ctx.file.render_page_url) {
      return { element: h("p", { class: "preview-empty", text: "This file has no text preview." }) };
    }
    return frameStage(ctx.file.render_page_url, { title: `Text preview: ${ctx.file.relpath}`, className: "stage-text" });
  },
};
