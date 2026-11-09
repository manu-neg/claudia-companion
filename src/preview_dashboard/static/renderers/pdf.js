/*
  PDF renderer: a link that opens the PDF as a top-level document on the preview origin — the
  only way a PDF is served (C5, C31). No iframe: framed PDFs are unreliable on phones anyway.
*/
import { h, httpsUrl } from "../dom.js";

export default {
  render(ctx) {
    const href = httpsUrl(ctx.file.preview_url);
    return {
      element: h(
        "div",
        { class: "preview-empty" },
        h("p", { text: "PDFs open in a new tab." }),
        href && h("a", { class: "button button-primary", href, target: "_blank", rel: "noopener noreferrer", text: "Open PDF" }),
      ),
    };
  },
};
