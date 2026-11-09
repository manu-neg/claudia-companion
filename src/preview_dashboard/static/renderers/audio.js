/*
  Audio renderer: native <audio> from the preview origin, metadata preload only.
*/
import { h, httpsUrl } from "../dom.js";

export default {
  render(ctx) {
    const src = httpsUrl(ctx.file.preview_url);
    const audio = h("audio", {
      class: "stage-audio",
      src,
      controls: true,
      preload: "metadata",
      "aria-label": `Audio: ${ctx.file.relpath}`,
    });
    return { element: h("div", { class: "stage stage-audio-wrap" }, audio) };
  },
};
