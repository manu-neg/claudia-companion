/*
  Video renderer: native <video> from the preview origin, metadata preload only (no autoplay;
  the owner's data plan matters on a phone).
*/
import { h, httpsUrl } from "../dom.js";

export default {
  render(ctx) {
    const src = httpsUrl(ctx.file.preview_url);
    const video = h("video", {
      class: "stage-video",
      src,
      controls: true,
      preload: "metadata",
      playsinline: true,
      "aria-label": `Video: ${ctx.file.relpath}`,
    });
    return { element: h("div", { class: "stage stage-media" }, video) };
  },
};
