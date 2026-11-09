/*
  Image renderer: <img> from the preview origin (never fetched or decoded by the dashboard's
  scripts). Tap to open full screen; tap again inside to switch between fit and actual size.
*/
import { expandable } from "../expand.js";
import { h, httpsUrl } from "../dom.js";

export function imageStage(ctx, { label = "Image" } = {}) {
  const src = httpsUrl(ctx.file.preview_url);
  if (!src) return { element: h("p", { class: "preview-empty", text: "This image can't be shown." }) };
  const img = h("img", {
    class: "stage-image",
    src,
    alt: `${label}: ${ctx.file.relpath}`,
    decoding: "async",
    referrerpolicy: "no-referrer",
  });
  const stage = h("div", { class: "stage stage-media" });
  const zoom = expandable(stage, { label: "Full screen" });
  const hit = h(
    "button",
    {
      type: "button",
      class: "stage-hit",
      "aria-label": "Open image full screen",
      on: {
        click: (event) => {
          if (stage.classList.contains("is-expanded")) stage.classList.toggle("is-zoomed");
          else zoom.open(event.currentTarget);
        },
      },
    },
    img,
  );
  stage.appendChild(hit);
  return { element: stage, actions: [zoom.button] };
}

export default {
  render(ctx) {
    return imageStage(ctx);
  },
};
