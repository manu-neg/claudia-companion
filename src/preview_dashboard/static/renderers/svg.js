/*
  SVG renderer: only ever as <img> (scripts in an SVG never run as an image), never an iframe
  or inline markup — the preview origin refuses SVG as a document anyway (C31).
*/
import { imageStage } from "./image.js";

export default {
  render(ctx) {
    return imageStage(ctx, { label: "Vector image" });
  },
};
