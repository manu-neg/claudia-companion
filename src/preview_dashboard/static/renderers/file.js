/*
  Download-only renderer: kinds without a preview (and unknown renderers). Shows a short note;
  the item view already offers the Download action.
*/
import { h } from "../dom.js";

export default {
  render() {
    return {
      element: h("div", { class: "preview-empty" }, h("p", { text: "This kind of file has no preview. Download it to open it." })),
    };
  },
};
