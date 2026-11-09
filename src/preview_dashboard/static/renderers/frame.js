/*
  Shared sandboxed-iframe stage for HTML bundles and rendered text. Always
  sandbox="allow-scripts" (never allow-same-origin/popups/forms/top-navigation) and only ever
  a preview-origin https URL from the API (C5, C23).
*/
import { expandable } from "../expand.js";
import { h, httpsUrl } from "../dom.js";

export function frameStage(url, { title, referrerPolicy = "no-referrer", className = "" }) {
  const src = httpsUrl(url);
  if (!src) return { element: h("p", { class: "preview-empty", text: "This preview can't be shown." }) };
  const frame = h("iframe", {
    class: "stage-frame",
    src,
    sandbox: "allow-scripts",
    referrerpolicy: referrerPolicy,
    title,
  });
  const stage = h("div", { class: `stage stage-framed ${className}`.trim() }, frame);
  const full = expandable(stage, { label: "Full screen" });
  return { element: stage, actions: [full.button] };
}
