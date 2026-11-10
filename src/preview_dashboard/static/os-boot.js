/*
  OS boot (docs/frontend-os.md): a classic, render-blocking script linked in <head> before the
  stylesheets. Reads the owner's OS choice (`pdash.os`, docs/security.md C23 exception), accepts
  only a name from the literal allowlist below (else the default), sets html[data-os] and
  preloads that OS's chrome font. Never throws; never writes storage (os/storage.js does).
*/
(function () {
  "use strict";
  // Must equal OSES / DEFAULT_OS in os/registry.js (tests/unit/test_os_contract.py checks it).
  var OSES = ["platinum", "aero", "neumorph"];
  var DEFAULT_OS = "platinum";
  // Per-OS font preloads: only vendored /static/fonts/ files (CSP font-src 'self').
  var PRELOAD_FONTS = {
    platinum: ["/static/fonts/pixelify-sans-400.woff2"],
    aero: ["/static/fonts/catamaran-400.woff2", "/static/fonts/catamaran-800.woff2"],
    neumorph: ["/static/fonts/nunito-400.woff2", "/static/fonts/nunito-800.woff2"],
  };

  var os = DEFAULT_OS;
  try {
    var saved = window.localStorage.getItem("pdash.os");
    if (OSES.indexOf(saved) !== -1) os = saved;
  } catch (err) {
    // Storage blocked (private mode, policy): the default OS applies.
  }
  document.documentElement.setAttribute("data-os", os);

  try {
    var fonts = PRELOAD_FONTS[os] || [];
    for (var i = 0; i < fonts.length; i += 1) {
      var link = document.createElement("link");
      link.rel = "preload";
      link.as = "font";
      link.type = "font/woff2";
      link.crossOrigin = "anonymous";
      link.href = fonts[i];
      document.head.appendChild(link);
    }
  } catch (err) {
    // A preload is an optimisation only; the fonts still load from fonts.css.
  }
})();
