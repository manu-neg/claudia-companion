/*
  Preview-origin renderer for the `progress` kind: runs inside the sandboxed /r/ page (opaque
  origin, no network). Parses progress.json from the JSON data block, re-validates it (ADR 0029
  schema v1; the file is untrusted) and draws title, note, "N / M done" meter, unit list and the
  "Who runs when" timeline. Text only via textContent; any mismatch shows a safe fallback.
*/
(function () {
  "use strict";

  var STATES = ["done", "running", "waiting", "blocked"];
  var LABELS = { done: "Done", running: "Running", waiting: "Waiting", blocked: "Blocked" };
  var ID_RE = /^[A-Za-z0-9-]{1,12}$/;
  var LANE_WIDTH = "9.5rem";
  var PHASE_MIN = "6.5rem";

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function isText(value, min, max) {
    if (typeof value !== "string") return false;
    // Code points, not UTF-16 units: matches the Python sanitizer's length rule.
    var n = Array.from(value).length;
    return n >= min && n <= max;
  }

  function isCount(value) {
    return typeof value === "number" && Math.floor(value) === value;
  }

  function isList(value, max) {
    return Array.isArray(value) && value.length <= max;
  }

  // Returns a clean copy of the schema-v1 document, or null when anything is off.
  function parse(text) {
    var data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      return null;
    }
    if (!data || typeof data !== "object" || Array.isArray(data) || data.version !== 1) return null;
    if (!isText(data.title, 1, 120) || !isText(data.note, 0, 500)) return null;
    if (!isText(data.updated_at, 0, 40)) return null;
    if (!isList(data.phases, 12) || !isList(data.units, 40) || !isList(data.timeline, 16)) return null;
    var phases = [];
    var i;
    for (i = 0; i < data.phases.length; i += 1) {
      if (!isText(data.phases[i], 1, 40)) return null;
      phases.push(data.phases[i]);
    }
    var units = [];
    var stateOf = {};
    for (i = 0; i < data.units.length; i += 1) {
      var u = data.units[i];
      if (!u || typeof u !== "object" || !isText(u.id, 1, 12) || !ID_RE.test(u.id)) return null;
      if (Object.prototype.hasOwnProperty.call(stateOf, u.id)) return null;
      if (!isText(u.name, 1, 120) || !isText(u.who, 0, 80) || !isText(u.detail, 0, 600)) return null;
      if (STATES.indexOf(u.state) < 0) return null;
      stateOf[u.id] = u.state;
      units.push({ id: u.id, name: u.name, who: u.who, detail: u.detail, state: u.state });
    }
    var lanes = [];
    for (i = 0; i < data.timeline.length; i += 1) {
      var lane = data.timeline[i];
      if (!lane || typeof lane !== "object" || !isText(lane.lane, 1, 60) || !isText(lane.model, 0, 40)) return null;
      if (!isList(lane.bars, 12)) return null;
      var bars = [];
      for (var j = 0; j < lane.bars.length; j += 1) {
        var b = lane.bars[j];
        if (!b || typeof b !== "object" || !isText(b.unit, 1, 12) || !isText(b.label, 0, 60)) return null;
        if (!Object.prototype.hasOwnProperty.call(stateOf, b.unit)) return null;
        if (!isCount(b.from) || !isCount(b.to) || b.from < 0 || b.from >= b.to || b.to > phases.length) return null;
        bars.push({ from: b.from, to: b.to, label: b.label, state: stateOf[b.unit], row: 0 });
      }
      lanes.push({ lane: lane.lane, model: lane.model, bars: bars });
    }
    return { title: data.title, note: data.note, updatedAt: data.updated_at, phases: phases, units: units, lanes: lanes };
  }

  // Bars that share a phase column get their own row inside the lane. Returns the row count.
  function stack(bars) {
    var ends = [];
    var sorted = bars.slice().sort(function (a, b) { return a.from - b.from || a.to - b.to; });
    sorted.forEach(function (bar) {
      var row = 0;
      while (row < ends.length && ends[row] > bar.from) row += 1;
      ends[row] = bar.to;
      bar.row = row;
    });
    return Math.max(1, ends.length);
  }

  // Grid placement goes through the CSSOM: the page CSP allows it, style attributes it does not.
  function place(node, column, row, span, rows) {
    node.style.gridColumn = column + " / span " + (span || 1);
    node.style.gridRow = row + " / span " + (rows || 1);
    return node;
  }

  function meter(units) {
    var done = units.filter(function (u) { return u.state === "done"; }).length;
    var section = el("section", "p-meter");
    section.setAttribute("aria-label", "Overall progress");
    var count = el("p", "p-count");
    count.appendChild(el("strong", "", done + " / " + units.length));
    count.appendChild(document.createTextNode(" done"));
    var segs = el("ul", "p-segs");
    segs.setAttribute("aria-hidden", "true");
    units.forEach(function (u) {
      var seg = el("li", "p-seg");
      seg.setAttribute("data-state", u.state);
      segs.appendChild(seg);
    });
    section.appendChild(count);
    section.appendChild(segs);
    return section;
  }

  function unitList(units) {
    var section = el("section", "p-units");
    section.setAttribute("aria-label", "Units");
    var list = el("ul", "p-unit-list");
    units.forEach(function (u) {
      var row = el("li", "p-unit");
      var chip = el("span", "p-chip", LABELS[u.state]);
      chip.setAttribute("data-state", u.state);
      var text = el("div", "p-unit-text");
      text.appendChild(el("p", "p-unit-name", u.name));
      if (u.detail) text.appendChild(el("p", "p-unit-detail", u.detail));
      row.appendChild(chip);
      row.appendChild(el("code", "p-unit-id", u.id));
      row.appendChild(text);
      if (u.who) row.appendChild(el("p", "p-unit-who", u.who));
      list.appendChild(row);
    });
    section.appendChild(list);
    return section;
  }

  function timeline(phases, lanes) {
    if (!phases.length || !lanes.length) return null;
    var columns = LANE_WIDTH + " repeat(" + phases.length + ", minmax(" + PHASE_MIN + ", 1fr))";
    var head = el("div", "p-tl-row p-tl-head");
    head.setAttribute("aria-hidden", "true");
    head.style.gridTemplateColumns = columns;
    phases.forEach(function (name, i) {
      head.appendChild(place(el("span", "p-tl-phase", name), i + 2, 1));
    });
    var list = el("ul", "p-tl-lanes");
    lanes.forEach(function (lane) {
      var rows = stack(lane.bars);
      var row = el("li", "p-tl-row");
      row.style.gridTemplateColumns = columns;
      var label = el("p", "p-tl-lane");
      label.appendChild(el("span", "p-tl-lane-name", lane.lane));
      if (lane.model) label.appendChild(el("span", "p-tl-model", lane.model));
      row.appendChild(place(label, 1, 1, 1, rows));
      phases.forEach(function (_, i) {
        var cell = el("span", "p-tl-cell");
        cell.setAttribute("aria-hidden", "true");
        row.appendChild(place(cell, i + 2, 1, 1, rows));
      });
      lane.bars.forEach(function (bar) {
        var node = el("p", "p-tl-bar");
        node.setAttribute("data-state", bar.state);
        node.appendChild(el("span", "p-sr", LABELS[bar.state] + ": "));
        node.appendChild(document.createTextNode(bar.label));
        row.appendChild(place(node, bar.from + 2, bar.row + 1, bar.to - bar.from));
      });
      list.appendChild(row);
    });
    var board = el("div", "p-tl-board");
    board.appendChild(head);
    board.appendChild(list);
    var scroll = el("div", "p-tl-scroll");
    scroll.setAttribute("tabindex", "0");
    scroll.setAttribute("role", "region");
    scroll.setAttribute("aria-label", "Who runs when, scrolls sideways");
    scroll.appendChild(board);
    var section = el("section", "p-timeline");
    section.appendChild(el("h2", "p-heading", "Who runs when"));
    section.appendChild(scroll);
    return section;
  }

  function formatTime(iso) {
    var date = new Date(iso);
    if (!iso || isNaN(date.getTime())) return "";
    return "Updated " + date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function fallback(root, truncated) {
    var box = el("div", "p-fallback");
    box.appendChild(el("p", "p-fallback-title", "This progress item can't be shown."));
    box.appendChild(
      el(
        "p",
        "p-fallback-text",
        truncated
          ? "The file is too large to show in full. Download it from the dashboard to read it."
          : "The file isn't a valid progress.json. Download it from the dashboard to read it."
      )
    );
    root.appendChild(box);
  }

  function main() {
    var root = document.getElementById("pdash-root");
    var view = null;
    try {
      var data = JSON.parse(document.getElementById("pdash-data").textContent);
      view = data.truncated ? null : parse(String(data.text));
      root.className = "p-root";
      if (!view) return fallback(root, Boolean(data.truncated));
      var head = el("header", "p-head");
      head.appendChild(el("h1", "p-title", view.title));
      if (view.note) head.appendChild(el("p", "p-note", view.note));
      var updated = formatTime(view.updatedAt);
      if (updated) head.appendChild(el("p", "p-updated", updated));
      root.appendChild(head);
      root.appendChild(meter(view.units));
      root.appendChild(unitList(view.units));
      var tl = timeline(view.phases, view.lanes);
      if (tl) root.appendChild(tl);
    } catch (err) {
      root.textContent = "";
      fallback(root, false);
    }
  }

  main();
})();
