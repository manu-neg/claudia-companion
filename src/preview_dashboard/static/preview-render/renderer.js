/*
  Preview-origin text renderer: runs inside the sandboxed /r/ page (opaque origin, no network).
  Reads the capped text from the JSON data block (#pdash-data) and renders it as
  markdown, highlighted code/diff, a JSON tree, a CSV table or plain text. HTML is only ever
  inserted as DOMPurify output (defense in depth on top of the sandbox; docs/frontend.md).
*/
(function () {
  "use strict";

  var MAX_CSV_ROWS = 2000;
  var MAX_CSV_COLUMNS = 200;
  var MAX_JSON_NODES = 20000;
  var MAX_HIGHLIGHT_CHARS = 1024 * 1024; // highlighting larger text would freeze the phone
  // marked + DOMPurify on huge (or pathological) markdown can hang the frame: show it as text.
  var MAX_MARKDOWN_CHARS = 512 * 1024;
  var JSON_OPEN_DEPTH = 2;

  // C23: html profile, no style/form/svg/math, only https/mailto/relative URLs. Protocol-relative
  // URLs (`//host`, and `\\host` / `/\host`, which browsers read the same way) are refused:
  // they would leave the preview origin while looking relative.
  var PURIFY_CONFIG = {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "form", "svg", "math", "input", "button", "textarea", "select"],
    FORBID_ATTR: ["style", "srcset"],
    ALLOWED_URI_REGEXP: /^(?![\/\\]{2})(?:(?:https|mailto):|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
  };
  // Highlighter output is only <span class="hljs-...">text</span>.
  var HIGHLIGHT_CONFIG = { ALLOWED_TAGS: ["span"], ALLOWED_ATTR: ["class"] };

  var LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".css": "css", ".scss": "scss", ".sh": "bash", ".bash": "bash",
    ".go": "go", ".rs": "rust", ".java": "java", ".c": "c", ".h": "c", ".cpp": "cpp",
    ".hpp": "cpp", ".rb": "ruby", ".php": "php", ".sql": "sql", ".yaml": "yaml",
    ".yml": "yaml", ".toml": "ini", ".ini": "ini", ".xml": "xml", ".swift": "swift",
    ".kt": "kotlin", ".json": "json", ".diff": "diff", ".patch": "diff",
  };

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    var units = ["KB", "MB", "GB"];
    var value = n / 1024;
    var i = 0;
    while (value >= 1024 && i < units.length - 1) {
      value /= 1024;
      i += 1;
    }
    return value.toFixed(value < 10 ? 1 : 0) + " " + units[i];
  }

  function sanitizeInto(target, html, config) {
    // DOMPurify is loaded only for renderers that insert HTML; fail closed without it.
    if (typeof DOMPurify === "undefined" || !DOMPurify.isSupported) {
      throw new Error("sanitizer unavailable");
    }
    target.innerHTML = DOMPurify.sanitize(html, config);
  }

  function plain(root, text, wrap) {
    var pre = el("pre", "r-pre" + (wrap ? " r-wrap" : ""));
    pre.appendChild(el("code", "r-code", text));
    root.appendChild(pre);
    return pre;
  }

  function highlighted(root, text, language) {
    var pre = el("pre", "r-pre");
    var code = el("code", "r-code hljs");
    pre.appendChild(code);
    root.appendChild(pre);
    var usable = typeof hljs !== "undefined" && language && hljs.getLanguage(language);
    if (!usable || text.length > MAX_HIGHLIGHT_CHARS) {
      code.textContent = text;
      return;
    }
    var result = hljs.highlight(text, { language: language, ignoreIllegals: true });
    sanitizeInto(code, result.value, HIGHLIGHT_CONFIG);
  }

  function renderMarkdown(root, data) {
    if (data.text.length > MAX_MARKDOWN_CHARS) {
      root.appendChild(el("p", "r-note", "This file is too long to format, so it's shown as text."));
      plain(root, data.text, true);
      return;
    }
    DOMPurify.addHook("afterSanitizeAttributes", function (node) {
      if (node.tagName === "A" && node.hasAttribute("href")) {
        node.setAttribute("target", "_blank");
        node.setAttribute("rel", "noopener noreferrer");
      }
    });
    // Raw HTML in the markdown is shown as text, never parsed as markup.
    marked.use({
      gfm: true,
      async: false,
      renderer: {
        html: function (token) {
          return escapeHtml(token.text);
        },
      },
    });
    var article = el("article", "r-markdown");
    article.setAttribute("dir", "auto");
    root.appendChild(article);
    sanitizeInto(article, marked.parse(data.text), PURIFY_CONFIG);
    var blocks = article.querySelectorAll("pre > code");
    for (var i = 0; i < blocks.length; i += 1) {
      var match = /(?:^|\s)language-([\w+-]+)/.exec(blocks[i].className);
      var language = match ? match[1].toLowerCase() : null;
      if (!language || typeof hljs === "undefined" || !hljs.getLanguage(language)) continue;
      var source = blocks[i].textContent;
      if (source.length > MAX_HIGHLIGHT_CHARS) continue;
      blocks[i].classList.add("hljs");
      var out = hljs.highlight(source, { language: language, ignoreIllegals: true });
      sanitizeInto(blocks[i], out.value, HIGHLIGHT_CONFIG);
    }
  }

  function jsonSummary(value) {
    if (Array.isArray(value)) return "[ " + value.length + (value.length === 1 ? " item ]" : " items ]");
    var n = Object.keys(value).length;
    return "{ " + n + (n === 1 ? " key }" : " keys }");
  }

  function renderJsonTree(root, text) {
    var value;
    try {
      value = JSON.parse(text);
    } catch (err) {
      root.appendChild(el("p", "r-note", "This isn't valid JSON (it may be cut off), so it's shown as text."));
      plain(root, text, false);
      return;
    }
    var budget = { nodes: 0 };
    var tree = el("div", "r-json");
    tree.appendChild(jsonNode(null, value, 0, budget));
    root.appendChild(tree);
    if (budget.nodes > MAX_JSON_NODES) {
      root.appendChild(el("p", "r-note", "Large document: only the first " + MAX_JSON_NODES + " values are shown."));
    }
  }

  function jsonNode(key, value, depth, budget) {
    budget.nodes += 1;
    var isContainer = value !== null && typeof value === "object";
    var row;
    if (!isContainer || budget.nodes > MAX_JSON_NODES) {
      row = el("div", "r-json-row");
      if (key !== null) row.appendChild(el("span", "r-json-key", key));
      var type = value === null ? "null" : typeof value;
      var shown = !isContainer ? (type === "string" ? JSON.stringify(value) : String(value)) : "…";
      row.appendChild(el("span", "r-json-" + type, shown));
      return row;
    }
    row = el("details", "r-json-node");
    row.open = depth < JSON_OPEN_DEPTH;
    var summary = el("summary", "r-json-summary");
    if (key !== null) summary.appendChild(el("span", "r-json-key", key));
    summary.appendChild(el("span", "r-json-meta", jsonSummary(value)));
    row.appendChild(summary);
    var children = el("div", "r-json-children");
    var keys = Array.isArray(value) ? value.map(function (_, i) { return String(i); }) : Object.keys(value);
    for (var i = 0; i < keys.length; i += 1) {
      if (budget.nodes > MAX_JSON_NODES) break;
      children.appendChild(jsonNode(keys[i], value[keys[i]], depth + 1, budget));
    }
    row.appendChild(children);
    return row;
  }

  // RFC 4180-style parser: quoted fields, doubled quotes, CR/LF/CRLF line ends.
  function parseDelimited(text, delimiter, maxRows) {
    var rows = [];
    var row = [];
    var field = "";
    var quoted = false;
    var i = 0;
    while (i < text.length && rows.length <= maxRows) {
      var c = text[i];
      if (quoted) {
        if (c === '"' && text[i + 1] === '"') { field += '"'; i += 2; continue; }
        if (c === '"') { quoted = false; i += 1; continue; }
        field += c; i += 1; continue;
      }
      if (c === '"' && field === "") { quoted = true; i += 1; continue; }
      if (c === delimiter) { row.push(field); field = ""; i += 1; continue; }
      if (c === "\r" || c === "\n") {
        row.push(field); rows.push(row); row = []; field = "";
        i += c === "\r" && text[i + 1] === "\n" ? 2 : 1;
        continue;
      }
      field += c; i += 1;
    }
    if (field !== "" || row.length) { row.push(field); rows.push(row); }
    return { rows: rows.slice(0, maxRows), more: rows.length > maxRows || i < text.length };
  }

  function renderCsv(root, data) {
    var delimiter = data.extension === ".tsv" ? "\t" : ",";
    var parsed = parseDelimited(data.text, delimiter, MAX_CSV_ROWS + 1);
    var rows = parsed.rows;
    if (!rows.length) {
      root.appendChild(el("p", "r-note", "This file is empty."));
      return;
    }
    var wrap = el("div", "r-table-wrap");
    var table = el("table", "r-table");
    var head = el("thead");
    var headRow = el("tr");
    rows[0].slice(0, MAX_CSV_COLUMNS).forEach(function (cell) {
      var th = el("th", null, cell);
      th.setAttribute("scope", "col");
      headRow.appendChild(th);
    });
    head.appendChild(headRow);
    table.appendChild(head);
    var body = el("tbody");
    var shown = Math.min(rows.length, MAX_CSV_ROWS + 1);
    for (var r = 1; r < shown; r += 1) {
      var tr = el("tr");
      rows[r].slice(0, MAX_CSV_COLUMNS).forEach(function (cell) {
        tr.appendChild(el("td", null, cell));
      });
      body.appendChild(tr);
    }
    table.appendChild(body);
    wrap.appendChild(table);
    root.appendChild(wrap);
    if (parsed.more || rows.length > MAX_CSV_ROWS + 1) {
      root.appendChild(el("p", "r-note", "Only the first " + MAX_CSV_ROWS + " rows are shown."));
    }
  }

  function banner(root, data) {
    if (!data.truncated) return;
    root.appendChild(
      el(
        "p",
        "r-banner",
        "Showing the first " + formatBytes(data.shown_bytes) + " of " + formatBytes(data.size) +
          ". Download the file from the dashboard to see all of it."
      )
    );
  }

  function main() {
    var root = document.getElementById("pdash-root");
    var data = JSON.parse(document.getElementById("pdash-data").textContent);
    banner(root, data);
    var body = el("div", "r-body");
    root.appendChild(body);
    try {
      if (data.renderer === "markdown") renderMarkdown(body, data);
      else if (data.renderer === "code") highlighted(body, data.text, LANGUAGE_BY_EXTENSION[data.extension]);
      else if (data.renderer === "diff") highlighted(body, data.text, "diff");
      else if (data.renderer === "json") renderJsonTree(body, data.text);
      else if (data.renderer === "csv") renderCsv(body, data);
      else plain(body, data.text, true);
    } catch (err) {
      // Any renderer failure degrades to plain text, never to raw HTML.
      body.textContent = "";
      body.appendChild(el("p", "r-note", "This file couldn't be formatted, so it's shown as text."));
      plain(body, data.text, true);
    }
  }

  main();
})();
