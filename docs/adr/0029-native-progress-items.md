# ADR 0029: Native progress items — `progress` kind + one-call MCP tools

**TL;DR:** A live work tracker is an item of kind `progress`: exactly one file `progress.json` (strict schema v1 below, ≤ 64 KiB). Claude writes it with **one** MCP call (`dashboard_progress_set` for the whole status, `dashboard_progress_update` for a one-unit/note patch); the MCP server validates it, keeps a private state copy under the intake root and publishes it through the normal intake → admin path as a new item or a new revision. The item view shows it through the usual `/r/` frame, drawn by a dedicated neutral renderer (unit P2, see Rendering).

## Schema (`progress.json`, version 1) — the contract for the renderer

The file the dashboard serves is canonical UTF-8 JSON (no BOM), **every key always present**, in this shape:

```text
{
  "version":    1,                       int, always 1 (renderer: anything else = invalid)
  "title":      string 1..120,           required
  "note":       string 0..500,           "" if unset
  "updated_at": string,                  UTC "YYYY-MM-DDTHH:MM:SSZ", set by the tool (never by the caller)
  "phases":     [string 1..40] 0..12,    column headers of the timeline, in order
  "units": [ 0..40 of {
      "id":     string ^[A-Za-z0-9-]{1,12}$, unique (exact match) within units
      "name":   string 1..120,
      "who":    string 0..80,             "" if unset (agent / person / model running it)
      "state":  "done" | "running" | "waiting" | "blocked",
      "detail": string 0..600             "" if unset
  } ],
  "timeline": [ 0..16 of {                one lane = one row ("who runs when")
      "lane":   string 1..60,
      "model":  string 0..40,             "" if unset
      "bars": [ 0..12 of {
          "unit":  string,                must equal some units[].id
          "from":  int,                   0 <= from < to <= len(phases)
          "to":    int,                   exclusive: the bar covers phase columns from..to-1
          "label": string 0..60           "" if unset
      } ]
  } ]
}
```

Rules that hold for every string: **plain text** (no Markdown/HTML meaning — render with `textContent` only), single line, already cleaned by the tool (control, bidi, zero-width/invisible characters removed, line breaks → spaces, NFC, trimmed). Limits count Unicode code points after cleaning. Unknown keys anywhere are rejected; `true`/`false` are not ints. Whole file ≤ 65 536 bytes. Bars in the same lane may overlap; bars of different lanes in the same column mean "in parallel".

Renderer obligations (P2): treat the file as untrusted — re-check shape, `version == 1`, types and bar refs defensively and show the generic "can't show this" state on any mismatch (a `progress` item can also be published by hand through `dashboard_publish(kind="progress")`, whose content the server does not parse, I4).

Example:

```json
{"version":1,"title":"Progress tool","note":"P2 starts once the schema lands.","updated_at":"2026-09-30T09:15:00Z","phases":["Build","Review","Merge"],"units":[{"id":"P1","name":"progress kind + MCP tools","who":"developer (Opus)","state":"running","detail":"schema done, tools in progress"},{"id":"P2","name":"progress renderer","who":"general-purpose (Sonnet)","state":"waiting","detail":""}],"timeline":[{"lane":"developer","model":"Opus","bars":[{"unit":"P1","from":0,"to":1,"label":"P1"}]},{"lane":"frontend","model":"Sonnet","bars":[{"unit":"P2","from":0,"to":2,"label":"P2"}]}]}
```

## Context

- Progress pages were rendered by local scripts and published with several shell calls per update: slow, and each call risks being blocked by the worktree guard (owner decision 2026-09-30, backlog §9).
- Goal: one MCP call per update, no files or scripts on Claude's side, and a page that looks native in every OS (ADR 0028).
- Constraints: the admin API receives bytes, never paths (I3), and never parses published content (I4); MCP intake (C10/C27, ADR 0006) and the admin secret scan (C15, ADR 0008) must stay the only publish path; revisions (ADR 0019) already give one stable link per item.

## Decision

- **Kind `progress`** (`kinds/progress.py`): accepts exactly one file named `progress.json`, served as `application/json`, TEXT preview, renderer id `progress` (drawn on the preview origin, see Rendering). It claims no extensions and scores confidence 1, so it is **never auto-detected** (`json` scores 100 on the same file) — only an explicit `kind="progress"` selects it (ADR 0009: a hint must be compatible, not just known).
- **Schema validation lives in the same module** as pure stdlib code (`validate_progress`, `progress_json_schema`), and runs in the MCP process before anything is written — the admin server still stores the bytes opaque (I4 unchanged).
- **Tools** (`interfaces/mcp/tools/progress.py`): `dashboard_progress_set(status, item_id?, title?, folder_id?, pinned?, expected_revision?)` and `dashboard_progress_update(item_id, unit_id?, state?, detail?, note?)`. They reuse `IntakePolicy.collect` + `AdminClient.publish` / `publish_revision` — no new admin endpoint.
- **State dir:** `<first intake root>/progress-state/`, mode 0700, one sub-dir per item named by its (validated) ULID holding `state.json` (`{"revision", "status"}`, written atomically after a successful publish). Each publish is staged in a fresh random `progress-state/stage-<hex>/progress.json` and removed afterwards. No path ever comes from the caller; directories are opened fd-relative with `O_NOFOLLOW` and must be real directories owned by the process user.
- **Security (C42):** the state dir gets no exemption — the staged file passes the unchanged intake policy (C10/C27) and the admin secret scan (C15); directories must be real (no symlink), owned by the process user, mode 0700; only canonical ULIDs name item dirs (also ids returned by the admin); no caller path anywhere.
- **State dir is private to these tools (amendment, F-MCP 2026-09-30):** `dashboard_publish`/`_update_content` use an intake policy with `progress-state` added to the denylist (`server.PUBLISH_ONLY_DENIED`, `publish_intake()`), so `state.json` files — and any bundle whose tree contains a `progress-state` dir, e.g. the whole outbox — are refused; only the progress tools' own intake (plain `IntakePolicy.from_settings`) reads their staged files.
- **Only progress items are revised (amendment, F-MCP):** `_set` with `item_id` first fetches the item and refuses unless its kind is `progress` ("use dashboard_update_content for other items"), so a tracker call can't silently turn a page into a tracker.
- **Concurrency:** `_update` always sends the stored revision as `expected_revision`, so a revision published by anyone else makes it fail with a conflict instead of overwriting (then `_set` with the full status). `_set` with `item_id` always sends the revision whose kind it just checked; a caller's `expected_revision` must equal it (else refused as a 409 conflict before anything is published), so the kind check can't be raced.

## Rendering

`progress` is a TEXT-mode kind rendered **on the preview origin** like markdown/json (ADR 0018), never on the dashboard: the dashboard must not fetch item bytes (security C5/C6/C19, `connect-src 'self'`), so there is no dashboard-side JSON reader. The dashboard registry maps `progress` to the shared `/r/` iframe renderer, and `renderer_page.py` gives it a self-contained page: `preview-render/progress.js` + `progress.css` only (no `theme.css`, `renderer.css`, vendor code). The script re-validates schema v1 (`version == 1`, limits, unique ids, bar refs), draws with `textContent` only, and shows a fixed "can't be shown" message on any mismatch or truncation. By owner rule the page is **OS-neutral**: it carries its own small light/dark token set (`--p-*`, system fonts, flat) and takes nothing from an OS theme, so it looks the same in Platinum and Aero; only the surrounding window is the OS's. Changing a progress item creates a new revision; the item view's existing polling re-renders the frame when the file changes.

## Consequences

- One tool call per tracker update; the page keeps one `viewer_url` and a version history.
- `_set` with `item_id` costs one extra admin call (`get_item`) and now conflicts, instead of overwriting, when the item changes between that check and the publish.
- The state copy is local to the host that published it: `_update` on an item it never wrote (or after the state dir was cleaned) fails without fetching anything and tells the caller to use `_set`.
- A `progress` item published by hand bypasses the schema check (the server does not parse content), so the renderer must stay defensive — accepted, it only affects display.
- Schema changes need a new `version` and a renderer that understands it.
