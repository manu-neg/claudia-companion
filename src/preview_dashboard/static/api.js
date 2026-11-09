/*
  Dashboard API client: same-origin JSON fetches with the exact CSRF headers the server demands
  (docs/api.md), ETag/If-None-Match revalidation, and a visibility-aware poller. The only place
  the UI talks to the network; item bytes are never fetched (they live on the preview origin).
*/

const POLL_INTERVAL_MS = 10_000;

export class ApiError extends Error {
  constructor(status, code) {
    super(`API ${status} ${code}`);
    this.status = status;
    this.code = code;
  }
}

async function request(method, path, { etag = null, signal } = {}) {
  // Only our own API paths; never a URL taken from data.
  if (typeof path !== "string" || !path.startsWith("/api/")) throw new Error("bad API path");
  const headers = { Accept: "application/json" };
  const init = {
    method,
    headers,
    mode: "same-origin",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    // GETs stay "no-referrer" (nothing to prove). POSTs need "same-origin": with
    // "no-referrer", Safari/WebKit sends Origin: null on same-origin POSTs too, which
    // fails the CSRF Origin check (C4) even for genuine same-origin requests.
    referrerPolicy: method === "POST" ? "same-origin" : "no-referrer",
    signal,
  };
  if (etag) headers["If-None-Match"] = etag;
  if (method === "POST") {
    // Exact values: anything else (e.g. "; charset=utf-8") is a 403 (C4).
    headers["Content-Type"] = "application/json";
    headers["X-PDash-CSRF"] = "1";
    init.body = "{}";
  }
  const response = await fetch(path, init);
  if (response.status === 304) return { status: 304, etag, data: null };
  if (!response.ok) {
    let code = "error";
    try {
      const body = await response.json();
      if (body && typeof body.error === "string") code = body.error;
    } catch {
      // Non-JSON error body: keep the generic code.
    }
    throw new ApiError(response.status, code);
  }
  return { status: response.status, etag: response.headers.get("ETag"), data: await response.json() };
}

/** GET `path`; with `etag`, a 304 returns `{status: 304, data: null}`. */
export function apiGet(path, options) {
  return request("GET", path, options);
}

/** POST an empty JSON body to `path` (trash/restore). */
export function apiPost(path, options) {
  return request("POST", path, options);
}

/**
 * Build `/api/items` query strings from defined values only. `folder`: a folder id or "unfiled".
 * `kind`: one kind name or an array of them (sent as one comma list, `kind=html,progress`: the
 * API refuses a repeated `kind` key).
 */
export function itemsPath({ state, kind, cursor, limit, folder }) {
  const params = new URLSearchParams();
  const kinds = (Array.isArray(kind) ? kind : [kind]).filter(Boolean);
  if (state && state !== "active") params.set("state", state);
  if (kinds.length) params.set("kind", kinds.join(","));
  if (folder) params.set("folder", folder);
  if (limit) params.set("limit", String(limit));
  if (cursor) params.set("cursor", cursor);
  const query = params.toString();
  return query ? `/api/items?${query}` : "/api/items";
}

/** `/api/items/<id>`, with `t=1` for a trashed item and `rev=<n>` for an older revision. */
export function itemPath(id, { trashed = false, rev = null } = {}) {
  const params = new URLSearchParams();
  if (trashed) params.set("t", "1");
  if (Number.isInteger(rev) && rev > 0) params.set("rev", String(rev));
  const query = params.toString();
  return `/api/items/${encodeURIComponent(id)}${query ? `?${query}` : ""}`;
}

/**
 * Call `tick` every ~10 s while the page is visible; pause when hidden and run once
 * right away when it becomes visible again. Returns a stop function.
 */
export function startPolling(tick, intervalMs = POLL_INTERVAL_MS) {
  let stopped = false;
  let running = false;
  const run = async () => {
    if (stopped || running || document.visibilityState !== "visible") return;
    running = true;
    try {
      await tick();
    } catch {
      // Transient failure: the next tick retries.
    } finally {
      running = false;
    }
  };
  const timer = setInterval(run, intervalMs);
  const onVisibility = () => {
    if (document.visibilityState === "visible") run();
  };
  document.addEventListener("visibilitychange", onVisibility);
  return () => {
    stopped = true;
    clearInterval(timer);
    document.removeEventListener("visibilitychange", onVisibility);
  };
}
