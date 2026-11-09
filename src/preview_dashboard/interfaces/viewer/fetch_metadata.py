"""Fetch-metadata (`Sec-Fetch-*`) resource isolation for both viewer apps (ADR 0012).

Defense in depth on top of CSP/CORP/CSRF (docs/security.md C31): each
response is only served for the kind of browser request it is meant for —
an SVG only as an `<img>`, HTML only in an iframe, a top-level document
only for PDFs and downloads. Requests without any `Sec-Fetch-*` header
(older browsers, some native media stacks, non-browser clients) are
allowed; a browser that sends the headers is held to them.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from preview_dashboard.interfaces.viewer._http import (
    DuplicateHeaderError,
    media_type_of,
    response_header,
    single_header,
)
from preview_dashboard.interfaces.viewer.errors import send_error
from preview_dashboard.interfaces.viewer.headers import PDF_MEDIA_TYPE, has_ambiguous_headers
from preview_dashboard.interfaces.viewer.hints import bundle_referer_bound, get_preview_hints
from preview_dashboard.interfaces.viewer.request_id import request_id_of
from preview_dashboard.kinds.base import PreviewMode

logger = logging.getLogger("preview_dashboard.viewer")

_SITES = frozenset({"same-origin", "same-site", "cross-site", "none"})
# The dashboard origin and the preview origin share a host, so they are
# same-site; a sandboxed preview document has an opaque origin, so its own
# sub-resource requests arrive as cross-site.
_FROM_DASHBOARD = frozenset({"same-origin", "same-site"})
_NAVIGATION_SITES = frozenset({"same-origin", "same-site", "none"})
# Every destination the preview app can legitimately serve; anything else
# (embed, object, worker, serviceworker, manifest, report, ...) is refused
# before the route runs.
PREVIEW_DESTS = frozenset(
    {"document", "iframe", "image", "video", "audio", "track", "script", "style", "empty"}
)
# `font` is absent on purpose: font loads are CORS-mode, which the viewer
# never answers, so bundle web fonts are unsupported (use data: URLs).
_BUNDLE_ONLY_DESTS = frozenset({"track", "script", "style"})


@dataclass(frozen=True, slots=True)
class FetchMetadata:
    """The request's `Sec-Fetch-Site/Dest/Mode` values (lowercase), None if absent."""

    site: str | None = None
    dest: str | None = None
    mode: str | None = None

    @property
    def present(self) -> bool:
        """True if the browser sent any fetch-metadata header."""
        return any(v is not None for v in (self.site, self.dest, self.mode))


class MalformedFetchMetadataError(Exception):
    """A `Sec-Fetch-*` header was duplicated or is not ASCII."""


def read_fetch_metadata(scope: Scope) -> FetchMetadata:
    """Parse the `Sec-Fetch-*` headers of `scope`.

    Raises:
        MalformedFetchMetadataError: a header is duplicated or not ASCII.
    """
    values: list[str | None] = []
    for name in (b"sec-fetch-site", b"sec-fetch-dest", b"sec-fetch-mode"):
        try:
            raw = single_header(scope, name)
            values.append(None if raw is None else raw.decode("ascii").strip().lower())
        except (DuplicateHeaderError, UnicodeDecodeError):
            raise MalformedFetchMetadataError(name.decode("ascii")) from None
    return FetchMetadata(site=values[0], dest=values[1], mode=values[2])


def dashboard_request_allowed(meta: FetchMetadata, method: str) -> bool:
    """Resource isolation policy for the dashboard app (UI + JSON).

    Same-origin and user-initiated (`none`) requests pass; from any other
    site only a top-level GET/HEAD navigation passes (e.g. a bookmark link),
    never a sub-resource load, an iframe or a fetch.
    """
    if not meta.present:
        return True
    if meta.site not in _SITES or meta.dest is None:
        return False
    if meta.site in {"same-origin", "none"}:
        return True
    return meta.dest == "document" and meta.mode == "navigate" and method in {"GET", "HEAD"}


def preview_request_allowed(meta: FetchMetadata) -> bool:
    """Coarse request-time check for the preview app (before any route runs)."""
    if not meta.present:
        return True
    return meta.site in _SITES and meta.dest in PREVIEW_DESTS


def preview_response_allowed(
    meta: FetchMetadata,
    *,
    media_type: str,
    preview_mode: PreviewMode | None,
    attachment: bool,
    bundle_subresource: bool,
    bundle_bound: bool = False,
) -> bool:
    """Decide whether a successful preview response may be delivered.

    Rules (only when fetch metadata is present):
    - `document` (top-level): only downloads (`attachment`) and PDFs of a
      DOCUMENT-mode item, and only from the dashboard or user-initiated.
    - `iframe`: HTML entry documents (SANDBOXED), TEXT-mode files and
      DOCUMENT PDFs, only when framed from the dashboard.
    - `image`: `image/*` (incl. SVG — the only way SVG is ever served);
      `video`/`audio`: `video/*` or `audio/*`. From the dashboard, or
      cross-site only for an HTML bundle's own sub-resources whose
      `Referer` binds them to their bundle (`bundle_bound`).
    - `track`/`script`/`style`: HTML bundle sub-resources only (cross-site
      only when bound).
    - `empty` (fetch, download): only downloads, from the dashboard.

    Args:
        meta: the request's fetch metadata.
        media_type: lowercase `type/subtype` of the response.
        preview_mode: the item kind's preview mode, or None if unknown.
        attachment: the response is a `Content-Disposition: attachment`.
        bundle_subresource: a non-entry file of an HTML bundle.
        bundle_bound: the request's `Referer` is a page of the same bundle
            (`hints.bundle_referer_bound`); required for any cross-site load.
    """
    if not meta.present:
        return True
    site, dest = meta.site, meta.dest
    if site not in _SITES or dest not in PREVIEW_DESTS:
        return False
    is_pdf_document = media_type == PDF_MEDIA_TYPE and preview_mode is PreviewMode.DOCUMENT
    if dest == "document":
        return site in _NAVIGATION_SITES and (attachment or is_pdf_document)
    if dest == "empty":
        return attachment and site in _NAVIGATION_SITES
    if attachment:
        return False  # a download is never embedded as a sub-resource
    if dest == "iframe":
        framable = (
            (preview_mode is PreviewMode.SANDBOXED and media_type == "text/html")
            or preview_mode is PreviewMode.TEXT
            or is_pdf_document
        )
        return framable and not bundle_subresource and site in _FROM_DASHBOARD
    cross_site_ok = site == "cross-site" and bundle_subresource and bundle_bound
    site_ok = site in _FROM_DASHBOARD or cross_site_ok
    if dest == "image":
        return site_ok and media_type.startswith("image/")
    if dest in {"video", "audio"}:
        return site_ok and media_type.startswith(("video/", "audio/"))
    # track/script/style: only an HTML bundle loads these from us.
    return (
        dest in _BUNDLE_ONLY_DESTS
        and bundle_subresource
        and (site in _FROM_DASHBOARD or cross_site_ok)
    )


def _deny_log(scope: Scope, where: str) -> None:
    logger.warning("fetch metadata denied (%s) request_id=%s", where, request_id_of(scope))


class DashboardFetchMetadataMiddleware:
    """Apply `dashboard_request_allowed` to every dashboard request (403 if denied)."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            try:
                allowed = dashboard_request_allowed(read_fetch_metadata(scope), scope["method"])
            except MalformedFetchMetadataError:
                allowed = False
            if not allowed:
                _deny_log(scope, "dashboard request")
                await send_error(scope, send, 403)
                return
        await self._app(scope, receive, send)


def _delivers_resource(status: int) -> bool:
    """2xx carries the resource; 304 releases the browser's cached copy of it."""
    return 200 <= status < 300 or status == 304


class _SuppressedError(Exception):
    """Internal: the route kept sending a body we already replaced with a 403."""


class PreviewFetchMetadataMiddleware:
    """Enforce the preview fetch-metadata policy centrally (routes cannot skip it).

    Request phase: `preview_request_allowed`. Response phase (2xx and 304;
    errors are inert JSON): `preview_response_allowed` using the response's
    Content-Type / Content-Disposition and the route's `PreviewHints`. A 304
    is checked too: it tells the browser to use its cached copy, i.e. it
    delivers that resource to the new context just like a 200 would. A
    denied response is replaced by a generic 403 and the route's body
    stream is aborted. A 2xx/304 with two Content-Type or
    Content-Disposition headers is always denied (ambiguous, fail closed).

    Args:
        app: the wrapped ASGI app.
        preview_origin: the preview app's own origin, for binding bundle
            sub-resources to their bundle via `Referer`.
    """

    def __init__(self, app: ASGIApp, *, preview_origin: str) -> None:
        self._app = app
        self._preview_origin = preview_origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        try:
            meta = read_fetch_metadata(scope)
        except MalformedFetchMetadataError:
            meta = None
        if meta is None or not preview_request_allowed(meta):
            _deny_log(scope, "preview request")
            await send_error(scope, send, 403)
            return

        denied = False

        async def checking_send(message: Message) -> None:
            nonlocal denied
            if denied:
                raise _SuppressedError
            if message["type"] == "http.response.start" and _delivers_resource(message["status"]):
                headers = list(message.get("headers", ()))
                disposition = response_header(headers, b"content-disposition") or b""
                hints = get_preview_hints(scope)
                if has_ambiguous_headers(headers) or not preview_response_allowed(
                    meta,
                    media_type=media_type_of(response_header(headers, b"content-type")),
                    preview_mode=hints.preview_mode,
                    attachment=disposition.strip().lower().startswith(b"attachment"),
                    bundle_subresource=hints.bundle_subresource,
                    bundle_bound=bundle_referer_bound(scope, hints, self._preview_origin),
                ):
                    denied = True
                    _deny_log(scope, "preview response")
                    await send_error(scope, send, 403)
                    return
            await send(message)

        # On denial the 403 is already sent; the route's remaining body is dropped.
        with contextlib.suppress(_SuppressedError):
            await self._app(scope, receive, checking_send)
