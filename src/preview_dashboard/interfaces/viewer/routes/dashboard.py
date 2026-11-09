"""Dashboard app routes: the JSON API and the UI's own static files.

Never serves item bytes: every item URL in the JSON points at the preview
origin (docs/security.md C5). The only state changes are POST trash/restore,
pin/unpin and "delete old versions" (revisions/prune, keep=1; C43), guarded
by the CSRF middleware (C4); folders are read only
(`GET /api/folders`, the `?folder=` filter, `folder` in item JSON; C40).
Static files come from an in-memory manifest, so no request value is ever
a filesystem path (I2, C20).
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Annotated

from fastapi import APIRouter, Path, Request
from starlette.responses import Response

from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.domain.folders import FolderId, Unfiled, parse_folder_filter
from preview_dashboard.domain.models import Item, ItemState
from preview_dashboard.domain.query import MAX_QUERY_KINDS, ItemQuery
from preview_dashboard.interfaces.folder_refs import folder_names, listing_json
from preview_dashboard.interfaces.viewer.conditional import body_etag, if_none_match
from preview_dashboard.interfaces.viewer.item_json import (
    REVISION_PARAM,
    TRASH_FLAG,
    ItemPresenter,
)
from preview_dashboard.interfaces.viewer.query_params import flag, parse_query
from preview_dashboard.interfaces.viewer.services import options_of, services_of
from preview_dashboard.interfaces.viewer.static_assets import INDEX_FILE, StaticAssets

router = APIRouter()

ItemIdParam = Annotated[str, Path(max_length=64)]
_STATES = {"active": ItemState.ACTIVE, "trashed": ItemState.TRASHED}
_MAX_LIMIT_DIGITS = 3
# Prune guard: the head revision the owner saw when confirming.
EXPECTED_PARAM = "expected"
# Same spelling rule as the preview URLs' revision segment (no `latest` here:
# omitting `rev` already means the head).
_REV_RE = re.compile(r"[1-9][0-9]{0,9}")
# Static files may be cached by the browser but must be revalidated, so a
# new UI version takes effect on the next load (private: never shared caches).
_STATIC_CACHE = "private, no-cache"


def _json(request: Request, payload: object, *, conditional: bool = False) -> Response:
    """Serialize `payload`; with `conditional`, answer 304 on a matching If-None-Match.

    JSON stays `no-store` (it describes private content): polling clients
    send `If-None-Match` themselves with the last `ETag` they saw.
    """
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    if not conditional:
        return Response(body, media_type="application/json")
    etag = body_etag(body)
    if if_none_match(request.scope, etag):
        return Response(status_code=304, headers={"ETag": etag})
    return Response(body, media_type="application/json", headers={"ETag": etag})


def _presenter(request: Request, items: Sequence[Item]) -> ItemPresenter:
    """A presenter that knows the folders of `items` (one folder read, after the items)."""
    services = services_of(request)
    names = folder_names(services.folders, items)
    return ItemPresenter(services.kinds, options_of(request), names)


def _kinds_param(raw: str) -> tuple[str, ...]:
    """Split `kind=a,b` into kinds; empty = all kinds.

    One comma-separated value rather than a repeated `kind` key, so the
    strict parser's "no repeated keys" rule (one meaning per URL) stands.
    Each name is syntax-checked and at most `MAX_QUERY_KINDS` are allowed
    by `ItemQuery`; an empty element (`a,,b`, trailing comma) is a 400.

    Raises:
        ValidationError: an empty element (the rest is checked by `ItemQuery`).
    """
    if not raw:
        return ()
    names = tuple(raw.split(","))
    if len(names) > MAX_QUERY_KINDS:
        # Checked here too so a long list is refused before any other work.
        raise ValidationError("invalid kind")
    if "" in names:
        raise ValidationError("invalid kind")
    return names


def _item_query(params: dict[str, str]) -> tuple[ItemQuery, FolderId | None]:
    """Build the listing query from strictly parsed parameters.

    Returns:
        The query, and the folder id that must exist (None: no such check).

    Raises:
        ValidationError: bad state, kind, limit, cursor or folder.
    """
    state = _STATES.get(params.get("state", "active"))
    if state is None:
        raise ValidationError("invalid state")
    raw_limit = params.get("limit")
    limit = None
    if raw_limit is not None:
        if not (raw_limit.isascii() and raw_limit.isdigit()) or len(raw_limit) > _MAX_LIMIT_DIGITS:
            raise ValidationError("invalid limit")
        limit = int(raw_limit)
    kinds = _kinds_param(params.get("kind") or "")
    cursor = params.get("cursor") or None
    raw_folder = params.get("folder")
    # A folder id or the literal `unfiled`; anything else (even empty) is a 400.
    folder = None if raw_folder is None else parse_folder_filter(raw_folder)
    must_exist = None if folder is None or isinstance(folder, Unfiled) else folder
    if limit is None:
        return ItemQuery(state=state, kinds=kinds, cursor=cursor, folder=folder), must_exist
    query = ItemQuery(state=state, kinds=kinds, cursor=cursor, limit=limit, folder=folder)
    return query, must_exist


@router.api_route("/api/kinds", methods=["GET", "HEAD"])
def list_kinds(request: Request) -> Response:
    """The content-kind registry (the frontend's single source of truth) + UI settings.

    `preview_origin` lets the UI refuse any item URL that points elsewhere.
    """
    parse_query(request.scope, ())
    services, options = services_of(request), options_of(request)
    return _json(
        request,
        {
            "kinds": list(services.kinds.describe()),
            "render_cap_bytes": options.render_cap_bytes,
            "preview_origin": options.preview_origin,
        },
        conditional=True,
    )


@router.api_route("/api/items", methods=["GET", "HEAD"])
def list_items(request: Request) -> Response:
    """One page of the feed (`state=active`) or the trash (`state=trashed`).

    Query: `state`, `kind` (one kind or a comma list of up to 8, e.g.
    `html,progress`), `limit` (1..200), `cursor` (from `next_cursor`),
    `folder` (a folder id or `unfiled`; an unknown folder id is a 404).
    Answers 304 when `If-None-Match` matches the page's ETag (cheap polling).
    """
    params = parse_query(request.scope, ("state", "kind", "limit", "cursor", "folder"))
    query, must_exist = _item_query(params)
    services = services_of(request)
    if must_exist is not None:
        # The repository returns an empty page for an unknown folder; the
        # contract (and the UI's "Page not found") needs a 404.
        services.folders.get(must_exist)
    page = services.queries.list(query)
    presenter = _presenter(request, page.items)
    return _json(
        request,
        {
            "items": [presenter.summary(item) for item in page.items],
            "next_cursor": page.next_cursor,
        },
        conditional=True,
    )


def _revision_param(params: dict[str, str]) -> int | None:
    raw = params.get(REVISION_PARAM)
    if raw is None:
        return None
    if _REV_RE.fullmatch(raw) is None:
        raise ValidationError("invalid revision")
    return int(raw)


@router.api_route("/api/items/{item_id}", methods=["GET", "HEAD"])
def get_item(request: Request, item_id: ItemIdParam) -> Response:
    """Item detail with every file's URLs, for the head or `?rev=<n>`.

    A trashed item is only returned with `?t=1` (the trash view); otherwise
    it is a 404, indistinguishable from a missing one. A pruned or unknown
    revision is a 404 too.
    """
    params = parse_query(request.scope, (TRASH_FLAG, REVISION_PARAM))
    allow_trashed = flag(params, TRASH_FLAG)
    item, revision = services_of(request).queries.revision(
        item_id, _revision_param(params), allow_trashed=allow_trashed
    )
    return _json(request, _presenter(request, [item]).detail(item, revision), conditional=True)


def _state_change(request: Request, item: Item) -> Response:
    return _json(request, {"item": _presenter(request, [item]).summary(item)})


@router.api_route("/api/folders", methods=["GET", "HEAD"])
def list_folders(request: Request) -> Response:
    """Every folder in name order with its active-item count, plus the unfiled count.

    Read only (C40): folders are organised by Claude through the admin API.
    Answers 304 when `If-None-Match` matches (cheap polling, like `/api/items`).
    """
    parse_query(request.scope, ())
    listing = services_of(request).folders.list(state=ItemState.ACTIVE)
    return _json(
        request,
        {"folders": listing_json(listing), "unfiled_count": listing.unfiled_count},
        conditional=True,
    )


@router.post("/api/items/{item_id}/trash")
def trash_item(request: Request, item_id: ItemIdParam) -> Response:
    """Move an item to the trash (idempotent). CSRF-checked by middleware."""
    parse_query(request.scope, ())
    return _state_change(request, services_of(request).trash.trash(item_id))


@router.post("/api/items/{item_id}/restore")
def restore_item(request: Request, item_id: ItemIdParam) -> Response:
    """Restore an item from the trash (idempotent). CSRF-checked by middleware."""
    parse_query(request.scope, ())
    return _state_change(request, services_of(request).trash.restore(item_id))


@router.post("/api/items/{item_id}/pin")
def pin_item(request: Request, item_id: ItemIdParam) -> Response:
    """Pin an active item (idempotent; trashed → 409). CSRF-checked by middleware."""
    parse_query(request.scope, ())
    return _state_change(request, services_of(request).pins.set_pinned(item_id, pinned=True))


@router.post("/api/items/{item_id}/unpin")
def unpin_item(request: Request, item_id: ItemIdParam) -> Response:
    """Unpin an active item (idempotent; trashed → 409). CSRF-checked by middleware."""
    parse_query(request.scope, ())
    return _state_change(request, services_of(request).pins.set_pinned(item_id, pinned=False))


@router.post("/api/items/{item_id}/revisions/prune")
def prune_revisions(request: Request, item_id: ItemIdParam) -> Response:
    """Permanently delete every version but the current one (ADR 0030, C43).

    ACTIVE items only (trashed → 409). Required `?expected=<n>` (missing → 400):
    the head the owner saw; a newer one → 409, so a version published meanwhile
    is never deleted unseen. Keep is fixed at 1 here. The viewer's blob store is
    read-only: the DB commit happens now, the orphan sweep frees the space
    after its grace period. CSRF-checked by middleware.
    """
    params = parse_query(request.scope, (EXPECTED_PARAM,))
    raw = params.get(EXPECTED_PARAM)
    # Required here (the UI always sends it): no blind permanent delete from the viewer.
    if raw is None or _REV_RE.fullmatch(raw) is None:
        raise ValidationError("invalid expected revision")
    result = services_of(request).history.prune_old(item_id, expected_revision=int(raw))
    return _json(
        request,
        {
            "item": _presenter(request, [result.item]).summary(result.item),
            "revisions_removed": result.revisions_removed,
            "bytes_freed": result.bytes_freed,
        },
    )


def _static(request: Request, name: str) -> Response:
    """Serve one manifest entry; anything not in the manifest is a 404."""
    parse_query(request.scope, ())
    assets: StaticAssets = request.app.state.static_assets
    asset = assets.get(name)
    if asset is None:
        raise NotFoundError("no such asset")
    headers = {"ETag": asset.etag, "Cache-Control": _STATIC_CACHE}
    if if_none_match(request.scope, asset.etag):
        return Response(status_code=304, headers=headers)
    return Response(asset.body, headers={**headers, "Content-Type": asset.content_type})


@router.api_route("/", methods=["GET", "HEAD"])
def index(request: Request) -> Response:
    """The single-page UI."""
    return _static(request, INDEX_FILE)


@router.api_route("/static/{name:path}", methods=["GET", "HEAD"])
def static_file(request: Request, name: str) -> Response:
    """A UI asset, looked up by exact name in the in-memory manifest."""
    return _static(request, name)
