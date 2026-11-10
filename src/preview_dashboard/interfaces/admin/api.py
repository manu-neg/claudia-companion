"""Admin API item routes (`/v1/...`): publish, revise, list, get, edit, trash, restore, move, kinds.

Thin translation layer: parse and bound the HTTP input, call one
application service (off the event loop), serialize the result. Inputs are
parsed by hand (not FastAPI models) so validation errors never echo input.
There is deliberately no item DELETE route: permanent deletion is the purge
job's, plus the explicit prune / empty-trash routes of `cleanup_api.py`
(ADR 0030, C43). Every item response carries a `viewer_url` and
its `folder` (ADR 0027). `require_admin` is the shared per-route defense
in depth against the admin/notifier token roles (C33), reused by
`folders_api.py` and `questions_api.py`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from typing import Final

import anyio.to_thread
from fastapi import APIRouter, Request
from starlette.requests import ClientDisconnect
from starlette.responses import JSONResponse

from preview_dashboard.bootstrap import AdminCore
from preview_dashboard.domain.errors import LimitExceededError, ValidationError
from preview_dashboard.domain.folders import FolderId, Unfiled, parse_folder_filter
from preview_dashboard.domain.models import Item, ItemFile, ItemState, parse_item_id
from preview_dashboard.domain.query import ItemQuery, Page
from preview_dashboard.interfaces.admin.auth import ADMIN_ROLE, role_of
from preview_dashboard.interfaces.admin.errors import (
    ClientDisconnectedError,
    ForbiddenError,
    RequestTimeoutError,
    UnsupportedMediaTypeError,
)
from preview_dashboard.interfaces.admin.multipart import (
    PublishFormLimits,
    publish_multipart,
    revision_form,
    stream_form,
)
from preview_dashboard.interfaces.folder_refs import FolderNames, folder_names, folder_ref

router = APIRouter(prefix="/v1")

MAX_JSON_BODY_BYTES: Final = 64 * 1024
_LIST_PARAMS: Final = frozenset({"kind", "state", "limit", "cursor", "folder"})
_PATCH_FIELDS: Final = frozenset({"title", "description", "pinned"})
_MOVE_FIELDS: Final = frozenset({"folder_id"})
# ASCII digits only: str.isdigit()/int() also accept "²" or "٣".
_LIMIT_RE: Final = re.compile(r"[0-9]{1,4}")
NO_STORE: Final = {"Cache-Control": "no-store"}


def admin_core(request: Request) -> AdminCore:
    """The admin core the app was built with (`build_admin_app`)."""
    core: AdminCore = request.app.state.core
    return core


def require_admin(request: Request) -> None:
    """Defense in depth next to `BearerAuthMiddleware`: only the admin token gets here.

    Shared by every route that needs it (`folders_api.py`, `questions_api.py`,
    and `move_item` below); called first, before any other request access.

    Raises:
        ForbiddenError: another (or no) token role.
    """
    if role_of(request.scope) != ADMIN_ROLE:
        raise ForbiddenError("this route needs the admin token")


def viewer_url(viewer_base: str | None, item: Item) -> str | None:
    """Return the owner-facing link for `item` (dashboard hash route), if configured."""
    return None if viewer_base is None else f"{viewer_base}/#/item/{item.id}"


def _file_json(f: ItemFile) -> dict[str, object]:
    return {"relpath": f.relpath, "size": f.size, "sha256": f.sha256, "media_type": f.media_type}


def item_json(item: Item, viewer_base: str | None, folders: FolderNames) -> dict[str, object]:
    """Serialize an item for admin responses (no blob ids: storage keys stay internal).

    `files`/`kind`/`entry_file`/`total_size` describe the head revision;
    `revisions` lists every kept revision, newest first (without files);
    `stored_size` is what the item occupies across all of them (quota).
    `folder` is `{"id", "name"}` resolved from `folders` (`folder_refs`), or null.
    """
    return {
        "id": item.id,
        "title": item.title,
        "description": item.description,
        "kind": item.kind,
        "state": item.state.value,
        "pinned": item.pinned,
        "created_at": item.created_at.isoformat(),
        "updated_at": item.updated_at.isoformat(),
        "trashed_at": None if item.trashed_at is None else item.trashed_at.isoformat(),
        "entry_file": item.entry_file,
        "total_size": item.total_size,
        "files": [_file_json(f) for f in item.files],
        "revision": item.revision,
        "revision_at": item.head.created_at.isoformat(),
        "stored_size": item.stored_size,
        "revisions": [
            {
                "number": r.number,
                "created_at": r.created_at.isoformat(),
                "kind": r.kind,
                "entry_file": r.entry_file,
                "file_count": len(r.files),
                "total_size": r.total_size,
            }
            for r in reversed(item.revisions)
        ],
        "folder": folder_ref(item, folders),
        "viewer_url": viewer_url(viewer_base, item),
    }


async def items_json(request: Request, items: Sequence[Item]) -> list[dict[str, object]]:
    """Serialize `items`, resolving their folders with one folder read (off the loop)."""
    lookup = admin_core(request).folders
    names = await run_blocking(lambda: folder_names(lookup, items))
    base = request.app.state.viewer_base
    return [item_json(item, base, names) for item in items]


async def _respond(request: Request, item: Item, status: int = 200) -> JSONResponse:
    (body,) = await items_json(request, [item])
    return JSONResponse(body, status_code=status, headers=NO_STORE)


async def run_blocking[T](func: Callable[[], T]) -> T:
    """Run a blocking service call in the threadpool (SQLite/filesystem I/O off the loop)."""
    return await anyio.to_thread.run_sync(func)


async def read_json_object(
    request: Request, *, max_bytes: int = MAX_JSON_BODY_BYTES
) -> dict[str, object]:
    """Read a bounded `application/json` body that must be a JSON object.

    `max_bytes` is raised only by the voice route (base64 audio, C56) and the
    notifier media route (base64 owner photo/voice note, C61).
    """
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/json":
        raise UnsupportedMediaTypeError("expected application/json")
    body = bytearray()
    try:
        with anyio.fail_after(30):
            async for chunk in request.stream():
                body += chunk
                if len(body) > max_bytes:
                    raise LimitExceededError("request body too large")
    except TimeoutError:
        raise RequestTimeoutError("request body stalled") from None
    except ClientDisconnect:
        raise ClientDisconnectedError("client disconnected before the body was complete") from None
    try:
        parsed = json.loads(bytes(body))
    except (ValueError, RecursionError):  # RecursionError: absurdly deep nesting
        raise ValidationError("body is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise ValidationError("body must be a JSON object")
    return parsed


def _parse_list_query(request: Request) -> tuple[ItemQuery, FolderId | None]:
    """The listing query, plus the folder id that must exist (None: no such check)."""
    params = request.query_params
    keys = [key for key, _ in params.multi_items()]
    if len(keys) != len(set(keys)) or not set(keys) <= _LIST_PARAMS:
        raise ValidationError(f"allowed query parameters: {', '.join(sorted(_LIST_PARAMS))}")
    state_raw = params.get("state", ItemState.ACTIVE.value)
    try:
        state = ItemState(state_raw)
    except ValueError:
        raise ValidationError("state must be 'active' or 'trashed'") from None
    kwargs: dict[str, object] = {"state": state}
    if "limit" in params:
        raw = params["limit"]
        if _LIMIT_RE.fullmatch(raw) is None:
            raise ValidationError("limit must be a positive integer")
        kwargs["limit"] = int(raw)
    if params.get("kind"):
        kwargs["kind"] = params["kind"]
    if params.get("cursor"):
        kwargs["cursor"] = params["cursor"]
    must_exist: FolderId | None = None
    if "folder" in params:
        # A folder id or the literal `unfiled`, else 400 (empty is not "all").
        folder = parse_folder_filter(params["folder"])
        kwargs["folder"] = folder
        must_exist = None if isinstance(folder, Unfiled) else folder
    query = ItemQuery(**kwargs)  # type: ignore[arg-type]  # values checked above / by ItemQuery
    return query, must_exist


@router.get("/health")
async def health() -> JSONResponse:
    """Liveness check (still requires the bearer token, like every route)."""
    return JSONResponse({"status": "ok"}, headers=NO_STORE)


@router.get("/kinds")
async def kinds(request: Request) -> JSONResponse:
    """The content-kind registry (same data the viewer serves at `/api/kinds`)."""
    return JSONResponse({"kinds": list(admin_core(request).kinds.describe())}, headers=NO_STORE)


@router.post("/items")
async def publish_item(request: Request) -> JSONResponse:
    """Publish a new item from a streamed multipart body (see docs/api.md)."""
    core = admin_core(request)
    limits: PublishFormLimits = request.app.state.publish_limits
    item = await publish_multipart(request, limits=limits, publish=core.publish.publish)
    return await _respond(request, item, status=201)


@router.post("/items/{item_id}/revisions")
async def publish_revision(request: Request, item_id: str) -> JSONResponse:
    """Publish new content for an existing item as its new head revision (see docs/api.md).

    Same manifest-first streamed multipart as `POST /v1/items`, with fields
    `kind_hint`, `expected_revision` and `manifest`. The id is checked
    before the body is read, so a bad id costs no upload.
    """
    parse_item_id(item_id)
    core = admin_core(request)
    limits: PublishFormLimits = request.app.state.publish_limits
    item = await stream_form(
        request, limits=limits, spec=revision_form(item_id), run=core.publish.publish_revision
    )
    return await _respond(request, item, status=201)


@router.get("/items")
async def list_items(request: Request) -> JSONResponse:
    """One page of items (pinned first, newest first), filtered by kind/state/folder.

    `folder` is a folder id or `unfiled`; an unknown folder id is a 404.
    """
    query, must_exist = _parse_list_query(request)
    core = admin_core(request)

    def run() -> Page[Item]:
        if must_exist is not None:
            # The repository returns an empty page for an unknown folder;
            # the contract is a 404 (NotFoundError), as on the viewer.
            core.folders.get(must_exist)
        return core.queries.list(query)

    page = await run_blocking(run)
    return JSONResponse(
        {"items": await items_json(request, page.items), "next_cursor": page.next_cursor},
        headers=NO_STORE,
    )


@router.get("/items/{item_id}")
async def get_item(request: Request, item_id: str) -> JSONResponse:
    """One item, in any state."""
    item = await run_blocking(lambda: admin_core(request).queries.get(item_id))
    return await _respond(request, item)


@router.patch("/items/{item_id}")
async def update_item(request: Request, item_id: str) -> JSONResponse:
    """Edit title/description/pinned of an active item (edited text is secret-scanned)."""
    body = await read_json_object(request)
    if not set(body) <= _PATCH_FIELDS:
        raise ValidationError(f"allowed fields: {', '.join(sorted(_PATCH_FIELDS))}")
    title = body.get("title")
    description = body.get("description")
    pinned = body.get("pinned")
    if title is not None and not isinstance(title, str):
        raise ValidationError("title must be a string")
    if description is not None and not isinstance(description, str):
        raise ValidationError("description must be a string")
    if pinned is not None and not isinstance(pinned, bool):
        raise ValidationError("pinned must be a boolean")
    item = await run_blocking(
        lambda: admin_core(request).lifecycle.update(
            item_id, title=title, description=description, pinned=pinned
        )
    )
    return await _respond(request, item)


@router.post("/items/{item_id}/trash")
async def trash_item(request: Request, item_id: str) -> JSONResponse:
    """Move an item to the trash (idempotent). It is purged after the retention period."""
    item = await run_blocking(lambda: admin_core(request).lifecycle.trash(item_id))
    return await _respond(request, item)


@router.post("/items/{item_id}/restore")
async def restore_item(request: Request, item_id: str) -> JSONResponse:
    """Restore an item from the trash (idempotent)."""
    item = await run_blocking(lambda: admin_core(request).lifecycle.restore(item_id))
    return await _respond(request, item)


@router.post("/items/{item_id}/move")
async def move_item(request: Request, item_id: str) -> JSONResponse:
    """File an item into a folder or unfile it (`{"folder_id": <id> | null}`), in any state.

    Idempotent (moving to the current folder changes nothing). Unknown item
    or folder → 404 (the folder is checked atomically with the save, C41).
    """
    require_admin(request)
    parse_item_id(item_id)
    body = await read_json_object(request)
    if set(body) != _MOVE_FIELDS:
        raise ValidationError('body must be exactly {"folder_id": <folder id> | null}')
    target = body["folder_id"]
    if target is not None and not isinstance(target, str):
        raise ValidationError("folder_id must be a string or null")
    item = await run_blocking(lambda: admin_core(request).folders.move(item_id, target))
    return await _respond(request, item)
