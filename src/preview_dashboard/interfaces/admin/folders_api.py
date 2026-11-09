"""Admin API folder routes (`/v1/folders`): list, create, rename, delete (ADR 0027).

Claude organises the dashboard through these (admin token only; the viewer
can only read folders, C40). Every route rechecks the token role itself
(`require_admin`, defense in depth next to `BearerAuthMiddleware`, C33).
Bodies are hand-parsed like item edits, names are sanitized and
secret-scanned by `FolderService` (C39), and a folder is deleted only when
no item in any state is filed in it (C41). Moving items is
`POST /v1/items/{id}/move` (`api.py`).
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from preview_dashboard.application.folders import FolderListing
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.folders import Folder, parse_folder_id
from preview_dashboard.domain.models import ItemState
from preview_dashboard.interfaces.admin.api import (
    NO_STORE,
    admin_core,
    read_json_object,
    require_admin,
    run_blocking,
)

router = APIRouter(prefix="/v1")

_NAME_FIELDS: Final = frozenset({"name"})


def folder_json(folder: Folder) -> dict[str, object]:
    """One folder for admin responses (the name is untrusted display text)."""
    return {
        "id": folder.id,
        "name": folder.name,
        "created_at": folder.created_at.isoformat(),
        "updated_at": folder.updated_at.isoformat(),
    }


def listing_json(active: FolderListing, trashed: FolderListing) -> dict[str, object]:
    """Folders in name order with active and trashed item counts, plus unfiled counts.

    `trashed_count` tells Claude why a delete would be refused (a folder
    holding only trashed items is not empty, C41).
    """
    in_trash = {e.folder.id: e.count for e in trashed.folders}
    return {
        "folders": [
            {
                **folder_json(e.folder),
                "count": e.count,
                "trashed_count": in_trash.get(e.folder.id, 0),
            }
            for e in active.folders
        ],
        "unfiled_count": active.unfiled_count,
        "unfiled_trashed_count": trashed.unfiled_count,
    }


def _no_query(request: Request) -> None:
    # One meaning per URL: a stray parameter (e.g. a typo'd filter) is a 400.
    if request.url.query:
        raise ValidationError("this route takes no query parameters")


async def _name_body(request: Request) -> str:
    body = await read_json_object(request)
    if set(body) != _NAME_FIELDS:
        raise ValidationError('body must be exactly {"name": <folder name>}')
    name = body["name"]
    if not isinstance(name, str):
        raise ValidationError("name must be a string")
    return name


@router.get("/folders")
async def list_folders(request: Request) -> JSONResponse:
    """Every folder (name order) with its item counts; no query parameters."""
    require_admin(request)
    _no_query(request)
    folders = admin_core(request).folders

    def run() -> dict[str, object]:
        return listing_json(folders.list(), folders.list(state=ItemState.TRASHED))

    return JSONResponse(await run_blocking(run), headers=NO_STORE)


@router.post("/folders")
async def create_folder(request: Request) -> JSONResponse:
    """Create a folder from `{"name"}` (409 name taken, 413 quota, 422 secret)."""
    require_admin(request)
    name = await _name_body(request)
    folder = await run_blocking(lambda: admin_core(request).folders.create(name))
    return JSONResponse(folder_json(folder), status_code=201, headers=NO_STORE)


@router.patch("/folders/{folder_id}")
async def rename_folder(request: Request, folder_id: str) -> JSONResponse:
    """Rename a folder from `{"name"}` (no-op if unchanged; 404, 409, 422)."""
    require_admin(request)
    parse_folder_id(folder_id)  # before reading the body: a bad id costs nothing
    name = await _name_body(request)
    folder = await run_blocking(lambda: admin_core(request).folders.rename(folder_id, name))
    return JSONResponse(folder_json(folder), headers=NO_STORE)


@router.delete("/folders/{folder_id}")
async def delete_folder(request: Request, folder_id: str) -> JSONResponse:
    """Delete an empty folder (409 while any item, active or trashed, is filed in it)."""
    require_admin(request)
    _no_query(request)
    parse_folder_id(folder_id)
    await run_blocking(lambda: admin_core(request).folders.delete(folder_id))
    return JSONResponse({"id": folder_id, "deleted": True}, headers=NO_STORE)
