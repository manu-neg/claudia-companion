"""Admin API permanent-delete routes (ADR 0030, docs/security.md C43).

`POST /v1/items/{id}/revisions/prune` and `POST /v1/trash/empty`; admin
token only, each route re-checks the role first (`require_admin`, C33).
"""

from __future__ import annotations

from typing import Final

from fastapi import APIRouter, Request
from starlette.responses import JSONResponse

from preview_dashboard.application import PruneResult, PurgeReport
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import parse_item_id
from preview_dashboard.interfaces.admin.api import (
    NO_STORE,
    admin_core,
    items_json,
    read_json_object,
    require_admin,
    run_blocking,
)

router = APIRouter(prefix="/v1")

_PRUNE_FIELDS: Final = frozenset({"keep", "expected_revision"})


def _optional_int(body: dict[str, object], key: str) -> int | None:
    """An int field or None (absent/null); bools and other types are 400s."""
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{key} must be an integer")
    return value


@router.post("/items/{item_id}/revisions/prune")
async def prune_revisions(request: Request, item_id: str) -> JSONResponse:
    """Permanently delete an active item's old revisions, keeping the newest `keep`.

    Body: `{"keep"?: 1..20 (default 1, head included), "expected_revision"?: int}`.
    Returns `{"item", "revisions_removed", "bytes_freed"}`; nothing to prune
    is a 200 with zero counts. Trashed → 409 `invalid_state`; a stale
    `expected_revision` → 409 `conflict`.
    """
    require_admin(request)
    parse_item_id(item_id)  # before the body: a bad id costs nothing
    body = await read_json_object(request)
    if not set(body) <= _PRUNE_FIELDS:
        raise ValidationError(f"allowed fields: {', '.join(sorted(_PRUNE_FIELDS))}")
    keep = _optional_int(body, "keep")
    expected = _optional_int(body, "expected_revision")
    history = admin_core(request).history

    def run() -> PruneResult:
        return history.prune_revisions(
            item_id, keep=1 if keep is None else keep, expected_revision=expected
        )

    result = await run_blocking(run)
    (item,) = await items_json(request, [result.item])
    return JSONResponse(
        {
            "item": item,
            "revisions_removed": result.revisions_removed,
            "bytes_freed": result.bytes_freed,
        },
        headers=NO_STORE,
    )


@router.post("/trash/empty")
async def empty_trash(request: Request) -> JSONResponse:
    """Permanently delete every trashed item now: `{"items_purged", "blobs_deleted"}`.

    An item restored while this runs is kept (atomic per-item delete).
    """
    require_admin(request)
    trash_bin = admin_core(request).trash_bin
    report: PurgeReport = await run_blocking(trash_bin.empty)
    return JSONResponse(
        {"items_purged": report.items_purged, "blobs_deleted": report.blobs_deleted},
        headers=NO_STORE,
    )
