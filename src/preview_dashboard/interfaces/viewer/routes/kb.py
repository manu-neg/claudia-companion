"""Dashboard app routes of the knowledge map (C57) and the pending-approvals panel.

GET/HEAD only, no query parameters, except one POST: the owner's Approve
(+ code) / Deny of an approval request, forwarded to the admin, which
decides (F-CL6, ADR 0043). They sit behind the same
middleware stack as every dashboard route (owner identity, Host, fetch
metadata, CSRF for unsafe methods, security headers: C2-C4, C21, C22, C31).
A note is requested by the opaque id its walk assigned, never by a path; the
map is off (404) unless `kb_root` is configured and safe. The preview app
never includes this router.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Path, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from preview_dashboard.application.kb_graph import (
    GraphNode,
    KbGraphService,
    NoteDetail,
    iso_date,
)
from preview_dashboard.application.pending_approvals import PendingApprovals
from preview_dashboard.domain.errors import (
    NotFoundError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.interfaces.viewer.conditional import body_etag, if_none_match
from preview_dashboard.interfaces.viewer.knowledge import Knowledge
from preview_dashboard.interfaces.viewer.query_params import parse_query
from preview_dashboard.wire.viewer_decisions import (
    decision_result_to_json,
    parse_decision_request,
)

logger = logging.getLogger("preview_dashboard.viewer.kb")

router = APIRouter()

NoteIdParam = Annotated[str, Path(max_length=64)]
ApprovalIdParam = Annotated[str, Path(max_length=64)]


def _json(request: Request, payload: object) -> Response:
    """ASCII JSON with an ETag; a matching If-None-Match gets a bare 304 (cheap polling)."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    etag = body_etag(body)
    if if_none_match(request.scope, etag):
        return Response(status_code=304, headers={"ETag": etag})
    return Response(body, media_type="application/json", headers={"ETag": etag})


def _knowledge(request: Request) -> Knowledge | None:
    knowledge: Knowledge | None = getattr(request.app.state, "knowledge", None)
    return knowledge


def _graph_service(request: Request) -> KbGraphService:
    """The map's service, or a 404 when the map is off."""
    knowledge = _knowledge(request)
    if knowledge is None or knowledge.graph is None:
        raise NotFoundError("knowledge map is off")
    return knowledge.graph


def _off_when_unavailable(exc: StorageUnavailableError) -> NotFoundError:
    # An unsafe/missing root turns the map off (fail closed); the reason stays in the log.
    logger.warning("knowledge map off: %s", exc)
    return NotFoundError("knowledge map is off")


def _node_json(node: GraphNode) -> dict[str, object]:
    return {
        "id": node.id,
        "title": node.title,
        "category": node.category,
        "tags": list(node.tags),
        "updated": iso_date(node.updated),
        "recent": node.recent,
        "degree": node.degree,
    }


def _note_json(detail: NoteDetail) -> dict[str, object]:
    return {
        **_node_json(detail.node),
        "body": detail.body,
        "links": [{"target": link.target, "id": link.id} for link in detail.links],
        "backlinks": [{"id": nid, "title": title} for nid, title in detail.backlinks],
    }


def _approvals_json(current: PendingApprovals) -> dict[str, object]:
    return {
        "available": current.available,
        "approvals": [
            {
                "id": entry.id,
                "action_text": entry.action_text,
                "kind": entry.kind,
                "target": entry.target,
                "state": entry.state,
                "expires_at": entry.expires_at.isoformat().replace("+00:00", "Z"),
            }
            for entry in current.approvals
        ],
    }


@router.api_route("/api/kb/graph", methods=["GET", "HEAD"])
def kb_graph(request: Request) -> Response:
    """The whole knowledge map, built from a fresh walk: notes, edges, categories.

    404 when the map is off (no `kb_root`, or the root is missing/unsafe).
    """
    parse_query(request.scope, ())
    service = _graph_service(request)
    try:
        graph = service.graph()
    except StorageUnavailableError as exc:
        raise _off_when_unavailable(exc) from None
    return _json(
        request,
        {
            "nodes": [_node_json(node) for node in graph.nodes],
            "edges": [
                {"source": edge.source, "target": edge.target, "kind": edge.kind}
                for edge in graph.edges
            ],
            "categories": [{"name": name, "count": count} for name, count in graph.categories],
            "skipped": graph.skipped,
            "truncated": graph.truncated,
        },
    )


@router.api_route("/api/kb/notes/{note_id}", methods=["GET", "HEAD"])
def kb_note(request: Request, note_id: NoteIdParam) -> Response:
    """One note by its opaque id (looked up in a fresh walk): body text, links, backlinks.

    400 for a malformed id, 404 for an unknown one or when the map is off.
    """
    parse_query(request.scope, ())
    service = _graph_service(request)
    try:
        detail = service.note(note_id)
    except StorageUnavailableError as exc:
        raise _off_when_unavailable(exc) from None
    return _json(request, _note_json(detail))


@router.api_route("/api/claudia/approvals", methods=["GET", "HEAD"])
def claudia_approvals(request: Request) -> Response:
    """Open approvals from the admin's snapshot, so the owner can check what the phone shows.

    Always 200: `available` false (and no entries) when there is no valid
    snapshot. `decisions` tells the UI whether Approve/Deny work here (F-CL6).
    """
    parse_query(request.scope, ())
    knowledge = _knowledge(request)
    if knowledge is None:
        return _json(request, {"available": False, "approvals": [], "decisions": False})
    payload = _approvals_json(knowledge.approvals.current())
    payload["decisions"] = knowledge.decisions is not None
    return _json(request, payload)


@router.post("/api/claudia/approvals/{approval_id}/decision")
async def claudia_decide(request: Request, approval_id: ApprovalIdParam) -> Response:
    """Forward the owner's Approve (+ code) or Deny to the admin, which decides (F-CL6).

    Behind the full dashboard stack (identity, Host, fetch metadata, CSRF,
    1 KiB body: C2-C4). The viewer only validates the shape and rate-limits;
    the admin re-validates everything. Body `{"decision": "approve", "code":
    "123456"}` or `{"decision": "deny"}`; the code never appears in a URL or
    a log. 404 when decisions are off, 400 malformed, 429 too many clicks,
    503 admin unreachable; otherwise 200 `{"result": ...}`.
    """
    parse_query(request.scope, ())
    knowledge = _knowledge(request)
    if knowledge is None or knowledge.decisions is None:
        raise NotFoundError("dashboard decisions are off")
    decisions = knowledge.decisions
    try:
        body = json.loads(await request.body())
    except (ValueError, RecursionError):
        raise ValidationError("body is not valid JSON") from None
    command = parse_decision_request(approval_id, body)
    result = await run_in_threadpool(decisions.decide, command)
    logger.info("dashboard decision forwarded: %s -> %s", command.decision, result)
    return Response(
        json.dumps(decision_result_to_json(result)).encode("ascii"),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )
