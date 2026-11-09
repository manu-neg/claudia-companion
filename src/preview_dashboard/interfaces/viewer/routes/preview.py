"""Preview app routes: item bytes only (inline, capped text, downloads), no `/api`.

Every route resolves item id + revision + manifest relpath through
`QueryService` (never a filesystem path, docs/security.md I2, C20), takes
the relpath only via `relpath_from_scope`, re-checks the stored media type
against the kind registry (tamper defense, C8) and declares `PreviewHints`
so the security middleware can pick the per-file CSP/CORP/fetch-metadata
verdict (C5, C31). URLs are `/<letter>/<id>/<rev>/<relpath>`, where `<rev>`
is a revision number or `latest` (the head at request time, ADR 0019).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Annotated

from fastapi import APIRouter, Path, Request
from starlette.responses import Response, StreamingResponse

from preview_dashboard.application.archive import download_filename
from preview_dashboard.application.queries import OpenedFile
from preview_dashboard.domain.errors import (
    InvalidPathError,
    NotFoundError,
    UnsupportedContentError,
    ValidationError,
)
from preview_dashboard.domain.models import Item, ItemFile, Revision, validate_revision_number
from preview_dashboard.interfaces.viewer._http import DuplicateHeaderError
from preview_dashboard.interfaces.viewer.conditional import (
    if_none_match,
    if_range_allows,
    single_range_header,
    strong_etag,
)
from preview_dashboard.interfaces.viewer.disposition import DispositionKind, content_disposition
from preview_dashboard.interfaces.viewer.errors import error_response
from preview_dashboard.interfaces.viewer.hints import PreviewHints, set_preview_hints
from preview_dashboard.interfaces.viewer.item_json import TRASH_FLAG
from preview_dashboard.interfaces.viewer.query_params import flag, parse_query
from preview_dashboard.interfaces.viewer.ranges import (
    ByteRange,
    RangeNotSatisfiableError,
    parse_range,
)
from preview_dashboard.interfaces.viewer.relpath_url import relpath_from_scope
from preview_dashboard.interfaces.viewer.renderer_page import RendererPage
from preview_dashboard.interfaces.viewer.request_id import request_id_of
from preview_dashboard.interfaces.viewer.services import options_of, services_of
from preview_dashboard.interfaces.viewer.streaming import (
    BlobStreamResponse,
    StoredBytesMismatchError,
    ZipStreamResponse,
)
from preview_dashboard.kinds.base import ContentKind, KindRegistry, PreviewMode

logger = logging.getLogger("preview_dashboard.viewer")

router = APIRouter()

ItemIdParam = Annotated[str, Path(max_length=64)]
RevParam = Annotated[str, Path(max_length=16)]
OCTET_STREAM = "application/octet-stream"
TEXT_RENDER_TYPE = "text/plain; charset=utf-8"
TRUNCATED_HEADER = "X-PDash-Truncated"
RENDER_PAGE_TYPE = "text/html; charset=utf-8"
LATEST = "latest"
# /i, /t, /r and /d + /<id>/<rev>/<relpath>: three segments before the relpath.
_RELPATH_SEGMENTS = 3
# One spelling per revision: no sign, no leading zero, ASCII digits only.
_REV_RE = re.compile(r"[1-9][0-9]{0,9}")


def parse_revision_segment(segment: str) -> int | None:
    """Parse a URL revision segment: `latest` -> None (the head), `<n>` -> n.

    Raises:
        ValidationError: anything else (`0`, `01`, `+1`, `Latest`, > 2**31-1).
    """
    if segment == LATEST:
        return None
    if _REV_RE.fullmatch(segment) is None:
        raise ValidationError("invalid revision")
    return validate_revision_number(int(segment))


@dataclass(frozen=True, slots=True)
class ServePlan:
    """How one stored file is served.

    Attributes:
        media_type: bare `type/subtype` sent (stored type, or octet-stream
            when it no longer matches the registry).
        content_type: full header value (UTF-8 charset for text types).
        disposition: `inline` or `attachment`.
        hints: what the security middleware needs to know.
    """

    media_type: str
    content_type: str
    disposition: DispositionKind
    hints: PreviewHints


def _kind_of(kinds: KindRegistry, kind_name: str) -> ContentKind | None:
    try:
        return kinds.get(kind_name)
    except UnsupportedContentError:  # kind no longer registered: download only
        return None


def _content_type(media_type: str) -> str:
    # HTML declares its own charset; other text is UTF-8 by convention and
    # an explicit charset stops encoding guessing.
    if media_type.startswith("text/") and media_type != "text/html":
        return f"{media_type}; charset=utf-8"
    if media_type == "application/json":
        return f"{media_type}; charset=utf-8"
    return media_type


def plan_for(
    kinds: KindRegistry,
    item: Item,
    revision: Revision,
    item_file: ItemFile,
    *,
    download: bool,
    rev_segment: str,
) -> ServePlan:
    """Decide Content-Type, disposition and hints for serving `item_file` of `revision`.

    The stored media type is re-derived from the revision's kind at serve
    time; if they differ (tampered row, changed registry, unknown kind) the
    file is served as `application/octet-stream` attachment (docs/security.md
    C8). `rev_segment` (the URL's revision segment) goes into the hints so
    bundle sub-resources are bound to their own item **and** revision.
    """
    kind = _kind_of(kinds, revision.kind)
    expected = kind.media_type(item_file.relpath) if kind is not None else None
    if kind is None or expected != item_file.media_type:
        logger.warning("stored media type does not match registry item=%s", item.id)
        return ServePlan(
            media_type=OCTET_STREAM,
            content_type=OCTET_STREAM,
            disposition="attachment",
            hints=PreviewHints(PreviewMode.DOWNLOAD, item_id=item.id, revision=rev_segment),
        )
    mode = kind.preview_mode
    attachment = download or mode is PreviewMode.DOWNLOAD or expected == OCTET_STREAM
    bundle_sub = (
        not attachment
        and mode is PreviewMode.SANDBOXED
        and item_file.relpath != revision.entry_file
    )
    return ServePlan(
        media_type=expected,
        content_type=_content_type(expected),
        disposition="attachment" if attachment else "inline",
        hints=PreviewHints(
            PreviewMode.DOWNLOAD if attachment else mode,
            bundle_subresource=bundle_sub,
            item_id=item.id,
            revision=rev_segment,
        ),
    )


def _check_raw_prefix(request: Request, prefix: str, item_id: str, rev: str) -> None:
    """The raw path's id and revision segments must be exactly the decoded parameters.

    Raises:
        InvalidPathError: the id or revision arrived percent-encoded or altered.
    """
    raw = request.scope.get("raw_path")
    expected = f"/{prefix}/{item_id}/{rev}".encode("ascii", "replace")
    if not isinstance(raw, bytes) or not (raw == expected or raw.startswith(expected + b"/")):
        raise InvalidPathError("item id and revision must not be encoded")


def _allow_trashed(request: Request) -> bool:
    return flag(parse_query(request.scope, (TRASH_FLAG,)), TRASH_FLAG)


def _open(request: Request, prefix: str, item_id: str, rev: str) -> OpenedFile:
    _check_raw_prefix(request, prefix, item_id, rev)
    number = parse_revision_segment(rev)
    allow_trashed = _allow_trashed(request)
    relpath = relpath_from_scope(request.scope, _RELPATH_SEGMENTS)
    return services_of(request).queries.open_file(
        item_id, relpath, allow_trashed=allow_trashed, revision=number
    )


def _basename(relpath: str) -> str:
    return relpath.rsplit("/", 1)[-1]


def _serve_file(request: Request, opened: OpenedFile, *, download: bool, rev: str) -> Response:
    """Full/range/conditional response for one opened file; owns `opened`.

    `opened` is closed here unless it is handed to the streaming response,
    which then closes it when the body ends, fails or the client leaves.
    """
    try:
        plan = plan_for(
            services_of(request).kinds,
            opened.item,
            opened.revision,
            opened.item_file,
            download=download,
            rev_segment=rev,
        )
        response = _file_response(request, opened, plan)
    except BaseException:
        opened.close()
        raise
    if not isinstance(response, BlobStreamResponse):
        opened.close()
    return response


def _file_response(request: Request, opened: OpenedFile, plan: ServePlan) -> Response:
    set_preview_hints(request.scope, plan.hints)
    item_file = opened.item_file
    etag = strong_etag(item_file.sha256)
    headers = {
        "Content-Type": plan.content_type,
        "Content-Disposition": content_disposition(plan.disposition, _basename(item_file.relpath)),
        "Accept-Ranges": "bytes",
        "ETag": etag,
    }
    # Content-Type on the 304 too: the PDF CSP exception is decided from it.
    if if_none_match(request.scope, etag):
        return Response(status_code=304, headers=headers)
    try:
        byte_range = _requested_range(request, etag, item_file.size)
    except RangeNotSatisfiableError as exc:
        return error_response(
            416, request_id_of(request.scope), [("Content-Range", exc.content_range)]
        )
    _check_stored_size(opened)
    status, start, length = 200, 0, item_file.size
    if byte_range is not None:
        status, start, length = 206, byte_range.start, byte_range.length
        headers["Content-Range"] = byte_range.content_range
    headers["Content-Length"] = str(length)
    if request.method == "HEAD":
        return Response(status_code=status, headers=headers)
    return BlobStreamResponse(
        opened.stream,
        start=start,
        length=length,
        status_code=status,
        headers=headers,
        expected_sha256=item_file.sha256 if byte_range is None else None,
    )


def _check_stored_size(opened: OpenedFile) -> None:
    """Refuse a blob whose real size differs from its manifest, before any header goes out.

    Range responses are not hashed (that would need the whole file), so
    this is their integrity check; full files are also hashed while streaming.

    Raises:
        StoredBytesMismatchError: sizes differ (→ generic 500).
    """
    actual = opened.stream.seek(0, os.SEEK_END)
    opened.stream.seek(0)
    if actual != opened.item_file.size:
        raise StoredBytesMismatchError("blob size does not match its manifest")


def _requested_range(request: Request, etag: str, size: int) -> ByteRange | None:
    """The single validated range to serve, or None for the whole file.

    Raises:
        RangeNotSatisfiableError: malformed, multi-range, duplicated or
            out-of-bounds `Range` (→ 416).
    """
    try:
        header = single_range_header(request.scope)
    except DuplicateHeaderError:
        raise RangeNotSatisfiableError(size) from None
    if header is None or not if_range_allows(request.scope, etag):
        return None
    return parse_range(header, size)


@router.api_route("/i/{item_id}/{rev}/{relpath:path}", methods=["GET", "HEAD"])
def inline_file(request: Request, item_id: ItemIdParam, rev: RevParam) -> Response:
    """One file of an item revision, inline, with its registry type (Range/ETag supported).

    `rev` is a kept revision number or `latest`; `?t=1` is required to
    serve a file of a trashed item (trash view).
    """
    opened = _open(request, "i", item_id, rev)
    return _serve_file(request, opened, download=False, rev=rev)


def trim_partial_utf8(data: bytes) -> bytes:
    """Drop an incomplete UTF-8 sequence cut off at the end of `data`.

    Byte-level only (no decoding of the content): looks at the last lead
    byte and removes it plus its continuation bytes if the sequence is short.
    """
    for back in range(1, min(4, len(data)) + 1):
        byte = data[-back]
        if byte & 0xC0 != 0x80:  # not a continuation byte: a lead or ASCII byte
            need = (
                1 if byte < 0x80 else 2 if byte >> 5 == 0b110 else 3 if byte >> 4 == 0b1110 else 4
            )
            return data if back >= need else data[:-back]
    return data


@dataclass(frozen=True, slots=True)
class CappedText:
    """The first `render_cap_bytes` of a TEXT-kind file.

    Attributes:
        item: the item.
        item_file: the file.
        kind: the revision's (render-capped) kind.
        data: the bytes, cut on a UTF-8 boundary when truncated (None when
            only headers are needed: a 304).
        truncated: the file is longer than the cap.
        etag: strong ETag of the capped bytes.
    """

    item: Item
    item_file: ItemFile
    kind: ContentKind
    data: bytes | None
    truncated: bool
    etag: str


def _read_capped(
    request: Request, prefix: str, item_id: str, rev: str, etag_suffix: str = ""
) -> CappedText:
    """Open a render-capped file and read at most `render_cap_bytes` of it.

    Declares TEXT hints for the security middleware. Skips the read when
    `If-None-Match` already matches (`data` is None then). A file that fits
    under the cap is checked against its manifest size **and** SHA-256
    (a truncated one can only be size-checked without reading it all).

    Raises:
        NotFoundError: unknown item/revision/file, trashed without `?t=1`,
            or the kind is not render-capped.
        StoredBytesMismatchError: the blob doesn't match its manifest.
    """
    services, options = services_of(request), options_of(request)
    with _open(request, prefix, item_id, rev) as opened:
        item, item_file = opened.item, opened.item_file
        kind = _kind_of(services.kinds, opened.revision.kind)
        if kind is None or not kind.render_capped:
            raise NotFoundError("not a text item")
        cap = options.render_cap_bytes
        set_preview_hints(
            request.scope, PreviewHints(kind.preview_mode, item_id=item.id, revision=rev)
        )
        etag = strong_etag(f"{item_file.sha256}-t{cap}{etag_suffix}")
        truncated = item_file.size > cap
        if if_none_match(request.scope, etag):
            return CappedText(item, item_file, kind, None, truncated, etag)
        _check_stored_size(opened)
        data = opened.stream.read(min(item_file.size, cap))
    if truncated:
        data = trim_partial_utf8(data)
    elif len(data) != item_file.size or hashlib.sha256(data).hexdigest() != item_file.sha256:
        raise StoredBytesMismatchError("blob does not match its manifest")
    return CappedText(item, item_file, kind, data, truncated, etag)


@router.api_route("/t/{item_id}/{rev}/{relpath:path}", methods=["GET", "HEAD"])
def render_text(request: Request, item_id: ItemIdParam, rev: RevParam) -> Response:
    """A TEXT-kind file as `text/plain; charset=utf-8`, cut at `render_cap_bytes`.

    Only for render-capped kinds (else 404); `X-PDash-Truncated: 1` when cut.
    Never served with the file's original type.
    """
    capped = _read_capped(request, "t", item_id, rev)
    headers = {
        "Content-Type": TEXT_RENDER_TYPE,
        "Content-Disposition": content_disposition("inline", _basename(capped.item_file.relpath)),
        "ETag": capped.etag,
    }
    if capped.truncated:
        headers[TRUNCATED_HEADER] = "1"
    if capped.data is None:
        return Response(status_code=304, headers=headers)
    if request.method == "HEAD":
        return Response(
            status_code=200, headers={**headers, "Content-Length": str(len(capped.data))}
        )
    return Response(capped.data, status_code=200, headers=headers)


@router.api_route("/r/{item_id}/{rev}/{relpath:path}", methods=["GET", "HEAD"])
def render_page(request: Request, item_id: ItemIdParam, rev: RevParam) -> Response:
    """An HTML page that renders a TEXT-kind file inside the sandboxed preview origin.

    Same rules as `/t` (render-capped kinds only, `?t=1` for trashed items,
    capped at `render_cap_bytes`). The text is embedded as escaped JSON and
    rendered client-side by the inlined renderer (see `renderer_page.py`);
    the security middleware applies the full sandbox CSP (C5).
    """
    page: RendererPage = request.app.state.renderer_page
    capped = _read_capped(request, "r", item_id, rev, etag_suffix=f"-r{page.version[:16]}")
    headers = {"Content-Type": RENDER_PAGE_TYPE, "ETag": capped.etag}
    if capped.truncated:
        headers[TRUNCATED_HEADER] = "1"
    if capped.data is None:
        return Response(status_code=304, headers=headers)
    relpath = capped.item_file.relpath
    body = page.render(
        renderer=capped.kind.renderer,
        text=capped.data.decode("utf-8", errors="replace"),
        meta={
            "filename": _basename(relpath),
            "extension": PurePosixPath(relpath).suffix.lower(),
            "truncated": capped.truncated,
            "shown_bytes": len(capped.data),
            "size": capped.item_file.size,
        },
    )
    if request.method == "HEAD":
        return Response(status_code=200, headers={**headers, "Content-Length": str(len(body))})
    return Response(body, status_code=200, headers=headers)


async def _no_body() -> AsyncIterator[bytes]:
    return
    yield b""  # pragma: no cover - makes this an async generator


@router.api_route("/d/{item_id}/{rev}", methods=["GET", "HEAD"])
def download_item(request: Request, item_id: ItemIdParam, rev: RevParam) -> Response:
    """Download a whole revision: its file if single-file, else a streamed ZIP.

    A ZIP failure after the headers went out aborts the connection (no
    clean end of body), so a partial archive never looks complete.
    """
    _check_raw_prefix(request, "d", item_id, rev)
    number = parse_revision_segment(rev)
    allow_trashed = _allow_trashed(request)
    services = services_of(request)
    item, revision = services.queries.revision(item_id, number, allow_trashed=allow_trashed)
    if len(revision.files) == 1:
        opened = services.queries.open_file(
            item_id,
            revision.files[0].relpath,
            allow_trashed=allow_trashed,
            revision=revision.number,
        )
        return _serve_file(request, opened, download=True, rev=rev)
    set_preview_hints(
        request.scope, PreviewHints(PreviewMode.DOWNLOAD, item_id=item.id, revision=rev)
    )
    archive = services.archive.stream_zip(
        item_id, allow_trashed=allow_trashed, revision=revision.number
    )
    # Name the version once an item has more than one, so downloads don't collide.
    name = download_filename(item, revision.number if item.revision > 1 else None)
    headers = {
        "Content-Type": "application/zip",
        "Content-Disposition": content_disposition("attachment", name),
        "Accept-Ranges": "none",
    }
    if request.method == "HEAD":
        archive.close()
        return StreamingResponse(_no_body(), headers=headers)
    return ZipStreamResponse(archive, headers=headers)


@router.api_route("/d/{item_id}/{rev}/{relpath:path}", methods=["GET", "HEAD"])
def download_file(request: Request, item_id: ItemIdParam, rev: RevParam) -> Response:
    """Download one file of an item revision as an attachment (Range supported)."""
    opened = _open(request, "d", item_id, rev)
    return _serve_file(request, opened, download=True, rev=rev)
