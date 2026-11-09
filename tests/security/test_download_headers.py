"""Security tests: download routes' headers and failure behaviour (docs/security.md C9, C31).

`/d/{id}` (single file or streamed ZIP) and `/d/{id}/1/{relpath}` always send
`Content-Disposition: attachment` with a sanitized RFC 6266 name, only from
the preview origin, never embeddable as a sub-resource. A blob that turns
out not to match its manifest mid-stream **aborts** the response: no clean
end-of-body is ever sent, so a partial/tampered download can't look complete.
"""

from __future__ import annotations

import io
import os
import zipfile
from collections.abc import Iterable
from datetime import datetime
from typing import Any, BinaryIO

import pytest

from preview_dashboard.domain.models import BlobRef
from preview_dashboard.interfaces.viewer.headers import sandbox_csp
from tests.app_support import make_publish
from tests.fakes import InMemoryBlobStore
from tests.viewer_support import (
    DASH_ORIGIN,
    OWNER,
    PREVIEW_HOST,
    StubServices,
    ViewerEnv,
    make_env,
    owner_headers,
)
from tests.viewer_wire_support import (
    connect,
    header,
    read_until_close,
    request_head,
    running_viewer_server,
)

pytestmark = pytest.mark.security


def test_single_file_item_downloads_as_attachment() -> None:
    env = make_env()
    item = env.publish({"report.pdf": b"%PDF-1.7 data"}, title="Report")
    response = env.preview_client().get(f"/d/{item.id}/1", headers=owner_headers())
    assert response.status_code == 200
    assert response.content == b"%PDF-1.7 data"
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == (
        "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
    )
    assert response.headers["accept-ranges"] == "bytes"
    assert response.headers["content-length"] == str(len(b"%PDF-1.7 data"))
    # Attachment → never the PDF exception: full sandbox CSP.
    assert response.headers["content-security-policy"] == sandbox_csp([DASH_ORIGIN])


def test_multi_file_item_downloads_as_zip_with_safe_name() -> None:
    env = make_env()
    title = 'Q3 "résumé"\r\nSet-Cookie: x=1; \u202eevil'
    item = env.publish({"index.html": b"<p>1</p>", "css/a.css": b"p{}"}, title=title)
    response = env.preview_client().get(f"/d/{item.id}/1", headers=owner_headers())
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith('attachment; filename="')
    assert disposition.isascii()
    assert "\r" not in disposition and "\n" not in disposition
    name = disposition.split('filename="', 1)[1].split('"', 1)[0]
    assert name.endswith(".zip") and "/" not in name and "\\" not in name
    assert "set-cookie" not in response.headers
    assert "content-length" not in response.headers  # streamed
    assert response.headers["accept-ranges"] == "none"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert sorted(archive.namelist()) == ["css/a.css", "index.html"]


def test_single_file_of_a_bundle_downloads_as_attachment() -> None:
    env = make_env()
    item = env.publish({"index.html": b"<p>1</p>", "img/logo.svg": b"<svg/>"}, title="B")
    response = env.preview_client().get(f"/d/{item.id}/1/img/logo.svg", headers=owner_headers())
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert response.headers["content-disposition"].startswith('attachment; filename="logo.svg"')


@pytest.mark.parametrize("dest", ["image", "script", "style", "iframe", "video"])
def test_downloads_are_never_embeddable(dest: str) -> None:
    env = make_env()
    single = env.publish({"a.png": b"\x89PNG"}, title="Pic")
    bundle = env.publish({"index.html": b"x", "b.js": b"1"}, title="B")
    for url in (f"/d/{single.id}/1", f"/d/{bundle.id}/1", f"/d/{bundle.id}/1/b.js"):
        response = env.preview_client().get(
            url, headers=owner_headers({"Sec-Fetch-Dest": dest, "Sec-Fetch-Site": "same-site"})
        )
        assert response.status_code == 403, (url, dest)


def test_downloads_allowed_as_top_level_navigation() -> None:
    env = make_env()
    item = env.publish({"index.html": b"x", "b.js": b"1"}, title="B")
    response = env.preview_client().get(
        f"/d/{item.id}/1",
        headers=owner_headers(
            {
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "navigate",
            }
        ),
    )
    assert response.status_code == 200


def test_download_range_and_416() -> None:
    env = make_env()
    item = env.publish({"clip.mp4": bytes(range(200))}, title="Clip")
    client = env.preview_client()
    part = client.get(f"/d/{item.id}/1", headers=owner_headers({"Range": "bytes=10-19"}))
    assert part.status_code == 206
    assert part.content == bytes(range(10, 20))
    assert part.headers["content-range"] == "bytes 10-19/200"
    assert part.headers["content-disposition"].startswith("attachment;")
    for bad in ("bytes=500-", "bytes=0-1,5-6", "items=0-1", "bytes=-0"):
        refused = client.get(f"/d/{item.id}/1", headers=owner_headers({"Range": bad}))
        assert refused.status_code == 416, bad
        assert refused.headers["content-range"] == "bytes */200"


def test_trashed_item_downloads_only_with_trash_flag() -> None:
    env = make_env()
    item = env.publish({"index.html": b"x", "b.js": b"1"}, title="B")
    env.services.trash.trash(item.id)
    client = env.preview_client()
    assert client.get(f"/d/{item.id}/1", headers=owner_headers()).status_code == 404
    assert client.get(f"/d/{item.id}/1/b.js", headers=owner_headers()).status_code == 404
    assert client.get(f"/d/{item.id}/1?t=1", headers=owner_headers()).status_code == 200
    assert client.get(f"/d/{item.id}/latest?t=1", headers=owner_headers()).status_code == 200
    assert client.get(f"/d/{item.id}/1?t=2", headers=owner_headers()).status_code == 400


# --- mid-stream failure aborts the connection --------------------------------------


class CorruptingBlobStore:
    """Serves chosen blobs tampered on disk: same size but flipped bytes (`corrupt`),
    or the right bytes plus one extra trailing byte (`extended`)."""

    def __init__(self, inner: InMemoryBlobStore) -> None:
        self.inner = inner
        self.corrupt: set[str] = set()
        self.extended: set[str] = set()

    def put(self, chunks: Iterable[bytes], max_bytes: int) -> BlobRef:
        return self.inner.put(chunks, max_bytes)

    def open(self, blob_id: str) -> BinaryIO:
        stream = self.inner.open(blob_id)
        if blob_id in self.corrupt:
            data = stream.read()
            return io.BytesIO(bytes(b ^ 0xFF for b in data))
        if blob_id in self.extended:
            return io.BytesIO(stream.read() + b"!")
        return stream

    def delete(self, blob_id: str) -> None:
        self.inner.delete(blob_id)

    def list_ids(self, created_before: datetime | None = None) -> set[str]:
        return self.inner.list_ids(created_before)

    def free_bytes(self) -> int:
        return self.inner.free_bytes()


def _corrupting_env() -> tuple[ViewerEnv, CorruptingBlobStore]:
    blobs = CorruptingBlobStore(InMemoryBlobStore())
    harness = make_publish(
        blobs=blobs, max_file_bytes=1_000_000, max_item_bytes=2_000_000, max_total_bytes=4_000_000
    )
    env = make_env(StubServices(harness.repo, blobs, harness.clock), publisher=harness.service)
    return env, blobs


async def _drive(app: Any, raw_path: str) -> list[dict[str, Any]]:
    """Run one GET like a server with ASGI 2.4 (no disconnect listener) and record sends."""
    messages: list[dict[str, Any]] = []
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": raw_path,
        "raw_path": raw_path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", PREVIEW_HOST.encode()), (b"tailscale-user-login", OWNER.encode())],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8788),
    }
    sent_request = False

    async def receive() -> dict[str, Any]:
        nonlocal sent_request
        if not sent_request:
            sent_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


def _completed(messages: list[dict[str, Any]]) -> bool:
    return any(
        m["type"] == "http.response.body" and not m.get("more_body", False) for m in messages
    )


async def test_zip_failure_mid_stream_aborts_without_clean_end() -> None:
    env, blobs = _corrupting_env()
    first, second = os.urandom(300_000), os.urandom(300_000)
    item = env.publish({"a.bin": first, "b.bin": second}, title="Two")
    blobs.corrupt.add(item.file("b.bin").blob_id)  # type: ignore[union-attr]
    messages = await _drive(env.preview, f"/d/{item.id}/1")
    assert messages[0]["type"] == "http.response.start"
    assert messages[0]["status"] == 200
    body = b"".join(m.get("body", b"") for m in messages[1:])
    assert body  # the archive had started streaming
    assert not _completed(messages)  # ...and was never terminated cleanly


async def test_blob_mismatch_mid_stream_aborts_single_file() -> None:
    env, blobs = _corrupting_env()
    item = env.publish({"a.txt": b"x" * 200_000}, title="One")
    blobs.corrupt.add(item.files[0].blob_id)
    for path in (f"/i/{item.id}/1/a.txt", f"/d/{item.id}/1", f"/d/{item.id}/1/a.txt"):
        messages = await _drive(env.preview, path)
        assert messages[0]["status"] == 200, path
        assert not _completed(messages), path


async def test_healthy_zip_completes_cleanly() -> None:
    env, _ = _corrupting_env()
    item = env.publish({"a.bin": os.urandom(1000), "b.bin": b"b"}, title="Two")
    messages = await _drive(env.preview, f"/d/{item.id}/1")
    assert _completed(messages)
    body = b"".join(m.get("body", b"") for m in messages[1:])
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.read("b.bin") == b"b"


# --- the same over a real uvicorn server: bytes on the wire < Content-Length -------


@pytest.mark.parametrize(
    ("size", "tamper"),
    [
        (0, "extended"),
        (10, "corrupt"),
        (10, "extended"),
        (64 * 1024, "corrupt"),
        (64 * 1024, "extended"),
        (200_000, "corrupt"),
        (200_000, "extended"),
    ],
)
@pytest.mark.parametrize("route", ["i", "d"])
def test_tampered_blob_never_reaches_the_client_complete(
    size: int, tamper: str, route: str
) -> None:
    """Size + digest are checked before the final chunk goes out (real uvicorn, raw socket).

    A blob whose real size differs from the manifest (`extended`: the right
    prefix plus one extra byte) is refused before the headers (→ 500), as
    are empty and single-chunk files that fail the digest; longer corrupt
    ones are cut off with fewer bytes than `Content-Length`. Either way the
    client never holds a complete tampered body.
    """
    env, blobs = _corrupting_env()
    item = env.publish({"a.bin": os.urandom(size)}, title="One")
    getattr(blobs, tamper).add(item.files[0].blob_id)
    path = f"/i/{item.id}/1/a.bin" if route == "i" else f"/d/{item.id}/1/a.bin"
    with running_viewer_server(env.preview) as port, connect(port) as conn:
        conn.sendall(request_head(path, PREVIEW_HOST, {"Connection": "close"}))
        head, body = read_until_close(conn)
    # Size mismatch, or the whole body is one chunk: fails before the head.
    if tamper == "extended" or size <= 64 * 1024:
        assert head.startswith(b"HTTP/1.1 500"), head
        assert b"a.bin" not in head and len(body) < 200
        return
    assert head.startswith(b"HTTP/1.1 200"), head
    assert header(head, "content-length") == str(size)
    assert len(body) < size


@pytest.mark.parametrize("size", [0, 10, 64 * 1024, 200_000])
def test_intact_blob_is_delivered_whole_over_the_wire(size: int) -> None:
    env, _ = _corrupting_env()
    data = os.urandom(size)
    item = env.publish({"a.bin": data}, title="One")
    with running_viewer_server(env.preview) as port, connect(port) as conn:
        conn.sendall(request_head(f"/i/{item.id}/1/a.bin", PREVIEW_HOST, {"Connection": "close"}))
        head, body = read_until_close(conn)
    assert head.startswith(b"HTTP/1.1 200")
    assert body == data
