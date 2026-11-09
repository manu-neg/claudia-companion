"""Integration tests: viewer routes over the real SQLite repository and FsBlobStore.

Covers the owner's flows end to end through both apps (full middleware
stack): feed polling with ETag/304, pagination, trash/restore (idempotent,
trash view, purge date, trashed bytes only with `?t=1`), pin/unpin
(idempotent, pinned first, trashed items refused), byte ranges for
video, the TEXT render cap, and a ZIP download round trip.
"""

from __future__ import annotations

import functools
import io
import os
import zipfile
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore
from preview_dashboard.adapters.sqlite import SqliteItemRepository, connect, default_db_path
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.domain.models import Item
from tests.app_support import make_publish
from tests.viewer_support import (
    PREVIEW_ORIGIN,
    StubServices,
    ViewerEnv,
    csrf_headers,
    make_env,
    owner_headers,
)

pytestmark = pytest.mark.integration

RENDER_CAP = 1000


@pytest.fixture
def env(tmp_path: Path) -> Iterator[ViewerEnv]:
    data = tmp_path / "data"
    data.mkdir()
    factory = functools.partial(connect, default_db_path(data))
    factory().close()
    repo = SqliteItemRepository(factory)
    with FsBlobStore(data, ids=UlidGenerator(), clock=SystemClock()) as store:
        harness = make_publish(
            repo=repo,
            blobs=store,
            max_file_bytes=4_000_000,
            max_item_bytes=8_000_000,
            max_total_bytes=64_000_000,
            max_items=100,
        )
        services = StubServices(repo, store, harness.clock)
        yield make_env(services, publisher=harness.service, render_cap_bytes=RENDER_CAP)


def _feed(env: ViewerEnv, **params: str) -> Any:
    return env.dash_client().get("/api/items", params=params, headers=owner_headers())


def test_feed_polling_etag_and_304(env: ViewerEnv) -> None:
    env.publish({"a.txt": b"one"}, title="One")
    first = _feed(env)
    assert first.status_code == 200
    etag = first.headers["etag"]
    assert first.headers["cache-control"] == "no-store"
    again = env.dash_client().get("/api/items", headers=owner_headers({"If-None-Match": etag}))
    assert again.status_code == 304
    assert again.content == b""
    assert again.headers["etag"] == etag
    env.publish({"b.txt": b"two"}, title="Two")
    changed = env.dash_client().get("/api/items", headers=owner_headers({"If-None-Match": etag}))
    assert changed.status_code == 200
    assert changed.headers["etag"] != etag
    assert [i["title"] for i in changed.json()["items"]] == ["Two", "One"]


def test_feed_item_shape_and_urls(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"<p>x</p>", "sub dir/é.css": b"p{}"}, title="Site")
    summary = _feed(env).json()["items"][0]
    assert summary["id"] == item.id
    assert summary["kind"] == "html"
    assert summary["preview_mode"] == "sandboxed"
    assert summary["state"] == "active"
    assert summary["file_count"] == 2
    assert summary["preview_url"] == f"{PREVIEW_ORIGIN}/i/{item.id}/1/index.html"
    assert summary["download_url"] == f"{PREVIEW_ORIGIN}/d/{item.id}/1"
    assert summary["render_url"] is None
    assert summary["created_at"].endswith("Z")
    detail = env.dash_client().get(f"/api/items/{item.id}", headers=owner_headers()).json()
    css = next(f for f in detail["files"] if f["relpath"] == "sub dir/é.css")
    assert css["preview_url"] == f"{PREVIEW_ORIGIN}/i/{item.id}/1/sub%20dir/%C3%A9.css"
    assert css["media_type"] == "text/css"
    # The encoded URL is exactly what the preview app decodes back.
    got = env.preview_client().get(css["preview_url"], headers=owner_headers())
    assert got.status_code == 200
    assert got.content == b"p{}"


def test_pagination_with_cursor(env: ViewerEnv) -> None:
    for n in range(5):
        env.publish({f"f{n}.txt": b"x"}, title=f"T{n}")
        env.services.clock.advance(timedelta(seconds=1))
    first = _feed(env, limit="2").json()
    assert len(first["items"]) == 2
    second = _feed(env, limit="2", cursor=first["next_cursor"]).json()
    third = _feed(env, limit="2", cursor=second["next_cursor"]).json()
    titles = [i["title"] for page in (first, second, third) for i in page["items"]]
    assert titles == ["T4", "T3", "T2", "T1", "T0"]
    assert third["next_cursor"] is None


@pytest.mark.parametrize(
    "query",
    [
        {"limit": "0"},
        {"limit": "201"},
        {"limit": "-1"},
        {"limit": "1e2"},
        {"state": "purged"},
        {"kind": "BAD"},
        {"kind": "html,"},
        {"kind": "html,BAD"},
        {"kind": ",".join(f"k{n}" for n in range(9))},
        {"cursor": "garbage"},
        {"bogus": "1"},
    ],
)
def test_bad_listing_queries_are_400(env: ViewerEnv, query: dict[str, str]) -> None:
    response = _feed(env, **query)
    assert response.status_code == 400
    assert set(response.json()) == {"error", "request_id"}


def test_feed_filters_by_several_kinds(env: ViewerEnv) -> None:
    env.publish({"index.html": b"<p>x</p>"}, title="Page")
    env.services.clock.advance(timedelta(seconds=1))
    env.publish({"notes.txt": b"x"}, title="Notes")
    env.services.clock.advance(timedelta(seconds=1))
    env.publish({"readme.md": b"# x"}, title="Readme")
    both = _feed(env, kind="html,markdown")
    assert both.status_code == 200
    assert [i["title"] for i in both.json()["items"]] == ["Readme", "Page"]
    # Order and repeats don't change the result (the query is canonical).
    same = _feed(env, kind="markdown,html,html")
    assert same.headers["etag"] == both.headers["etag"]
    assert [i["title"] for i in _feed(env, kind="text").json()["items"]] == ["Notes"]
    assert len(_feed(env, kind="").json()["items"]) == 3  # empty = all kinds
    # Paging across mixed kinds: no gaps, no repeats.
    first = _feed(env, kind="html,markdown", limit="1").json()
    second = _feed(env, kind="html,markdown", limit="1", cursor=first["next_cursor"]).json()
    assert [i["title"] for i in first["items"] + second["items"]] == ["Readme", "Page"]
    assert second["next_cursor"] is None


def test_duplicate_query_params_are_400(env: ViewerEnv) -> None:
    response = env.dash_client().get(
        "/api/items?state=active&state=trashed", headers=owner_headers()
    )
    assert response.status_code == 400


def test_trash_restore_flow(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"<p>x</p>", "a.css": b"p{}"}, title="Site")
    dash, prev = env.dash_client(), env.preview_client()

    trashed = dash.post(f"/api/items/{item.id}/trash", headers=csrf_headers(), content=b"{}")
    assert trashed.status_code == 200
    body = trashed.json()["item"]
    assert body["state"] == "trashed"
    trashed_at = datetime.fromisoformat(body["trashed_at"])
    purge_at = datetime.fromisoformat(body["purge_at"])
    assert purge_at - trashed_at == timedelta(days=14)
    # Trashed URLs carry the explicit trash flag.
    assert body["preview_url"].endswith("/index.html?t=1")
    assert body["download_url"].endswith("?t=1")

    # Idempotent: a second click is a no-op, not an error.
    twice = dash.post(f"/api/items/{item.id}/trash", headers=csrf_headers())
    assert twice.status_code == 200
    assert twice.json()["item"]["trashed_at"] == body["trashed_at"]

    assert _feed(env).json()["items"] == []
    assert [i["id"] for i in _feed(env, state="trashed").json()["items"]] == [item.id]
    assert dash.get(f"/api/items/{item.id}", headers=owner_headers()).status_code == 404
    assert dash.get(f"/api/items/{item.id}?t=1", headers=owner_headers()).status_code == 200
    assert prev.get(f"/i/{item.id}/1/index.html", headers=owner_headers()).status_code == 404
    assert prev.get(f"/i/{item.id}/1/index.html?t=1", headers=owner_headers()).status_code == 200

    restored = dash.post(f"/api/items/{item.id}/restore", headers=csrf_headers(), content=b"{}")
    assert restored.status_code == 200
    assert restored.json()["item"]["state"] == "active"
    assert restored.json()["item"]["purge_at"] is None
    assert dash.post(f"/api/items/{item.id}/restore", headers=csrf_headers()).status_code == 200
    assert [i["id"] for i in _feed(env).json()["items"]] == [item.id]
    assert prev.get(f"/i/{item.id}/1/index.html", headers=owner_headers()).status_code == 200


def test_trash_errors(env: ViewerEnv) -> None:
    dash = env.dash_client()
    assert (
        dash.post("/api/items/7ZZZZZZZZZZZZZZZZZZZZZZZZZ/trash", headers=csrf_headers()).status_code
        == 404
    )
    assert dash.post("/api/items/not-an-id/trash", headers=csrf_headers()).status_code == 400
    # Without the CSRF headers nothing changes.
    item = env.publish({"a.txt": b"x"}, title="A")
    assert dash.post(f"/api/items/{item.id}/trash", headers=owner_headers()).status_code == 403
    assert _feed(env).json()["items"][0]["state"] == "active"


def test_pin_unpin_flow(env: ViewerEnv) -> None:
    older = env.publish({"a.txt": b"a"}, title="Older")
    env.services.clock.advance(timedelta(minutes=1))
    newer = env.publish({"b.txt": b"b"}, title="Newer")
    dash = env.dash_client()
    assert [i["id"] for i in _feed(env).json()["items"]] == [newer.id, older.id]

    pinned = dash.post(f"/api/items/{older.id}/pin", headers=csrf_headers(), content=b"{}")
    assert pinned.status_code == 200
    body = pinned.json()["item"]
    assert body["id"] == older.id
    assert body["pinned"] is True
    assert body["state"] == "active"
    # Same response shape as trash/restore: the full summary.
    trash_shape = dash.post(f"/api/items/{newer.id}/restore", headers=csrf_headers()).json()
    assert set(body) == set(trash_shape["item"])
    # Pinned first; the pin survives a re-read from SQLite.
    assert [i["id"] for i in _feed(env).json()["items"]] == [older.id, newer.id]
    detail = dash.get(f"/api/items/{older.id}", headers=owner_headers()).json()
    assert detail["pinned"] is True

    # Idempotent: a second pin is a no-op (no write, `updated_at` unchanged).
    twice = dash.post(f"/api/items/{older.id}/pin", headers=csrf_headers())
    assert twice.status_code == 200
    assert twice.json()["item"] == body

    unpinned = dash.post(f"/api/items/{older.id}/unpin", headers=csrf_headers(), content=b"{}")
    assert unpinned.status_code == 200
    assert unpinned.json()["item"]["pinned"] is False
    assert datetime.fromisoformat(unpinned.json()["item"]["updated_at"]) > datetime.fromisoformat(
        body["updated_at"]
    )
    again = dash.post(f"/api/items/{older.id}/unpin", headers=csrf_headers())
    assert again.status_code == 200
    assert again.json()["item"] == unpinned.json()["item"]
    assert [i["id"] for i in _feed(env).json()["items"]] == [newer.id, older.id]


@pytest.mark.parametrize("action", ["pin", "unpin"])
def test_pin_refuses_trashed_items(env: ViewerEnv, action: str) -> None:
    item = env.publish({"a.txt": b"x"}, title="A")
    dash = env.dash_client()
    assert dash.post(f"/api/items/{item.id}/trash", headers=csrf_headers()).status_code == 200
    before = dash.get(f"/api/items/{item.id}?t=1", headers=owner_headers()).json()
    response = dash.post(f"/api/items/{item.id}/{action}", headers=csrf_headers())
    assert response.status_code == 409
    assert set(response.json()) == {"error", "request_id"}
    assert response.json()["error"] == "conflict"
    after = dash.get(f"/api/items/{item.id}?t=1", headers=owner_headers()).json()
    assert after == before


@pytest.mark.parametrize("action", ["pin", "unpin"])
def test_pin_errors(env: ViewerEnv, action: str) -> None:
    dash = env.dash_client()
    missing = f"/api/items/7ZZZZZZZZZZZZZZZZZZZZZZZZZ/{action}"
    assert dash.post(missing, headers=csrf_headers()).status_code == 404
    assert dash.post(f"/api/items/not-an-id/{action}", headers=csrf_headers()).status_code == 400
    assert dash.post(f"/api/items/{'A' * 65}/{action}", headers=csrf_headers()).status_code == 400
    item = env.publish({"a.txt": b"x"}, title="A")
    # Strict query: no parameters accepted.
    assert (
        dash.post(f"/api/items/{item.id}/{action}?x=1", headers=csrf_headers()).status_code == 400
    )
    # GET is not a state change: no such route.
    assert dash.get(f"/api/items/{item.id}/{action}", headers=owner_headers()).status_code == 405
    # Without the CSRF headers nothing changes.
    assert dash.post(f"/api/items/{item.id}/{action}", headers=owner_headers()).status_code == 403
    assert _feed(env).json()["items"][0]["pinned"] is False


def test_video_ranges(env: ViewerEnv) -> None:
    data = os.urandom(1_500_000)
    item = env.publish({"clip.mp4": data}, title="Clip")
    client = env.preview_client()
    url = f"/i/{item.id}/1/clip.mp4"
    etag = f'"{item.files[0].sha256}"'

    full = client.get(url, headers=owner_headers({"Range": "bytes=0-"}))
    assert full.status_code == 206
    assert full.content == data
    assert full.headers["content-range"] == f"bytes 0-{len(data) - 1}/{len(data)}"
    assert full.headers["content-type"] == "video/mp4"
    assert full.headers["accept-ranges"] == "bytes"

    mid = client.get(url, headers=owner_headers({"Range": "bytes=1000-1999"}))
    assert mid.status_code == 206
    assert mid.content == data[1000:2000]
    assert mid.headers["content-length"] == "1000"

    tail = client.get(url, headers=owner_headers({"Range": "bytes=-10"}))
    assert tail.content == data[-10:]

    beyond = client.get(url, headers=owner_headers({"Range": f"bytes={len(data)}-"}))
    assert beyond.status_code == 416
    assert beyond.headers["content-range"] == f"bytes */{len(data)}"

    stale = client.get(url, headers=owner_headers({"Range": "bytes=0-9", "If-Range": '"old"'}))
    assert stale.status_code == 200
    assert len(stale.content) == len(data)
    fresh = client.get(url, headers=owner_headers({"Range": "bytes=0-9", "If-Range": etag}))
    assert fresh.status_code == 206

    head = client.head(url, headers=owner_headers())
    assert head.status_code == 200
    assert head.headers["content-length"] == str(len(data))
    assert head.content == b""

    dup = client.get(
        url, headers=[*owner_headers().items(), ("Range", "bytes=0-1"), ("Range", "bytes=2-3")]
    )
    assert dup.status_code == 416

    cached = client.get(url, headers=owner_headers({"If-None-Match": etag}))
    assert cached.status_code == 304


def test_render_cap_truncates_on_a_character_boundary(env: ViewerEnv) -> None:
    text = ("é" * 800).encode()  # 1600 bytes, cap 1000 lands inside nothing odd
    text = b"a" + text  # shift so the cap splits a 2-byte character
    item = env.publish({"notes.md": text}, title="Long")
    response = env.preview_client().get(f"/t/{item.id}/1/notes.md", headers=owner_headers())
    assert response.status_code == 200
    assert response.headers["x-pdash-truncated"] == "1"
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert len(response.content) <= RENDER_CAP
    assert len(response.content) >= RENDER_CAP - 3
    response.content.decode("utf-8")  # strict: no partial character at the end
    assert text.startswith(response.content)

    short = env.publish({"s.md": b"# hi"}, title="Short")
    small = env.preview_client().get(f"/t/{short.id}/1/s.md", headers=owner_headers())
    assert small.content == b"# hi"
    assert "x-pdash-truncated" not in small.headers

    kinds = env.dash_client().get("/api/kinds", headers=owner_headers()).json()
    assert kinds["render_cap_bytes"] == RENDER_CAP
    assert {k["name"]: k["render_capped"] for k in kinds["kinds"]}["markdown"] is True

    detail = env.dash_client().get(f"/api/items/{item.id}", headers=owner_headers()).json()
    assert detail["render_url"] == f"{PREVIEW_ORIGIN}/t/{item.id}/1/notes.md"


def test_zip_download_round_trip(env: ViewerEnv) -> None:
    files = {
        "index.html": b"<p>hi</p>",
        "css/site.css": b"p{color:red}",
        "img/logo.png": os.urandom(50_000),
        "deep/a/b/c.txt": b"deep",
    }
    item: Item = env.publish(files, title="Round trip")
    response = env.preview_client().get(f"/d/{item.id}/1", headers=owner_headers())
    assert response.status_code == 200
    assert "Round-trip.zip" in response.headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert sorted(archive.namelist()) == sorted(files)
        for name, data in files.items():
            assert archive.read(name) == data
            info = archive.getinfo(name)
            assert (info.external_attr >> 16) & 0o170000 == 0o100000  # regular file


def test_static_index_and_etag(env: ViewerEnv) -> None:
    client = env.dash_client()
    index = client.get("/", headers=owner_headers())
    assert index.status_code == 200
    assert index.headers["content-type"] == "text/html; charset=utf-8"
    assert index.headers["cache-control"] == "private, no-cache"
    assert index.headers["x-frame-options"] == "DENY"
    again = client.get("/", headers=owner_headers({"If-None-Match": index.headers["etag"]}))
    assert again.status_code == 304
