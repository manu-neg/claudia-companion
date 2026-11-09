"""Unit tests for the viewer route helpers and route edge cases (unit 8b).

Pure helpers (strict query parsing, conditional requests, UTF-8 trimming,
serve plans, Referer binding, item JSON) plus route behaviour over the
in-memory fakes that the security/integration suites don't pin down.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from typing import Any

import pytest

from preview_dashboard.config import Settings
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.interfaces.viewer._http import DuplicateHeaderError
from preview_dashboard.interfaces.viewer.conditional import (
    body_etag,
    if_none_match,
    if_range_allows,
    single_range_header,
)
from preview_dashboard.interfaces.viewer.hints import PreviewHints, bundle_referer_bound
from preview_dashboard.interfaces.viewer.item_json import ItemPresenter
from preview_dashboard.interfaces.viewer.query_params import flag, parse_query
from preview_dashboard.interfaces.viewer.routes.preview import (
    ServePlan,
    plan_for,
    trim_partial_utf8,
)
from preview_dashboard.interfaces.viewer.services import ViewerOptions
from preview_dashboard.interfaces.viewer.static_assets import StaticAssets, default_static_dir
from preview_dashboard.kinds import default_registry
from preview_dashboard.kinds.base import PreviewMode
from tests.viewer_support import PREVIEW_ORIGIN, make_env, make_settings, owner_headers

pytestmark = pytest.mark.unit

ITEM = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _scope(query: bytes = b"", headers: list[tuple[bytes, bytes]] | None = None) -> dict[str, Any]:
    return {"type": "http", "query_string": query, "headers": headers or []}


# --- query parsing --------------------------------------------------------------------


def test_parse_query_accepts_declared_keys() -> None:
    assert parse_query(_scope(b"state=trashed&limit=5"), ("state", "limit")) == {
        "state": "trashed",
        "limit": "5",
    }
    assert parse_query(_scope(b""), ()) == {}


@pytest.mark.parametrize(
    "query",
    [b"x=1", b"state=a&state=b", b"state", b"&&", b"a=%ff", "é=1".encode(), b"s=" + b"x" * 600],
)
def test_parse_query_rejects_anything_odd(query: bytes) -> None:
    with pytest.raises(ValidationError):
        parse_query(_scope(query), ("state",))


def test_flag_is_exactly_one() -> None:
    assert flag({"t": "1"}, "t") is True
    assert flag({}, "t") is False
    for bad in ("", "0", "true", "11"):
        with pytest.raises(ValidationError):
            flag({"t": bad}, "t")


# --- conditional requests ---------------------------------------------------------------


def test_if_none_match_variants() -> None:
    etag = body_etag(b"x")
    assert if_none_match(_scope(headers=[(b"if-none-match", etag.encode())]), etag)
    assert if_none_match(_scope(headers=[(b"if-none-match", b'"a", ' + etag.encode())]), etag)
    assert if_none_match(_scope(headers=[(b"if-none-match", b"W/" + etag.encode())]), etag)
    assert if_none_match(_scope(headers=[(b"if-none-match", b"*")]), etag)
    assert not if_none_match(_scope(headers=[(b"if-none-match", b'"other"')]), etag)
    assert not if_none_match(_scope(headers=[(b"if-none-match", "é".encode())]), etag)
    assert not if_none_match(_scope(), etag)


def test_if_range_and_range_header() -> None:
    etag = '"abc"'
    assert if_range_allows(_scope(), etag)
    assert if_range_allows(_scope(headers=[(b"if-range", b'"abc"')]), etag)
    assert not if_range_allows(_scope(headers=[(b"if-range", b"Wed, 21 Oct 2015")]), etag)
    two = [(b"if-range", b'"abc"'), (b"if-range", b'"abc"')]
    assert not if_range_allows(_scope(headers=two), etag)
    assert single_range_header(_scope()) is None
    with pytest.raises(DuplicateHeaderError):
        single_range_header(_scope(headers=[(b"range", b"bytes=0-1"), (b"range", b"bytes=0-1")]))


# --- UTF-8 trimming ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"abc", b"abc"),
        ("aé".encode(), "aé".encode()),
        ("aé".encode()[:-1], b"a"),
        ("a€".encode()[:-1], b"a"),
        ("a€".encode()[:-2], b"a"),
        ("a😀".encode()[:-1], b"a"),
        ("a😀".encode()[:-3], b"a"),
        ("a😀".encode(), "a😀".encode()),
        (b"", b""),
        (b"\x80\x80\x80\x80", b"\x80\x80\x80\x80"),  # not UTF-8 at all: left as is
    ],
)
def test_trim_partial_utf8(data: bytes, expected: bytes) -> None:
    assert trim_partial_utf8(data) == expected


# --- serve plans and bundle binding -----------------------------------------------------


def test_plan_for_bundle_members_and_downloads() -> None:
    env = make_env()
    kinds = default_registry()
    item = env.publish({"index.html": b"x", "a.js": b"1", "data.xml": b"<x/>"}, title="B")
    head = item.head

    def plan(relpath: str, *, download: bool = False) -> ServePlan:
        item_file = head.file(relpath)
        assert item_file is not None
        return plan_for(kinds, item, head, item_file, download=download, rev_segment="1")

    entry = plan("index.html")
    assert entry.disposition == "inline"
    assert entry.hints == PreviewHints(PreviewMode.SANDBOXED, False, item.id, "1")
    sub = plan("a.js")
    assert sub.hints.bundle_subresource is True
    assert sub.hints.revision == "1"
    assert sub.content_type == "text/javascript; charset=utf-8"
    opaque = plan("data.xml")
    assert opaque.disposition == "attachment"
    assert opaque.hints.bundle_subresource is False
    download = plan("a.js", download=True)
    assert download.disposition == "attachment"
    assert download.hints.preview_mode is PreviewMode.DOWNLOAD


@pytest.mark.parametrize(
    ("referers", "expected"),
    [
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/1/index.html"], True),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/1/sub/x.html?y=1"], True),
        ([], False),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/1"], False),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}x/index.html"], False),
        ([f"{PREVIEW_ORIGIN}.evil.example/i/{ITEM}/1/index.html"], False),
        ([f"http://dash.example.ts.net:8443/i/{ITEM}/1/index.html"], False),
        ([f"{PREVIEW_ORIGIN}/d/{ITEM}/1/index.html"], False),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/1/a", f"{PREVIEW_ORIGIN}/i/{ITEM}/1/b"], False),
        # Bound to the revision too (ADR 0019): another revision's page, or the
        # `latest` alias vs a numbered URL, is not the same bundle.
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/2/index.html"], False),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/10/index.html"], False),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/latest/index.html"], False),
        ([f"{PREVIEW_ORIGIN}/i/{ITEM}/index.html"], False),
    ],
)
def test_bundle_referer_bound(referers: list[str], expected: bool) -> None:
    headers = [(b"referer", r.encode()) for r in referers]
    hints = PreviewHints(PreviewMode.SANDBOXED, True, ITEM, "1")
    assert bundle_referer_bound(_scope(headers=headers), hints, PREVIEW_ORIGIN) is expected


def test_bundle_referer_bound_latest_alias_binds_to_itself() -> None:
    headers = [(b"referer", f"{PREVIEW_ORIGIN}/i/{ITEM}/latest/index.html".encode())]
    latest = PreviewHints(PreviewMode.SANDBOXED, True, ITEM, "latest")
    assert bundle_referer_bound(_scope(headers=headers), latest, PREVIEW_ORIGIN)
    numbered = PreviewHints(PreviewMode.SANDBOXED, True, ITEM, "1")
    assert not bundle_referer_bound(_scope(headers=headers), numbered, PREVIEW_ORIGIN)


def test_bundle_binding_needs_hint_item_id_and_revision() -> None:
    headers = [(b"referer", f"{PREVIEW_ORIGIN}/i/{ITEM}/1/index.html".encode())]
    for hints in (
        PreviewHints(PreviewMode.SANDBOXED, False, ITEM, "1"),
        PreviewHints(PreviewMode.SANDBOXED, True, None, "1"),
        PreviewHints(PreviewMode.SANDBOXED, True, ITEM, None),
    ):
        assert not bundle_referer_bound(_scope(headers=headers), hints, PREVIEW_ORIGIN)


# --- options, presenter, static ---------------------------------------------------------


def test_viewer_options_fail_closed() -> None:
    bad = Settings.model_construct(**{**make_settings().model_dump(), "render_cap_bytes": 0})
    with pytest.raises(ValueError, match="render_cap_bytes"):
        ViewerOptions.from_settings(bad, PREVIEW_ORIGIN)


def test_presenter_marks_trashed_urls() -> None:
    env = make_env()
    item = env.publish({"a.txt": b"x"}, title="T")
    options = ViewerOptions.from_settings(make_settings(), PREVIEW_ORIGIN)
    presenter = ItemPresenter(default_registry(), options, {})
    active = presenter.summary(item)
    assert active["render_url"] == f"{PREVIEW_ORIGIN}/t/{item.id}/1/a.txt"
    assert active["purge_at"] is None
    trashed = item.trashed(item.updated_at + timedelta(seconds=1))
    summary = presenter.summary(trashed)
    assert str(summary["preview_url"]).endswith("?t=1")
    assert str(summary["render_url"]).endswith("?t=1")
    assert summary["state"] == "trashed"


def test_presenter_unknown_kind_is_download_only() -> None:
    env = make_env()
    item = dataclasses.replace(env.publish({"a.txt": b"x"}, title="T"), kind="gone")
    options = ViewerOptions.from_settings(make_settings(), PREVIEW_ORIGIN)
    summary = ItemPresenter(default_registry(), options, {}).summary(item)
    assert summary["preview_mode"] == "download"
    assert summary["render_url"] is None


def test_packaged_static_dir_has_the_index() -> None:
    assets = StaticAssets.load(default_static_dir())
    index = assets.get("index.html")
    assert index is not None
    assert index.content_type == "text/html; charset=utf-8"
    assert b"<script>" not in index.body and b"style=" not in index.body  # CSP: nothing inline


# --- route edge cases -------------------------------------------------------------------


def test_kinds_endpoint_shape() -> None:
    env = make_env()
    body = env.dash_client().get("/api/kinds", headers=owner_headers()).json()
    assert set(body) == {"kinds", "render_cap_bytes", "preview_origin"}
    assert body["preview_origin"] == PREVIEW_ORIGIN
    assert body["kinds"] == list(default_registry().describe())
    assert env.dash_client().get("/api/kinds?x=1", headers=owner_headers()).status_code == 400


def test_encoded_item_id_is_rejected() -> None:
    """The id segment must arrive literally (it is also taken from the decoded path)."""
    env = make_env()
    item = env.publish({"a.txt": b"x"}, title="T")
    encoded = "".join(f"%{ord(c):02X}" for c in item.id)
    for prefix in ("i", "t", "d"):
        tail = "" if prefix == "d" else "/a.txt"
        for url in (f"/{prefix}/{encoded}/1{tail}", f"/{prefix}/{item.id}/%31{tail}"):
            response = env.preview_client().get(url, headers=owner_headers())
            assert response.status_code == 400, url


def test_zip_head_has_headers_but_builds_nothing() -> None:
    env = make_env()
    item = env.publish({"index.html": b"x", "a.css": b"p{}"}, title="B")
    response = env.preview_client().head(f"/d/{item.id}/1", headers=owner_headers())
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.content == b""


def test_render_head_reports_length() -> None:
    env = make_env()
    item = env.publish({"a.txt": b"hello"}, title="T")
    response = env.preview_client().head(f"/t/{item.id}/1/a.txt", headers=owner_headers())
    assert response.headers["content-length"] == "5"
    assert response.content == b""


def test_overlong_item_id_is_400() -> None:
    env = make_env()
    response = env.dash_client().get("/api/items/" + "A" * 65, headers=owner_headers())
    assert response.status_code == 400


def test_concurrent_edit_conflict_is_409() -> None:
    """A lost optimistic-concurrency race (ConflictError) answers 409, not 500."""
    from preview_dashboard.domain.errors import ConflictError
    from preview_dashboard.interfaces.viewer.errors import status_for
    from tests.viewer_support import csrf_headers

    assert status_for(ConflictError("changed")) == 409

    class RacingTrash:
        def trash(self, item_id: str) -> Any:
            raise ConflictError("changed concurrently")

        def restore(self, item_id: str) -> Any:
            raise ConflictError("changed concurrently")

    env = make_env()
    item = env.publish({"a.txt": b"x"}, title="T")
    env.services._trash = RacingTrash()  # type: ignore[assignment]
    for action in ("trash", "restore"):
        response = env.dash_client().post(f"/api/items/{item.id}/{action}", headers=csrf_headers())
        assert response.status_code == 409
        assert response.json()["error"] == "conflict"


def test_pin_conflict_is_409() -> None:
    """A lost race on pin/unpin (ConflictError after the one retry) answers 409."""
    from preview_dashboard.domain.errors import ConflictError
    from tests.viewer_support import csrf_headers

    calls: list[tuple[str, bool]] = []

    class RacingPins:
        def set_pinned(self, item_id: str, *, pinned: bool) -> Any:
            calls.append((item_id, pinned))
            raise ConflictError("changed concurrently")

    env = make_env()
    item = env.publish({"a.txt": b"x"}, title="T")
    env.services._pins = RacingPins()
    for action in ("pin", "unpin"):
        response = env.dash_client().post(f"/api/items/{item.id}/{action}", headers=csrf_headers())
        assert response.status_code == 409
        assert response.json()["error"] == "conflict"
    assert calls == [(item.id, True), (item.id, False)]


def test_pin_routes_map_to_the_pin_flag_only() -> None:
    """pin → set_pinned(True), unpin → set_pinned(False); the response is the summary."""
    from tests.viewer_support import csrf_headers

    env = make_env()
    item = env.publish({"a.txt": b"x"}, title="T")
    client = env.dash_client()
    pinned = client.post(f"/api/items/{item.id}/pin", headers=csrf_headers()).json()["item"]
    assert pinned["pinned"] is True
    assert (pinned["title"], pinned["state"]) == ("T", "active")
    unpinned = client.post(f"/api/items/{item.id}/unpin", headers=csrf_headers()).json()["item"]
    assert unpinned["pinned"] is False
