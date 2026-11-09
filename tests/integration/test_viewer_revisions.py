"""Viewer routes for item revisions (ADR 0019): revision URL segment, `latest` alias, JSON.

Preview URLs are `/<letter>/<id>/<rev>/<relpath>` with `<rev>` a kept
revision number or `latest`; the dashboard JSON names concrete numbers,
lists every kept revision and serves any of them with `?rev=<n>`.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from preview_dashboard.domain.models import MAX_REVISIONS
from tests.viewer_support import PREVIEW_ORIGIN, ViewerEnv, make_env, owner_headers

pytestmark = pytest.mark.integration


@pytest.fixture
def env() -> ViewerEnv:
    return make_env()


def _get(env: ViewerEnv, path: str) -> tuple[int, bytes, dict[str, str]]:
    response = env.preview_client().get(path, headers=owner_headers())
    return response.status_code, response.content, dict(response.headers)


def test_each_revision_serves_its_own_bytes_and_latest_follows_the_head(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"<p>one</p>"})
    env.revise(item.id, {"index.html": b"<p>two</p>"})
    assert _get(env, f"/i/{item.id}/1/index.html")[1] == b"<p>one</p>"
    assert _get(env, f"/i/{item.id}/2/index.html")[1] == b"<p>two</p>"
    assert _get(env, f"/i/{item.id}/latest/index.html")[1] == b"<p>two</p>"
    env.revise(item.id, {"index.html": b"<p>three</p>"})
    assert _get(env, f"/i/{item.id}/latest/index.html")[1] == b"<p>three</p>"
    assert _get(env, f"/i/{item.id}/3/index.html")[0] == 200
    assert _get(env, f"/i/{item.id}/4/index.html")[0] == 404


def test_files_are_looked_up_in_their_own_revision(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"x", "old.css": b"a{}"})
    env.revise(item.id, {"index.html": b"y", "new.css": b"b{}"})
    assert _get(env, f"/i/{item.id}/1/old.css")[0] == 200
    assert _get(env, f"/i/{item.id}/2/old.css")[0] == 404
    assert _get(env, f"/i/{item.id}/latest/old.css")[0] == 404
    assert _get(env, f"/i/{item.id}/1/new.css")[0] == 404
    assert _get(env, f"/d/{item.id}/2/new.css")[0] == 200


def test_old_revision_is_served_with_its_own_kind(env: ViewerEnv) -> None:
    item = env.publish({"notes.md": b"# old"})
    env.revise(item.id, {"index.html": b"<p>new</p>"})
    status, body, headers = _get(env, f"/t/{item.id}/1/notes.md")
    assert (status, body) == (200, b"# old")
    assert headers["content-type"] == "text/plain; charset=utf-8"
    assert _get(env, f"/r/{item.id}/1/notes.md")[0] == 200
    # The head is html now: not render-capped.
    assert _get(env, f"/t/{item.id}/2/index.html")[0] == 404
    assert _get(env, f"/i/{item.id}/2/index.html")[2]["content-type"] == "text/html"


def test_pruned_revisions_are_gone(env: ViewerEnv) -> None:
    item = env.publish({"a.txt": b"1"})
    for n in range(2, MAX_REVISIONS + 2):
        env.revise(item.id, {"a.txt": str(n).encode()})
    assert _get(env, f"/i/{item.id}/1/a.txt")[0] == 404
    assert _get(env, f"/d/{item.id}/1")[0] == 404
    assert _get(env, f"/i/{item.id}/2/a.txt")[1] == b"2"
    detail = env.dash_client().get(f"/api/items/{item.id}?rev=1", headers=owner_headers())
    assert detail.status_code == 404


@pytest.mark.parametrize(
    "rev", ["0", "01", "+1", "-1", "1.0", "LATEST", "Latest", "99999999999", "2147483648", "1e2"]
)
def test_malformed_revision_segments_are_400(env: ViewerEnv, rev: str) -> None:
    item = env.publish({"a.txt": b"1"})
    for path in (f"/i/{item.id}/{rev}/a.txt", f"/d/{item.id}/{rev}", f"/t/{item.id}/{rev}/a.txt"):
        assert _get(env, path)[0] == 400, path


def test_old_url_shape_without_revision_is_not_served(env: ViewerEnv) -> None:
    item = env.publish({"a.txt": b"1", "b.txt": b"2"})
    # `/i/<id>/a.txt` would read "a.txt" as the revision: refused, never guessed.
    assert _get(env, f"/i/{item.id}/a.txt")[0] in {400, 404}
    assert _get(env, f"/d/{item.id}")[0] == 404


def test_zip_of_an_old_revision(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"one", "a.css": b"x"}, title="My Site")
    env.revise(item.id, {"index.html": b"two", "b.css": b"y"})
    status, body, headers = _get(env, f"/d/{item.id}/1")
    assert status == 200
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert sorted(archive.namelist()) == ["a.css", "index.html"]
        assert archive.read("index.html") == b"one"
    assert 'filename="My-Site-v1.zip"' in headers["content-disposition"]
    latest = _get(env, f"/d/{item.id}/latest")
    assert 'filename="My-Site-v2.zip"' in latest[2]["content-disposition"]


def test_never_revised_item_zip_keeps_the_plain_name(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"one", "a.css": b"x"}, title="My Site")
    assert 'filename="My-Site.zip"' in _get(env, f"/d/{item.id}/1")[2]["content-disposition"]


def test_item_json_lists_revisions_and_names_concrete_urls(env: ViewerEnv) -> None:
    item = env.publish({"index.html": b"one"})
    env.revise(item.id, {"index.html": b"two", "a.css": b"x"})
    client = env.dash_client()
    head = client.get(f"/api/items/{item.id}", headers=owner_headers()).json()
    assert head["revision"] == head["latest_revision"] == 2
    assert [r["number"] for r in head["revisions"]] == [2, 1]
    assert head["revisions"][1]["file_count"] == 1
    assert head["preview_url"] == f"{PREVIEW_ORIGIN}/i/{item.id}/2/index.html"
    assert head["download_url"] == f"{PREVIEW_ORIGIN}/d/{item.id}/2"
    assert [f["relpath"] for f in head["files"]] == ["index.html", "a.css"]
    old = client.get(f"/api/items/{item.id}?rev=1", headers=owner_headers()).json()
    assert old["revision"] == 1
    assert old["latest_revision"] == 2
    assert old["preview_url"] == f"{PREVIEW_ORIGIN}/i/{item.id}/1/index.html"
    assert [f["relpath"] for f in old["files"]] == ["index.html"]
    assert old["files"][0]["download_url"] == f"{PREVIEW_ORIGIN}/d/{item.id}/1/index.html"
    listed = client.get("/api/items", headers=owner_headers()).json()["items"][0]
    assert listed["revision"] == 2
    # URLs always name a concrete revision (a page and its sub-resources match).
    assert "/latest" not in json.dumps(head)


@pytest.mark.parametrize("query", ["rev=0", "rev=01", "rev=latest", "rev=", "rev=1&rev=1", "r=1"])
def test_detail_rejects_bad_revision_queries(env: ViewerEnv, query: str) -> None:
    item = env.publish({"a.txt": b"1"})
    response = env.dash_client().get(f"/api/items/{item.id}?{query}", headers=owner_headers())
    assert response.status_code == 400


def test_trashed_item_revisions_need_the_trash_flag(env: ViewerEnv) -> None:
    item = env.publish({"a.txt": b"1"})
    env.revise(item.id, {"a.txt": b"2"})
    env.services.trash.trash(item.id)
    client = env.dash_client()
    assert client.get(f"/api/items/{item.id}?rev=1", headers=owner_headers()).status_code == 404
    old = client.get(f"/api/items/{item.id}?rev=1&t=1", headers=owner_headers())
    assert old.status_code == 200
    assert old.json()["preview_url"].endswith(f"/i/{item.id}/1/a.txt?t=1")
    assert _get(env, f"/i/{item.id}/1/a.txt")[0] == 404
    assert _get(env, f"/i/{item.id}/1/a.txt?t=1")[0] == 200
