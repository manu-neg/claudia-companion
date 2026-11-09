"""Integration tests for the admin API over real adapters (SQLite + filesystem).

Full publish → list → get → patch → trash → restore flows for every content
kind, response shape (viewer URL, no blob ids), and multipart edge cases:
field order, manifest matching, malformed bodies, rollback on failure.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from preview_dashboard.bootstrap import AdminCore
from tests.admin_support import (
    BOUNDARY,
    DASHBOARD_HOST,
    ResponseLike,
    admin_client,
    auth,
    multipart_body,
    multipart_headers,
    publish,
)

pytestmark = pytest.mark.integration

# One sample per kind: (kind, files).
KIND_SAMPLES: list[tuple[str, list[tuple[str, bytes]]]] = [
    ("image", [("photo.png", b"\x89PNG\r\n\x1a\n fake")]),
    ("svg", [("logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>")]),
    ("html", [("index.html", b"<h1>x</h1>"), ("css/app.css", b"h1{}"), ("app.js", b"1;")]),
    ("video", [("clip.mp4", b"\x00\x00\x00\x18ftypmp42")]),
    ("audio", [("song.mp3", b"ID3fake")]),
    ("pdf", [("doc.pdf", b"%PDF-1.4 fake")]),
    ("markdown", [("README.md", b"# Title\n")]),
    ("code", [("main.py", b"print('hi')\n")]),
    ("json", [("data.json", b'{"a": 1}')]),
    ("csv", [("table.csv", b"a,b\n1,2\n")]),
    ("text", [("notes.txt", b"hello\n")]),
    ("diff", [("change.diff", b"--- a\n+++ b\n")]),
    ("file", [("archive.bin", b"\x00\x01\x02")]),
]


@pytest.fixture
def admin(tmp_path: Path) -> Iterator[tuple[TestClient, str, AdminCore]]:
    with admin_client(tmp_path) as ctx:
        yield ctx


def _blob_files(tmp_path: Path) -> list[Path]:
    root = tmp_path / "data"
    return [p for sub in ("blobs", "staging") for p in (root / sub).rglob("*") if p.is_file()]


class TestFlowsPerKind:
    @pytest.mark.parametrize(("kind", "files"), KIND_SAMPLES, ids=[k for k, _ in KIND_SAMPLES])
    def test_full_lifecycle(self, admin, kind, files):
        client, token, _ = admin
        created = publish(client, token, files, title=f"A {kind}", description="desc")
        assert created.status_code == 201, created.text
        item = created.json()
        assert item["kind"] == kind
        assert item["state"] == "active"
        assert [f["relpath"] for f in item["files"]] == [p for p, _ in files]
        for entry, (_, data) in zip(item["files"], files, strict=True):
            assert entry["size"] == len(data)
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        item_id = item["id"]

        got = client.get(f"/v1/items/{item_id}", headers=auth(token))
        assert got.status_code == 200
        assert got.json() == item

        listed = client.get("/v1/items", params={"kind": kind}, headers=auth(token)).json()
        assert [i["id"] for i in listed["items"]] == [item_id]

        patched = client.patch(
            f"/v1/items/{item_id}",
            json={"title": "Renamed", "description": "", "pinned": True},
            headers=auth(token),
        )
        assert patched.status_code == 200
        assert (patched.json()["title"], patched.json()["pinned"]) == ("Renamed", True)

        trashed = client.post(f"/v1/items/{item_id}/trash", headers=auth(token))
        assert trashed.status_code == 200
        assert trashed.json()["state"] == "trashed"
        assert trashed.json()["trashed_at"] is not None
        active = client.get("/v1/items", headers=auth(token)).json()["items"]
        assert item_id not in [i["id"] for i in active]
        in_trash = client.get("/v1/items", params={"state": "trashed"}, headers=auth(token))
        assert [i["id"] for i in in_trash.json()["items"]] == [item_id]

        restored = client.post(f"/v1/items/{item_id}/restore", headers=auth(token))
        assert restored.status_code == 200
        assert restored.json()["state"] == "active"
        assert restored.json()["trashed_at"] is None


class TestResponses:
    def test_item_shape_has_viewer_url_and_no_blob_ids(self, admin):
        client, token, _ = admin
        item = publish(client, token, [("a.txt", b"x")]).json()
        assert item["viewer_url"] == f"https://{DASHBOARD_HOST}/#/item/{item['id']}"
        assert "blob_id" not in json.dumps(item)
        assert set(item) == {
            "id",
            "title",
            "description",
            "kind",
            "state",
            "pinned",
            "created_at",
            "updated_at",
            "trashed_at",
            "entry_file",
            "total_size",
            "files",
            "revision",
            "revision_at",
            "stored_size",
            "revisions",
            "folder",
            "viewer_url",
        }
        assert item["folder"] is None
        assert item["revision"] == 1
        assert item["revisions"] == [
            {
                "number": 1,
                "created_at": item["created_at"],
                "kind": "text",
                "entry_file": "a.txt",
                "file_count": 1,
                "total_size": 1,
            }
        ]

    def test_viewer_url_is_null_without_allowed_hosts(self, tmp_path):
        with admin_client(tmp_path, allowed_hosts=frozenset()) as (client, token, _):
            assert publish(client, token, [("a.txt", b"x")]).json()["viewer_url"] is None

    def test_json_responses_are_no_store(self, admin):
        client, token, _ = admin
        response = client.get("/v1/health", headers=auth(token))
        assert response.json() == {"status": "ok"}
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-request-id"]

    def test_kinds_lists_registry(self, admin):
        client, token, core = admin
        body = client.get("/v1/kinds", headers=auth(token)).json()
        assert [k["name"] for k in body["kinds"]] == [k["name"] for k in core.kinds.describe()]

    def test_pinned_items_come_first_and_paging_works(self, admin):
        client, token, _ = admin
        ids = [publish(client, token, [(f"{n}.txt", b"x")]).json()["id"] for n in range(3)]
        pinned = publish(client, token, [("p.txt", b"x")], pinned=True).json()["id"]
        first = client.get("/v1/items", params={"limit": 2}, headers=auth(token)).json()
        assert [i["id"] for i in first["items"]] == [pinned, ids[2]]
        second = client.get(
            "/v1/items", params={"limit": 2, "cursor": first["next_cursor"]}, headers=auth(token)
        ).json()
        assert [i["id"] for i in second["items"]] == [ids[1], ids[0]]
        assert second["next_cursor"] is None

    def test_trash_and_restore_are_idempotent(self, admin):
        client, token, _ = admin
        item_id = publish(client, token, [("a.txt", b"x")]).json()["id"]
        first = client.post(f"/v1/items/{item_id}/trash", headers=auth(token)).json()
        again = client.post(f"/v1/items/{item_id}/trash", headers=auth(token)).json()
        assert first["trashed_at"] == again["trashed_at"]
        assert client.post(f"/v1/items/{item_id}/restore", headers=auth(token)).status_code == 200
        assert client.post(f"/v1/items/{item_id}/restore", headers=auth(token)).status_code == 200

    def test_patch_trashed_item_is_conflict(self, admin):
        client, token, _ = admin
        item_id = publish(client, token, [("a.txt", b"x")]).json()["id"]
        client.post(f"/v1/items/{item_id}/trash", headers=auth(token))
        response = client.patch(f"/v1/items/{item_id}", json={"title": "x"}, headers=auth(token))
        assert response.status_code == 409

    def test_concurrent_edit_conflict_is_409(self, admin, monkeypatch):
        from preview_dashboard.domain.errors import ConflictError

        client, token, core = admin
        item_id = publish(client, token, [("a.txt", b"x")]).json()["id"]

        def conflicting(*args: object, **kwargs: object) -> None:
            raise ConflictError("item changed concurrently; re-read and retry")

        monkeypatch.setattr(core.lifecycle, "trash", conflicting)
        response = client.post(f"/v1/items/{item_id}/trash", headers=auth(token))
        assert response.status_code == 409
        assert response.json()["error"] == "conflict"

    @pytest.mark.parametrize(
        "body",
        [{"kind": "html"}, {"title": 5}, {"pinned": "yes"}, {"description": ["x"]}, []],
        ids=["unknown-field", "title-type", "pinned-type", "description-type", "not-object"],
    )
    def test_patch_rejects_bad_bodies(self, admin, body):
        client, token, _ = admin
        item_id = publish(client, token, [("a.txt", b"x")]).json()["id"]
        response = client.patch(f"/v1/items/{item_id}", json=body, headers=auth(token))
        assert response.status_code == 400

    def test_patch_requires_json_content_type(self, admin):
        client, token, _ = admin
        item_id = publish(client, token, [("a.txt", b"x")]).json()["id"]
        response = client.patch(
            f"/v1/items/{item_id}",
            content=b'{"title": "x"}',
            headers={**auth(token), "Content-Type": "text/plain"},
        )
        assert response.status_code == 415

    def test_unknown_item_is_404_and_bad_id_is_400(self, admin):
        client, token, _ = admin
        assert client.get("/v1/items/" + "0" * 26, headers=auth(token)).status_code == 404
        assert client.get("/v1/items/not-an-id", headers=auth(token)).status_code == 400
        missing = "/v1/items/" + "0" * 26 + "/trash"
        assert client.post(missing, headers=auth(token)).status_code == 404

    @pytest.mark.parametrize(
        "params",
        [
            {"state": "gone"},
            {"limit": "0"},
            {"limit": "abc"},
            {"limit": "99999"},
            {"limit": "²"},
            {"limit": "٣"},
            {"limit": "1²"},
            {"limit": "+5"},
            {"limit": " 5"},
            {"limit": ""},
            {"x": "1"},
            {"cursor": "bogus"},
            {"kind": "Bad Kind"},
        ],
    )
    def test_list_rejects_bad_query(self, admin, params):
        client, token, _ = admin
        assert client.get("/v1/items", params=params, headers=auth(token)).status_code == 400

    def test_list_rejects_duplicate_params(self, admin):
        client, token, _ = admin
        response = client.get("/v1/items?state=active&state=trashed", headers=auth(token))
        assert response.status_code == 400

    def test_no_hard_delete_endpoint(self, admin):
        client, token, _ = admin
        item_id = publish(client, token, [("a.txt", b"x")]).json()["id"]
        assert client.delete(f"/v1/items/{item_id}", headers=auth(token)).status_code == 405
        assert client.get(f"/v1/items/{item_id}", headers=auth(token)).status_code == 200


class TestMultipartEdgeCases:
    def _post(self, client: TestClient, token: str, body: bytes, **headers: str) -> ResponseLike:
        return client.post(
            "/v1/items", content=body, headers={**multipart_headers(token), **headers}
        )

    def test_utf8_relpath_and_fields_round_trip(self, admin):
        client, token, _ = admin
        response = publish(
            client, token, [("résumé/notes.txt", b"x")], title="Café ☕", description="ünï"
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["files"][0]["relpath"] == "résumé/notes.txt"
        assert (body["title"], body["description"]) == ("Café ☕", "ünï")

    def test_httpx_native_multipart_encoding_works(self, admin):
        # The documented client recipe: httpx sends data fields before files.
        client, token, _ = admin
        files = [("site/index.html", b"<p>x</p>"), ("site/é.css", b"p{}")]
        response = client.post(
            "/v1/items",
            data={"title": "Native", "manifest": json.dumps([p for p, _ in files])},
            files=[("file", (p, b)) for p, b in files],
            headers=auth(token),
        )
        assert response.status_code == 201, response.text
        assert [f["relpath"] for f in response.json()["files"]] == [p for p, _ in files]

    def test_empty_file_is_allowed(self, admin):
        client, token, _ = admin
        response = publish(client, token, [("empty.txt", b"")])
        assert response.status_code == 201
        assert response.json()["files"][0]["size"] == 0

    def test_kind_hint_and_pinned(self, admin):
        client, token, _ = admin
        response = publish(client, token, [("a.txt", b"x")], kind_hint="text", pinned=True)
        assert (response.json()["kind"], response.json()["pinned"]) == ("text", True)

    def test_incompatible_kind_hint_is_422(self, admin):
        client, token, _ = admin
        assert publish(client, token, [("a.txt", b"x")], kind_hint="image").status_code == 422

    def test_boundary_straddling_large_file(self, admin):
        client, token, _ = admin
        data = os.urandom(50_000) + b"--" + BOUNDARY.encode()[:-1] + os.urandom(10_000)
        response = publish(client, token, [("blob.bin", data)])
        assert response.status_code == 201
        assert response.json()["files"][0]["sha256"] == hashlib.sha256(data).hexdigest()

    @pytest.mark.parametrize(
        ("fields", "files"),
        [
            ([("manifest", '["a.txt"]')], [("a.txt", b"x")]),  # missing title
            ([("title", "t")], [("a.txt", b"x")]),  # missing manifest
            ([("title", "t"), ("manifest", "not json")], [("a.txt", b"x")]),
            ([("title", "t"), ("manifest", '{"a": 1}')], [("a.txt", b"x")]),
            ([("title", "t"), ("manifest", "[1]")], [("a.txt", b"x")]),
            ([("title", "t"), ("manifest", "[]")], [("a.txt", b"x")]),
            ([("title", "t"), ("manifest", '["a.txt"]')], [("b.txt", b"x")]),  # name mismatch
            ([("title", "t"), ("manifest", '["a.txt", "b.txt"]')], [("a.txt", b"x")]),  # fewer
            ([("title", "t"), ("manifest", '["a.txt"]')], [("a.txt", b"x"), ("b.txt", b"y")]),
            ([("title", "t"), ("manifest", '["a.txt"]'), ("bogus", "1")], [("a.txt", b"x")]),
            ([("title", "t"), ("title", "u"), ("manifest", '["a.txt"]')], [("a.txt", b"x")]),
            ([("title", "t"), ("pinned", "maybe"), ("manifest", '["a.txt"]')], [("a.txt", b"x")]),
            ([("title", "t"), ("manifest", '["../x.txt"]')], [("../x.txt", b"x")]),
            ([("title", "t"), ("manifest", '["a.txt"]')], []),  # no file parts
            ([("title", b"\xff\xfe"), ("manifest", '["a.txt"]')], [("a.txt", b"x")]),
        ],
        ids=[
            "no-title",
            "no-manifest",
            "manifest-not-json",
            "manifest-object",
            "manifest-non-string",
            "manifest-empty",
            "filename-mismatch",
            "fewer-files",
            "extra-file",
            "unknown-field",
            "duplicate-field",
            "bad-pinned",
            "traversal-relpath",
            "no-files",
            "invalid-utf8",
        ],
    )
    def test_malformed_forms_are_400(self, admin, tmp_path, fields, files):
        client, token, _ = admin
        response = self._post(client, token, multipart_body(fields, files))
        assert response.status_code == 400, response.text
        assert set(response.json()) == {"error", "message", "request_id"}
        assert client.get("/v1/items", headers=auth(token)).json()["items"] == []
        assert _blob_files(tmp_path) == []

    def test_field_after_file_is_400(self, admin):
        client, token, _ = admin
        body = multipart_body([("title", "t"), ("manifest", '["a.txt"]')], [("a.txt", b"x")])
        # Move the closing delimiter so a field follows the file part.
        tail = f"--{BOUNDARY}--\r\n".encode()
        extra = multipart_body([("description", "late")])
        response = self._post(client, token, body[: -len(tail)] + extra)
        assert response.status_code == 400

    def test_wrong_file_field_name_is_400(self, admin):
        client, token, _ = admin
        body = multipart_body(
            [("title", "t"), ("manifest", '["a.txt"]')], [("a.txt", b"x")], file_field="upload"
        )
        assert self._post(client, token, body).status_code == 400

    def test_transfer_encoding_header_is_400(self, admin):
        client, token, _ = admin
        body = multipart_body(
            [("title", "t"), ("manifest", '["a.txt"]')],
            [("a.txt", b"x")],
            extra_part_headers=["Content-Transfer-Encoding: base64"],
        )
        assert self._post(client, token, body).status_code == 400

    def test_truncated_body_is_400_and_rolled_back(self, admin, tmp_path):
        client, token, _ = admin
        body = multipart_body([("title", "t"), ("manifest", '["a.txt"]')], [("a.txt", b"x" * 500)])
        response = self._post(client, token, body[:-30])
        assert response.status_code == 400
        assert client.get("/v1/items", headers=auth(token)).json()["items"] == []
        assert _blob_files(tmp_path) == []

    def test_missing_closing_delimiter_never_commits(self, admin, tmp_path):
        client, token, _ = admin
        body = multipart_body([("title", "t"), ("manifest", '["a.txt"]')], [("a.txt", b"x")])
        response = self._post(client, token, body[: -len(f"--{BOUNDARY}--\r\n")])
        assert response.status_code == 400
        assert client.get("/v1/items", headers=auth(token)).json()["items"] == []
        assert _blob_files(tmp_path) == []

    @pytest.mark.parametrize(
        "content_type",
        ["application/json", "multipart/form-data", "multipart/mixed; boundary=x", ""],
    )
    def test_wrong_content_type_is_415(self, admin, content_type):
        client, token, _ = admin
        body = multipart_body([("title", "t"), ("manifest", '["a.txt"]')], [("a.txt", b"x")])
        response = client.post(
            "/v1/items", content=body, headers={**auth(token), "Content-Type": content_type}
        )
        assert response.status_code == 415

    def test_failed_publish_leaves_nothing_and_next_publish_works(self, admin, tmp_path):
        client, token, _ = admin
        # Second file over the per-file limit: the first file's blob must be rolled back.
        response = publish(
            client, token, [("a.txt", b"x" * 100), ("b.txt", b"y" * (64 * 1024 + 1))]
        )
        assert response.status_code == 413
        assert _blob_files(tmp_path) == []
        assert publish(client, token, [("c.txt", b"z")]).status_code == 201


class TestChunkChannel:
    """The publish thread's view of the upload: strictly in order, never skipping bytes."""

    @pytest.mark.parametrize("stray_index", [0, 2], ids=["earlier-file", "later-file"])
    def test_chunk_of_another_file_aborts(self, stray_index):
        import anyio
        import anyio.to_thread

        from preview_dashboard.interfaces.admin.multipart import (
            _Chunk,
            _FileChunks,
            _UploadAbortedError,
        )

        async def scenario() -> list[bytes]:
            send, receive = anyio.create_memory_object_stream[_Chunk](max_buffer_size=8)
            await send.send(_Chunk(1, b"ok"))
            await send.send(_Chunk(stray_index, b"stray"))
            await send.send(_Chunk(1, b"never"))
            await send.send(_Chunk(1, None))
            seen: list[bytes] = []

            def consume() -> None:
                for data in _FileChunks(receive, 1):
                    seen.append(data)

            with pytest.raises(_UploadAbortedError):
                await anyio.to_thread.run_sync(consume)
            send.close()
            receive.close()
            return seen

        assert anyio.run(scenario) == [b"ok"]


class TestOverRealSocket:
    """The same flow through uvicorn on a Unix socket, with a chunked streamed body."""

    def test_chunked_streaming_publish(self, tmp_path):
        import secrets

        from preview_dashboard.bootstrap import build_core
        from preview_dashboard.interfaces.admin.app import build_admin_app
        from tests.admin_support import (
            make_settings,
            publish_body,
            running_admin_server,
            uds_client,
        )

        token = secrets.token_urlsafe(32)
        data = os.urandom(60_000)
        body = publish_body([("data.bin", data), ("readme.txt", b"hi")], title="Streamed")

        def chunks() -> Iterator[bytes]:
            for start in range(0, len(body), 997):  # odd size: splits boundaries too
                yield body[start : start + 997]

        with build_core(make_settings(tmp_path), role="admin") as core:
            app = build_admin_app(core, token=token.encode())
            sock_path = tmp_path / "run" / "admin.sock"
            with running_admin_server(app, sock_path), uds_client(sock_path) as client:
                response = client.post(
                    "/v1/items", content=chunks(), headers=multipart_headers(token)
                )
                assert response.status_code == 201, response.text
                files = response.json()["files"]
                assert files[0]["sha256"] == hashlib.sha256(data).hexdigest()
                assert files[1]["size"] == 2
