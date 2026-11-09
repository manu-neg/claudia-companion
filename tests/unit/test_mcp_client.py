"""Tests for `AdminClient` (interfaces/mcp/client.py): wire format, auth, error mapping.

Stub transports (`httpx.MockTransport`) pin down the exact request shape —
manifest-first multipart streamed chunk by chunk, bearer header, URL safety —
and the mapping of admin error bodies to typed exceptions. A real admin API
on a tmp Unix socket proves the whole round trip, including rollback when an
upload goes wrong mid-stream.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from python_multipart.multipart import parse_options_header

from preview_dashboard.interfaces.mcp.client import (
    MAX_RESPONSE_BYTES,
    AdminAuthError,
    AdminClient,
    AdminClientError,
    AdminConflictError,
    AdminInputError,
    AdminLimitError,
    AdminNotFoundError,
    AdminRejectedError,
    AdminServerError,
    AdminUnavailableError,
    _PublishBody,
    error_from_response,
)
from preview_dashboard.interfaces.mcp.errors import IntakeError, IntakeErrorCode
from preview_dashboard.interfaces.token_file import TokenFileError
from tests.admin_support import make_settings, write_token
from tests.mcp_support import fake_aws_key, live_admin, write_file

pytestmark = pytest.mark.unit

TOKEN = secrets.token_urlsafe(32).encode()
ITEM_ID = "01J0000000000000000000000A"


class FakeUpload:
    """An UploadFile that records when its reader is opened and yields fixed chunks."""

    def __init__(self, relpath: str, chunks: list[bytes], *, size: int | None = None) -> None:
        self.relpath = relpath
        self._chunks = chunks
        self.size = sum(map(len, chunks)) if size is None else size
        self.opened = 0

    @contextmanager
    def open_reader(self, chunk_size: int = 65536) -> Iterator[Iterator[bytes]]:
        self.opened += 1
        yield iter(self._chunks)


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> AdminClient:
    return AdminClient(Path("/unused.sock"), TOKEN, transport=httpx.MockTransport(handler))


def _item(**extra: object) -> dict[str, object]:
    return {"id": ITEM_ID, "title": "t", "files": [], "viewer_url": None, **extra}


def _parse_multipart(body: bytes, content_type: str) -> list[tuple[str, str | None, bytes]]:
    """Split a multipart body into (name, filename, data) in wire order."""
    _, params = parse_options_header(content_type)
    boundary = b"--" + params[b"boundary"]
    parts = body.split(boundary)
    assert parts[0] == b""
    assert parts[-1] == b"--\r\n"
    out = []
    for raw in parts[1:-1]:
        head, _, data = raw[2:].partition(b"\r\n\r\n")
        assert data.endswith(b"\r\n")
        disposition = head.split(b"\r\n")[0]
        _, opts = parse_options_header(disposition.split(b":", 1)[1])
        filename = opts.get(b"filename")
        out.append(
            (opts[b"name"].decode(), None if filename is None else filename.decode(), data[:-2])
        )
    return out


# --- request shape ------------------------------------------------------------------


def test_bearer_token_on_every_request_and_never_in_repr() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "ok", "kinds": []})

    client = _client(handler)
    client.health()
    client.kinds()
    assert [r.headers["authorization"] for r in seen] == [f"Bearer {TOKEN.decode()}"] * 2
    assert TOKEN.decode() not in repr(client)


def test_accept_encoding_identity_on_every_request() -> None:
    # The admin API never compresses; asking for identity means the bytes
    # this client parses are exactly what MAX_RESPONSE_BYTES bounds, with no
    # decompression step in between (unit 10b follow-up, Info).
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "ok"})

    _client(handler).health()
    assert seen[0].headers["accept-encoding"] == "identity"


def test_publish_is_manifest_first_multipart_with_exact_length() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        captured["headers"] = request.headers
        return httpx.Response(201, json=_item())

    files = [
        FakeUpload("index.html", [b"<h1>", b"hi</h1>"]),
        FakeUpload("css/app.css", [b"body{}"]),
        FakeUpload("img/été.png", [b"\x89PNG\r\n--not-a-boundary\r\n"]),
    ]
    _client(handler).publish(
        files, title="Tîtle\nline2", description="d", kind_hint="html", pinned=True
    )
    headers = captured["headers"]
    body = captured["body"]
    assert isinstance(headers, httpx.Headers) and isinstance(body, bytes)
    assert int(headers["content-length"]) == len(body)
    assert "transfer-encoding" not in headers
    parts = _parse_multipart(body, headers["content-type"])
    names = [p[0] for p in parts]
    assert names == ["title", "description", "kind_hint", "pinned", "manifest"] + ["file"] * 3
    fields = {name: data for name, _, data in parts[:5]}
    assert fields["title"].decode() == "Tîtle\nline2"
    assert fields["pinned"] == b"true"
    manifest = json.loads(fields["manifest"])
    assert manifest == [f.relpath for f in files]
    assert [p[1] for p in parts[5:]] == manifest  # filename == next manifest entry
    assert [p[2] for p in parts[5:]] == [b"<h1>hi</h1>", b"body{}", files[2]._chunks[0]]


def test_publish_revision_is_manifest_first_multipart_with_exact_length() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = request.read()
        captured["headers"] = request.headers
        return httpx.Response(201, json=_item(revision=2))

    files = [FakeUpload("index.html", [b"<h1>v2</h1>"])]
    _client(handler).publish_revision(ITEM_ID, files, kind_hint="html", expected_revision=1)
    assert captured["path"] == f"/v1/items/{ITEM_ID}/revisions"
    headers = captured["headers"]
    body = captured["body"]
    assert isinstance(headers, httpx.Headers) and isinstance(body, bytes)
    assert int(headers["content-length"]) == len(body)
    parts = _parse_multipart(body, headers["content-type"])
    names = [p[0] for p in parts]
    assert names == ["kind_hint", "expected_revision", "manifest", "file"]
    fields = {name: data for name, _, data in parts[:3]}
    assert fields["kind_hint"] == b"html"
    assert fields["expected_revision"] == b"1"
    assert json.loads(fields["manifest"]) == ["index.html"]


def test_publish_revision_optional_fields_omitted() -> None:
    captured: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        captured["ct"] = request.headers["content-type"].encode()
        return httpx.Response(201, json=_item(revision=2))

    _client(handler).publish_revision(ITEM_ID, [FakeUpload("a.txt", [b"x"])])
    parts = _parse_multipart(captured["body"], captured["ct"].decode())
    assert [p[0] for p in parts] == ["manifest", "file"]


def test_publish_revision_item_id_validated_before_building_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not send")

    client = _client(handler)
    with pytest.raises(AdminInputError):
        client.publish_revision("../kinds", [FakeUpload("a.txt", [b"x"])])


def test_publish_revision_upload_size_mismatch_aborts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        return httpx.Response(201, json=_item(revision=2))

    with pytest.raises(AdminInputError) as exc:
        _client(handler).publish_revision(ITEM_ID, [FakeUpload("a.txt", [b"abc"], size=5)])
    assert exc.value.code == "upload_changed"


def test_optional_fields_omitted_and_pinned_false() -> None:
    captured: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read()
        captured["ct"] = request.headers["content-type"].encode()
        return httpx.Response(201, json=_item())

    _client(handler).publish([FakeUpload("a.txt", [b"x"])], title="t")
    parts = _parse_multipart(captured["body"], captured["ct"].decode())
    assert [p[0] for p in parts] == ["title", "pinned", "manifest", "file"]


def test_body_streams_chunks_lazily() -> None:
    """No whole-file buffering: each file is opened only when reached, chunk by chunk."""
    big = [b"a" * 1000] * 50
    first, second = FakeUpload("a.bin", big), FakeUpload("b.bin", [b"b" * 10])
    body = _PublishBody([first, second], [("title", "t")], chunk_size=1000)
    stream = iter(body)
    next(stream)  # fields incl. manifest
    assert (first.opened, second.opened) == (0, 0)
    next(stream)  # first file's part header
    pieces = [next(stream) for _ in range(50)]
    assert all(len(p) == 1000 for p in pieces)
    assert (first.opened, second.opened) == (1, 0)
    rest = list(stream)
    assert second.opened == 1
    assert len(b"".join(rest)) < 500  # only headers/terminators + 10 bytes left


def test_upload_size_mismatch_aborts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        request.read()
        return httpx.Response(201, json=_item())

    for upload in (
        FakeUpload("a.txt", [b"abc"], size=5),  # delivers fewer bytes than announced
        FakeUpload("a.txt", [b"abc", b"def"], size=4),  # more
    ):
        with pytest.raises(AdminInputError) as exc:
            _client(handler).publish([upload], title="t")
        assert exc.value.code == "upload_changed"


@pytest.mark.parametrize("bad", ['a"b.txt', "a\\b.txt", "a\r\nX-Evil: 1", "", "a\x00b"])
def test_unsafe_filename_refused_before_sending(bad: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not send")

    with pytest.raises(AdminInputError):
        _client(handler).publish([FakeUpload(bad, [b"x"])], title="t")


def test_empty_publish_refused() -> None:
    with pytest.raises(AdminInputError):
        _client(lambda r: httpx.Response(500)).publish([], title="t")


@pytest.mark.parametrize("item_id", ["../kinds", "01j0000000000000000000000a", "x" * 26, ""])
def test_item_id_validated_before_building_url(item_id: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not send")

    client = _client(handler)
    for call in (client.get_item, client.trash_item, client.restore_item):
        with pytest.raises(AdminInputError):
            call(item_id)


def test_list_params_and_limit_bounds() -> None:
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(200, json={"items": [], "next_cursor": None})

    client = _client(handler)
    client.list_items(state="trashed", kind="html", limit=5, cursor="abc&x=1")
    assert dict(seen[0].params) == {
        "state": "trashed",
        "kind": "html",
        "limit": "5",
        "cursor": "abc&x=1",
    }
    for limit in (0, 201):
        with pytest.raises(AdminInputError):
            client.list_items(limit=limit)


def test_update_sends_only_given_fields() -> None:
    bodies: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.read()))
        return httpx.Response(200, json=_item())

    client = _client(handler)
    client.update_item(ITEM_ID, pinned=False)
    client.update_item(ITEM_ID, title="n", description="")
    assert bodies == [{"pinned": False}, {"title": "n", "description": ""}]
    with pytest.raises(AdminInputError):
        client.update_item(ITEM_ID)


# --- error mapping ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, AdminInputError),
        (401, AdminAuthError),
        (403, AdminAuthError),
        (404, AdminNotFoundError),
        (408, AdminLimitError),
        (409, AdminConflictError),
        (413, AdminLimitError),
        (415, AdminInputError),
        (422, AdminRejectedError),
        (429, AdminLimitError),
        (500, AdminServerError),
        (502, AdminServerError),
        (302, AdminServerError),
    ],
)
def test_status_maps_to_typed_error(status: int, cls: type[AdminClientError]) -> None:
    body = {"error": "some_code", "message": "safe text", "request_id": "abc123"}
    handler = lambda r: httpx.Response(status, json=body)  # noqa: E731
    with pytest.raises(cls) as exc:
        _client(handler).get_item(ITEM_ID)
    assert exc.value.status == status
    assert exc.value.code == "some_code"
    assert exc.value.request_id == "abc123"
    assert "safe text" in str(exc.value)


def test_secret_rejection_carries_rule_and_relpath_only() -> None:
    body = {
        "error": "secret_detected",
        "message": "secret detected",
        "rule": "AWS access key id",
        "relpath": "conf.txt",
    }
    err = error_from_response(422, body)
    assert isinstance(err, AdminRejectedError)
    assert (err.rule, err.relpath) == ("AWS access key id", "conf.txt")
    assert "AWS access key id" in str(err) and "conf.txt" in str(err)


def test_429_retry_after() -> None:
    handler = lambda r: httpx.Response(  # noqa: E731
        429, json={"error": "rate_limited"}, headers={"Retry-After": "60"}
    )
    with pytest.raises(AdminLimitError) as exc:
        _client(handler).kinds()
    assert exc.value.retry_after == 60


def test_error_text_is_escaped_and_bounded() -> None:
    err = error_from_response(400, {"error": "x", "message": "a\u202eb\x1b[31m" + "z" * 5000})
    text = str(err)
    assert "\u202e" not in text and "\x1b" not in text
    assert len(text) < 500


@pytest.mark.parametrize("raw", [b"not json", b"", b"[1,2]", b'"str"'])
def test_non_json_error_bodies(raw: bytes) -> None:
    handler = lambda r: httpx.Response(500, content=raw)  # noqa: E731
    with pytest.raises(AdminServerError) as exc:
        _client(handler).kinds()
    assert exc.value.code == "http_500"


def test_malformed_success_body() -> None:
    handler = lambda r: httpx.Response(200, content=b"[]")  # noqa: E731
    with pytest.raises(AdminUnavailableError) as exc:
        _client(handler).kinds()
    assert exc.value.code == "bad_response"


def test_absurdly_nested_response_body_is_malformed_not_a_crash() -> None:
    # json.loads on deeply nested brackets raises RecursionError, not
    # ValueError; must be handled the same as any other malformed body
    # (unit 10b follow-up, Info), never propagate as an unhandled exception.
    nested = b"[" * 100_000
    handler = lambda r: httpx.Response(200, content=nested)  # noqa: E731
    with pytest.raises(AdminUnavailableError) as exc:
        _client(handler).kinds()
    assert exc.value.code == "bad_response"


def test_oversized_response_refused() -> None:
    handler = lambda r: httpx.Response(200, content=b" " * (MAX_RESPONSE_BYTES + 1))  # noqa: E731
    with pytest.raises(AdminUnavailableError):
        _client(handler).kinds()


@pytest.mark.parametrize("exc", [httpx.ConnectError("boom /secret/path"), httpx.ReadTimeout("t")])
def test_transport_errors_are_unavailable(exc: Exception) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    with pytest.raises(AdminUnavailableError) as info:
        _client(handler).kinds()
    assert "/secret/path" not in str(info.value)


def test_missing_socket_is_unavailable(tmp_path: Path) -> None:
    client = AdminClient(tmp_path / "nope.sock", TOKEN)
    with pytest.raises(AdminUnavailableError) as exc:
        client.health()
    assert TOKEN.decode() not in str(exc.value)


# --- token file (shared C12 loader) ------------------------------------------------


def test_from_settings_refuses_insecure_token_file(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    write_token(settings.admin_token_file, mode=0o644)
    with pytest.raises(TokenFileError):
        AdminClient.from_settings(settings)


def test_from_settings_refuses_symlinked_token(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    real = tmp_path / "secrets" / "real.token"
    write_token(real)
    os.symlink(real, settings.admin_token_file)
    with pytest.raises(TokenFileError):
        AdminClient.from_settings(settings)


# --- against a real admin API on a Unix socket ---------------------------------------


def test_round_trip_against_real_admin(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        site = admin.outbox / "site"
        write_file(site / "index.html", "<link href=css/app.css><h1>hi</h1>")
        write_file(site / "css" / "app.css", "h1{color:red}")
        with admin.client() as client:
            assert client.health() == {"status": "ok"}
            kinds = client.kinds()["kinds"]
            assert isinstance(kinds, list)
            assert any(k.get("name") == "html" for k in kinds)
            with admin.intake().collect([str(site)]) as bundle:
                item = client.publish(bundle.files, title="Site", pinned=True, chunk_size=7)
            assert item["kind"] == "html"
            assert item["pinned"] is True
            files = item["files"]
            assert isinstance(files, list)
            assert [f["relpath"] for f in files] == ["css/app.css", "index.html"]
            assert str(item["viewer_url"]).endswith(f"/#/item/{item['id']}")
            item_id = str(item["id"])
            assert client.get_item(item_id)["title"] == "Site"
            assert client.update_item(item_id, title="Renamed")["title"] == "Renamed"
            assert client.trash_item(item_id)["state"] == "trashed"
            with pytest.raises(AdminConflictError):
                client.update_item(item_id, title="x")
            assert client.list_items()["items"] == []
            assert len(client.list_items(state="trashed")["items"]) == 1  # type: ignore[arg-type]
            assert client.restore_item(item_id)["state"] == "active"
            with pytest.raises(AdminNotFoundError):
                client.get_item("01J0000000000000000000000Z")


def test_wrong_token_is_auth_error(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        wrong = secrets.token_urlsafe(32).encode()
        with (
            AdminClient(admin.settings.admin_socket, wrong) as client,
            pytest.raises(AdminAuthError) as exc,
        ):
            client.health()
        assert exc.value.status == 401
        assert wrong.decode() not in str(exc.value)
        assert admin.token not in str(exc.value)


def test_secret_content_rejected_by_admin(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        f = write_file(admin.outbox / "conf.txt", f"key = {fake_aws_key()}\n")
        with admin.client() as client, admin.intake().collect([str(f)]) as bundle:
            with pytest.raises(AdminRejectedError) as exc:
                client.publish(bundle.files, title="conf")
            assert exc.value.rule == "AWS access key id"
            assert exc.value.relpath == "conf.txt"
            assert fake_aws_key() not in str(exc.value)
            assert client.list_items()["items"] == []


def test_file_changed_mid_upload_rolls_back(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        f = write_file(admin.outbox / "a.txt", b"x" * 60_000)
        with admin.client() as client, admin.intake().collect([str(f)]) as bundle:
            os.truncate(f, 10)  # shrinks after intake measured it
            with pytest.raises(IntakeError) as exc:
                client.publish(bundle.files, title="t", chunk_size=4096)
            assert exc.value.code is IntakeErrorCode.CHANGED
            assert client.list_items()["items"] == []


def test_fake_upload_short_read_rolls_back(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin, admin.client() as client:
        with pytest.raises(AdminInputError):
            client.publish([FakeUpload("a.txt", [b"abc"], size=50)], title="t")
        assert client.list_items()["items"] == []


def test_publish_revision_round_trip_against_real_admin(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        f1 = write_file(admin.outbox / "v1" / "index.html", "<h1>v1</h1>")
        with admin.client() as client:
            with admin.intake().collect([str(f1)], base=str(f1.parent)) as bundle:
                item = client.publish(bundle.files, title="Page")
            item_id = str(item["id"])
            assert item["revision"] == 1

            f2 = write_file(admin.outbox / "v2" / "index.html", "<h1>v2</h1>")
            with admin.intake().collect([str(f2)], base=str(f2.parent)) as bundle:
                revised = client.publish_revision(item_id, bundle.files, expected_revision=1)
            assert revised["revision"] == 2
            assert revised["id"] == item_id
            assert revised["title"] == "Page"  # unchanged: only content moves

            # A stale expected_revision is refused, not silently applied.
            with (
                admin.intake().collect([str(f2)], base=str(f2.parent)) as bundle,
                pytest.raises(AdminConflictError) as exc,
            ):
                client.publish_revision(item_id, bundle.files, expected_revision=1)
            assert exc.value.code == "conflict"

            client.trash_item(item_id)
            with (
                admin.intake().collect([str(f2)], base=str(f2.parent)) as bundle,
                pytest.raises(AdminConflictError) as exc,
            ):
                client.publish_revision(item_id, bundle.files)
            assert exc.value.code == "invalid_state"


def test_publish_revision_unknown_item_is_not_found(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin, admin.client() as client:
        f = write_file(admin.outbox / "a.txt", "x")
        with admin.intake().collect([str(f)]) as bundle, pytest.raises(AdminNotFoundError):
            client.publish_revision("01J0000000000000000000000Z", bundle.files)


def test_from_settings_token_group_must_be_trusted(tmp_path: Path) -> None:
    """A root:<service group> 0640 token file needs that group passed explicitly."""
    settings = make_settings(tmp_path)
    write_token(settings.admin_token_file, mode=0o640)
    foreign_gid = 54321
    os.chown(settings.admin_token_file, 0, foreign_gid)
    with pytest.raises(TokenFileError):
        AdminClient.from_settings(settings)
    AdminClient.from_settings(settings, token_gids=(foreign_gid,)).close()
