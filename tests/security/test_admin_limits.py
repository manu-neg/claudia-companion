"""Security tests for admin publish limits (C11, C15, C18, C26).

Oversize bodies/files/fields/manifests → 413 counted on the stream (never
trusting Content-Length), too many parts → 413, quota → 413, rate limit →
429, secrets → 422 with a neutral label and no secret in the response,
slow (slowloris) clients → 408 with everything rolled back.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import secrets
import select
import socket
import time
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient
from starlette.types import ASGIApp

from preview_dashboard.bootstrap import AdminCore, build_core
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.multipart import MAX_FIELD_BYTES, PublishFormLimits
from tests.admin_support import (
    BOUNDARY,
    ResponseLike,
    admin_client,
    auth,
    make_settings,
    multipart_body,
    multipart_headers,
    publish,
    publish_body,
    running_admin_server,
    uds_client,
)

pytestmark = pytest.mark.security

# Built at runtime so no secret-shaped literal sits in the repo (gitleaks).
FAKE_AWS_KEY = "AK" + "IA" + "QZ7XW4B2" + "MLKH3VDN"


def _blob_files(tmp_path: Path) -> list[Path]:
    root = tmp_path / "data"
    return [p for sub in ("blobs", "staging") for p in (root / sub).rglob("*") if p.is_file()]


def _items(client: TestClient | httpx.Client, token: str) -> list[dict[str, object]]:
    items: list[dict[str, object]] = client.get("/v1/items", headers=auth(token)).json()["items"]
    return items


def _tight(tmp_path: Path, **changes: object) -> PublishFormLimits:
    base = PublishFormLimits.for_settings(make_settings(tmp_path))
    return dataclasses.replace(base, **changes)  # type: ignore[arg-type]


class TestSizeLimits:
    def test_file_over_per_file_limit_is_413_and_rolled_back(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            response = publish(client, token, [("big.bin", b"x" * (64 * 1024 + 1))])
            assert response.status_code == 413
            assert response.json()["error"] == "limit_exceeded"
            assert _items(client, token) == []
        assert _blob_files(tmp_path) == []

    def test_body_limit_counts_streamed_bytes_despite_lying_content_length(self, tmp_path):
        limits = _tight(tmp_path, max_body_bytes=1000)
        with admin_client(tmp_path, form_limits=limits) as (client, token, _):
            body = publish_body([("a.bin", b"x" * 2000)])
            response = client.post(
                "/v1/items",
                content=body,
                headers={**multipart_headers(token), "Content-Length": "10"},
            )
            assert response.status_code == 413
            assert response.json()["message"] == "request body too large"
            assert _items(client, token) == []
        assert _blob_files(tmp_path) == []

    def test_declared_oversize_content_length_rejected_up_front(self, tmp_path):
        limits = _tight(tmp_path, max_body_bytes=1000)
        with admin_client(tmp_path, form_limits=limits) as (client, token, _):
            response = client.post(
                "/v1/items",
                content=publish_body([("a.txt", b"x")]),
                headers={**multipart_headers(token), "Content-Length": "999999999"},
            )
        assert response.status_code == 413

    def test_too_many_parts_is_413(self, tmp_path):
        with admin_client(tmp_path, max_files=3) as (client, token, _):
            fields = [
                ("title", "t"),
                ("description", "d"),
                ("kind_hint", "text"),
                ("pinned", "false"),
                ("folder_id", ""),
                ("manifest", json.dumps(["a.txt", "b.txt", "c.txt"])),
            ]
            # Cap = max_files + 6 fields = 9; the 4th file is the 10th part.
            files = [(f"{n}.txt", b"x") for n in "abcd"]
            response = client.post(
                "/v1/items", content=multipart_body(fields, files), headers=multipart_headers(token)
            )
            assert response.status_code == 413
            assert "form parts" in response.json()["message"]
            assert _items(client, token) == []

    def test_manifest_with_too_many_files_is_413(self, tmp_path):
        with admin_client(tmp_path, max_files=2) as (client, token, _):
            files = [(f"{n}.txt", b"x") for n in "abc"]
            assert publish(client, token, files).status_code == 413

    def test_huge_field_is_413(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            response = publish(client, token, [("a.txt", b"x")], title="t" * (MAX_FIELD_BYTES + 1))
        assert response.status_code == 413
        assert "t" * 100 not in response.text  # never echoed

    def test_huge_manifest_is_413(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            # JSON whitespace padding: valid JSON, but over the manifest byte cap.
            manifest = "[" + " " * 40_000 + '"a.txt"]'
            body = multipart_body([("title", "t"), ("manifest", manifest)], [("a.txt", b"x")])
            response = client.post("/v1/items", content=body, headers=multipart_headers(token))
        assert response.status_code == 413

    def test_too_many_part_headers_is_400(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            body = multipart_body(
                [("title", "t"), ("manifest", '["a.txt"]')],
                [("a.txt", b"x")],
                extra_part_headers=[f"X-Pad-{n}: 1" for n in range(8)],
            )
            response = client.post("/v1/items", content=body, headers=multipart_headers(token))
        assert response.status_code == 400

    def test_oversized_part_header_is_400(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            body = multipart_body(
                [("title", "t"), ("manifest", '["a.txt"]')],
                [("a.txt", b"x")],
                extra_part_headers=["X-Pad: " + "a" * 8192],
            )
            response = client.post("/v1/items", content=body, headers=multipart_headers(token))
        assert response.status_code == 400

    def test_item_quota_is_413(self, tmp_path):
        with admin_client(tmp_path, max_items=1) as (client, token, _):
            assert publish(client, token, [("a.txt", b"x")]).status_code == 201
            response = publish(client, token, [("b.txt", b"x")])
            assert response.status_code == 413
            assert "quota" in response.json()["message"]


class TestRateLimit:
    def test_rate_limit_is_429_with_retry_after(self, tmp_path):
        with admin_client(tmp_path, publish_rate_per_hour=2) as (client, token, _):
            assert publish(client, token, [("a.txt", b"x")]).status_code == 201
            # Failed attempts count too (probing the scan is not free).
            assert publish(client, token, [("../b.txt", b"x")]).status_code == 400
            response = publish(client, token, [("c.txt", b"x")])
            assert response.status_code == 429
            assert response.json()["error"] == "rate_limited"
            assert int(response.headers["retry-after"]) > 0
            assert len(_items(client, token)) == 1


class TestSecretScan:
    def _assert_rejected(self, response: ResponseLike) -> None:
        assert response.status_code == 422
        body = response.json()
        assert body["error"] == "secret_detected"
        assert body["rule"] == "AWS access key id"
        assert FAKE_AWS_KEY not in response.text
        assert FAKE_AWS_KEY[:8] not in response.text

    def test_secret_in_file_content(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            data = b"x" * 70_000 + f" key={FAKE_AWS_KEY} ".encode() + b"y" * 10
            response = publish(client, token, [("ok.txt", b"fine"), ("conf.txt", data[-100:])])
            self._assert_rejected(response)
            assert response.json()["relpath"] == "conf.txt"
            assert _items(client, token) == []
        assert _blob_files(tmp_path) == []

    def test_secret_in_title_description_or_relpath(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            self._assert_rejected(publish(client, token, [("a.txt", b"x")], title=FAKE_AWS_KEY))
            self._assert_rejected(
                publish(client, token, [("a.txt", b"x")], description=f"see {FAKE_AWS_KEY}")
            )
            relpath_hit = publish(client, token, [(f"{FAKE_AWS_KEY}.txt", b"x")])
            self._assert_rejected(relpath_hit)
            # A match in the metadata carries no relpath: the key is omitted.
            assert "relpath" not in relpath_hit.json()
            assert _items(client, token) == []

    def test_secret_in_patch_is_rejected_and_item_unchanged(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            item = publish(client, token, [("a.txt", b"x")], description="clean").json()
            response = client.patch(
                f"/v1/items/{item['id']}",
                json={"description": f"oops {FAKE_AWS_KEY}"},
                headers=auth(token),
            )
            self._assert_rejected(response)
            fetched = client.get(f"/v1/items/{item['id']}", headers=auth(token)).json()
            assert fetched["description"] == "clean"

    def test_patch_body_limit(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            item = publish(client, token, [("a.txt", b"x")]).json()
            response = client.patch(
                f"/v1/items/{item['id']}",
                content=json.dumps({"description": "d" * 70_000}).encode(),
                headers={**auth(token), "Content-Type": "application/json"},
            )
        assert response.status_code == 413


class TestDeepJson:
    """Absurdly nested JSON is a 400, never a RecursionError → 500 (C26)."""

    def test_deeply_nested_patch_body_is_400(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            item = publish(client, token, [("a.txt", b"x")]).json()
            depth = 30_000  # ~60 KB: under the 64 KiB body cap, far over the recursion limit
            body = b'{"title": ' + b"[" * depth + b"]" * depth + b"}"
            response = client.patch(
                f"/v1/items/{item['id']}",
                content=body,
                headers={**auth(token), "Content-Type": "application/json"},
            )
            assert response.status_code == 400
            assert response.json()["error"] == "invalid_input"

    def test_deeply_nested_manifest_is_400_and_stores_nothing(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            depth = 15_000  # under the manifest cap for 10 files
            fields: list[tuple[str, str | bytes]] = [
                ("title", "t"),
                ("manifest", "[" * depth + "]" * depth),
            ]
            response = client.post(
                "/v1/items",
                content=multipart_body(fields, [("a.txt", b"x")]),
                headers=multipart_headers(token),
            )
            assert response.status_code == 400
            assert _items(client, token) == []
        assert _blob_files(tmp_path) == []


class TestClientDisconnect:
    """A client vanishing mid-upload: rollback, one quiet INFO line, nothing sensitive logged."""

    MARKER = b"BODY-MARKER-" + b"q" * 64

    def test_disconnect_mid_upload_is_quiet_and_rolled_back(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)
        settings = make_settings(tmp_path)
        token = secrets.token_urlsafe(32)
        body = publish_body([("a.bin", self.MARKER * 200)])
        head = (
            "POST /v1/items HTTP/1.1\r\nHost: admin.local\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode()
        sock_path = tmp_path / "run" / "admin.sock"
        with build_core(settings, role="admin") as core:
            app = build_admin_app(core, token=token.encode())
            with running_admin_server(app, sock_path):
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                with client:
                    client.connect(str(sock_path))
                    client.sendall(head + body[: len(body) // 2])  # well into the file part
                    time.sleep(0.2)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not self._disconnect_lines(caplog):
                    time.sleep(0.05)
                with uds_client(sock_path) as http:
                    assert _items(http, token) == []
        assert _blob_files(tmp_path) == []
        lines = self._disconnect_lines(caplog)
        assert len(lines) == 1
        assert lines[0].levelno == logging.INFO
        records = [r for r in caplog.records if not r.name.startswith("httpx")]
        assert not [r for r in records if r.exc_info or r.levelno >= logging.ERROR]
        text = "\n".join(caplog.text.splitlines() + [r.getMessage() for r in records])
        assert "Traceback" not in text
        assert token not in text
        assert "BODY-MARKER" not in text
        assert "qqqq" not in text

    @staticmethod
    def _disconnect_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
        return [r for r in caplog.records if "ClientDisconnectedError" in r.getMessage()]


class TestSlowClient:
    """Slowloris: a stalled body must not pin a publish (quota, thread, staging file)."""

    def _serve(self, tmp_path: Path, **limit_changes: object) -> tuple[AdminCore, ASGIApp, str]:
        settings = make_settings(tmp_path)
        core = build_core(settings, role="admin")
        token = secrets.token_urlsafe(32)
        limits = _tight(tmp_path, **limit_changes)
        app = build_admin_app(core, token=token.encode(), form_limits=limits)
        return core, app, token

    def _stalled_request(self, sock_path: Path, token: str, *, drip: float | None) -> bytes:
        body = publish_body([("a.bin", b"x" * 5000)])
        head = (
            "POST /v1/items HTTP/1.1\r\nHost: admin.local\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(10)
        with client:
            client.connect(str(sock_path))
            # Send everything up to the middle of the file part, then stall/drip.
            client.sendall(head + body[: len(body) - 2500])
            if drip is not None:
                deadline = time.monotonic() + 5
                for byte in body[len(body) - 2500 :]:
                    if select.select([client], [], [], 0)[0]:
                        break  # the server answered: stop dripping
                    try:
                        client.sendall(bytes([byte]))
                    except OSError:
                        break  # server gave up on us: expected
                    time.sleep(drip)
                    if time.monotonic() > deadline:
                        break
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = client.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response

    def test_stalled_body_times_out_and_rolls_back(self, tmp_path):
        core, app, token = self._serve(tmp_path, read_timeout=0.3)
        sock_path = tmp_path / "run" / "admin.sock"
        with core, running_admin_server(app, sock_path):
            started = time.monotonic()
            response = self._stalled_request(sock_path, token, drip=None)
            assert response.startswith(b"HTTP/1.1 408")
            assert time.monotonic() - started < 5
            with uds_client(sock_path) as client:
                # Quota/rate reservation released and nothing left on disk.
                assert _items(client, token) == []
                assert publish(client, token, [("ok.txt", b"x")]).status_code == 201
        assert len(_blob_files(tmp_path)) == 1

    def test_dripping_body_hits_total_deadline(self, tmp_path):
        core, app, token = self._serve(tmp_path, read_timeout=1.0, total_timeout=0.6)
        sock_path = tmp_path / "run" / "admin.sock"
        with core, running_admin_server(app, sock_path):
            started = time.monotonic()
            response = self._stalled_request(sock_path, token, drip=0.05)
            assert response.startswith(b"HTTP/1.1 408")
            assert time.monotonic() - started < 5
            with uds_client(sock_path) as client:
                assert _items(client, token) == []
        assert _blob_files(tmp_path) == []
