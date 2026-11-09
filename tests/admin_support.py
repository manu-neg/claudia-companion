"""Shared helpers for admin API tests: settings over a tmp data dir, app, client, forms.

Builds the real admin core (`bootstrap.build_core(role="admin")`, real
SQLite + filesystem adapters) and the real admin app, served in-process by
Starlette's TestClient. Also builds multipart publish bodies by hand so
tests control part order, headers and sizes exactly.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from starlette.testclient import TestClient

from preview_dashboard.bootstrap import AdminCore, build_core
from preview_dashboard.config import Settings
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.multipart import PublishFormLimits


class ResponseLike(Protocol):
    """What tests read from a response (TestClient uses `httpx2`, the UDS client `httpx`)."""

    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def json(self) -> Any: ...  # arbitrary JSON


DASHBOARD_HOST = "dash.example.ts.net"
BOUNDARY = "pdashtestboundary7MA4YWxkTrZu0gW"

SMALL_LIMITS: dict[str, Any] = {
    "max_files": 10,
    "max_file_bytes": 64 * 1024,
    "max_item_bytes": 256 * 1024,
    "max_total_bytes": 4 * 1024 * 1024,
    "max_items": 50,
    "publish_rate_per_hour": 100,
    "min_free_disk_bytes": 1024,
}


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Settings over `tmp_path/data` (created 0750) with small limits."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o750, exist_ok=True)
    os.chmod(data_dir, 0o750)  # noqa: S103 - group read is the production layout
    options: dict[str, Any] = {
        "data_dir": data_dir,
        "allowed_hosts": frozenset({DASHBOARD_HOST}),
        "admin_token_file": tmp_path / "secrets" / "admin.token",
        "admin_socket": tmp_path / "run" / "admin.sock",
        **SMALL_LIMITS,
        **overrides,
    }
    return Settings(**options)


def write_token(path: Path, token: str | None = None, *, mode: int = 0o600) -> str:
    """Write a token file (creating its 0700 parent); return the token."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = token if token is not None else secrets.token_urlsafe(32)
    path.write_text(value + "\n")
    os.chmod(path, mode)
    return value


@contextmanager
def admin_client(
    tmp_path: Path,
    *,
    allowed_peer_uids: Sequence[int] = (),
    form_limits: PublishFormLimits | None = None,
    **overrides: Any,
) -> Iterator[tuple[TestClient, str, AdminCore]]:
    """Yield `(client, token, core)` for a fresh admin app over a tmp data dir."""
    settings = make_settings(tmp_path, **overrides)
    token = secrets.token_urlsafe(32)
    with build_core(settings, role="admin") as core:
        app = build_admin_app(
            core,
            token=token.encode("ascii"),
            allowed_peer_uids=allowed_peer_uids,
            form_limits=form_limits,
        )
        with TestClient(app, base_url="http://admin.local") as client:
            yield client, token, core


def auth(token: str) -> dict[str, str]:
    """Authorization header for `token`."""
    return {"Authorization": f"Bearer {token}"}


def multipart_body(
    fields: Sequence[tuple[str, str | bytes]],
    files: Sequence[tuple[str, bytes]] = (),
    *,
    boundary: str = BOUNDARY,
    file_field: str = "file",
    extra_part_headers: Sequence[str] = (),
) -> bytes:
    """Build a multipart/form-data body: fields first (in order), then files."""
    out = bytearray()
    for name, value in fields:
        data = value.encode("utf-8") if isinstance(value, str) else value
        out += f"--{boundary}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"\r\n'.encode()
        for header in extra_part_headers:
            out += f"{header}\r\n".encode()
        out += b"\r\n" + data + b"\r\n"
    for relpath, data in files:
        out += f"--{boundary}\r\n".encode()
        out += (
            f'Content-Disposition: form-data; name="{file_field}"; filename="{relpath}"\r\n'
        ).encode()
        out += b"Content-Type: application/octet-stream\r\n\r\n"
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out)


def publish_body(
    files: Sequence[tuple[str, bytes]],
    *,
    title: str = "A title",
    description: str | None = None,
    kind_hint: str | None = None,
    pinned: bool | None = None,
    manifest: Sequence[str] | None = None,
) -> bytes:
    """A well-formed publish body; `manifest` defaults to the files' relpaths."""
    fields: list[tuple[str, str | bytes]] = [("title", title)]
    if description is not None:
        fields.append(("description", description))
    if kind_hint is not None:
        fields.append(("kind_hint", kind_hint))
    if pinned is not None:
        fields.append(("pinned", "true" if pinned else "false"))
    names = [p for p, _ in files] if manifest is None else list(manifest)
    fields.append(("manifest", json.dumps(names, ensure_ascii=False)))
    return multipart_body(fields, files)


def revision_body(
    files: Sequence[tuple[str, bytes]],
    *,
    kind_hint: str | None = None,
    expected_revision: str | None = None,
    manifest: Sequence[str] | None = None,
) -> bytes:
    """A well-formed `POST /v1/items/{id}/revisions` body (fields, then files)."""
    fields: list[tuple[str, str | bytes]] = []
    if kind_hint is not None:
        fields.append(("kind_hint", kind_hint))
    if expected_revision is not None:
        fields.append(("expected_revision", expected_revision))
    names = [p for p, _ in files] if manifest is None else list(manifest)
    fields.append(("manifest", json.dumps(names, ensure_ascii=False)))
    return multipart_body(fields, files)


def multipart_headers(token: str, *, boundary: str = BOUNDARY) -> dict[str, str]:
    """Auth + multipart Content-Type headers."""
    return {**auth(token), "Content-Type": f"multipart/form-data; boundary={boundary}"}


def publish(
    client: TestClient, token: str, files: Sequence[tuple[str, bytes]], **kwargs: Any
) -> Any:
    """POST a publish request; returns the response."""
    return client.post(
        "/v1/items", content=publish_body(files, **kwargs), headers=multipart_headers(token)
    )


def revise(
    client: TestClient,
    token: str,
    item_id: str,
    files: Sequence[tuple[str, bytes]],
    **kwargs: Any,
) -> Any:
    """POST a new revision of `item_id`; returns the response."""
    return client.post(
        f"/v1/items/{item_id}/revisions",
        content=revision_body(files, **kwargs),
        headers=multipart_headers(token),
    )


@contextmanager
def running_admin_server(app: Any, socket_path: Path, **overrides: Any) -> Iterator[Any]:
    """Serve `app` with the production uvicorn config on a real Unix socket (thread).

    Yields the `uvicorn.Server`; stops it and removes the socket on exit.
    """
    import threading
    import time

    import uvicorn

    from preview_dashboard.interfaces.admin.server import admin_socket, uvicorn_config

    socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    with admin_socket(socket_path) as sock:
        server = uvicorn.Server(uvicorn_config(app, **overrides))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline or not thread.is_alive():
                raise RuntimeError("admin test server did not start")
            time.sleep(0.01)
        try:
            yield server
        finally:
            server.should_exit = True
            thread.join(timeout=10)


def uds_client(socket_path: Path) -> Any:
    """An httpx client talking HTTP over the Unix socket."""
    import httpx

    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(socket_path)), base_url="http://admin.local"
    )
