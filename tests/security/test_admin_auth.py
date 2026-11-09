"""Security tests for admin API authentication and surface (C12, C19, C21, C26, C29).

Bearer token: missing/wrong/malformed → 401 before routing, constant-time
digest comparison, token file refusals. Surface: no docs/OpenAPI, no
cookies/CORS, generic 500s. Logs never contain the token or Authorization.
Unix socket: exact 0660 mode, safe binding, SO_PEERCRED allowlist, hardened
uvicorn (no Server header).
"""

from __future__ import annotations

import errno
import hmac
import logging
import os
import secrets
import socket
import stat
from pathlib import Path

import pytest
from starlette.types import ASGIApp

from preview_dashboard.bootstrap import AdminCore
from preview_dashboard.interfaces.admin.app import build_admin_app
from preview_dashboard.interfaces.admin.auth import (
    MIN_TOKEN_CHARS,
    PeerCredentials,
    TokenFileError,
    TokenVerifier,
    load_admin_token,
    read_peer_credentials,
)
from preview_dashboard.interfaces.admin.server import (
    SOCKET_MODE,
    UnsafeSocketPathError,
    bind_admin_socket,
    uvicorn_config,
)
from tests.admin_support import (
    admin_client,
    auth,
    make_settings,
    publish,
    running_admin_server,
    uds_client,
    write_token,
)

pytestmark = pytest.mark.security

# A gid that is neither root nor ours (used only where we can chgrp: as root).
_FOREIGN_GID = os.getegid() + 4242 if os.getegid() else 4242


# --- bearer token on requests -----------------------------------------------------


class TestBearerToken:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer wrong-token-" + "x" * 40},
            {"Authorization": "Bearer "},
            {"Authorization": "Basic dXNlcjpwYXNz"},
            {"Authorization": "Token abc"},
        ],
        ids=["missing", "wrong", "empty", "basic", "other-scheme"],
    )
    def test_bad_credentials_are_401(self, tmp_path, headers):
        with admin_client(tmp_path) as (client, _, _):
            response = client.get("/v1/items", headers=headers)
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
        assert set(response.json()) == {"error", "request_id"}

    def test_token_variants_are_401(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            for value in (f"Bearer  {token}", f"Bearer {token} ", f"Bearer {token[:-1]}"):
                assert client.get("/v1/items", headers={"Authorization": value}).status_code == 401

    def test_duplicate_authorization_headers_are_401(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            headers = [("Authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")]
            assert client.get("/v1/items", headers=headers).status_code == 401

    def test_scheme_is_case_insensitive(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            response = client.get("/v1/health", headers={"Authorization": f"bearer {token}"})
        assert response.status_code == 200

    def test_auth_runs_before_routing(self, tmp_path):
        with admin_client(tmp_path) as (client, _, _):
            for path in ("/nope", "/v1/items/" + "0" * 26, "/docs"):
                assert client.get(path).status_code == 401
            assert client.delete("/v1/items/x").status_code == 401

    def test_publish_without_token_stores_nothing(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            response = publish(client, "x" * 43, [("a.txt", b"x")])
            assert response.status_code == 401
            assert client.get("/v1/items", headers=auth(token)).json()["items"] == []

    def test_comparison_is_constant_time_over_fixed_size_digests(self, monkeypatch):
        calls: list[tuple[int, int]] = []
        real = hmac.compare_digest

        def spy(a: bytes, b: bytes) -> bool:
            calls.append((len(a), len(b)))
            return bool(real(a, b))

        # auth looks the function up on the module at call time.
        monkeypatch.setattr(hmac, "compare_digest", spy)
        token = secrets.token_urlsafe(32).encode()
        verifier = TokenVerifier(token)
        for values in ([], [b"Bearer x"], [b"Bearer " + token * 10], [b"a", b"b"], [b"Basic t"]):
            assert verifier.verify(values) is False
        assert verifier.verify([b"Bearer " + token]) is True
        # Exactly one comparison per request, always of two 32-byte digests.
        assert calls == [(32, 32)] * 6

    def test_verifier_refuses_short_token(self):
        with pytest.raises(ValueError, match="short"):
            TokenVerifier(b"short")

    def test_verifier_refuses_low_variety_token(self):
        with pytest.raises(ValueError, match="distinct"):
            TokenVerifier(b"abcdefghijklmno" * 4)  # 60 chars, 15 distinct


# --- token file ------------------------------------------------------------------------


class TestTokenFile:
    def test_accepts_0640_and_0600(self, tmp_path):
        for mode in (0o640, 0o600, 0o400):
            path = tmp_path / f"t{mode:o}" / "admin.token"
            token = write_token(path, mode=mode)
            assert load_admin_token(path) == token.encode()

    @pytest.mark.parametrize("mode", [0o660, 0o644, 0o604, 0o602, 0o666], ids=lambda m: f"{m:o}")
    def test_refuses_group_writable_or_world_accessible(self, tmp_path, mode):
        path = tmp_path / "s" / "admin.token"
        write_token(path, mode=mode)
        with pytest.raises(TokenFileError, match="group-writable or accessible by others"):
            load_admin_token(path)

    def test_refuses_symlink(self, tmp_path):
        target = tmp_path / "s" / "real.token"
        write_token(target)
        link = tmp_path / "s" / "admin.token"
        link.symlink_to(target)
        with pytest.raises(TokenFileError, match="cannot open"):
            load_admin_token(link)

    def test_refuses_directory_and_fifo(self, tmp_path):
        directory = tmp_path / "s" / "dir.token"
        directory.mkdir(parents=True, mode=0o700)
        with pytest.raises(TokenFileError):
            load_admin_token(directory)
        fifo = tmp_path / "s" / "fifo.token"
        os.mkfifo(fifo, 0o600)
        with pytest.raises(TokenFileError, match="not a regular file"):
            load_admin_token(fifo)  # O_NONBLOCK: must not hang

    def test_refuses_missing_file(self, tmp_path):
        with pytest.raises(TokenFileError, match="cannot open"):
            load_admin_token(tmp_path / "missing.token")

    @pytest.mark.parametrize(
        "content",
        ["", "\n", "x" * (MIN_TOKEN_CHARS - 1), "has space " + "x" * 50, "é" * 50, "a\nb" * 30],
        ids=["empty", "newline", "short", "space", "non-ascii", "multi-line"],
    )
    def test_refuses_empty_short_or_malformed_tokens(self, tmp_path, content):
        path = tmp_path / "s" / "admin.token"
        write_token(path, content)
        with pytest.raises(TokenFileError) as info:
            load_admin_token(path)
        assert content.strip() == "" or content.strip() not in str(info.value)

    @pytest.mark.parametrize("content", ["x" * 60, "ab" * 30, "abcdefghijklmno" * 4])
    def test_refuses_low_variety_tokens(self, tmp_path, content):
        path = tmp_path / "s" / "admin.token"
        write_token(path, content)
        with pytest.raises(TokenFileError, match="distinct") as info:
            load_admin_token(path)
        assert content not in str(info.value)

    def test_accepts_sixteen_distinct_characters(self, tmp_path):
        path = tmp_path / "s" / "admin.token"
        token = write_token(path, "abcdefghijklmnop" * 3)
        assert load_admin_token(path) == token.encode()

    def test_refuses_a_file_carrying_a_posix_acl(self, tmp_path, monkeypatch):
        """F-C item 3: a POSIX ACL can grant read access invisible in
        `st_mode`; `os.listxattr` is monkeypatched since this repo's tmpfs
        may not support ACLs at all."""
        path = tmp_path / "s" / "admin.token"
        write_token(path)
        monkeypatch.setattr(os, "listxattr", lambda fd: ["user.other", "system.posix_acl_access"])
        with pytest.raises(TokenFileError, match="POSIX ACL"):
            load_admin_token(path)

    def test_accepts_a_file_with_unrelated_xattrs_but_no_acl(self, tmp_path, monkeypatch):
        path = tmp_path / "s" / "admin.token"
        token = write_token(path)
        monkeypatch.setattr(os, "listxattr", lambda fd: ["user.other"])
        assert load_admin_token(path) == token.encode()

    def test_treats_listxattr_enotsup_as_no_acl(self, tmp_path, monkeypatch):
        """Filesystems without xattr support at all raise ENOTSUP/EOPNOTSUPP
        on the *first* xattr call -- that means "no ACL", not an error."""
        path = tmp_path / "s" / "admin.token"
        token = write_token(path)

        def _raise(fd):
            raise OSError(errno.ENOTSUP, "Operation not supported")

        monkeypatch.setattr(os, "listxattr", _raise)
        assert load_admin_token(path) == token.encode()

    def test_refuses_on_an_unexpected_listxattr_error(self, tmp_path, monkeypatch):
        path = tmp_path / "s" / "admin.token"
        write_token(path)

        def _raise(fd):
            raise OSError(errno.EIO, "I/O error")

        monkeypatch.setattr(os, "listxattr", _raise)
        with pytest.raises(TokenFileError, match="cannot check ACLs"):
            load_admin_token(path)

    @pytest.mark.skipif(os.geteuid() != 0, reason="chgrp to a foreign group needs root")
    def test_refuses_untrusted_group_unless_trusted(self, tmp_path):
        foreign = _FOREIGN_GID
        path = tmp_path / "s" / "admin.token"
        token = write_token(path, mode=0o640)
        os.chown(path, -1, foreign)
        with pytest.raises(TokenFileError, match="untrusted group"):
            load_admin_token(path)
        os.chmod(path, 0o600)  # the group is checked even without g+r
        with pytest.raises(TokenFileError, match="untrusted group"):
            load_admin_token(path)
        assert load_admin_token(path, trusted_gids={foreign}) == token.encode()

    def test_accepts_root_or_own_group(self, tmp_path):
        path = tmp_path / "s" / "admin.token"
        token = write_token(path, mode=0o640)
        assert os.stat(path).st_gid in {0, os.getegid()}
        assert load_admin_token(path) == token.encode()

    def test_refuses_oversized_file(self, tmp_path):
        path = tmp_path / "s" / "admin.token"
        write_token(path, "x" * 5000)
        with pytest.raises(TokenFileError, match="too large"):
            load_admin_token(path)

    def test_refuses_untrusted_owner(self, tmp_path):
        path = tmp_path / "s" / "admin.token"
        write_token(path)
        with pytest.raises(TokenFileError, match="untrusted owner"):
            load_admin_token(path, trusted_uids={os.geteuid() + 12345})

    def test_refuses_writable_parent_directory(self, tmp_path):
        path = tmp_path / "s" / "admin.token"
        write_token(path)
        os.chmod(path.parent, 0o770)  # noqa: S103 - deliberately unsafe fixture
        with pytest.raises(TokenFileError, match="directory"):
            load_admin_token(path)

    def test_error_never_contains_token(self, tmp_path):
        path = tmp_path / "s" / "admin.token"
        token = write_token(path, mode=0o644)
        with pytest.raises(TokenFileError) as info:
            load_admin_token(path)
        assert token not in str(info.value)


# --- surface ---------------------------------------------------------------------------


class TestSurface:
    @pytest.mark.parametrize(
        "path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/v1/openapi.json"]
    )
    def test_no_docs_routes(self, tmp_path, path):
        with admin_client(tmp_path) as (client, token, _):
            assert client.get(path, headers=auth(token)).status_code == 404

    def test_no_cookies_or_cors_headers(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            item = publish(client, token, [("a.txt", b"x")]).json()
            responses = [
                client.get("/v1/items", headers={**auth(token), "Origin": "https://evil.example"}),
                client.options(
                    "/v1/items",
                    headers={
                        **auth(token),
                        "Origin": "https://evil.example",
                        "Access-Control-Request-Method": "POST",
                    },
                ),
                client.get(f"/v1/items/{item['id']}", headers=auth(token)),
                client.get("/v1/items"),
            ]
        for response in responses:
            assert "set-cookie" not in response.headers
            assert not [h for h in response.headers if h.lower().startswith("access-control-")]

    def test_unexpected_errors_are_generic_500(self, tmp_path, monkeypatch):
        with admin_client(tmp_path) as (client, token, core):

            def boom(item_id: str) -> None:
                raise RuntimeError("internal detail /var/lib/secret-path")

            monkeypatch.setattr(core.queries, "get", boom)
            response = client.get("/v1/items/" + "0" * 26, headers=auth(token))
        assert response.status_code == 500
        assert set(response.json()) == {"error", "request_id"}
        assert "secret-path" not in response.text
        assert response.json()["request_id"] == response.headers["x-request-id"]

    def test_client_request_id_is_not_echoed(self, tmp_path):
        with admin_client(tmp_path) as (client, token, _):
            response = client.get("/v1/health", headers={**auth(token), "X-Request-Id": "forged"})
        assert response.headers["x-request-id"] != "forged"

    def test_uvicorn_config_is_hardened(self, tmp_path):
        settings = make_settings(tmp_path)
        del settings
        config = uvicorn_config(lambda scope, receive, send: None)  # type: ignore[arg-type,return-value]
        assert config.proxy_headers is False
        assert config.server_header is False
        assert config.access_log is False
        assert config.limit_concurrency is not None
        assert config.h11_max_incomplete_event_size is not None


# --- logs (C29) ----------------------------------------------------------------------------


class TestLogging:
    def test_token_and_authorization_never_logged(self, tmp_path, caplog):
        caplog.set_level(logging.DEBUG)
        with admin_client(tmp_path) as (client, token, _):
            publish(client, token, [("a.txt", b"x")])
            client.get("/v1/items?kind=text", headers=auth(token))
            client.get("/v1/items", headers={"Authorization": f"Bearer {token}x"})
            client.get("/v1/items", headers={"Authorization": f"Bearer {token[:20]}"})
            client.get("/nope", headers=auth(token))
        # The test client's own httpx logger records the URL it sent; skip it.
        server = [r for r in caplog.records if not r.name.startswith("httpx")]
        text = " ".join(f"{r.getMessage()} {r.args}" for r in server)
        assert token not in text
        assert token[:20] not in text
        assert "authorization" not in text.lower()
        assert "Bearer" not in text
        assert "kind=text" not in text  # no query strings
        assert any("GET /v1/items" in r.getMessage() for r in server)


# --- peer credentials + real Unix socket ------------------------------------------------------


class TestPeerPolicyInProcess:
    def test_allowlist_without_known_peer_fails_closed(self, tmp_path):
        with admin_client(tmp_path, allowed_peer_uids=[os.geteuid()]) as (client, token, _):
            assert client.get("/v1/health", headers=auth(token)).status_code == 403

    def test_read_peer_credentials_of_socketpair(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with left, right:
            creds = read_peer_credentials(left)
        assert creds == PeerCredentials(pid=os.getpid(), uid=os.geteuid(), gid=os.getegid())

    def test_read_peer_credentials_of_non_socket_is_none(self):
        assert read_peer_credentials(object()) is None


class TestUnixSocket:
    @pytest.fixture
    def run_dir(self, tmp_path: Path) -> Path:
        run = tmp_path / "run"
        run.mkdir(mode=0o750)
        return run

    def test_socket_mode_is_exactly_0660(self, run_dir):
        path = run_dir / "admin.sock"
        old = os.umask(0)  # even a permissive umask must not widen it
        try:
            sock = bind_admin_socket(path)
        finally:
            os.umask(old)
        with sock:
            st = os.lstat(path)
            assert stat.S_ISSOCK(st.st_mode)
            assert stat.S_IMODE(st.st_mode) == SOCKET_MODE

    def test_replaces_stale_socket_but_never_a_file(self, run_dir):
        path = run_dir / "admin.sock"
        bind_admin_socket(path).close()
        bind_admin_socket(path).close()  # stale socket file: replaced
        other = run_dir / "not-a-socket"
        other.write_text("keep me")
        with pytest.raises(UnsafeSocketPathError):
            bind_admin_socket(other)
        assert other.read_text() == "keep me"

    def test_refuses_to_replace_a_live_instance_socket(self, run_dir):
        path = run_dir / "admin.sock"
        with bind_admin_socket(path) as live:
            with pytest.raises(UnsafeSocketPathError, match="in use"):
                bind_admin_socket(path)
            assert stat.S_ISSOCK(os.lstat(path).st_mode)  # not unlinked
            # The live instance still accepts connections on its path.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with probe:
                probe.connect(str(path))
            assert live.fileno() != -1

    def test_refuses_writable_parent(self, tmp_path):
        run = tmp_path / "open"
        run.mkdir()
        os.chmod(run, 0o777)  # noqa: S103 - deliberately unsafe fixture
        with pytest.raises(UnsafeSocketPathError):
            bind_admin_socket(run / "admin.sock")

    def test_refuses_mode_granting_others(self, run_dir):
        with pytest.raises(ValueError, match="others"):
            bind_admin_socket(run_dir / "admin.sock", mode=0o666)

    def _served(self, tmp_path: Path, allowed: list[int]) -> tuple[AdminCore, ASGIApp, str]:
        from preview_dashboard.bootstrap import build_core

        settings = make_settings(tmp_path)
        token = secrets.token_urlsafe(32)
        core = build_core(settings, role="admin")
        app = build_admin_app(core, token=token.encode(), allowed_peer_uids=allowed)
        return core, app, token

    def test_real_socket_round_trip_with_peer_allowlist(self, tmp_path, caplog):
        caplog.set_level(logging.INFO)
        core, app, token = self._served(tmp_path, [os.geteuid()])
        sock_path = tmp_path / "run" / "admin.sock"
        with core, running_admin_server(app, sock_path), uds_client(sock_path) as client:
            response = client.get("/v1/health", headers=auth(token))
            assert response.status_code == 200
            assert "server" not in response.headers
            assert client.get("/v1/health").status_code == 401
        assert any(f"peer_uid={os.geteuid()}" in r.getMessage() for r in caplog.records)

    def test_real_socket_refuses_peer_not_in_allowlist(self, tmp_path):
        core, app, token = self._served(tmp_path, [os.geteuid() + 4242])
        sock_path = tmp_path / "run" / "admin.sock"
        with core, running_admin_server(app, sock_path), uds_client(sock_path) as client:
            assert client.get("/v1/health", headers=auth(token)).status_code == 403
