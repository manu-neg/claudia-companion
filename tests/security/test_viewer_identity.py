"""Security tests for the viewer Host + owner-identity gate (docs/security.md C2, C3, I6).

Both apps are built through the real factory; a dummy `/ok` route stands in
for business routes. Duplicate-header cases use a raw ASGI scope because
HTTP clients merge or refuse them.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.responses import PlainTextResponse

from preview_dashboard.config import ConfigError, Settings
from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from preview_dashboard.interfaces.viewer.identity import IdentityMiddleware
from preview_dashboard.interfaces.viewer.origins import ViewerOrigins
from tests.viewer_support import (
    DASH_HOST,
    OWNER,
    PREVIEW_HOST,
    StubServices,
    call_asgi,
    dashboard_app,
    dashboard_client,
    make_settings,
    owner_headers,
    preview_app,
    preview_client,
)

pytestmark = pytest.mark.security


def _with_ok_route(app: SecuredApp) -> SecuredApp:
    @app.inner.get("/ok")
    def ok() -> PlainTextResponse:
        return PlainTextResponse("ok")

    return app


@pytest.fixture
def dash() -> SecuredApp:
    return _with_ok_route(dashboard_app())


@pytest.fixture
def prev() -> SecuredApp:
    return _with_ok_route(preview_app())


# --- C2: owner identity ------------------------------------------------------


def test_owner_is_admitted_on_both_apps(dash: SecuredApp, prev: SecuredApp) -> None:
    assert dashboard_client(dash).get("/ok", headers=owner_headers()).text == "ok"
    assert preview_client(prev).get("/ok", headers=owner_headers()).text == "ok"


@pytest.mark.parametrize(
    "login",
    [
        "",
        "Owner@example.com",  # wrong case: byte-exact match only
        "OWNER@EXAMPLE.COM",
        "someone@example.com",
        "owner@example.com.evil.com",
        "xowner@example.com",
        "owner@example.co",
        "owner@example.com,owner@example.com",
        "owner@example.com\x00",
    ],
)
def test_wrong_login_is_403(dash: SecuredApp, login: str) -> None:
    response = dashboard_client(dash).get("/ok", headers={"Tailscale-User-Login": login})
    assert response.status_code == 403
    assert response.json()["error"] == "forbidden"


def test_missing_login_is_403_on_both_apps(dash: SecuredApp, prev: SecuredApp) -> None:
    assert dashboard_client(dash).get("/ok").status_code == 403
    assert preview_client(prev).get("/ok").status_code == 403


@pytest.mark.parametrize("app_name", ["dash", "prev"])
async def test_duplicated_login_is_403_even_if_both_match(
    app_name: str, dash: SecuredApp, prev: SecuredApp
) -> None:
    app, host = (dash, DASH_HOST) if app_name == "dash" else (prev, PREVIEW_HOST)
    login = OWNER.encode()
    result = await call_asgi(
        app,
        path="/ok",
        headers=[
            (b"host", host.encode()),
            (b"tailscale-user-login", login),
            (b"tailscale-user-login", login),
        ],
    )
    assert result.status == 403


async def test_surrounding_ows_is_tolerated_like_http_parsers_do(dash: SecuredApp) -> None:
    result = await call_asgi(
        dash,
        path="/ok",
        headers=[(b"host", DASH_HOST.encode()), (b"tailscale-user-login", b" " + OWNER.encode())],
    )
    assert result.status == 200


async def test_non_utf8_login_is_403(dash: SecuredApp) -> None:
    result = await call_asgi(
        dash,
        path="/ok",
        headers=[(b"host", DASH_HOST.encode()), (b"tailscale-user-login", b"owner\xff")],
    )
    assert result.status == 403


def test_other_tailscale_headers_do_not_substitute(dash: SecuredApp) -> None:
    response = dashboard_client(dash).get(
        "/ok", headers={"Tailscale-User-Name": OWNER, "X-Forwarded-User": OWNER}
    )
    assert response.status_code == 403


def test_denial_body_is_generic_and_does_not_echo(dash: SecuredApp) -> None:
    response = dashboard_client(dash).get(
        "/ok", headers={"Tailscale-User-Login": "attacker-marker@evil"}
    )
    assert response.status_code == 403
    assert "attacker-marker" not in response.text
    assert set(response.json()) == {"error", "request_id"}
    assert response.json()["request_id"] == response.headers["x-request-id"]


def test_denial_log_never_contains_header_values(
    dash: SecuredApp, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    dashboard_client(dash).get("/ok", headers={"Tailscale-User-Login": "attacker-marker@evil"})
    assert caplog.records, "denials must be logged"
    assert "attacker-marker" not in caplog.text


async def test_websocket_is_refused(dash: SecuredApp) -> None:
    result = await call_asgi(
        dash,
        path="/ok",
        scope_type="websocket",
        headers=[(b"host", DASH_HOST.encode()), (b"tailscale-user-login", OWNER.encode())],
    )
    assert result.messages == [{"type": "websocket.close", "code": 1008}]


# --- C3: exact Host per app -----------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "DASH.example.ts.net",  # exact, lowercase only
        f"{DASH_HOST}.",
        f"{DASH_HOST}:443",
        f"{DASH_HOST}:8787",
        PREVIEW_HOST,  # cross-app confusion
        "127.0.0.1:8787",
        "localhost",
        f"x.{DASH_HOST}",
    ],
)
async def test_dashboard_rejects_other_hosts_with_421(dash: SecuredApp, host: str) -> None:
    result = await call_asgi(
        dash,
        path="/ok",
        headers=[(b"host", host.encode()), (b"tailscale-user-login", OWNER.encode())],
    )
    assert result.status == 421


@pytest.mark.parametrize(
    "host", [DASH_HOST, f"{DASH_HOST}:443", f"{DASH_HOST}:8444", "127.0.0.1:8788", "evil:8443"]
)
async def test_preview_rejects_other_hosts_with_421(prev: SecuredApp, host: str) -> None:
    result = await call_asgi(
        prev,
        path="/ok",
        headers=[(b"host", host.encode()), (b"tailscale-user-login", OWNER.encode())],
    )
    assert result.status == 421


async def test_missing_host_is_400(dash: SecuredApp) -> None:
    result = await call_asgi(dash, path="/ok", headers=[(b"tailscale-user-login", OWNER.encode())])
    assert result.status == 400


async def test_duplicated_host_is_400(dash: SecuredApp) -> None:
    result = await call_asgi(
        dash,
        path="/ok",
        headers=[
            (b"host", DASH_HOST.encode()),
            (b"host", DASH_HOST.encode()),
            (b"tailscale-user-login", OWNER.encode()),
        ],
    )
    assert result.status == 400


async def test_host_is_checked_before_identity(dash: SecuredApp) -> None:
    result = await call_asgi(dash, path="/ok", headers=[(b"host", b"evil.example")])
    assert result.status == 421


# --- I6: fail closed at start-up ---------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"owner_login": ""},
        {"owner_login": "   "},
        {"allowed_hosts": frozenset()},
        {"preview_origin": ""},
    ],
)
def test_viewer_refuses_to_start_when_unconfigured(overrides: dict[str, object]) -> None:
    settings = make_settings(**overrides)
    with pytest.raises(ConfigError):
        ViewerOrigins.from_settings(settings)
    with pytest.raises(ConfigError):
        dashboard_app(**overrides)
    with pytest.raises(ConfigError):
        preview_app(**overrides)


@pytest.mark.parametrize(
    "fields",
    [
        {"owner_login": "owner@example.com\u200b"},
        {"owner_login": " owner@example.com"},
        {"allowed_hosts": frozenset({"*.ts.net"})},
        {"allowed_hosts": frozenset({"Dash.example"})},
        {"preview_origin": "http://dash.example.ts.net:8443"},
        {"preview_origin": "https://dash.example.ts.net"},
        {"preview_origin": "https://dash.example.ts.net:443"},
        {"preview_origin": "https://dash.example.ts.net:8443/"},
        {"preview_origin": f"https://{PREVIEW_HOST}", "allowed_hosts": frozenset({PREVIEW_HOST})},
    ],
)
def test_unvalidated_settings_are_rechecked(fields: dict[str, object]) -> None:
    base = make_settings()
    # model_construct skips pydantic validation: the viewer re-checks anyway.
    settings = Settings.model_construct(**{**base.model_dump(), **fields})
    with pytest.raises(ConfigError):
        ViewerOrigins.from_settings(settings)


def test_identity_middleware_refuses_empty_configuration() -> None:
    async def app(scope, receive, send):  # pragma: no cover - never called
        raise AssertionError

    with pytest.raises(ValueError, match="configured"):
        IdentityMiddleware(app, owner_login="", allowed_hosts=[DASH_HOST])
    with pytest.raises(ValueError, match="configured"):
        IdentityMiddleware(app, owner_login=OWNER, allowed_hosts=[])


def test_stub_services_satisfy_protocol() -> None:
    assert StubServices().kinds.get("pdf").name == "pdf"
