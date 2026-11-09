"""Unit tests for the viewer's pure building blocks.

`ViewerOrigins`, `csp_for`, `cache_control`, error mapping, header helpers
and preview hints — no ASGI app involved.
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    DomainError,
    InvalidPathError,
    InvalidStateError,
    LimitExceededError,
    NotFoundError,
    SecretDetectedError,
    StorageUnavailableError,
    UnsupportedContentError,
    ValidationError,
)
from preview_dashboard.interfaces.viewer._http import (
    DuplicateHeaderError,
    media_type_of,
    single_header,
)
from preview_dashboard.interfaces.viewer.errors import (
    STORAGE_RETRY_AFTER_SECONDS,
    error_body,
    register_exception_handlers,
    status_for,
)
from preview_dashboard.interfaces.viewer.headers import (
    cache_control,
    csp_for,
    dashboard_csp,
    pdf_csp,
    sandbox_csp,
)
from preview_dashboard.interfaces.viewer.hints import (
    STRICTEST,
    PreviewHints,
    get_preview_hints,
    set_preview_hints,
)
from preview_dashboard.interfaces.viewer.limits import MethodAllowlistMiddleware
from preview_dashboard.interfaces.viewer.origins import ViewerOrigins
from preview_dashboard.kinds import default_registry
from preview_dashboard.kinds.base import PreviewMode
from tests.viewer_support import DASH_HOST, OWNER, PREVIEW_HOST, PREVIEW_ORIGIN, make_settings

pytestmark = pytest.mark.unit

ANCESTORS = ("https://dash.example.ts.net",)


def test_origins_from_settings() -> None:
    origins = ViewerOrigins.from_settings(
        make_settings(allowed_hosts=frozenset({"b.example", DASH_HOST}))
    )
    assert origins.owner_login == OWNER
    assert origins.dashboard_hosts == frozenset({"b.example", DASH_HOST})
    assert origins.dashboard_origins == ("https://b.example", f"https://{DASH_HOST}")
    assert origins.preview_origin == PREVIEW_ORIGIN
    assert origins.preview_host == PREVIEW_HOST


@pytest.mark.parametrize("mode", list(PreviewMode))
@pytest.mark.parametrize(
    "media_type",
    ["image/svg+xml", "text/html", "application/pdf", "", "application/json", "Application/PDF"],
)
def test_csp_for_sandboxes_everything_but_pdf_documents(mode: PreviewMode, media_type: str) -> None:
    csp = csp_for(media_type, mode, frame_ancestors=ANCESTORS)
    if media_type == "application/pdf" and mode is PreviewMode.DOCUMENT:
        assert csp == pdf_csp(ANCESTORS)
    else:
        assert csp == sandbox_csp(ANCESTORS)


def test_csp_for_unknown_mode_is_sandboxed() -> None:
    assert csp_for("application/pdf", None, frame_ancestors=ANCESTORS) == sandbox_csp(ANCESTORS)


def test_csp_for_requires_frame_ancestors() -> None:
    with pytest.raises(ValueError, match="frame_ancestors"):
        csp_for("image/png", PreviewMode.MEDIA, frame_ancestors=())


def test_every_registered_kind_media_type_gets_a_policy() -> None:
    """Only the pdf kind's own type under DOCUMENT escapes the sandbox."""
    registry = default_registry()
    for kind in registry.all():
        for ext in kind.extensions or {".bin"}:
            media_type = kind.media_type(f"f{ext}")
            csp = csp_for(media_type, kind.preview_mode, frame_ancestors=ANCESTORS)
            if kind.name == "pdf":
                assert "sandbox" not in csp
            else:
                assert csp.startswith("sandbox allow-scripts;"), (kind.name, ext)


def test_pdf_csp_has_no_script_src() -> None:
    assert "script-src" not in pdf_csp(ANCESTORS)
    assert "object-src 'none'" in pdf_csp(ANCESTORS)


def test_dashboard_csp_mentions_preview_only_where_needed() -> None:
    csp = dashboard_csp(PREVIEW_ORIGIN)
    directives = {d.split(" ", 1)[0]: d for d in csp.split("; ")}
    for name in ("img-src", "media-src", "frame-src"):
        assert PREVIEW_ORIGIN in directives[name]
    for name in ("script-src", "style-src", "connect-src", "default-src"):
        assert PREVIEW_ORIGIN not in directives[name]


@pytest.mark.parametrize(
    ("route", "expected"),
    [
        (None, "DEFAULT"),
        (b"public, max-age=60", "DEFAULT"),
        (b"max-age=60", "DEFAULT"),
        (b"private, s-maxage=60", "DEFAULT"),
        (b"no-cache", "DEFAULT"),
        (b"private, max-age=60", "private, max-age=60"),
        (b"no-store", "no-store"),
        (b"PRIVATE", "PRIVATE"),
    ],
)
def test_cache_control(route: bytes | None, expected: str) -> None:
    assert cache_control(route, "DEFAULT") == expected


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (NotFoundError("x"), 404),
        (InvalidStateError("x"), 409),
        (AlreadyExistsError("x"), 409),
        (LimitExceededError("x"), 413),
        (UnsupportedContentError("x"), 415),
        (StorageUnavailableError("x"), 503),
        (ValidationError("x"), 400),
        (InvalidPathError("x"), 400),
        (SecretDetectedError("rule"), 400),
        (DomainError("x"), 400),
    ],
)
def test_status_for(exc: DomainError, status: int) -> None:
    assert status_for(exc) == status


def _raising_app(exc: Exception) -> TestClient:
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/boom")
    async def boom() -> None:
        raise exc

    return TestClient(app, raise_server_exceptions=False)


def test_storage_refusal_is_503_with_retry_after_and_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # C24 (ADR 0025): a failed trust check is transient and server-side.
    client = _raising_app(StorageUnavailableError("-wal owned by an untrusted uid"))
    with caplog.at_level(logging.INFO, logger="preview_dashboard.viewer"):
        response = client.get("/boom")
    assert response.status_code == 503
    assert response.headers["retry-after"] == str(STORAGE_RETRY_AFTER_SECONDS) == "5"
    assert response.json()["error"] == "service_unavailable"
    assert "untrusted" not in response.text
    (record,) = [r for r in caplog.records if "-> 503" in r.getMessage()]
    assert record.levelno == logging.WARNING


def test_client_errors_stay_info_without_retry_after(caplog: pytest.LogCaptureFixture) -> None:
    client = _raising_app(NotFoundError("x"))
    with caplog.at_level(logging.INFO, logger="preview_dashboard.viewer"):
        response = client.get("/boom")
    assert response.status_code == 404
    assert "retry-after" not in response.headers
    (record,) = [r for r in caplog.records if "-> 404" in r.getMessage()]
    assert record.levelno == logging.INFO


def test_error_body_is_fixed_shape() -> None:
    assert json.loads(error_body(404, "abc")) == {"error": "not_found", "request_id": "abc"}
    assert json.loads(error_body(599, "abc"))["error"] == "error"


def test_single_header() -> None:
    scope = {"headers": [(b"a", b"1"), (b"b", b"2"), (b"b", b"3")]}
    assert single_header(scope, b"a") == b"1"
    assert single_header(scope, b"c") is None
    with pytest.raises(DuplicateHeaderError):
        single_header(scope, b"b")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, ""),
        (b"", ""),
        (b"Application/PDF; x=1", "application/pdf"),
        (b"image/svg+xml", "image/svg+xml"),
    ],
)
def test_media_type_of(value: bytes | None, expected: str) -> None:
    assert media_type_of(value) == expected


def test_hints_default_to_strictest() -> None:
    assert get_preview_hints({}) is STRICTEST
    assert get_preview_hints({"state": {"pdash.preview_hints": "DOCUMENT"}}) is STRICTEST
    scope: dict[str, object] = {}
    hints = PreviewHints(PreviewMode.DOCUMENT)
    set_preview_hints(scope, hints)
    assert get_preview_hints(scope) is hints


def test_method_allowlist_refuses_options() -> None:
    async def app(scope, receive, send):  # pragma: no cover - never called
        raise AssertionError

    with pytest.raises(ValueError, match="OPTIONS"):
        MethodAllowlistMiddleware(app, methods=("GET", "OPTIONS"))
