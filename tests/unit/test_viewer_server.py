"""Unit tests for `interfaces/viewer/server.py`: both apps wired, hardened uvicorn, shutdown.

uvicorn is never started for real: servers are inspected, or their `serve`
coroutine is replaced, so no ports are bound.
"""

from __future__ import annotations

import asyncio
import os
import signal
from contextlib import ExitStack
from typing import Any, cast

import pytest
import uvicorn

from preview_dashboard.application import (
    ArchiveService,
    FolderService,
    HistoryService,
    LifecycleService,
    QueryService,
)
from preview_dashboard.bootstrap import (
    FolderReader,
    PinControl,
    RevisionPruner,
    TrashControl,
    ViewerCore,
)
from preview_dashboard.interfaces.http_server import (
    HEADER_TIMEOUT_SECONDS,
    HeaderTimeoutH11Protocol,
)
from preview_dashboard.interfaces.viewer import server as server_module
from preview_dashboard.interfaces.viewer.app_factory import SecuredApp
from preview_dashboard.interfaces.viewer.server import (
    ManagedServer,
    ViewerCoreLike,
    build_servers,
    run_servers,
    serve,
)
from preview_dashboard.kinds import default_registry
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryBlobStore,
    InMemoryFolderRepository,
    InMemoryItemRepository,
    SequentialIdGenerator,
)
from tests.viewer_support import make_settings

pytestmark = pytest.mark.unit


def _core() -> tuple[ViewerCore, list[str]]:
    repo, blobs, kinds = InMemoryItemRepository(), InMemoryBlobStore(), default_registry()
    closed: list[str] = []
    resources = ExitStack()
    resources.callback(closed.append, "closed")
    lifecycle = LifecycleService(repo=repo, clock=FixedClock(), scanner=FakeContentScanner())
    core = ViewerCore(
        settings=make_settings(viewer_port=18787, preview_port=18788),
        _resources=resources,
        kinds=kinds,
        queries=QueryService(repo=repo, blobs=blobs, kinds=kinds),
        trash=TrashControl(lifecycle),
        pins=PinControl(lifecycle),
        archive=ArchiveService(repo=repo, blobs=blobs),
        folders=FolderReader(
            FolderService(
                folders=InMemoryFolderRepository(repo),
                items=repo,
                clock=FixedClock(),
                ids=SequentialIdGenerator(),
                scanner=FakeContentScanner(),
            )
        ),
        history=RevisionPruner(
            HistoryService(repo=repo, blobs=blobs, clock=FixedClock(), delete_blobs=False)
        ),
    )
    return core, closed


def test_viewer_core_satisfies_the_protocol() -> None:
    core, _ = _core()
    typed: ViewerCoreLike = core  # mypy checks the structural match
    assert typed.kinds is core.kinds


def test_build_servers_wires_both_apps_with_hardened_config() -> None:
    core, _ = _core()
    dashboard, preview = build_servers(core)
    for server, port in ((dashboard, 18787), (preview, 18788)):
        config = server.config
        assert isinstance(server, ManagedServer)
        assert config.host == "127.0.0.1"
        assert config.port == port
        assert config.server_header is False
        assert config.proxy_headers is False
        assert config.forwarded_allow_ips == ""
        assert config.access_log is False
        assert config.limit_concurrency == server_module.LIMIT_CONCURRENCY
        assert config.timeout_keep_alive == server_module.TIMEOUT_KEEP_ALIVE_SECONDS
        assert config.ws == "none"
        assert config.lifespan == "off"
        assert config.timeout_graceful_shutdown == server_module.TIMEOUT_GRACEFUL_SHUTDOWN_SECONDS
        assert isinstance(config.http, type)
        assert issubclass(config.http, HeaderTimeoutH11Protocol)
        assert config.http.header_timeout == HEADER_TIMEOUT_SECONDS
        assert isinstance(config.app, SecuredApp)
        assert config.app.inner.state.services is core
    dash_app = cast(SecuredApp, dashboard.config.app)
    preview_app = cast(SecuredApp, preview.config.app)
    assert hasattr(dash_app.inner.state, "static_assets")  # the dashboard app
    assert not hasattr(preview_app.inner.state, "static_assets")  # the preview app


def test_serve_runs_both_servers_and_closes_core(monkeypatch: pytest.MonkeyPatch) -> None:
    core, closed = _core()
    served: list[int] = []

    async def fake_serve(self: uvicorn.Server, sockets: Any = None) -> None:
        served.append(self.config.port)

    monkeypatch.setattr(ManagedServer, "serve", fake_serve)
    serve(core)
    assert sorted(served) == [18787, 18788]
    assert closed == ["closed"]


def test_serve_closes_core_on_startup_failure() -> None:
    core, closed = _core()
    broken = ViewerCore(
        settings=make_settings().model_copy(update={"owner_login": ""}),
        _resources=core._resources,
        kinds=core.kinds,
        queries=core.queries,
        trash=core.trash,
        pins=core.pins,
        archive=core.archive,
        folders=core.folders,
        history=core.history,
    )
    with pytest.raises(Exception, match="owner_login"):
        serve(broken)
    assert closed == ["closed"]


class _FakeServer:
    def __init__(self, fail: bool = False) -> None:
        self.should_exit = False
        self.force_exit = False
        self.fail = fail
        self.stopped_by_peer = False

    async def serve(self) -> None:
        if self.fail:
            raise OSError("address in use")
        while not self.should_exit:
            await asyncio.sleep(0.001)
        self.stopped_by_peer = True


def test_one_failing_server_stops_the_other() -> None:
    good, bad = _FakeServer(), _FakeServer(fail=True)
    with pytest.raises(OSError, match="address in use"):
        asyncio.run(run_servers(cast(list[uvicorn.Server], [good, bad])))
    assert good.should_exit and good.stopped_by_peer


def test_sigterm_stops_both_and_restores_handlers() -> None:
    before = signal.getsignal(signal.SIGTERM)
    first, second = _FakeServer(), _FakeServer()

    async def scenario() -> None:
        runner = asyncio.create_task(run_servers(cast(list[uvicorn.Server], [first, second])))
        await asyncio.sleep(0.01)
        os.kill(os.getpid(), signal.SIGTERM)
        await asyncio.wait_for(runner, timeout=2)

    asyncio.run(scenario())
    assert first.stopped_by_peer and second.stopped_by_peer
    assert signal.getsignal(signal.SIGTERM) == before
