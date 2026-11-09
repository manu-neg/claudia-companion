"""Shared helpers for viewer tests: canonical settings, apps and request headers.

Builds both viewer apps through the real factory (full middleware stack).
`StubServices` is the real application services over empty in-memory
fakes, so security-layer tests can add tiny dummy routes to `app.inner`;
`ViewerEnv` adds a publisher so route tests can serve real items.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from urllib.parse import unquote_to_bytes

from starlette.testclient import TestClient

from preview_dashboard.application import (
    ArchiveService,
    FolderService,
    HistoryService,
    IncomingFile,
    LifecycleService,
    PublishCommand,
    PublishService,
    QueryService,
    RevisionCommand,
)
from preview_dashboard.bootstrap import FolderReader, RevisionPruner
from preview_dashboard.config import Settings
from preview_dashboard.domain.models import Item
from preview_dashboard.interfaces.folder_refs import FolderLookup
from preview_dashboard.interfaces.viewer.app_factory import (
    SecuredApp,
    build_dashboard_app,
    build_preview_app,
)
from preview_dashboard.interfaces.viewer.services import (
    HistoryActions,
    ItemArchiver,
    ItemQueries,
    PinActions,
    TrashActions,
    ViewerServices,
)
from preview_dashboard.kinds import default_registry
from preview_dashboard.kinds.base import KindRegistry
from preview_dashboard.ports.blobstore import BlobStore
from preview_dashboard.ports.folders import FolderRepository
from preview_dashboard.ports.repository import ItemRepository
from tests.app_support import make_publish
from tests.fakes import (
    FakeContentScanner,
    FixedClock,
    InMemoryBlobStore,
    InMemoryFolderRepository,
    InMemoryItemRepository,
    SequentialIdGenerator,
)

OWNER = "owner@example.com"
DASH_HOST = "dash.example.ts.net"
DASH_ORIGIN = f"https://{DASH_HOST}"
PREVIEW_HOST = f"{DASH_HOST}:8443"
PREVIEW_ORIGIN = f"https://{PREVIEW_HOST}"


class StubServices:
    """`ViewerServices` made of the real application services over in-memory fakes.

    `folder_admin` is the full `FolderService` (tests organise folders with
    it); the apps only get `folders`, the read-only `FolderReader` (C40).
    Pass `folders` when `repo` is not an `InMemoryItemRepository` (e.g. the
    SQLite folder repository over the same database).
    """

    def __init__(
        self,
        repo: ItemRepository | None = None,
        blobs: BlobStore | None = None,
        clock: FixedClock | None = None,
        folders: FolderRepository | None = None,
    ) -> None:
        self._kinds = default_registry()
        self.repo = repo if repo is not None else InMemoryItemRepository()
        self.blobs = blobs if blobs is not None else InMemoryBlobStore()
        self.clock = clock if clock is not None else FixedClock()
        self._queries = QueryService(repo=self.repo, blobs=self.blobs, kinds=self._kinds)
        self._trash = LifecycleService(
            repo=self.repo, clock=self.clock, scanner=FakeContentScanner()
        )
        self._pins: PinActions = self._trash
        self._archive = ArchiveService(repo=self.repo, blobs=self.blobs)
        if folders is None:
            items = self.repo if isinstance(self.repo, InMemoryItemRepository) else None
            folders = InMemoryFolderRepository(items)
        self.folder_repo: FolderRepository = folders
        # Folder ids from their own range, so they never equal a test's item ids.
        self.folder_admin = FolderService(
            folders=self.folder_repo,
            items=self.repo,
            clock=self.clock,
            ids=SequentialIdGenerator(start=10**12),
            scanner=FakeContentScanner(),
        )
        self._folders = FolderReader(self.folder_admin)
        # Wired like the real viewer core: keep=1 only, blobs left to the sweep.
        self._history = RevisionPruner(
            HistoryService(repo=self.repo, blobs=self.blobs, clock=self.clock, delete_blobs=False)
        )

    @property
    def kinds(self) -> KindRegistry:
        return self._kinds

    @property
    def queries(self) -> ItemQueries:
        return self._queries

    @property
    def trash(self) -> TrashActions:
        return self._trash

    @property
    def pins(self) -> PinActions:
        return self._pins

    @property
    def archive(self) -> ItemArchiver:
        return self._archive

    @property
    def folders(self) -> FolderLookup:
        return self._folders

    @property
    def history(self) -> HistoryActions:
        return self._history


def make_settings(**overrides: Any) -> Settings:
    """Settings for the viewer; explicit kwargs so env vars can't leak in."""
    values: dict[str, Any] = {
        "owner_login": OWNER,
        "allowed_hosts": frozenset({DASH_HOST}),
        "preview_origin": PREVIEW_ORIGIN,
        "viewer_port": 8787,
        "preview_port": 8788,
    }
    values.update(overrides)
    return Settings(**values)


def dashboard_app(**overrides: Any) -> SecuredApp:
    return build_dashboard_app(make_settings(**overrides), StubServices())


def preview_app(**overrides: Any) -> SecuredApp:
    return build_preview_app(make_settings(**overrides), StubServices())


@dataclass
class ViewerEnv:
    """Both apps over one set of real services, plus a publisher to add items."""

    services: StubServices
    publisher: PublishService
    dashboard: SecuredApp
    preview: SecuredApp
    settings: Settings
    items: list[Item] = field(default_factory=list)

    def publish(
        self,
        files: Mapping[str, bytes],
        *,
        title: str = "A title",
        kind: str | None = None,
        folder_id: str | None = None,
    ) -> Item:
        """Publish `files` (relpath -> bytes) through the real PublishService."""
        item = self.publisher.publish(
            PublishCommand(
                title=title,
                files=[IncomingFile(relpath=r, chunks=[d]) for r, d in files.items()],
                kind_hint=kind,
                folder_id=folder_id,
            )
        )
        self.items.append(item)
        return item

    def revise(
        self,
        item_id: str,
        files: Mapping[str, bytes],
        *,
        kind: str | None = None,
        after: timedelta = timedelta(minutes=1),
    ) -> Item:
        """Publish `files` as a new revision of `item_id`, `after` later on the fake clock."""
        self.services.clock.advance(after)
        return self.publisher.publish_revision(
            RevisionCommand(
                item_id=item_id,
                files=[IncomingFile(relpath=r, chunks=[d]) for r, d in files.items()],
                kind_hint=kind,
            )
        )

    def dash_client(self) -> TestClient:
        return dashboard_client(self.dashboard)

    def preview_client(self) -> TestClient:
        return preview_client(self.preview)


def make_env(
    services: StubServices | None = None,
    *,
    publisher: PublishService | None = None,
    **overrides: Any,
) -> ViewerEnv:
    """Build a `ViewerEnv`; `overrides` patch the viewer settings."""
    if services is None:
        harness = make_publish(
            max_file_bytes=10_000_000,
            max_item_bytes=20_000_000,
            max_total_bytes=100_000_000,
            max_items=1_000,
            capacity=200_000_000,
        )
        services = StubServices(harness.repo, harness.blobs, harness.clock, harness.folders)
        publisher = harness.service
    if publisher is None:
        raise ValueError("a custom services object needs its publisher")
    settings = make_settings(**overrides)
    viewer_services: ViewerServices = services
    return ViewerEnv(
        services=services,
        publisher=publisher,
        dashboard=build_dashboard_app(settings, viewer_services),
        preview=build_preview_app(settings, viewer_services),
        settings=settings,
    )


def route_paths(app: SecuredApp) -> set[str]:
    """Every route path of an app, descending into included routers.

    FastAPI >= 0.13x wraps `include_router` routers lazily, so a flat scan
    of `app.routes` would see no paths at all.
    """
    paths: set[str] = set()
    pending: list[Any] = list(app.inner.routes)
    while pending:
        route = pending.pop()
        path = getattr(route, "path", None)
        if isinstance(path, str):
            paths.add(path)
        original = getattr(route, "original_router", None)
        if original is not None:
            pending.extend(original.routes)
    return paths


def raw_scope_path(raw: str) -> tuple[str, bytes]:
    """(decoded `path`, `raw_path`) as an ASGI server would build them from `raw`."""
    raw_bytes = raw.encode("latin-1")
    return unquote_to_bytes(raw).decode("utf-8", "replace"), raw_bytes


def dashboard_client(app: SecuredApp) -> TestClient:
    return TestClient(app, base_url=DASH_ORIGIN, raise_server_exceptions=False)


def preview_client(app: SecuredApp) -> TestClient:
    return TestClient(app, base_url=PREVIEW_ORIGIN, raise_server_exceptions=False)


def owner_headers(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    headers = {"Tailscale-User-Login": OWNER}
    headers.update(extra or {})
    return headers


def csrf_headers(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Headers of a legitimate dashboard POST (passes the whole CSRF matrix)."""
    headers = owner_headers(
        {
            "Content-Type": "application/json",
            "Origin": DASH_ORIGIN,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "X-PDash-CSRF": "1",
        }
    )
    headers.update(extra or {})
    return headers


class AsgiResult:
    """Collected response of one raw ASGI call."""

    def __init__(self) -> None:
        self.status: int | None = None
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = b""
        self.messages: list[dict[str, Any]] = []

    def header(self, name: str) -> str | None:
        key = name.lower().encode("latin-1")
        for k, v in self.headers:
            if k == key:
                return v.decode("latin-1")
        return None


async def call_asgi(
    app: Any,
    *,
    method: str = "GET",
    path: str = "/",
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
    raw_path: bytes | None = None,
    scope_type: str = "http",
) -> AsgiResult:
    """Drive an ASGI app with a hand-built scope (e.g. duplicated headers)."""
    scope: dict[str, Any] = {
        "type": scope_type,
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode("ascii"),
        "query_string": b"",
        "root_path": "",
        "headers": headers or [],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8787),
    }
    result = AsgiResult()
    sent_body = False

    async def receive() -> dict[str, Any]:
        nonlocal sent_body
        if scope_type == "websocket":
            return {"type": "websocket.connect"}
        if not sent_body:
            sent_body = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        result.messages.append(message)
        if message["type"] == "http.response.start":
            result.status = message["status"]
            result.headers = list(message.get("headers", []))
        elif message["type"] == "http.response.body":
            result.body += message.get("body", b"")

    await app(scope, receive, send)
    return result
