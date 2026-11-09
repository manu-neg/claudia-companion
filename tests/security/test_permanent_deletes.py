"""Security tests for C43: permanent deletes (prune old revisions, empty trash; ADR 0030).

Admin token family only (role re-checked), ACTIVE-only prune with bounded
`keep` and the head kept, and a restore racing empty-trash on real SQLite.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.clock import SystemClock
from preview_dashboard.adapters.fs_blobstore import FsBlobStore
from preview_dashboard.adapters.sqlite import SqliteItemRepository
from preview_dashboard.adapters.ulid import UlidGenerator
from preview_dashboard.application import (
    IncomingFile,
    LifecycleService,
    PublishCommand,
    PurgeService,
    RevisionCommand,
)
from preview_dashboard.bootstrap import AdminCore, connection_factory
from preview_dashboard.domain.models import MAX_REVISIONS, Item, ItemState
from preview_dashboard.domain.query import ItemQuery, Page
from preview_dashboard.interfaces.admin import cleanup_api
from preview_dashboard.interfaces.admin.auth import PeerCredentials
from preview_dashboard.interfaces.admin.errors import ForbiddenError
from tests.admin_support import admin_client, auth
from tests.fakes import FakeContentScanner
from tests.notify_admin_support import asgi_client, bearer, notify_app

pytestmark = pytest.mark.security

ADMIN, NOTIFIER, NONE, WRONG = "admin", "notifier", "none", "wrong"


def _publish(core: AdminCore, revisions: int = 3) -> Item:
    item = core.publish.publish(
        PublishCommand(title="T", files=[IncomingFile(relpath="a.txt", chunks=[b"v1"])])
    )
    for n in range(2, revisions + 1):
        item = core.publish.publish_revision(
            RevisionCommand(
                item_id=item.id, files=[IncomingFile(relpath="a.txt", chunks=[f"v{n}".encode()])]
            )
        )
    return item


def _blob_files(tmp_path: Path) -> set[str]:
    return {p.name for p in (tmp_path / "data" / "blobs").rglob("*") if p.is_file()}


# --- C43 / C33: admin token family only --------------------------------------------------


ROUTES: list[tuple[str, dict[str, Any] | None]] = [
    ("/v1/items/{iid}/revisions/prune", {"keep": 1}),
    ("/v1/trash/empty", None),
]


@pytest.mark.parametrize("token_kind", [ADMIN, NOTIFIER, NONE, WRONG])
@pytest.mark.parametrize(("template", "body"), ROUTES)
def test_c43_routes_need_the_admin_token(
    tmp_path: Path, token_kind: str, template: str, body: dict[str, Any] | None
) -> None:
    with notify_app(tmp_path) as rig, TestClient(rig.app) as client:
        item = _publish(rig.core)
        trashed = _publish(rig.core, revisions=1)
        rig.core.lifecycle.trash(trashed.id)
        before = _blob_files(tmp_path)
        headers = {
            ADMIN: bearer(rig.admin_token),
            NOTIFIER: bearer(rig.notifier_token),
            WRONG: bearer(secrets.token_urlsafe(32)),
            NONE: {},
        }[token_kind]
        response = client.post(template.format(iid=item.id), json=body, headers=headers)
        item_after = rig.core.queries.get(item.id)
        trash_after = rig.core.queries.list(ItemQuery(state=ItemState.TRASHED)).items
    if token_kind in (NONE, WRONG):
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"
    elif token_kind == NOTIFIER:
        assert response.status_code == 403
    else:
        assert response.status_code == 200, response.text
        return
    # Refused: nothing changed, nothing deleted.
    assert item_after == item
    assert [i.id for i in trash_after] == [trashed.id]
    assert _blob_files(tmp_path) == before


async def test_c43_routes_are_in_the_admin_peer_family(tmp_path: Path) -> None:
    with notify_app(tmp_path, allowed_peer_uids=[1000], notifier_peer_uids=[2000]) as rig:
        item = _publish(rig.core)
        rig.core.lifecycle.trash(_publish(rig.core, revisions=1).id)
        notifier_peer = PeerCredentials(pid=1, uid=2000, gid=1)
        async with asgi_client(rig.app, peer=notifier_peer) as client:
            prune = await client.post(
                f"/v1/items/{item.id}/revisions/prune", json={}, headers=bearer(rig.admin_token)
            )
            empty = await client.post("/v1/trash/empty", headers=bearer(rig.admin_token))
        assert (prune.status_code, empty.status_code) == (403, 403)
        assert rig.core.queries.get(item.id) == item
        assert len(rig.core.queries.list(ItemQuery(state=ItemState.TRASHED)).items) == 1


async def test_c43_routes_recheck_the_token_role() -> None:
    """Defense in depth: `require_admin` runs before anything else touches the request."""

    class _NotifierOnlyRequest:
        scope: ClassVar[dict[str, Any]] = {"state": {"pdash.token_role": "notifier"}}

        def __getattr__(self, name: str) -> Any:
            raise AssertionError(f"touched request.{name} before the admin-role check")

    request = _NotifierOnlyRequest()
    calls: Iterable[Any] = (
        cleanup_api.prune_revisions(request, "x"),  # type: ignore[arg-type]
        cleanup_api.empty_trash(request),  # type: ignore[arg-type]
    )
    for coro in calls:
        with pytest.raises(ForbiddenError):
            await coro


def test_c43_no_item_delete_or_viewer_route() -> None:
    """Permanent deletes exist only as these two admin POSTs (no DELETE, R2 adds the viewer's)."""
    paths = {
        (m, getattr(r, "path", None))
        for r in cleanup_api.router.routes
        for m in getattr(r, "methods", ())
    }
    assert paths == {
        ("POST", "/v1/items/{item_id}/revisions/prune"),
        ("POST", "/v1/trash/empty"),
    }


# --- C43: prune boundaries -----------------------------------------------------------------


@pytest.mark.parametrize("keep", [0, -1, MAX_REVISIONS + 1, True, "1", 1.5, None])
def test_c43_bad_keep_is_400_and_nothing_deleted(tmp_path: Path, keep: object) -> None:
    with admin_client(tmp_path) as (client, token, core):
        item = _publish(core)
        before = _blob_files(tmp_path)
        body: dict[str, object] = {"keep": keep}
        response = client.post(
            f"/v1/items/{item.id}/revisions/prune", json=body, headers=auth(token)
        )
        if keep is None:  # null = the default (1): allowed
            assert response.status_code == 200
            return
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_input"
        assert core.queries.get(item.id) == item
        assert _blob_files(tmp_path) == before


def test_c43_trashed_item_is_refused(tmp_path: Path) -> None:
    with admin_client(tmp_path) as (client, token, core):
        item = _publish(core)
        trashed = core.lifecycle.trash(item.id)
        before = _blob_files(tmp_path)
        response = client.post(
            f"/v1/items/{item.id}/revisions/prune", json={"keep": 1}, headers=auth(token)
        )
        assert response.status_code == 409
        assert response.json()["error"] == "invalid_state"
        assert core.queries.get(item.id) == trashed
        assert _blob_files(tmp_path) == before


@pytest.mark.parametrize("keep", [1, 2, 4])
def test_c43_head_is_never_deleted(tmp_path: Path, keep: int) -> None:
    with admin_client(tmp_path) as (client, token, core):
        item = _publish(core, revisions=4)
        client.post(
            f"/v1/items/{item.id}/revisions/prune", json={"keep": keep}, headers=auth(token)
        )
        after = core.queries.get(item.id)
        assert after.head == item.head
        assert len(after.revisions) == min(keep, 4)
        with core.queries.open_file(item.id, "a.txt", allow_trashed=False) as opened:
            assert opened.stream.read() == b"v4"


# --- C43: empty trash vs a concurrent restore (real SQLite) ---------------------------------


class _RestoreAfterListing:
    """Real SQLite repository; the owner restores `victim` right after the trash listing."""

    def __init__(self, inner: SqliteItemRepository, victim: Item) -> None:
        self._inner = inner
        self._victim: Item | None = victim

    def list(self, query: ItemQuery) -> Page[Item]:
        page = self._inner.list(query)
        if self._victim is not None:
            # A separate service + connection, as the viewer process would be.
            LifecycleService(
                repo=self._inner, clock=SystemClock(), scanner=FakeContentScanner()
            ).restore(self._victim.id)
            self._victim = None
        return page

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_c43_item_restored_during_empty_trash_survives(tmp_path: Path) -> None:
    with admin_client(tmp_path) as (_, _, core):
        kept = _publish(core)
        gone = _publish(core, revisions=2)
        for item in (kept, gone):
            core.lifecycle.trash(item.id)
        kept_blobs = {f.blob_id for f in kept.all_files}
        gone_blobs = {f.blob_id for f in core.queries.get(gone.id).all_files}
        repo = SqliteItemRepository(connection_factory(core.settings, migrate=False))
        with FsBlobStore(
            Path(core.settings.data_dir), ids=UlidGenerator(), clock=SystemClock()
        ) as blobs:
            service = PurgeService(
                repo=_RestoreAfterListing(repo, kept),
                blobs=blobs,
                clock=SystemClock(),
                retention=timedelta(days=14),
                orphan_grace=timedelta(days=1),
            )
            report = service.empty_trash()
        assert report.items_purged == 1
        survivor = core.queries.get(kept.id)
        assert survivor.state is ItemState.ACTIVE
        on_disk = _blob_files(tmp_path)
        assert kept_blobs <= on_disk
        assert not gone_blobs & on_disk
