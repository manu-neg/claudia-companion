"""Security tests: the viewer's "delete old versions" route (C43, ADR 0030, unit R2).

`POST /api/items/{id}/revisions/prune` keeps only the head, refuses trashed
items and stale views, accepts no `keep`, and leaves blobs to the orphan
sweep (the viewer's blob store is read-only) without a warning per blob.
The CSRF/identity matrix for this route lives in `test_viewer_state_changes.py`.
"""

from __future__ import annotations

import logging

import pytest

from preview_dashboard.domain.models import Item, ItemId
from tests.viewer_support import ViewerEnv, csrf_headers, make_env

pytestmark = pytest.mark.security


def _three_versions(env: ViewerEnv) -> Item:
    item = env.publish({"a.txt": b"one"}, title="A")
    env.revise(item.id, {"a.txt": b"two!"})
    return env.revise(item.id, {"a.txt": b"three"})


def test_prune_keeps_only_the_head_and_reports_counts() -> None:
    env = make_env()
    item = _three_versions(env)
    response = env.dash_client().post(
        f"/api/items/{item.id}/revisions/prune?expected=3", headers=csrf_headers(), content=b"{}"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["revisions_removed"] == 2
    assert body["bytes_freed"] == len(b"one") + len(b"two!")
    assert [r["number"] for r in body["item"]["revisions"]] == [3]
    stored = env.services.repo.get(ItemId(item.id))
    assert [r.number for r in stored.revisions] == [3]


def test_nothing_to_prune_is_a_no_op() -> None:
    env = make_env()
    item = env.publish({"a.txt": b"x"})
    response = env.dash_client().post(
        f"/api/items/{item.id}/revisions/prune?expected=1", headers=csrf_headers(), content=b"{}"
    )
    assert response.status_code == 200
    assert response.json()["revisions_removed"] == 0
    assert env.services.repo.get(ItemId(item.id)) == item


def test_trashed_item_is_409_and_unchanged() -> None:
    env = make_env()
    item = env.services.trash.trash(_three_versions(env).id)
    response = env.dash_client().post(
        f"/api/items/{item.id}/revisions/prune?expected=3", headers=csrf_headers(), content=b"{}"
    )
    assert response.status_code == 409
    assert env.services.repo.get(ItemId(item.id)) == item


def test_stale_expected_revision_is_409_and_unchanged() -> None:
    """A version published after the owner opened the dialog is never deleted unseen."""
    env = make_env()
    item = _three_versions(env)
    response = env.dash_client().post(
        f"/api/items/{item.id}/revisions/prune?expected=2", headers=csrf_headers(), content=b"{}"
    )
    assert response.status_code == 409
    assert env.services.repo.get(ItemId(item.id)) == item


@pytest.mark.parametrize(
    "query",
    [
        "?expected=0",
        "?expected=x",
        "?expected=",
        "?expected=1&expected=1",
        "?keep=2",
        "?expected=3&keep=1",
        "",  # `expected` is required: no blind permanent delete from the viewer
    ],
)
def test_bad_or_missing_query_is_400_and_unchanged(query: str) -> None:
    """`expected` is required; keep is fixed at 1: a `keep` parameter is refused."""
    env = make_env()
    item = _three_versions(env)
    response = env.dash_client().post(
        f"/api/items/{item.id}/revisions/prune{query}", headers=csrf_headers(), content=b"{}"
    )
    assert response.status_code == 400
    assert env.services.repo.get(ItemId(item.id)) == item


def test_unknown_item_is_404() -> None:
    env = make_env()
    response = env.dash_client().post(
        "/api/items/01ARZ3NDEKTSV4RRFFQ69G5FAV/revisions/prune?expected=1",
        headers=csrf_headers(),
        content=b"{}",
    )
    assert response.status_code == 404


def test_blobs_are_left_to_the_orphan_sweep_without_warnings(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Read-only blob store: commit only, no delete attempt, no WARNING per blob."""
    env = make_env()
    item = _three_versions(env)
    before = env.services.blobs.list_ids()
    with caplog.at_level(logging.INFO):
        response = env.dash_client().post(
            f"/api/items/{item.id}/revisions/prune?expected=3",
            headers=csrf_headers(),
            content=b"{}",
        )
    assert response.status_code == 200
    assert env.services.blobs.list_ids() == before  # freed later by the hourly sweep
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("orphan sweep" in r.getMessage() for r in caplog.records)
