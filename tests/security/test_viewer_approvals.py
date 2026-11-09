"""Security tests: the viewer's read-only pending-approvals list (C57, unit M8).

The viewer reads the admin's snapshot file and fails closed: absent, malformed,
unexpected keys, unknown kinds, unsafe permissions or a symlink all read as
"unavailable" with no entries; expired entries are dropped.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from preview_dashboard.adapters.kb_reader import FileApprovalsSnapshot
from preview_dashboard.application.pending_approvals import PendingApprovalsService
from tests.fakes import FixedClock
from tests.kb_viewer_support import kb_client
from tests.viewer_support import owner_headers

pytestmark = pytest.mark.security

ULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def _entry(clock: FixedClock, **overrides: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": ULID,
        "action_text": "Merge PR 42 into main",
        "kind": None,
        "target": None,
        "state": "pending",
        "expires_at": (clock.now() + timedelta(minutes=5)).isoformat(),
    }
    entry.update(overrides)
    return entry


def _write(tmp_path: Path, payload: object, mode: int = 0o640) -> Path:
    folder = tmp_path / "run"
    folder.mkdir(mode=0o750, exist_ok=True)
    os.chmod(folder, 0o750)  # noqa: S103 - mirrors the production mode
    path = folder / "approvals.json"
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), "utf-8")
    os.chmod(path, mode)
    return path


def _current(path: Path, clock: FixedClock) -> Any:
    return PendingApprovalsService(FileApprovalsSnapshot(path), clock).current()


def test_absent_snapshot_is_unavailable(tmp_path: Path) -> None:
    clock = FixedClock()
    result = _current(tmp_path / "none.json", clock)
    assert not result.available and result.approvals == ()
    assert not PendingApprovalsService(None, clock).current().available


def test_valid_snapshot_is_listed(tmp_path: Path) -> None:
    clock = FixedClock()
    path = _write(tmp_path, {"version": 1, "approvals": [_entry(clock)]})
    result = _current(path, clock)
    assert result.available
    assert [a.id for a in result.approvals] == [ULID]


def test_route_serves_the_snapshot(tmp_path: Path) -> None:
    clock = FixedClock()
    path = _write(tmp_path, {"version": 1, "approvals": [_entry(clock)]})
    body = kb_client(None, snapshot=path, clock=clock).get(
        "/api/claudia/approvals", headers=owner_headers()
    )
    assert body.status_code == 200
    data = body.json()
    assert data["available"] is True
    assert data["approvals"][0]["action_text"] == "Merge PR 42 into main"
    assert data["approvals"][0]["expires_at"].endswith("Z")


def test_route_without_snapshot_is_none(tmp_path: Path) -> None:
    response = kb_client(None).get("/api/claudia/approvals", headers=owner_headers())
    assert response.status_code == 200
    assert response.json() == {"available": False, "approvals": []}


def test_expired_entries_are_dropped(tmp_path: Path) -> None:
    clock = FixedClock()
    old = _entry(clock, expires_at=(clock.now() - timedelta(seconds=1)).isoformat())
    path = _write(tmp_path, {"version": 1, "approvals": [old]})
    result = _current(path, clock)
    assert result.available and result.approvals == ()


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[]",
        {"version": 2, "approvals": []},
        {"version": 1},
        {"version": 1, "approvals": [], "extra": 1},
        {"version": 1, "approvals": "x"},
    ],
)
def test_malformed_snapshot_is_unavailable(tmp_path: Path, payload: object) -> None:
    clock = FixedClock()
    assert not _current(_write(tmp_path, payload), clock).available


@pytest.mark.parametrize(
    "overrides",
    [
        {"extra": "x"},
        {"kind": "rm-everything"},
        {"state": "denied"},
        {"id": "not-a-ulid"},
        {"action_text": "x" * 201},
        {"action_text": "line\u0007bell"},
        {"expires_at": "2026-01-01T00:00:00"},
    ],
)
def test_one_bad_entry_makes_it_unavailable(tmp_path: Path, overrides: dict[str, Any]) -> None:
    clock = FixedClock()
    entries = [_entry(clock), _entry(clock, **overrides)]
    result = _current(_write(tmp_path, {"version": 1, "approvals": entries}), clock)
    assert not result.available and result.approvals == ()


def test_too_many_entries_is_unavailable(tmp_path: Path) -> None:
    clock = FixedClock()
    path = _write(tmp_path, {"version": 1, "approvals": [_entry(clock)] * 51})
    assert not _current(path, clock).available


@pytest.mark.parametrize("mode", [0o660, 0o646])
def test_writable_snapshot_is_unavailable(tmp_path: Path, mode: int) -> None:
    clock = FixedClock()
    path = _write(tmp_path, {"version": 1, "approvals": [_entry(clock)]}, mode)
    assert not _current(path, clock).available


def test_writable_directory_is_unavailable(tmp_path: Path) -> None:
    clock = FixedClock()
    path = _write(tmp_path, {"version": 1, "approvals": [_entry(clock)]})
    os.chmod(path.parent, 0o770)  # noqa: S103 - the unsafe mode under test
    assert not _current(path, clock).available


def test_symlinked_snapshot_is_unavailable(tmp_path: Path) -> None:
    clock = FixedClock()
    real = _write(tmp_path, {"version": 1, "approvals": [_entry(clock)]})
    alias = real.parent / "alias.json"
    alias.symlink_to(real)
    assert not _current(alias, clock).available
    (tmp_path / "linkdir").symlink_to(real.parent)
    assert not _current(tmp_path / "linkdir" / "approvals.json", clock).available


def test_oversized_snapshot_is_unavailable(tmp_path: Path) -> None:
    clock = FixedClock()
    path = _write(tmp_path, " " * (256 * 1024 + 1))
    assert not _current(path, clock).available
