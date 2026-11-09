"""Shared helpers for the viewer knowledge-map tests: tmp KB trees and apps wired to them.

The real KB does not exist in tests: each test builds its own tree under a tmp
dir (owned by the test user, mode 0750 like production) and points the
dashboard app at it through `Knowledge`.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from starlette.testclient import TestClient

from preview_dashboard.adapters.kb_reader import FileApprovalsSnapshot, FsKbReader
from preview_dashboard.application.kb_graph import KbGraphService
from preview_dashboard.application.pending_approvals import PendingApprovalsService
from preview_dashboard.interfaces.viewer.app_factory import SecuredApp, build_dashboard_app
from preview_dashboard.interfaces.viewer.knowledge import Knowledge
from tests.fakes import FixedClock
from tests.viewer_support import StubServices, dashboard_client, make_settings

KEY = b"k" * 32


def write_kb(root: Path, files: Mapping[str, str | bytes]) -> Path:
    """Create `root` (0750) and the given files (relpath -> text or bytes, 0640)."""
    root.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chmod(root, 0o750)  # noqa: S103 - test tree mirrors the production mode
    for relpath, content in files.items():
        path = root / relpath
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        path.write_bytes(data)
        os.chmod(path, 0o640)
    for directory in [p for p in root.rglob("*") if p.is_dir() and not p.is_symlink()]:
        os.chmod(directory, 0o750)  # noqa: S103 - test tree mirrors the production mode
    return root


def reader(root: Path) -> FsKbReader:
    """A reader that expects the test user (not root) to own the tree."""
    return FsKbReader(root, expected_uid=os.getuid())


def graph_service(root: Path, clock: FixedClock | None = None) -> KbGraphService:
    return KbGraphService(reader(root), clock or FixedClock(), key=KEY)


def kb_app(
    root: Path | None,
    *,
    snapshot: Path | None = None,
    clock: FixedClock | None = None,
) -> SecuredApp:
    """The dashboard app with the knowledge map on `root` (None = map off)."""
    clock = clock or FixedClock()
    graph = graph_service(root, clock) if root is not None else None
    source = FileApprovalsSnapshot(snapshot) if snapshot is not None else None
    knowledge = Knowledge(graph=graph, approvals=PendingApprovalsService(source, clock))
    return build_dashboard_app(make_settings(), StubServices(), knowledge=knowledge)


def kb_client(root: Path | None, **kwargs: object) -> TestClient:
    return dashboard_client(kb_app(root, **kwargs))  # type: ignore[arg-type]
