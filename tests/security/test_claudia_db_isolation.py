"""Security tests for S-C1 S1 (C44, C46, C47, C28): the admin-only Claudia database.

Approvals and owner messages must not live where the viewer can write. The
Claudia DB is created only by the admin role with dir 0700 / file 0600, and
any looser mode, foreign owner, symlink, hardlink or newer schema is refused
(fail closed, never "fixed"). The viewer core never opens it; the purge job
opens it only when Claudia is on, never creates it.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite.claudia_db import (
    CLAUDIA_DIR_MODE,
    CLAUDIA_FILE_MODE,
    connect_claudia,
    default_claudia_db_path,
)
from preview_dashboard.adapters.sqlite.connection import UnsafeDatabasePathError, default_db_path
from preview_dashboard.adapters.sqlite.connection import connect as connect_items
from preview_dashboard.adapters.sqlite.migrations import DatabaseSetupError
from preview_dashboard.bootstrap import build_core
from tests.admin_support import make_settings
from tests.claudia_admin_support import claudia_app

pytestmark = pytest.mark.security


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


@pytest.fixture
def created(tmp_path: Path) -> Path:
    path = default_claudia_db_path(tmp_path)
    connect_claudia(path).close()
    return path


def test_s1_created_with_exact_private_modes_regardless_of_umask(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        path = default_claudia_db_path(tmp_path)
        connect_claudia(path).close()
    finally:
        os.umask(old)
    assert _mode(path.parent) == CLAUDIA_DIR_MODE == 0o700
    assert _mode(path) == CLAUDIA_FILE_MODE == 0o600
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            assert _mode(sidecar) & 0o077 == 0


@pytest.mark.parametrize("mode", [0o750, 0o710, 0o701, 0o770, 0o2700 | 0o070])
def test_s1_looser_directory_is_refused(created: Path, mode: int) -> None:
    os.chmod(created.parent, mode)
    with pytest.raises(UnsafeDatabasePathError, match="Claudia directory"):
        connect_claudia(created)
    assert _mode(created.parent) == mode  # refused, never "fixed"


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o610])
def test_s1_looser_file_is_refused(created: Path, mode: int) -> None:
    os.chmod(created, mode)
    with pytest.raises(UnsafeDatabasePathError, match="Claudia database file"):
        connect_claudia(created)
    with pytest.raises(UnsafeDatabasePathError):
        connect_claudia(created, create=False)


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_s1_looser_sidecar_is_refused(created: Path, suffix: str) -> None:
    sidecar = created.with_name(created.name + suffix)
    sidecar.touch(mode=0o600)
    os.chmod(sidecar, 0o640)
    with pytest.raises(UnsafeDatabasePathError, match=suffix):
        connect_claudia(created)


def test_s1_symlinked_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o700)
    (tmp_path / "claudia").symlink_to(real)
    with pytest.raises(UnsafeDatabasePathError, match="real directory"):
        connect_claudia(default_claudia_db_path(tmp_path))


def test_s1_symlinked_file_is_refused(tmp_path: Path) -> None:
    path = default_claudia_db_path(tmp_path)
    path.parent.mkdir(mode=0o700)
    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    path.symlink_to(target)
    with pytest.raises(UnsafeDatabasePathError, match="symlink"):
        connect_claudia(path)


def test_s1_hardlinked_file_is_refused(created: Path, tmp_path: Path) -> None:
    os.link(created, tmp_path / "second-link")
    with pytest.raises(UnsafeDatabasePathError, match="one link"):
        connect_claudia(created)


def test_s1_group_writable_data_dir_is_refused(created: Path, tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o770)  # noqa: S103 - deliberately unsafe fixture
    try:
        with pytest.raises(UnsafeDatabasePathError, match="data directory"):
            connect_claudia(created)
    finally:
        os.chmod(tmp_path, 0o700)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to hand the file to another uid")
def test_s1_foreign_owner_is_refused(created: Path) -> None:
    os.chown(created, 65534, -1)  # e.g. the viewer's uid
    with pytest.raises(UnsafeDatabasePathError, match="not owned by the admin user"):
        connect_claudia(created)


def test_s1_item_db_never_holds_approvals_or_messages(tmp_path: Path) -> None:
    # The viewer writes the item DB: a forged row there must have no table to land in.
    path = default_db_path(tmp_path)
    connect_items(path).close()
    raw = sqlite3.connect(path)
    try:
        names = {r[0] for r in raw.execute("SELECT name FROM sqlite_master")}
    finally:
        raw.close()
    assert "approval_requests" not in names
    assert "owner_messages" not in names


def test_s1_admin_creates_the_private_db_and_the_stores_use_it(tmp_path: Path) -> None:
    with claudia_app(tmp_path) as rig:
        data_dir = Path(rig.core.settings.data_dir)
        path = default_claudia_db_path(data_dir)
        assert _mode(path.parent) == 0o700
        assert _mode(path) == 0o600
        raw = sqlite3.connect(path)
        try:
            names = {r[0] for r in raw.execute("SELECT name FROM sqlite_master")}
        finally:
            raw.close()
        assert {"approval_requests", "owner_messages"} <= names


def test_s1_viewer_and_purge_never_create_it(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, claudia_enabled=False)
    with build_core(settings, role="admin"):
        pass
    claudia_dir = default_claudia_db_path(Path(settings.data_dir)).parent
    assert not claudia_dir.exists()  # Claudia off: not even the admin makes it
    with build_core(settings, role="viewer"):
        pass
    with build_core(settings, role="purge") as core:
        report = core.purge.run()
    assert not claudia_dir.exists()
    assert (report.inbox_failed, report.approvals_expired) == (False, 0)


def test_s1_purge_opens_but_never_creates_when_claudia_is_on(tmp_path: Path) -> None:
    with claudia_app(tmp_path) as rig:
        settings = rig.core.settings
    path = default_claudia_db_path(Path(settings.data_dir))
    os.unlink(path)
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            os.unlink(sidecar)
    with build_core(settings, role="purge") as core:
        report = core.purge.run()
    assert report.inbox_failed is True  # contained, flagged, and nothing created
    assert not path.exists()
    with pytest.raises(DatabaseSetupError):
        connect_claudia(path, create=False)
