"""G2 / ADR 0025: `-wal`/`-shm` recreated by the viewer must not lock the admin out.

Reproduces the 2026-09-27 incident (admin: "-wal file is owned by an
untrusted uid"): SQLite deletes the sidecars when the last connection
closes, and whichever process opens the DB next recreates them as its own
uid. Two uids aren't available in tests, so the viewer's ownership is
simulated by rewriting `st_uid` in the adapter's `lstat` (plus one real
`chown` test when running as root). Main DB file and dirs stay C24-strict,
and a refusal is a 503 + Retry-After (server-side), never a 400.
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import connection as connection_module
from preview_dashboard.adapters.sqlite.connection import (
    SIDECAR_SUFFIXES,
    UnsafeDatabasePathError,
    connect,
    default_db_path,
)
from preview_dashboard.bootstrap import StorageTrust, connection_factory, effective_trust
from preview_dashboard.domain.errors import StorageUnavailableError, ValidationError
from preview_dashboard.interfaces import cli
from preview_dashboard.interfaces.admin.errors import STORAGE_RETRY_AFTER_SECONDS, classify
from preview_dashboard.interfaces.viewer.errors import status_for
from tests.admin_support import admin_client, auth, make_settings

pytestmark = pytest.mark.integration

_ROOT = os.geteuid() == 0
VIEWER_UID = 54_997  # stands in for pdash-viewer; no test process runs as it


def _with_uid(st: os.stat_result, uid: int) -> os.stat_result:
    fields = list(st[:10])
    fields[4] = uid  # st_uid
    return os.stat_result(fields)


def _pretend_owned_by(monkeypatch: pytest.MonkeyPatch, uid: int, *suffixes: str) -> None:
    """Make the adapter see entries ending in `suffixes` as owned by `uid`."""
    real = connection_module._lstat_at

    def lstat_at(dir_fd: int, name: str) -> os.stat_result | None:
        st = real(dir_fd, name)
        if st is not None and name.endswith(suffixes):
            return _with_uid(st, uid)
        return st

    monkeypatch.setattr(connection_module, "_lstat_at", lstat_at)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = default_db_path(tmp_path)
    connect(path).close()
    return path


def _sidecars(db_path: Path) -> list[Path]:
    return [db_path.with_name(db_path.name + s) for s in SIDECAR_SUFFIXES]


def _viewer_opens(db_path: Path) -> sqlite3.Connection:
    """What a viewer request does in a gap: open the WAL DB and read (plain sqlite3)."""
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return conn


class TestReproduction:
    """The root cause, step by step (hypothesis confirmed)."""

    def test_last_close_deletes_sidecars_and_the_next_opener_recreates_them(
        self, db_path: Path
    ) -> None:
        assert not any(p.exists() for p in _sidecars(db_path))  # gap: no -wal/-shm
        viewer = _viewer_opens(db_path)
        try:
            # Created by the opener, i.e. owned by *its* uid (pdash-viewer in prod).
            assert all(p.exists() for p in _sidecars(db_path))
        finally:
            viewer.close()
        assert not any(p.exists() for p in _sidecars(db_path))

    @pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
    def test_admin_without_sidecar_trust_refuses_viewer_owned_sidecar(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
    ) -> None:
        viewer = _viewer_opens(db_path)
        try:
            _pretend_owned_by(monkeypatch, VIEWER_UID, suffix)
            with pytest.raises(UnsafeDatabasePathError, match=f"{suffix} file is owned"):
                connect(db_path)  # the admin's pre-fix trust set: its own euid only
        finally:
            viewer.close()


class TestSidecarTrust:
    """`trusted_sidecar_uids` covers `-wal`/`-shm` only (ADR 0025)."""

    def test_admin_accepts_viewer_owned_sidecars(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        viewer = _viewer_opens(db_path)
        try:
            _pretend_owned_by(monkeypatch, VIEWER_UID, *SIDECAR_SUFFIXES)
            conn = connect(db_path, trusted_sidecar_uids={VIEWER_UID})
            conn.execute("SELECT count(*) FROM items").fetchone()
            conn.close()
        finally:
            viewer.close()

    def test_post_connect_check_also_uses_sidecar_trust(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # No sidecars before connecting: they appear during connect (post-check path).
        _pretend_owned_by(monkeypatch, VIEWER_UID, *SIDECAR_SUFFIXES)
        with pytest.raises(UnsafeDatabasePathError, match="-wal file is owned"):
            connect(db_path)
        connect(db_path, trusted_sidecar_uids={VIEWER_UID}).close()

    def test_main_db_file_is_never_covered(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _pretend_owned_by(monkeypatch, VIEWER_UID, db_path.name)
        with pytest.raises(UnsafeDatabasePathError, match="database file is owned"):
            connect(db_path, trusted_sidecar_uids={VIEWER_UID})

    def test_other_uids_still_refused(self, db_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        viewer = _viewer_opens(db_path)
        try:
            _pretend_owned_by(monkeypatch, VIEWER_UID + 1, "-wal")
            with pytest.raises(UnsafeDatabasePathError, match="-wal file is owned"):
                connect(db_path, trusted_sidecar_uids={VIEWER_UID})
        finally:
            viewer.close()

    @pytest.mark.parametrize("suffix", SIDECAR_SUFFIXES)
    def test_mode_checks_still_apply_to_trusted_sidecars(
        self, db_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
    ) -> None:
        sidecar = db_path.with_name(db_path.name + suffix)
        sidecar.write_bytes(b"")
        os.chmod(sidecar, 0o664)
        _pretend_owned_by(monkeypatch, VIEWER_UID, suffix)
        with pytest.raises(UnsafeDatabasePathError, match=suffix):
            connect(db_path, trusted_sidecar_uids={VIEWER_UID})

    def test_sidecar_trust_does_not_extend_to_directories(self, tmp_path: Path) -> None:
        path = default_db_path(tmp_path)
        connect(path).close()
        # The layout is owned by this euid; trusting it for sidecars only is not enough.
        with pytest.raises(UnsafeDatabasePathError, match="untrusted uid"):
            connect(path, trusted_uids={os.geteuid() + 1}, trusted_sidecar_uids={os.geteuid()})

    @pytest.mark.skipif(not _ROOT, reason="chown to a foreign uid needs root")
    def test_real_foreign_owned_sidecars(self, db_path: Path) -> None:
        viewer = _viewer_opens(db_path)
        try:
            for sidecar in _sidecars(db_path):
                os.chown(sidecar, VIEWER_UID, -1)
            with pytest.raises(UnsafeDatabasePathError, match="owned by an untrusted uid"):
                connect(db_path)
            conn = connect(db_path, trusted_sidecar_uids={VIEWER_UID})
            conn.execute("SELECT count(*) FROM items").fetchone()
            conn.close()
        finally:
            viewer.close()


class TestWiring:
    """`--trusted-sidecar-uid` → `StorageTrust.sidecar_uids` → `connect`."""

    def test_effective_trust_keeps_sidecar_uids_separate(self) -> None:
        trust = effective_trust(sidecar_uids=[VIEWER_UID])
        assert trust == StorageTrust(sidecar_uids=frozenset({VIEWER_UID}))
        assert trust.uids is None  # the layout itself: still only this euid
        assert effective_trust() == StorageTrust()

    def test_connection_factory_passes_sidecar_uids(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = make_settings(tmp_path)
        trust = StorageTrust(sidecar_uids=frozenset({VIEWER_UID}))
        _pretend_owned_by(monkeypatch, VIEWER_UID, *SIDECAR_SUFFIXES)
        connection_factory(settings, trust)().close()
        with pytest.raises(UnsafeDatabasePathError):
            connection_factory(settings)().close()

    @pytest.mark.parametrize("command", ["serve-admin", "purge", "migrate"])
    def test_cli_flag_reaches_the_trust(self, command: str) -> None:
        args = cli.build_parser().parse_args([command, "--trusted-sidecar-uid", str(VIEWER_UID)])
        assert args.trusted_sidecar_uid == [VIEWER_UID]
        if command != "migrate":
            assert cli._sidecar_trust(args) == StorageTrust(sidecar_uids=frozenset({VIEWER_UID}))

    def test_without_flag_nothing_extra_is_trusted(self) -> None:
        args = argparse.Namespace(trusted_sidecar_uid=None)
        assert cli._sidecar_trust(args) == StorageTrust()

    def test_migrate_command_uses_the_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[StorageTrust | None] = []

        def fake_migrate(_settings: object, trust: StorageTrust | None = None) -> int:
            seen.append(trust)
            return 7

        monkeypatch.setattr(cli, "load_settings", lambda: make_settings(tmp_path))
        monkeypatch.setattr(cli, "migrate_database", fake_migrate)
        assert cli.main(["migrate", "--trusted-sidecar-uid", str(VIEWER_UID)]) == 0
        assert seen == [StorageTrust(sidecar_uids=frozenset({VIEWER_UID}))]


class TestRefusalIsServerSide:
    """A C24 refusal is 503 + Retry-After, never 400 `invalid_input` (the incident)."""

    def test_unsafe_path_is_storage_unavailable_not_validation(self) -> None:
        exc = UnsafeDatabasePathError("database -wal file is owned by an untrusted uid")
        assert isinstance(exc, StorageUnavailableError)
        assert not isinstance(exc, ValidationError)
        assert classify(exc) == (503, "storage_unavailable")
        assert status_for(exc) == 503

    def test_admin_api_answers_503_with_retry_after(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with admin_client(tmp_path) as (client, token, _core):
            viewer = _viewer_opens(default_db_path(tmp_path / "data"))
            try:
                _pretend_owned_by(monkeypatch, VIEWER_UID, "-wal")
                with caplog.at_level(logging.INFO, logger="preview_dashboard.admin"):
                    response = client.get("/v1/items", headers=auth(token))
            finally:
                viewer.close()
            assert response.status_code == 503
            assert response.json()["error"] == "storage_unavailable"
            assert response.headers["retry-after"] == str(STORAGE_RETRY_AFTER_SECONDS)
            assert any(
                r.levelno == logging.WARNING and "-> 503" in r.getMessage() for r in caplog.records
            )
            monkeypatch.undo()
            assert client.get("/v1/items", headers=auth(token)).status_code == 200
