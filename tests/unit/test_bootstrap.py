"""Tests for the composition root: per-role wiring, least privilege, lifecycle, C16.

Uses real adapters over a tmp data dir (bootstrap's whole job is wiring
them), but only checks what each role gets, not the services' behavior.
"""

from __future__ import annotations

import dataclasses
import os
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard import config as config_module
from preview_dashboard.application import (
    ArchiveService,
    FolderService,
    HistoryService,
    LifecycleService,
    PublishService,
    PurgeService,
    QueryService,
)
from preview_dashboard.bootstrap import (
    AdminCore,
    FolderReader,
    PinControl,
    PurgeCore,
    ReadOnlyBlobStore,
    RevisionPruner,
    StorageTrust,
    TrashBin,
    TrashControl,
    ViewerCore,
    build_core,
    effective_trust,
    migrate_database,
    publish_limits,
    verify_config,
)
from preview_dashboard.config import ConfigError, Settings
from tests.admin_support import make_settings
from tests.fakes import InMemoryBlobStore

pytestmark = pytest.mark.unit


def _migrated(tmp_path: Path) -> Settings:
    """Settings over a data dir whose schema the admin side has created."""
    settings = make_settings(tmp_path)
    migrate_database(settings)
    return settings


def _service_fields(core: object) -> dict[str, object]:
    return {
        f.name: getattr(core, f.name)
        for f in dataclasses.fields(core)  # type: ignore[arg-type]
        if not f.name.startswith("_") and f.name != "settings"
    }


class TestRoles:
    def test_admin_core(self, tmp_path):
        with build_core(make_settings(tmp_path), role="admin") as core:
            assert isinstance(core, AdminCore)
            assert isinstance(core.publish, PublishService)
            assert isinstance(core.queries, QueryService)
            assert isinstance(core.lifecycle, LifecycleService)
            assert isinstance(core.folders, FolderService)
            assert set(_service_fields(core)) == {
                "kinds",
                "publish",
                "queries",
                "lifecycle",
                "folders",
                "questions",
                "notify",
                "outbox",
                "question_events",
                "outbox_events",
                "answer_sources",
                "history",
                "trash_bin",
                "claudia",
            }
            # Claudia (ADR 0031) is off unless `claudia_enabled`.
            assert core.claudia is None
            # Permanent deletes (ADR 0030): prune + empty trash only, no timed purge.
            assert isinstance(core.history, HistoryService)
            assert isinstance(core.trash_bin, TrashBin)
            assert {n for n in dir(core.trash_bin) if not n.startswith("_")} == {"empty"}

    def test_viewer_core_has_no_publish_or_edit_capability(self, tmp_path):
        with build_core(_migrated(tmp_path), role="viewer") as core:
            assert isinstance(core, ViewerCore)
            assert set(_service_fields(core)) == {
                "kinds",
                "queries",
                "trash",
                "pins",
                "archive",
                "folders",
                "history",
            }
            assert not hasattr(core, "publish")
            assert not hasattr(core, "lifecycle")
            assert not any(
                isinstance(v, PublishService | LifecycleService | PurgeService)
                for v in _service_fields(core).values()
            )
            assert isinstance(core.trash, TrashControl)
            assert not hasattr(core.trash, "update")
            # Pin control exposes the pin flag only: no text edits (C15).
            assert isinstance(core.pins, PinControl)
            assert not hasattr(core.pins, "update")
            assert core.pins._lifecycle is core.trash._lifecycle
            assert isinstance(core.archive, ArchiveService)
            # Folders are read-only in the viewer (C40).
            assert isinstance(core.folders, FolderReader)
            assert not isinstance(core.folders, FolderService)
            for write in ("create", "rename", "delete", "move", "add", "delete_if_empty"):
                assert not hasattr(core.folders, write)
            # Delete old versions (ADR 0030): keep=1 only, over the read-only store,
            # blobs left to the orphan sweep (no per-blob warnings).
            assert isinstance(core.history, RevisionPruner)
            assert {n for n in dir(core.history) if not n.startswith("_")} == {"prune_old"}
            assert isinstance(core.history._history._blobs, ReadOnlyBlobStore)
            assert core.history._history._delete_blobs_now is False

    def test_viewer_blob_store_is_read_only(self, tmp_path):
        with build_core(_migrated(tmp_path), role="viewer") as core:
            store = core.queries._blobs  # wiring check: the read path's store
            assert isinstance(store, ReadOnlyBlobStore)
            with pytest.raises(PermissionError):
                store.put([b"x"], max_bytes=10)
            with pytest.raises(PermissionError):
                store.delete("0" * 26)

    def test_purge_core_only_purges(self, tmp_path):
        with build_core(_migrated(tmp_path), role="purge") as core:
            assert isinstance(core, PurgeCore)
            assert set(_service_fields(core)) == {"purge", "history"}
            assert isinstance(core.history, HistoryService)
            report = core.purge.run()
            assert report.items_purged == 0
            assert set(report.maintenance) == {"staging"}

    def test_unknown_role_is_refused(self, tmp_path):
        with pytest.raises(ValueError, match="role"):
            build_core(make_settings(tmp_path), role="root")  # type: ignore[call-overload]


class TestResources:
    def test_close_releases_blob_store(self, tmp_path):
        core = build_core(make_settings(tmp_path), role="admin")
        core.close()
        core.close()  # idempotent
        with pytest.raises(RuntimeError):
            core.queries._blobs.free_bytes()

    def test_missing_data_dir_fails_fast(self, tmp_path):
        settings = make_settings(tmp_path, data_dir=tmp_path / "absent")
        with pytest.raises(FileNotFoundError):
            build_core(settings, role="admin")

    def test_untrusted_owner_fails_fast(self, tmp_path):
        trust = StorageTrust(uids=frozenset({os.geteuid() + 999}))
        with pytest.raises(Exception, match=r"untrusted|owned|trusted"):
            build_core(make_settings(tmp_path), role="admin", trust=trust)

    def test_insecure_config_file_refused(self, tmp_path, monkeypatch):
        conf_dir = tmp_path / "etc"
        conf_dir.mkdir(mode=0o755)
        conf = conf_dir / "config.toml"
        conf.write_text("")
        os.chmod(conf, 0o666)  # noqa: S103 - deliberately unsafe fixture
        monkeypatch.setenv("PDASH_CONFIG", str(conf))
        with pytest.raises(ConfigError):
            build_core(make_settings(tmp_path), role="viewer")

    def test_explicit_missing_config_file_refused(self, tmp_path, monkeypatch):
        """I6: a PDASH_CONFIG naming a missing file must not fall back to defaults."""
        missing = tmp_path / "gone" / "config.toml"
        monkeypatch.setenv("PDASH_CONFIG", str(missing))
        with pytest.raises(ConfigError, match=r"PDASH_CONFIG names .* does not exist"):
            verify_config()
        with pytest.raises(ConfigError, match="does not exist"):
            build_core(make_settings(tmp_path), role="admin")
        assert not (tmp_path / "data" / "db").exists()

    @pytest.mark.parametrize("value", [None, ""])
    def test_missing_default_config_file_is_fine(self, tmp_path, monkeypatch, value):
        # Only an *explicit* path must exist; the default /etc file is optional.
        monkeypatch.setattr(config_module, "_DEFAULT_CONFIG_FILE", tmp_path / "absent.toml")
        if value is None:
            monkeypatch.delenv("PDASH_CONFIG", raising=False)
        else:
            monkeypatch.setenv("PDASH_CONFIG", value)
        verify_config()

    @pytest.mark.parametrize("role", ["viewer", "purge"])
    def test_non_admin_roles_never_create_the_database(self, tmp_path, role):
        from preview_dashboard.adapters.sqlite import DatabaseSetupError

        with pytest.raises(DatabaseSetupError, match="does not exist yet"):
            build_core(make_settings(tmp_path), role=role)
        assert not (tmp_path / "data" / "db").exists()

    @pytest.mark.parametrize("role", ["viewer", "purge"])
    def test_non_admin_roles_never_migrate(self, tmp_path, role):
        import sqlite3

        from preview_dashboard.adapters.sqlite import DatabaseSetupError

        settings = _migrated(tmp_path)
        db = tmp_path / "data" / "db" / "items.sqlite3"
        with sqlite3.connect(db) as conn:
            conn.execute("PRAGMA user_version = 0")  # as if never migrated
        conn.close()
        with pytest.raises(DatabaseSetupError, match="version 0"):
            build_core(settings, role=role)
        with sqlite3.connect(db) as conn:
            assert conn.execute("PRAGMA user_version").fetchone() == (0,)
        conn.close()

    def test_admin_role_creates_and_migrates(self, tmp_path):
        with build_core(make_settings(tmp_path), role="admin"):
            pass
        assert (tmp_path / "data" / "db" / "items.sqlite3").is_file()

    def test_migrate_database_reports_version(self, tmp_path):
        assert migrate_database(make_settings(tmp_path)) >= 1
        assert (tmp_path / "data" / "db" / "items.sqlite3").is_file()


class TestMapping:
    def test_publish_limits_from_settings(self, tmp_path):
        settings = make_settings(tmp_path, publish_timeout_seconds=90, orphan_grace_seconds=900)
        limits = publish_limits(settings)
        assert limits.max_files == settings.max_files
        assert limits.max_file_bytes == settings.max_file_bytes
        assert limits.max_item_bytes == settings.max_item_bytes
        assert limits.max_total_bytes == settings.max_total_bytes
        assert limits.max_items == settings.max_items
        assert limits.min_free_disk_bytes == settings.min_free_disk_bytes
        assert limits.timeout == timedelta(seconds=90)

    def test_effective_trust(self):
        assert effective_trust() == StorageTrust()
        trust = effective_trust(extra_uids=[4242], gid=77)
        assert trust.uids == frozenset({os.geteuid(), 4242})
        assert trust.gid == 77

    def test_read_only_store_delegates_reads(self):
        inner = InMemoryBlobStore()
        ref = inner.put([b"abc"], max_bytes=10)
        store = ReadOnlyBlobStore(inner)
        with store.open(ref.blob_id) as stream:
            assert stream.read() == b"abc"
        assert store.list_ids() == {ref.blob_id}
        assert store.free_bytes() == inner.free_bytes()


class TestPurgeWiring:
    def test_purge_removes_expired_trash_and_compacts(self, tmp_path, monkeypatch):
        from datetime import UTC, datetime

        from preview_dashboard.adapters.sqlite import SqliteItemRepository
        from preview_dashboard.application import IncomingFile, PublishCommand

        calls: list[bool] = []
        real_compact = SqliteItemRepository.compact

        def spy(self: SqliteItemRepository, **kwargs: object) -> bool:
            calls.append(True)
            return real_compact(self)

        monkeypatch.setattr(SqliteItemRepository, "compact", spy)
        settings = make_settings(tmp_path)
        with build_core(settings, role="admin") as admin:
            item = admin.publish.publish(
                PublishCommand(title="t", files=[IncomingFile(relpath="a.txt", chunks=[b"x"])])
            )
            admin.lifecycle.trash(item.id)
        with build_core(settings, role="purge") as purge:
            report = purge.purge.run(now=datetime(2100, 1, 1, tzinfo=UTC))
        assert (report.items_purged, report.blobs_deleted) == (1, 1)
        assert calls == [True]


class TestPruneCompactWiring:
    """Every role's HistoryService compacts the WAL after a committed prune (C24)."""

    @staticmethod
    def _spy(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
        from preview_dashboard.adapters.sqlite import SqliteItemRepository

        calls: list[bool] = []
        real_compact = SqliteItemRepository.compact

        def spy(self: SqliteItemRepository, **kwargs: object) -> bool:
            calls.append(True)
            return real_compact(self)

        monkeypatch.setattr(SqliteItemRepository, "compact", spy)
        return calls

    @staticmethod
    def _two_revisions(settings: Settings, *, revise: bool = True) -> str:
        from preview_dashboard.application import IncomingFile, PublishCommand, RevisionCommand

        with build_core(settings, role="admin") as admin:
            item = admin.publish.publish(
                PublishCommand(title="t", files=[IncomingFile(relpath="a.txt", chunks=[b"x"])])
            )
            if revise:
                admin.publish.publish_revision(
                    RevisionCommand(
                        item_id=item.id, files=[IncomingFile(relpath="a.txt", chunks=[b"yy"])]
                    )
                )
            return item.id

    @pytest.mark.parametrize("role", ["admin", "viewer", "purge"])
    @pytest.mark.parametrize("revise", [True, False])
    def test_compacts_once_only_when_something_was_pruned(
        self, tmp_path, monkeypatch, role, revise
    ):
        settings = make_settings(tmp_path)
        item_id = self._two_revisions(settings, revise=revise)
        calls = self._spy(monkeypatch)
        with build_core(settings, role=role) as core:
            if role == "viewer":
                result = core.history.prune_old(item_id)
            else:
                result = core.history.prune_revisions(item_id, keep=1)
        assert result.revisions_removed == (1 if revise else 0)
        assert calls == ([True] if revise else [])


class TestNotifyWiring:
    """ADR 0021 wiring: SQLite store, one shared alert limiter, channels, links, purge."""

    def test_admin_core_wires_the_question_services(self, tmp_path):
        from preview_dashboard.adapters.sqlite import (
            SqliteNotificationOutbox,
            SqliteQuestionRepository,
        )
        from preview_dashboard.adapters.wakeups import AsyncioOutboxEvents, AsyncioQuestionEvents

        settings = make_settings(
            tmp_path,
            notify_enabled=True,
            notify_owner_chat_id=4242,
            notify_rate_per_hour=7,
            question_ttl_seconds=600,
        )
        with build_core(settings, role="admin") as core:
            questions, notify = core.questions, core.notify
            assert isinstance(questions._repo, SqliteQuestionRepository)
            assert isinstance(questions._outbox, SqliteNotificationOutbox)
            assert isinstance(notify._outbox, SqliteNotificationOutbox)
            # One alert budget for ask + notify (C37).
            assert questions._limiter is notify._limiter
            assert questions._limiter._limit == 7  # type: ignore[attr-defined]
            assert questions._channels == notify._channels == ("telegram",)
            assert questions._ttl == timedelta(seconds=600)
            assert questions._links.base == "https://dash.example.ts.net"
            assert isinstance(core.question_events, AsyncioQuestionEvents)
            assert isinstance(core.outbox_events, AsyncioOutboxEvents)
            assert questions._events is core.question_events
            assert questions._outbox_events is notify._outbox_events is core.outbox_events
            assert core.answer_sources == ("telegram",)

    def test_disabled_notifications_have_no_channels(self, tmp_path):
        with build_core(make_settings(tmp_path), role="admin") as core:
            assert core.questions._channels == core.notify._channels == ()
            assert core.answer_sources == ()

    def test_purge_expires_due_questions(self, tmp_path):
        from preview_dashboard.application import AskCommand, QuestionHousekeeping
        from preview_dashboard.domain.questions import QuestionState
        from tests.fakes import FixedClock

        settings = make_settings(tmp_path, notify_enabled=True, notify_owner_chat_id=4242)
        clock = FixedClock()
        with build_core(settings, role="admin", clock=clock) as admin:
            question = admin.questions.ask(
                AskCommand(
                    prompt="Ship it?",
                    options=[("a", "Yes"), ("b", "No")],
                    session_label="purge test",
                    expires_in=timedelta(seconds=60),
                )
            )
        clock.advance(timedelta(minutes=5))
        with build_core(settings, role="purge", clock=clock) as purge:
            assert isinstance(purge.purge._questions, QuestionHousekeeping)
            report = purge.purge.run()
        assert report.questions_expired == 1
        with build_core(settings, role="admin", clock=clock) as admin:
            assert admin.questions.get(question.id).state is QuestionState.EXPIRED
