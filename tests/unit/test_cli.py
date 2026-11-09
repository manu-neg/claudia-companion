"""Tests for the `preview-dashboard` CLI: gen-token, purge, migrate, check-config, errors.

Commands run in-process via `cli.main(argv, out=...)`; config comes from
`PDASH_*` env vars pointed at a tmp data dir (and, via conftest, an empty
TOML file, so the host's /etc config is never read).
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import stat
from pathlib import Path

import pytest

from preview_dashboard.application import (
    IncomingFile,
    PublishCommand,
    PurgeReport,
    RevisionCommand,
)
from preview_dashboard.bootstrap import build_core
from preview_dashboard.config import Settings
from preview_dashboard.interfaces import cli
from preview_dashboard.interfaces.admin.auth import load_admin_token
from tests.admin_support import write_token

pytestmark = pytest.mark.unit


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data = tmp_path / "data"
    data.mkdir(mode=0o750)
    monkeypatch.setenv("PDASH_DATA_DIR", str(data))
    monkeypatch.setenv("PDASH_ADMIN_TOKEN_FILE", str(tmp_path / "secrets" / "admin.token"))
    return tmp_path


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return cli.main(list(argv), out=out), out.getvalue()


class TestGenToken:
    def test_creates_private_token_file(self, tmp_path):
        path = tmp_path / "admin.token"
        code, output = run("gen-token", "--out", str(path))
        assert code == 0
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o640
        token = path.read_text().strip()
        assert len(token) >= 43
        assert token not in output
        assert load_admin_token(path) == token.encode()

    def test_mode_is_exact_whatever_the_umask(self, tmp_path):
        old = os.umask(0)
        try:
            run("gen-token", "--out", str(tmp_path / "t"))
        finally:
            os.umask(old)
        assert stat.S_IMODE(os.lstat(tmp_path / "t").st_mode) == 0o640

    def test_tokens_are_unique(self, tmp_path):
        run("gen-token", "--out", str(tmp_path / "a"))
        run("gen-token", "--out", str(tmp_path / "b"))
        assert (tmp_path / "a").read_text() != (tmp_path / "b").read_text()

    def test_refuses_to_overwrite(self, tmp_path, capsys):
        path = tmp_path / "admin.token"
        path.write_text("existing")
        code, _ = run("gen-token", "--out", str(path))
        assert code == cli.EXIT_FAILED
        assert path.read_text() == "existing"
        assert "refusing to overwrite" in capsys.readouterr().err

    def test_refuses_symlink(self, tmp_path):
        target = tmp_path / "target"
        link = tmp_path / "admin.token"
        link.symlink_to(target)
        code, _ = run("gen-token", "--out", str(link))
        assert code == cli.EXIT_FAILED
        assert not target.exists()

    def test_unknown_group(self, tmp_path):
        code, _ = run("gen-token", "--out", str(tmp_path / "t"), "--group", "no-such-group-x")
        assert code == cli.EXIT_FAILED
        assert not (tmp_path / "t").exists()

    def test_group_is_applied(self, tmp_path):
        import grp

        group = grp.getgrgid(os.getegid()).gr_name
        path = tmp_path / "t"
        assert run("gen-token", "--out", str(path), "--group", group)[0] == 0
        assert os.lstat(path).st_gid == os.getegid()

    def test_group_by_numeric_gid(self, tmp_path):
        path = tmp_path / "t"
        assert run("gen-token", "--out", str(path), "--group", str(os.getegid()))[0] == 0
        assert os.lstat(path).st_gid == os.getegid()

    def test_unknown_numeric_gid(self, tmp_path):
        code, _ = run("gen-token", "--out", str(tmp_path / "t"), "--group", "4294967294")
        assert code == cli.EXIT_FAILED
        assert not (tmp_path / "t").exists()

    def test_token_the_loader_would_refuse_is_not_kept(self, tmp_path, capsys):
        unsafe = tmp_path / "shared"
        unsafe.mkdir()
        os.chmod(unsafe, 0o777)  # noqa: S103 - deliberately unsafe fixture
        code, _ = run("gen-token", "--out", str(unsafe / "admin.token"))
        assert code == cli.EXIT_FAILED
        assert not (unsafe / "admin.token").exists()
        assert "refusing to keep" in capsys.readouterr().err

    @pytest.mark.skipif(os.geteuid() != 0, reason="chgrp to a foreign group needs root")
    def test_explicit_group_is_trusted_by_the_self_check(self, tmp_path):
        import grp

        other = next(g for g in grp.getgrall() if g.gr_gid not in {0, os.getegid()})
        path = tmp_path / "t"
        assert run("gen-token", "--out", str(path), "--group", other.gr_name)[0] == 0
        assert os.lstat(path).st_gid == other.gr_gid


class TestTokenGroupTrust:
    @pytest.mark.skipif(os.geteuid() != 0, reason="chgrp to a foreign group needs root")
    def test_check_config_refuses_foreign_group_unless_trusted(self, env):
        import grp

        other = next(g for g in grp.getgrall() if g.gr_gid not in {0, os.getegid()})
        path = env / "secrets" / "admin.token"
        write_token(path, mode=0o640)
        os.chown(path, -1, other.gr_gid)
        code, output = run("check-config")
        assert code == cli.EXIT_FAILED
        assert "untrusted group" in json.loads(output)["credentials_file"]
        assert run("check-config", "--token-group", other.gr_name)[0] == 0
        assert run("check-config", "--token-group", str(other.gr_gid))[0] == 0

    def test_unknown_token_group_is_refused(self, env, capsys):
        write_token(env / "secrets" / "admin.token")
        assert run("check-config", "--token-group", "no-such-group-x")[0] == cli.EXIT_FAILED
        assert "unknown group" in capsys.readouterr().err


class TestPurge:
    def test_prints_json_report(self, env):
        assert run("migrate")[0] == 0  # purge never creates the schema itself
        code, output = run("purge")
        assert code == 0
        report = json.loads(output)
        # Every PurgeReport field is printed (question housekeeping included).
        assert set(report) == {f.name for f in dataclasses.fields(PurgeReport)}
        assert report["maintenance"] == {"staging": 0}
        for key in (
            "items_purged",
            "blobs_deleted",
            "orphans_deleted",
            "questions_expired",
            "questions_deleted",
            "notifications_deleted",
        ):
            assert report[key] == 0, key

    def test_refuses_before_the_schema_exists(self, env, capsys):
        assert run("purge")[0] == cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert "does not exist yet" in err
        assert "Traceback" not in err
        assert not (env / "data" / "db").exists()

    def test_has_no_now_override(self, env):
        with pytest.raises(SystemExit):
            cli.main(["purge", "--now", "2100-01-01T00:00:00+00:00"])


def _seed(revisions: int = 3, *, trash: bool = False) -> str:
    """Publish one item with `revisions` revisions through the admin core; return its id."""
    with build_core(Settings(), role="admin") as core:
        item = core.publish.publish(
            PublishCommand(
                title="Seeded title", files=[IncomingFile(relpath="a.txt", chunks=[b"v1"])]
            )
        )
        for n in range(2, revisions + 1):
            core.publish.publish_revision(
                RevisionCommand(
                    item_id=item.id,
                    files=[IncomingFile(relpath="a.txt", chunks=[f"v{n}".encode()])],
                )
            )
        if trash:
            core.lifecycle.trash(item.id)
        return item.id


class TestPermanentDeletes:
    def test_prune_revisions_prints_json(self, env):
        item_id = _seed(4)
        code, output = run("prune-revisions", item_id, "--keep", "2")
        assert code == 0
        assert json.loads(output) == {
            "item_id": item_id,
            "revision": 4,
            "revisions_kept": 2,
            "revisions_removed": 2,
            "bytes_freed": 4,
        }
        code, output = run("prune-revisions", item_id)  # default keep 1
        assert (code, json.loads(output)["revisions_removed"]) == (0, 1)
        assert json.loads(run("prune-revisions", item_id)[1])["revisions_removed"] == 0
        assert "Seeded title" not in output  # published text stays out of the report

    def test_prune_refusals_are_one_line(self, env, capsys):
        item_id = _seed(2, trash=True)
        assert run("prune-revisions", item_id)[0] == cli.EXIT_FAILED
        err = capsys.readouterr().err
        assert "prune-revisions refused" in err and "Traceback" not in err
        assert run("prune-revisions", "0" * 26)[0] == cli.EXIT_FAILED

    @pytest.mark.parametrize(
        "argv",
        [
            ["prune-revisions", "not-an-id"],
            ["prune-revisions", "0" * 26, "--keep", "0"],
            ["prune-revisions", "0" * 26, "--keep", "21"],
            ["prune-revisions", "0" * 26, "--keep", "٣"],
        ],
    )
    def test_prune_usage_errors(self, env, argv):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code == cli.EXIT_USAGE

    def test_empty_trash_prints_json(self, env):
        kept = _seed(1)
        _seed(2, trash=True)
        code, output = run("empty-trash")
        assert (code, json.loads(output)) == (0, {"items_purged": 1, "blobs_deleted": 2})
        assert json.loads(run("empty-trash")[1]) == {"items_purged": 0, "blobs_deleted": 0}
        with build_core(Settings(), role="admin") as core:
            assert core.queries.get(kept).state.value == "active"


class TestOtherCommands:
    def test_migrate(self, env):
        code, output = run("migrate")
        assert code == 0
        assert "schema at version" in output
        assert (env / "data" / "db" / "items.sqlite3").is_file()

    def test_check_config_ok(self, env):
        write_token(env / "secrets" / "admin.token")
        code, output = run("check-config")
        assert code == 0
        report = json.loads(output)
        assert report["config"] == "ok"
        assert report["credentials_file"] == "ok"

    def test_check_config_bad_token_file(self, env):
        token = write_token(env / "secrets" / "admin.token", mode=0o644)
        code, output = run("check-config")
        assert code == cli.EXIT_FAILED
        assert token not in output
        assert run("check-config", "--skip-token")[0] == 0

    def test_insecure_config_file_refuses(self, env, monkeypatch, capsys):
        conf_dir = env / "etc"
        conf_dir.mkdir(mode=0o755)
        conf = conf_dir / "config.toml"
        conf.write_text("")
        os.chmod(conf, 0o664)
        monkeypatch.setenv("PDASH_CONFIG", str(conf))
        assert run("purge")[0] == cli.EXIT_USAGE
        assert "refusing to start" in capsys.readouterr().err

    def test_invalid_settings_refuse(self, env, monkeypatch):
        monkeypatch.setenv("PDASH_VIEWER_HOST", "0.0.0.0")  # noqa: S104 - must be refused
        assert run("check-config", "--skip-token")[0] == cli.EXIT_USAGE

    def test_serve_admin_refuses_bad_token_file(self, env, capsys):
        write_token(env / "secrets" / "admin.token", mode=0o666)
        assert run("serve-admin")[0] == cli.EXIT_USAGE
        assert "admin token file" in capsys.readouterr().err

    def test_serve_viewer_without_viewer_server_module(self, env, monkeypatch, capsys):
        monkeypatch.setattr(cli, "VIEWER_SERVER_MODULE", "preview_dashboard.no_such_module")
        assert run("serve-viewer")[0] == cli.EXIT_FAILED
        assert "not available yet" in capsys.readouterr().err

    def test_serve_viewer_calls_viewer_server(self, env, monkeypatch):
        import sys
        import types

        seen: list[object] = []
        module = types.ModuleType("fake_viewer_server")
        module.serve = seen.append  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "fake_viewer_server", module)
        monkeypatch.setattr(cli, "VIEWER_SERVER_MODULE", "fake_viewer_server")
        assert run("migrate")[0] == 0  # the viewer never creates the schema itself
        assert run("serve-viewer", "--trusted-owner-uid", str(os.geteuid()))[0] == 0
        assert type(seen[0]).__name__ == "ViewerCore"

    def test_rejects_bad_uid(self):
        with pytest.raises(SystemExit):
            cli.main(["serve-admin", "--allowed-peer-uid", "-1"])

    def test_requires_a_command(self):
        with pytest.raises(SystemExit):
            cli.main([])
