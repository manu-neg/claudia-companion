"""Tests for `scripts/export_release.py` (unit R1, shareable release).

Each test builds a throwaway git repo, so exclusions, refusals, the secret
scan and the personal-data denylist are checked without the real repo.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import export_release as er

pytestmark = pytest.mark.unit

GIT = shutil.which("git")
REAL_TEMPLATES = Path(__file__).resolve().parents[2] / "scripts" / "release_templates"
# Joined at runtime so this file never trips the real export's agent-path rule.
CLAUDE_DIR = ".claude"


@pytest.fixture(autouse=True)
def _hermetic_git(monkeypatch: pytest.MonkeyPatch) -> None:
    # This host's global git identity must not leak into (or out of) the tests.
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def git(repo: Path, *args: str) -> None:
    assert GIT is not None
    subprocess.run(  # noqa: S603 - resolved git, fixed argv
        [GIT, "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        timeout=30,
    )


def write(repo: Path, rel: str, text: str = "x\n") -> Path:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    for name in ("README.release.md", "CLAUDE.release.md"):
        write(root, f"scripts/release_templates/{name}", (REAL_TEMPLATES / name).read_text())
    files = [
        "src/app.py",
        "docs/setup.md",
        "README.md",
        "CLAUDE.md",
        "HANDOFF.md",
        f"{CLAUDE_DIR}/agents/dev.md",
        f"{CLAUDE_DIR}/orchestrator/claudia-spikes/v4/samples.jsonl",
        "notes/run.jsonl",
        "data/app.db",
        "deploy/admin.token",
        "deploy/totp.secret",
        "notes/memory/m.md",
        "outbox/x.html",
        "sub/CLAUDE.md",
        "sub/Claude.MD",
        "tests/fixtures/samples.jsonl",
    ]
    for rel in files:
        write(root, rel, f"content of {rel}\n")
    script = write(root, "deploy/run.sh", "#!/bin/sh\necho hi\n")
    script.chmod(0o755)
    commit(root)
    return root


def commit(root: Path) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "c")


def export(
    repo: Path,
    out: Path,
    *,
    config: Path | None = None,
    secrets_dir: Path | None = None,
    extra_deny: tuple[str, ...] | list[str] = (),
    allow_dirty: bool = False,
) -> er.ExportResult:
    # None by default: the host's real /etc config and secret files must not
    # matter (or be read) here.
    return er.export_release(
        repo,
        out,
        config=config,
        secrets_dir=secrets_dir,
        extra_deny=extra_deny,
        allow_dirty=allow_dirty,
    )


# --- exclusions -----------------------------------------------------------------------


def test_exports_only_shareable_files_and_the_release_templates(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = export(repo, out)
    assert set(result.files) == {
        "src/app.py",
        "docs/setup.md",
        "deploy/run.sh",
        "tests/fixtures/samples.jsonl",
        "scripts/release_templates/README.release.md",
        "scripts/release_templates/CLAUDE.release.md",
        "README.md",
        "CLAUDE.md",
    }
    exported = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
    assert exported == set(result.files)
    # The owner's README/CLAUDE.md are replaced, never copied.
    assert (out / "README.md").read_text() == (REAL_TEMPLATES / "README.release.md").read_text()
    assert (out / "CLAUDE.md").read_text() == (REAL_TEMPLATES / "CLAUDE.release.md").read_text()
    assert os.stat(out / "deploy/run.sh").st_mode & 0o777 == 0o755
    assert os.stat(out / "src/app.py").st_mode & 0o777 == 0o644


@pytest.mark.parametrize(
    "rel",
    [
        "CLAUDE.md",
        "HANDOFF.md",
        "README.md",
        f"{CLAUDE_DIR}/settings.json",
        "a/.Claude/x",
        f"{CLAUDE_DIR}/orchestrator/backlog.md",
        "x/memory/notes.md",
        "outbox/a.png",
        "sub/claude.md",
        "deploy/admin.token",
        "deploy/x.TOKEN",
        "totp.secret",
        "k.pem",
        "k.key",
        ".env",
        "deploy/prod.env",
        # secrets-2: everything .gitignore treats as secret or runtime data.
        ".env.local",
        "deploy/.ENV.prod",
        "certs/client.p12",
        "certs/client.PFX",
        "data/app.db",
        "data/app.db-wal",
        "data/app.db-shm",
        "data/app.sqlite",
        "data/app.sqlite3",
        "config.toml",
        "deploy/Config.toml",
        "keys/id_rsa",
        "keys/id_rsa.pub",
        "keys/id_ed25519",
        "keys/id_ed25519.pub",
        # JSONL ships only as curated test fixtures.
        "notes/run.jsonl",
        "tests/run.jsonl",
        "tests/fixtures/sub/x.jsonl",
        "transcript.JSONL",
    ],
)
def test_is_excluded(rel: str) -> None:
    assert er.is_excluded(rel)


@pytest.mark.parametrize(
    "rel",
    ["docs/README.md", "src/x/token_file.py", "docs/security.md", "scripts/export_release.py",
     "scripts/release_templates/CLAUDE.release.md", "tests/unit/test_memory_x.py",
     "tests/fixtures/screen_samples.jsonl", "deploy/config.example.toml",
     "src/x/sqlite_store.py", "docs/env.md"],
)  # fmt: skip
def test_is_not_excluded(rel: str) -> None:
    assert not er.is_excluded(rel)


# --- refusals ---------------------------------------------------------------------------


def test_refuses_a_non_empty_out_dir(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "old").write_text("x")
    with pytest.raises(er.ExportError, match="not empty"):
        export(repo, out)
    assert sorted(p.name for p in out.iterdir()) == ["old"]


def test_accepts_an_existing_empty_out_dir(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert export(repo, out).files


def test_refuses_a_symlinked_out_dir(repo: Path, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "out"
    out.symlink_to(target)
    with pytest.raises(er.ExportError, match="symlink"):
        export(repo, out)
    assert not any(target.iterdir())


def test_refuses_a_group_or_other_writable_out_dir(repo: Path, tmp_path: Path) -> None:
    for i, mode in enumerate((0o775, 0o757, 0o1777)):
        out = tmp_path / f"out{i}"
        out.mkdir()
        out.chmod(mode)
        with pytest.raises(er.ExportError, match="group/other-writable"):
            export(repo, out)
        assert not any(out.iterdir())


@pytest.mark.skipif(os.geteuid() != 0, reason="chown to another uid needs root")
def test_refuses_an_out_dir_owned_by_someone_else(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir(mode=0o755)
    os.chown(out, 65534, -1)
    with pytest.raises(er.ExportError, match="not owned"):
        export(repo, out)
    assert not any(out.iterdir())


def test_writes_never_follow_a_planted_subdir_symlink(tmp_path: Path) -> None:
    # A subdir swapped for a symlink after the checks must not redirect writes.
    out = tmp_path / "out"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with er._open_out(out) as fd:
        (out / "src").symlink_to(elsewhere)
        with pytest.raises(er.ExportError, match="symlink"):
            er._write(fd, "src/app.py", b"x\n", executable=False)
        er._write(fd, "docs/a/b.md", b"y\n", executable=False)
    assert not any(elsewhere.iterdir())
    assert (out / "docs/a/b.md").read_bytes() == b"y\n"


def test_creating_out_refuses_a_racing_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "out"
    out.symlink_to(target)  # appeared after the pre-checks
    with pytest.raises(er.ExportError, match="symlink"), er._open_out(out):
        pass


def test_refuses_out_inside_the_repo(repo: Path) -> None:
    with pytest.raises(er.ExportError, match="outside the repository"):
        export(repo, repo / "release")


def test_refuses_a_missing_parent(repo: Path, tmp_path: Path) -> None:
    with pytest.raises(er.ExportError, match="parent"):
        export(repo, tmp_path / "no" / "out")


def test_refuses_a_tracked_symlink(repo: Path, tmp_path: Path) -> None:
    (repo / "src" / "link.py").symlink_to("/etc/hostname")
    commit(repo)
    out = tmp_path / "out"
    with pytest.raises(er.ExportError, match="symlink"):
        export(repo, out)
    assert not out.exists()


def test_refuses_a_dirty_tree_unless_allowed(repo: Path, tmp_path: Path) -> None:
    write(repo, "src/new.py", "y\n")
    with pytest.raises(er.ExportError, match="uncommitted"):
        export(repo, tmp_path / "out")
    result = export(repo, tmp_path / "out2", allow_dirty=True)
    assert "src/new.py" in result.files  # untracked, not ignored: exported and scanned


def test_ignored_files_are_never_exported(repo: Path, tmp_path: Path) -> None:
    write(repo, ".gitignore", "*.log\n")
    commit(repo)
    write(repo, "debug.log", "secret-ish\n")
    result = export(repo, tmp_path / "out", allow_dirty=True)
    assert "debug.log" not in result.files


def test_missing_template_is_refused(repo: Path, tmp_path: Path) -> None:
    (repo / "scripts/release_templates/CLAUDE.release.md").unlink()
    commit(repo)
    with pytest.raises(er.ExportError, match="template"):
        export(repo, tmp_path / "out")


# --- secret scan + denylist -----------------------------------------------------------


def test_secret_scanner_hit_fails_and_writes_nothing(repo: Path, tmp_path: Path) -> None:
    # Built at runtime so this test file itself stays scan-clean.
    write(repo, "src/conf.py", "KEY = '" + "AKIA" + "Q" * 16 + "'\n")
    commit(repo)
    out = tmp_path / "out"
    with pytest.raises(er.ExportError) as info:
        export(repo, out)
    message = str(info.value)
    assert "src/conf.py: secret rule 'AWS access key id'" in message
    assert "AKIA" not in message  # never the matched bytes
    assert not out.exists()


def test_secret_in_an_excluded_file_does_not_block(repo: Path, tmp_path: Path) -> None:
    write(repo, ".claude/x.md", "AKIA" + "Q" * 16 + "\n")
    commit(repo)
    assert export(repo, tmp_path / "out").files


def test_config_denylist_hit_fails(repo: Path, tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(
        'owner_login = "friend@corp.test"\n'
        'allowed_hosts = ["box.corp-net.ts.net"]\n'
        'preview_origin = "https://preview.corp-net.ts.net:8443"\n'
        "notify_owner_chat_id = 4242424242\n"
    )
    write(repo, "docs/a.md", "Mail FRIEND@corp.test\n")
    write(repo, "docs/b.md", "host box.corp-net.ts.net\n")
    write(repo, "docs/c.md", "origin preview.corp-net.ts.net\n")
    write(repo, "docs/d.md", "chat 4242424242\n")
    write(repo, "docs/e.md", "not a chat id: 142424242429\n")
    commit(repo)
    out = tmp_path / "out"
    with pytest.raises(er.ExportError) as info:
        export(repo, out, config=config)
    message = str(info.value)
    assert "docs/a.md: personal data (config owner_login)" in message
    assert "docs/b.md: personal data (config allowed_hosts)" in message
    assert "docs/c.md: personal data (config preview_origin host)" in message
    assert "docs/d.md: personal data (config notify_owner_chat_id)" in message
    assert "docs/e.md" not in message  # digits glued to a longer number
    assert "friend@corp.test" not in message.lower()  # label only, never the value
    assert not out.exists()


def test_missing_config_fails_closed(repo: Path, tmp_path: Path) -> None:
    # A typo'd --config must not silently drop the owner's values.
    with pytest.raises(er.ExportError, match="not found"):
        export(repo, tmp_path / "out", config=tmp_path / "absent.toml")
    assert not (tmp_path / "out").exists()


# --- installed secret files (secrets-1) ------------------------------------------------


def make_secrets(tmp_path: Path) -> Path:
    # Fake install dir: never the host's real /etc/preview-dashboard.
    secrets = tmp_path / "etc-pdash"
    secrets.mkdir()
    (secrets / "admin.token").write_text("tok-" + "a1b2c3d4" * 4 + "\n")
    (secrets / "totp.secret").write_text("JBSWY3DP" + "EHPK3PXP" * 2 + "\n")
    (secrets / "short.token").write_text("abc\n")  # too short to deny
    (secrets / "notes.txt").write_text("not-a-secret-file-value\n")
    return secrets


def test_installed_token_and_totp_contents_are_denied(repo: Path, tmp_path: Path) -> None:
    secrets = make_secrets(tmp_path)
    write(repo, "docs/a.md", "token tok-" + "a1b2c3d4" * 4 + " leaked\n")
    write(repo, "docs/b.md", "key JBSWY3DP" + "EHPK3PXP" * 2 + "\n")
    write(repo, "docs/c.md", "abc and not-a-secret-file-value\n")
    commit(repo)
    out = tmp_path / "out"
    with pytest.raises(er.ExportError) as info:
        export(repo, out, secrets_dir=secrets)
    message = str(info.value)
    assert "docs/a.md: personal data (secret file admin.token)" in message
    assert "docs/b.md: personal data (secret file totp.secret)" in message
    assert "docs/c.md" not in message
    assert "a1b2c3d4" not in message and "JBSWY3DP" not in message  # never the value
    assert not out.exists()


def test_clean_tree_passes_with_secret_files_and_lists_labels(repo: Path, tmp_path: Path) -> None:
    result = export(repo, tmp_path / "out", secrets_dir=make_secrets(tmp_path))
    assert "secret file admin.token" in result.deny_labels
    assert "secret file totp.secret" in result.deny_labels
    assert "secret file short.token" not in result.deny_labels
    assert all("a1b2" not in label for label in result.deny_labels)


def test_missing_secrets_dir_means_none_installed(repo: Path, tmp_path: Path) -> None:
    result = export(repo, tmp_path / "out", secrets_dir=tmp_path / "absent")
    assert not any(label.startswith("secret file") for label in result.deny_labels)


def test_unreadable_secret_file_fails_closed(repo: Path, tmp_path: Path) -> None:
    secrets = make_secrets(tmp_path)
    # A symlinked or non-regular secret can't be checked safely (root reads
    # anything, so chmod 000 would not test this): refuse.
    (secrets / "link.token").symlink_to(secrets / "admin.token")
    with pytest.raises(er.ExportError, match=r"cannot read secret file link\.token"):
        export(repo, tmp_path / "out", secrets_dir=secrets)
    (secrets / "link.token").unlink()
    (secrets / "dir.secret").mkdir()
    with pytest.raises(er.ExportError, match=r"dir\.secret is not a regular file"):
        export(repo, tmp_path / "out", secrets_dir=secrets)
    assert not (tmp_path / "out").exists()


def test_unlistable_secrets_dir_fails_closed(repo: Path, tmp_path: Path) -> None:
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("x")
    with pytest.raises(er.ExportError, match="cannot list"):
        export(repo, tmp_path / "out", secrets_dir=not_a_dir)


# --- owner-only agent paths (secrets-4) -------------------------------------------------


def test_owner_only_agent_paths_in_text_are_denied(repo: Path, tmp_path: Path) -> None:
    write(repo, "docs/a.md", f"see `{CLAUDE_DIR}/orchestrator/backlog.md` 5.5\n")
    write(repo, "docs/b.md", f"list in {CLAUDE_DIR.upper()}/Agents/x.md\n")
    write(repo, "docs/c.md", f"deny Edit on {CLAUDE_DIR}/settings.json\n")  # a Claude Code path
    commit(repo)
    with pytest.raises(er.ExportError) as info:
        export(repo, tmp_path / "out")
    message = str(info.value)
    assert "docs/a.md: personal data (owner-only agent path)" in message
    assert "docs/b.md: personal data (owner-only agent path)" in message
    assert "docs/c.md" not in message


def test_unreadable_config_fails_closed(repo: Path, tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text("owner_login = \n")  # not TOML
    with pytest.raises(er.ExportError, match="cannot read"):
        export(repo, tmp_path / "out", config=config)


def test_extra_deny_and_git_identity_and_remote(repo: Path, tmp_path: Path) -> None:
    git(repo, "config", "user.email", "dev@home.test")
    git(repo, "remote", "add", "origin", "git@github.com:someowner/somerepo.git")
    write(repo, "docs/a.md", "by dev@home.test\n")
    write(repo, "docs/b.md", "see someowner/somerepo#3\n")
    write(repo, "docs/c.md", "codename bluefinch\n")
    commit(repo)
    with pytest.raises(er.ExportError) as info:
        export(repo, tmp_path / "out", extra_deny=["BlueFinch"])
    message = str(info.value)
    assert "docs/a.md: personal data (git user.email)" in message
    assert "docs/b.md: personal data (git remote owner)" in message
    assert "docs/c.md: personal data (--deny #1)" in message


def test_checkout_path_and_real_tailnet_names_are_denied(repo: Path, tmp_path: Path) -> None:
    write(repo, "docs/a.md", f"cd {repo.resolve()}/src\n")
    # Split so this test file never trips the real export's tailnet rule.
    write(repo, "docs/b.md", "open https://box.tail" + "0a1b2c.ts.net\n")
    write(repo, "docs/c.md", "example: my-host.tailXXXX.ts.net\n")  # placeholder, allowed
    commit(repo)
    with pytest.raises(er.ExportError) as info:
        export(repo, tmp_path / "out")
    message = str(info.value)
    assert "docs/a.md: personal data (checkout path)" in message
    assert "docs/b.md: personal data (tailnet host name)" in message
    assert "docs/c.md" not in message


def test_short_terms_are_not_denied(repo: Path, tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text('owner_login = "a@b"\nnotify_owner_chat_id = 1\n')
    assert export(repo, tmp_path / "out", config=config).files


# --- CLI ----------------------------------------------------------------------------------


def test_main_reports_success_and_refusal(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.toml"
    config.write_text('owner_login = "friend@corp.test"\n')
    secrets = make_secrets(tmp_path)
    args = ["--repo", str(repo), "--config", str(config), "--secrets-dir", str(secrets)]
    assert er.main([*args, "--out", str(tmp_path / "out")]) == 0
    stdout = capsys.readouterr().out
    assert "exported 8 files" in stdout
    # secrets-6: the loaded sources are named (labels only, never values).
    assert "denylist sources: tailnet host name, owner-only agent path, " in stdout
    assert "config owner_login" in stdout and "secret file admin.token" in stdout
    assert "friend@corp.test" not in stdout and "a1b2c3d4" not in stdout
    assert er.main([*args, "--out", str(tmp_path / "out")]) == 1  # now non-empty
    assert "not empty" in capsys.readouterr().err


def test_main_config_must_exist_unless_no_config(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = ["--repo", str(repo), "--secrets-dir", str(tmp_path / "absent")]
    missing = ["--config", str(tmp_path / "none.toml")]
    assert er.main([*base, *missing, "--out", str(tmp_path / "out1")]) == 1
    assert "not found" in capsys.readouterr().err
    assert er.main([*base, "--no-config", "--out", str(tmp_path / "out2")]) == 0
    assert "config owner_login" not in capsys.readouterr().out
    with pytest.raises(SystemExit):  # both at once is ambiguous
        er.main([*base, *missing, "--no-config", "--out", str(tmp_path / "out3")])
