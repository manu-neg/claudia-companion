"""Security tests for MCP intake (docs/security.md C10, C27).

One or more tests per control: allowlist (incl. the `startswith` trap and
symlinked roots), pseudo-filesystems, case-insensitive/NFC denylist and
`(full)` patterns, symlinks at every depth, hardlinks, FIFOs/devices,
lstat->open swap races, filesystem boundary, growth during read, and fd leaks.
"""

from __future__ import annotations

import dataclasses
import errno
import os
import signal
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from preview_dashboard.interfaces.mcp import intake as intake_mod
from preview_dashboard.interfaces.mcp.errors import IntakeError, IntakeErrorCode
from tests.intake_support import clean_env, make_policy, open_fd_count, read_all

pytestmark = [pytest.mark.security, pytest.mark.usefixtures("clean_env")]
__all__ = ["clean_env"]  # fixture re-export (keeps ruff from flagging the import)

SECRET = b"-----TOP SECRET CONTENT-----"


@pytest.fixture
def outbox(tmp_path: Path) -> Path:
    root = tmp_path / "outbox"
    root.mkdir()
    return root


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A file outside every allowed root, standing in for a real secret."""
    target = tmp_path / "elsewhere" / "private.txt"
    target.parent.mkdir()
    target.write_bytes(SECRET)
    return target


@pytest.fixture
def alarm() -> Iterator[None]:
    """Fail (instead of hanging forever) if the test blocks for > 5 s."""

    def _timeout(signum: int, frame: object) -> None:
        raise TimeoutError("intake blocked")

    previous = signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(5)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def _write(path: Path, data: bytes = b"ok") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _reject(policy: intake_mod.IntakePolicy, *paths: Path | str) -> IntakeError:
    with pytest.raises(IntakeError) as exc:
        policy.collect([str(p) for p in paths])
    # Messages never carry file contents.
    assert SECRET.decode() not in str(exc.value)
    return exc.value


# --- allowlist (C10) ------------------------------------------------------


def test_path_outside_roots_rejected(outbox: Path, outside: Path) -> None:
    err = _reject(make_policy(outbox), outside)
    assert err.code is IntakeErrorCode.OUTSIDE_ROOTS
    assert str(outbox) in str(err)  # tells the agent where it may publish from
    assert str(outside.parent) not in str(err)  # only the basename is echoed


def test_startswith_trap_sibling_rejected(tmp_path: Path, outbox: Path) -> None:
    evil = _write(tmp_path / "outbox-evil" / "a.txt")
    assert str(evil).startswith(str(outbox))
    assert _reject(make_policy(outbox), evil).code is IntakeErrorCode.OUTSIDE_ROOTS


def test_symlinked_root_is_resolved_and_usable(tmp_path: Path) -> None:
    real = tmp_path / "real-outbox"
    _write(real / "a.txt", b"hello")
    link = tmp_path / "outbox"
    link.symlink_to(real)
    policy = make_policy(link)
    for requested in (link / "a.txt", real / "a.txt"):
        with policy.collect([str(requested)]) as bundle:
            assert read_all(bundle) == {"a.txt": b"hello"}


@pytest.mark.parametrize("path", ["/proc/self/environ", "/sys/kernel", "/dev/null", "/proc"])
def test_pseudo_filesystems_always_rejected(outbox: Path, path: str) -> None:
    assert _reject(make_policy(outbox), path).code is IntakeErrorCode.OUTSIDE_ROOTS


def test_root_symlinked_into_proc_rejected(tmp_path: Path) -> None:
    link = tmp_path / "outbox"
    link.symlink_to("/proc/self")
    err = _reject(make_policy(link), link / "environ")
    assert err.code is IntakeErrorCode.OUTSIDE_ROOTS


# --- denylist -------------------------------------------------------------


@pytest.mark.parametrize(
    ("relpath", "patterns"),
    [
        ("ID_RSA", {"id_*", "*_rsa"}),
        (".ENV", {".env", "*.env"}),
        ("app/.Env.local", {".env.*"}),
        ("proj/.Git/config", {".git"}),
        (".config/gh/hosts.yml", {".config/gh"}),
        (".CONFIG/GH/hosts.yml", {".config/gh"}),
        ("Server.PEM", {"*.pem"}),
        ("MY_SECRET.txt", {"*secret*.*"}),
        ("backup/.Ssh/known", {".ssh"}),
    ],
)
def test_denylist_case_insensitive(outbox: Path, relpath: str, patterns: set[str]) -> None:
    f = _write(outbox / relpath, SECRET)
    err = _reject(make_policy(outbox), f)
    assert err.code is IntakeErrorCode.DENIED
    # The message names the matching pattern (any one of those that match).
    assert any(f"pattern '{p}'" in str(err) for p in patterns)


def test_denylist_applies_inside_directory_bundle(outbox: Path) -> None:
    _write(outbox / "site" / "index.html")
    _write(outbox / "site" / ".git" / "config", SECRET)
    err = _reject(make_policy(outbox), outbox / "site")
    assert err.code is IntakeErrorCode.DENIED
    assert "site/.git" in str(err)


def test_denylist_on_resolved_path_of_symlinked_root(tmp_path: Path) -> None:
    real = tmp_path / ".aws" / "exported"
    _write(real / "a.txt")
    link = tmp_path / "outbox"
    link.symlink_to(real)
    err = _reject(make_policy(link), link / "a.txt")
    assert err.code is IntakeErrorCode.DENIED
    assert "'.aws'" in str(err)


def test_denylist_nfc_nfd_variants(outbox: Path) -> None:
    policy = make_policy(outbox, intake_denied_patterns=frozenset({"caf\u00e9*"}))
    for name in ("cafe\u0301.txt", "CAF\u00c9.txt"):  # NFD and uppercase NFC
        f = _write(outbox / name)
        assert _reject(policy, f).code is IntakeErrorCode.DENIED
        f.unlink()


def test_config_added_pattern_enforced(outbox: Path) -> None:
    f = _write(outbox / "internal-notes.md")
    policy = make_policy(outbox, intake_denied_patterns=frozenset({"internal-*"}))
    assert _reject(policy, f).code is IntakeErrorCode.DENIED


def test_denied_request_path_component(outbox: Path) -> None:
    f = _write(outbox / ".kube" / "notes.txt")
    assert _reject(make_policy(outbox), f).code is IntakeErrorCode.DENIED


# --- symlinks / file types (C27) -----------------------------------------


def test_symlinked_file_rejected(outbox: Path, outside: Path) -> None:
    link = outbox / "innocent.txt"
    link.symlink_to(outside)
    assert _reject(make_policy(outbox), link).code is IntakeErrorCode.SYMLINK


def test_symlinked_intermediate_dir_rejected(outbox: Path, outside: Path) -> None:
    (outbox / "docs").symlink_to(outside.parent)
    err = _reject(make_policy(outbox), outbox / "docs" / outside.name)
    assert err.code is IntakeErrorCode.SYMLINK


def test_symlink_inside_directory_bundle_rejects_whole_publish(outbox: Path, outside: Path) -> None:
    _write(outbox / "site" / "index.html")
    (outbox / "site" / "data.txt").symlink_to(outside)
    err = _reject(make_policy(outbox), outbox / "site")
    assert err.code is IntakeErrorCode.SYMLINK
    assert "site/data.txt" in str(err)


def test_symlinked_subdir_inside_bundle_rejected(outbox: Path, outside: Path) -> None:
    _write(outbox / "site" / "index.html")
    (outbox / "site" / "assets").symlink_to(outside.parent)
    assert _reject(make_policy(outbox), outbox / "site").code is IntakeErrorCode.SYMLINK


def test_dangling_symlink_rejected(outbox: Path) -> None:
    (outbox / "gone.txt").symlink_to(outbox / "missing")
    assert _reject(make_policy(outbox), outbox / "gone.txt").code is IntakeErrorCode.SYMLINK


def test_hardlink_rejected(outbox: Path, outside: Path) -> None:
    link = outbox / "notes.txt"
    os.link(outside, link)
    err = _reject(make_policy(outbox), link)
    assert err.code is IntakeErrorCode.HARDLINK
    assert "2 hard links" in str(err)


def test_hardlink_inside_bundle_rejected(outbox: Path, outside: Path) -> None:
    _write(outbox / "site" / "index.html")
    os.link(outside, outbox / "site" / "notes.txt")
    assert _reject(make_policy(outbox), outbox / "site").code is IntakeErrorCode.HARDLINK


@pytest.mark.usefixtures("alarm")
def test_fifo_rejected_without_hanging(outbox: Path) -> None:
    fifo = outbox / "pipe.txt"
    os.mkfifo(fifo)
    assert _reject(make_policy(outbox), fifo).code is IntakeErrorCode.NOT_REGULAR


@pytest.mark.usefixtures("alarm")
def test_fifo_inside_bundle_rejected(outbox: Path) -> None:
    _write(outbox / "site" / "index.html")
    os.mkfifo(outbox / "site" / "pipe")
    assert _reject(make_policy(outbox), outbox / "site").code is IntakeErrorCode.NOT_REGULAR


def test_device_file_inside_bundle_rejected(outbox: Path) -> None:
    _write(outbox / "site" / "index.html")
    try:
        os.mknod(outbox / "site" / "null", stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except PermissionError:
        pytest.skip("mknod needs CAP_MKNOD")
    assert _reject(make_policy(outbox), outbox / "site").code is IntakeErrorCode.NOT_REGULAR


def test_unix_socket_rejected(outbox: Path) -> None:
    import socket

    path = outbox / "s.sock"
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind(str(path))
        assert _reject(make_policy(outbox), path).code is IntakeErrorCode.NOT_REGULAR


# --- swap races between lstat and open (TOCTOU) ---------------------------


def _swap_after_classify(monkeypatch: pytest.MonkeyPatch, victim: Path, swap: object) -> None:
    """Run `swap()` right after intake lstat()s `victim`, before it opens it."""
    original = intake_mod._Collector._classify

    def patched(self, parent, name, root, rel):
        st = original(self, parent, name, root, rel)
        if name == victim.name:
            swap()  # type: ignore[operator]
        return st

    monkeypatch.setattr(intake_mod._Collector, "_classify", patched)


def test_file_swapped_for_symlink_after_lstat(
    monkeypatch: pytest.MonkeyPatch, outbox: Path, outside: Path
) -> None:
    victim = _write(outbox / "a.txt")

    def swap() -> None:
        victim.unlink()
        victim.symlink_to(outside)

    _swap_after_classify(monkeypatch, victim, swap)
    assert _reject(make_policy(outbox), victim).code is IntakeErrorCode.SYMLINK


def test_dir_swapped_for_symlink_after_lstat(
    monkeypatch: pytest.MonkeyPatch, outbox: Path, outside: Path
) -> None:
    victim = outbox / "docs"
    _write(victim / outside.name)

    def swap() -> None:
        (victim / outside.name).unlink()
        victim.rmdir()
        victim.symlink_to(outside.parent)

    _swap_after_classify(monkeypatch, victim, swap)
    err = _reject(make_policy(outbox), victim / outside.name)
    assert err.code is IntakeErrorCode.SYMLINK


def test_file_replaced_by_other_inode_after_lstat(
    monkeypatch: pytest.MonkeyPatch, outbox: Path, outside: Path
) -> None:
    victim = _write(outbox / "a.txt")

    def swap() -> None:
        # Rename (not unlink) keeps the old inode alive, so the replacement
        # can't reuse its inode number.
        victim.rename(outbox / "moved.txt")
        _write(victim, SECRET)  # new inode, same name

    _swap_after_classify(monkeypatch, victim, swap)
    assert _reject(make_policy(outbox), victim).code is IntakeErrorCode.CHANGED


@pytest.mark.usefixtures("alarm")
def test_file_swapped_for_fifo_after_lstat_does_not_hang(
    monkeypatch: pytest.MonkeyPatch, outbox: Path
) -> None:
    victim = _write(outbox / "a.txt")

    def swap() -> None:
        victim.unlink()
        os.mkfifo(victim)

    _swap_after_classify(monkeypatch, victim, swap)
    assert _reject(make_policy(outbox), victim).code is IntakeErrorCode.CHANGED


def test_filesystem_boundary_rejected(monkeypatch: pytest.MonkeyPatch, outbox: Path) -> None:
    f = _write(outbox / "a.txt")
    original = intake_mod._Collector._open_root

    def fake_dev(self, root):
        opened = original(self, root)
        # Pretend the root lives on another device.
        return dataclasses.replace(opened, dev=opened.dev + 1)

    monkeypatch.setattr(intake_mod._Collector, "_open_root", fake_dev)
    assert _reject(make_policy(outbox), f).code is IntakeErrorCode.FILESYSTEM_BOUNDARY


# --- mount-id check (C27, F2) --------------------------------------------


def test_mount_id_reads_fdinfo(outbox: Path) -> None:
    fd = os.open(outbox, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert isinstance(intake_mod.mount_id(fd), int)
    finally:
        os.close(fd)
    assert intake_mod.mount_id(987654) is None  # not an open fd


def test_bind_mount_on_same_filesystem_rejected(
    monkeypatch: pytest.MonkeyPatch, outbox: Path
) -> None:
    f = _write(outbox / "a.txt")
    real = intake_mod.mount_id
    state = {"calls": 0}

    def other_mount_after_root(fd: int) -> int | None:
        state["calls"] += 1
        value = real(fd)
        # First call is the root; everything after "is" on a bind mount.
        return value if state["calls"] == 1 or value is None else value + 1

    monkeypatch.setattr(intake_mod, "mount_id", other_mount_after_root)
    err = _reject(make_policy(outbox), f)
    assert err.code is IntakeErrorCode.FILESYSTEM_BOUNDARY
    assert "mount" in str(err)


def test_unverifiable_root_mount_fails_closed(
    monkeypatch: pytest.MonkeyPatch, outbox: Path
) -> None:
    f = _write(outbox / "a.txt")
    monkeypatch.setattr(intake_mod, "mount_id", lambda fd: None)
    before = open_fd_count()
    assert _reject(make_policy(outbox), f).code is IntakeErrorCode.FILESYSTEM_BOUNDARY
    assert open_fd_count() == before


def test_unverifiable_file_mount_fails_closed(
    monkeypatch: pytest.MonkeyPatch, outbox: Path
) -> None:
    _write(outbox / "d" / "a.txt")
    real = intake_mod.mount_id
    state = {"calls": 0}

    def unreadable_after_root(fd: int) -> int | None:
        state["calls"] += 1
        return real(fd) if state["calls"] == 1 else None

    monkeypatch.setattr(intake_mod, "mount_id", unreadable_after_root)
    err = _reject(make_policy(outbox), outbox / "d")
    assert err.code is IntakeErrorCode.FILESYSTEM_BOUNDARY


def test_real_bind_mount_rejected(tmp_path: Path, outbox: Path, outside: Path) -> None:
    """A secret dir bind-mounted into the outbox (same st_dev) is refused."""
    target = outbox / "innocent"
    target.mkdir()
    rc = os.system(f"mount --bind {outside.parent} {target} 2>/dev/null")  # noqa: S605
    if rc != 0:
        pytest.skip("bind mounts not permitted here")
    try:
        err = _reject(make_policy(outbox), target / "private.txt")
        assert err.code is IntakeErrorCode.FILESYSTEM_BOUNDARY
    finally:
        os.system(f"umount {target}")  # noqa: S605


# --- resolved-root re-validation (C10, F1) ---------------------------------


@pytest.mark.parametrize("target", ["/", "/root", "/etc", "/home", "/usr", "/var"])
def test_root_symlinked_to_forbidden_tree_rejected(tmp_path: Path, target: str) -> None:
    link = tmp_path / "outbox"
    link.symlink_to(target)
    err = _reject(make_policy(link), link / "passwd")
    assert err.code is IntakeErrorCode.OUTSIDE_ROOTS
    assert "forbidden" in str(err)


def test_root_symlinked_to_data_dir_rejected(tmp_path: Path) -> None:
    data = tmp_path / "data"
    _write(data / "db" / "x.txt")
    link = tmp_path / "outbox"
    link.symlink_to(data)
    err = _reject(make_policy(link, data_dir=data), link / "db" / "x.txt")
    assert err.code is IntakeErrorCode.OUTSIDE_ROOTS


def test_root_symlinked_to_parent_of_data_dir_rejected(tmp_path: Path) -> None:
    holder = tmp_path / "srv"
    data = holder / "data"
    _write(holder / "a.txt")
    data.mkdir()
    link = tmp_path / "outbox"
    link.symlink_to(holder)
    err = _reject(make_policy(link, data_dir=data), link / "a.txt")
    assert err.code is IntakeErrorCode.OUTSIDE_ROOTS


def test_root_symlinked_to_token_dir_rejected(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "etc-pdash"
    _write(secrets_dir / "notes.txt")
    link = tmp_path / "outbox"
    link.symlink_to(secrets_dir)
    policy = make_policy(link, admin_token_file=secrets_dir / "admin.token")
    assert _reject(policy, link / "notes.txt").code is IntakeErrorCode.OUTSIDE_ROOTS


def test_root_overlapping_symlinked_data_dir_rejected(tmp_path: Path) -> None:
    """Sensitive paths are compared resolved too: data_dir may itself be a symlink."""
    real_data = tmp_path / "outbox" / "data"
    real_data.mkdir(parents=True)
    _write(tmp_path / "outbox" / "a.txt")
    data_link = tmp_path / "data-link"
    data_link.symlink_to(real_data)
    policy = make_policy(tmp_path / "outbox", data_dir=data_link)
    err = _reject(policy, tmp_path / "outbox" / "a.txt")
    assert err.code is IntakeErrorCode.OUTSIDE_ROOTS


def test_good_root_still_works_next_to_bad_one(tmp_path: Path, outbox: Path) -> None:
    _write(outbox / "a.txt", b"fine")
    bad = tmp_path / "bad"
    bad.symlink_to("/etc")
    policy = make_policy(outbox, bad)
    with policy.collect([str(outbox / "a.txt")]) as bundle:
        assert read_all(bundle) == {"a.txt": b"fine"}
    assert _reject(policy, bad / "hostname").code is IntakeErrorCode.OUTSIDE_ROOTS


# --- request hygiene (F3, depth cap) ----------------------------------------


@pytest.mark.parametrize("bad", ["\ud800", "\udfff", "a\udc80b"])
def test_surrogates_in_request_rejected(outbox: Path, bad: str) -> None:
    raw = str(outbox) + "/" + bad
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([raw])
    assert exc.value.code is IntakeErrorCode.INVALID_REQUEST
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(outbox / "a")], base=raw)
    assert exc.value.code is IntakeErrorCode.INVALID_REQUEST


def test_request_depth_capped(outbox: Path) -> None:
    deep = str(outbox) + "/x" * (intake_mod.MAX_REQUEST_DEPTH + 1)
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([deep])
    assert exc.value.code is IntakeErrorCode.INVALID_REQUEST


# --- OS errors mapped, never raw (F4) ----------------------------------------


def _eio(*args: object, **kwargs: object) -> None:
    raise OSError(errno.EIO, os.strerror(errno.EIO))


def test_scandir_error_is_unreadable(monkeypatch: pytest.MonkeyPatch, outbox: Path) -> None:
    _write(outbox / "d" / "a.txt")
    monkeypatch.setattr(os, "scandir", _eio)
    before = open_fd_count()
    assert _reject(make_policy(outbox), outbox / "d").code is IntakeErrorCode.UNREADABLE
    assert open_fd_count() == before


def test_fstat_error_is_unreadable(monkeypatch: pytest.MonkeyPatch, outbox: Path) -> None:
    f = _write(outbox / "a.txt")
    policy = make_policy(outbox)
    real = os.fstat
    state = {"calls": 0}

    def flaky(fd: int) -> os.stat_result:
        state["calls"] += 1
        if state["calls"] > 1:  # root fstat passes, the file's fails
            raise OSError(errno.EIO, "I/O error")
        return real(fd)

    monkeypatch.setattr(os, "fstat", flaky)
    assert _reject(policy, f).code is IntakeErrorCode.UNREADABLE


def test_pread_error_is_unreadable(monkeypatch: pytest.MonkeyPatch, outbox: Path) -> None:
    f = _write(outbox / "a.txt", b"data")
    with make_policy(outbox).collect([str(f)]) as bundle:
        monkeypatch.setattr(os, "pread", _eio)
        with pytest.raises(IntakeError) as exc, bundle.files[0].open_reader() as chunks:
            list(chunks)
    assert exc.value.code is IntakeErrorCode.UNREADABLE


# --- reading only from the verified fd -----------------------------------


def test_reads_come_from_opened_fd_not_path(outbox: Path, outside: Path) -> None:
    f = _write(outbox / "a.txt", b"original")
    with make_policy(outbox).collect([str(f)]) as bundle:
        # Replace the name with a symlink to a secret after intake: the
        # reader must still deliver the originally opened file.
        f.unlink()
        f.symlink_to(outside)
        assert read_all(bundle) == {"a.txt": b"original"}


def test_file_growing_during_read_rejected(outbox: Path) -> None:
    f = _write(outbox / "log.txt", b"0123456789")
    with make_policy(outbox).collect([str(f)]) as bundle:
        item = bundle.files[0]
        delivered = b""
        with (
            pytest.raises(IntakeError) as exc,
            item.open_reader(chunk_size=4) as chunks,
        ):
            for chunk in chunks:
                delivered += chunk
                if len(delivered) == 4:
                    with f.open("ab") as grow:
                        grow.write(b"MORE" * 100)
    assert exc.value.code is IntakeErrorCode.CHANGED
    assert "grew" in str(exc.value)
    assert len(delivered) <= 10  # never read past the checked size


# --- fd hygiene -------------------------------------------------------------


def test_no_fd_leaks(outbox: Path, outside: Path) -> None:
    _write(outbox / "site" / "index.html")
    _write(outbox / "site" / "css" / "a.css")
    bad = outbox / "bad"
    _write(bad / "ok.txt")
    _write(bad / "sub" / "zz.txt")
    (bad / "sub" / "zzz-link").symlink_to(outside)
    policy = make_policy(outbox)
    before = open_fd_count()
    for _ in range(20):
        with policy.collect([str(outbox / "site")]) as bundle:
            read_all(bundle)
        with pytest.raises(IntakeError):
            policy.collect([str(bad)])
        with pytest.raises(IntakeError):
            policy.collect([str(outbox / "missing" / "x")])
    assert open_fd_count() == before


def test_bundle_holds_fds_until_closed(outbox: Path) -> None:
    for i in range(3):
        _write(outbox / "d" / f"{i}.txt")
    before = open_fd_count()
    bundle = make_policy(outbox).collect([str(outbox / "d")])
    assert open_fd_count() == before + 3  # one per file, no directory fds kept
    bundle.close()
    assert open_fd_count() == before
