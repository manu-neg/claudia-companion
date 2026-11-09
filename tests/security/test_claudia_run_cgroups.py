"""C58 / host-flow-5: every Claudia run gets its own cgroup; `/stop` kills the whole cgroup.

The runner moves each fresh `claude` child into a per-run cgroup before it
gets its prompt (and refuses the run if it can't), `/stop` signals the
cgroup's members and then `cgroup.kill`s it, and `busy()` follows the
cgroup, so detached background jobs are seen and killed even after their
parent exited. Never touches the real cgroupfs or systemd: the runner
tests use a fake containment, `RunCgroups` runs on a tmp directory.
"""

from __future__ import annotations

import os
import signal
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from preview_dashboard.adapters.claude_cli import (
    ClaudeCliConfig,
    CliClaudeRunner,
    RunCgroups,
    delegated_cgroup_root,
)
from preview_dashboard.application.claudia.runs import TOOL_SETS, ToolSetName
from preview_dashboard.interfaces.claudia.main import (
    HostConfig,
    RunCgroupError,
    parse_args,
    run_containment,
)
from preview_dashboard.ports.claudia_host import RunOutcome, RunRequest
from tests.claudia_host_support import WINDOW_A, read_record, write_fake_claude

pytestmark = pytest.mark.security


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    return True


@dataclass
class FakeContainment:
    """`RunContainment` over a tmp dir; `held` keeps a cgroup populated after its run."""

    root: Path
    fail_create: bool = False
    fail_join: bool = False
    held: bool = False
    joined: list[tuple[Path, int]] = field(default_factory=list)
    killed: list[Path] = field(default_factory=list)
    signalled: list[tuple[Path, signal.Signals]] = field(default_factory=list)
    removed: list[Path] = field(default_factory=list)

    def create(self, pid: int) -> Path:
        if self.fail_create:
            raise PermissionError("no cgroup")
        path = self.root / f"run-{pid}"
        path.mkdir()
        return path

    def join(self, cgroup: Path, pid: int) -> None:
        if self.fail_join:
            raise OSError("write to cgroup.procs failed")
        self.joined.append((cgroup, pid))

    def populated(self, cgroup: Path) -> bool:
        if cgroup in self.killed:
            return False
        pids = [pid for path, pid in self.joined if path == cgroup]
        return self.held or any(_group_alive(pid) for pid in pids)

    def kill(self, cgroup: Path) -> None:
        self.killed.append(cgroup)
        for path, pid in self.joined:
            if path == cgroup and _group_alive(pid):
                os.killpg(pid, signal.SIGKILL)

    def signal_all(self, cgroup: Path, sig: signal.Signals) -> None:
        self.signalled.append((cgroup, sig))

    def remove(self, cgroup: Path) -> bool:
        if self.populated(cgroup):
            return False
        cgroup.rmdir()
        self.removed.append(cgroup)
        return True


def _runner(
    tmp_path: Path, containment: FakeContainment, **fake: object
) -> tuple[CliClaudeRunner, Path]:
    workdir = tmp_path / "work"
    workdir.mkdir()
    script = write_fake_claude(tmp_path, **fake)  # type: ignore[arg-type]
    config = ClaudeCliConfig(
        claude_bin=script,
        mcp_config=tmp_path / "mcp.json",
        settings=tmp_path / "s.json",
        workdir=workdir,
        run_timeout=60,
    )
    return CliClaudeRunner(config, {"PATH": "/usr/bin:/bin"}, containment=containment), workdir


def _request() -> RunRequest:
    tools = TOOL_SETS[ToolSetName.FULL]
    return RunRequest(
        window_id=WINDOW_A,
        resume=False,
        prompt="hola",
        allowed_tools=tools.allowed,
        disallowed_tools=tools.disallowed,
        builtin_tools=tools.builtins,
    )


def _cgroups(tmp_path: Path) -> FakeContainment:
    root = tmp_path / "cg"
    root.mkdir()
    return FakeContainment(root)


# --- the runner ----------------------------------------------------------------------------


def test_c58_each_run_is_placed_in_its_own_cgroup(tmp_path: Path) -> None:
    containment = _cgroups(tmp_path)
    runner, workdir = _runner(tmp_path, containment)
    outcome = runner.run(_request())
    assert outcome.exit_code == 0 and not outcome.is_error
    [(cgroup, pid)] = containment.joined
    assert pid == read_record(workdir)["pid"]
    assert read_record(workdir)["stdin"] == "hola"  # the prompt came after the move
    assert containment.removed == [cgroup]  # empty after the run: cleaned up
    assert not runner.busy()


@pytest.mark.parametrize("failure", ["fail_create", "fail_join"])
def test_c58_a_run_without_its_own_cgroup_is_refused(tmp_path: Path, failure: str) -> None:
    """Fail closed: a run `/stop` could not fully reach never gets its prompt."""
    containment = _cgroups(tmp_path)
    setattr(containment, failure, True)
    runner, workdir = _runner(tmp_path, containment, sleep=60.0)
    outcome = runner.run(_request())
    assert outcome.is_error and outcome.exit_code is None
    if (workdir / "record.json").exists():
        assert read_record(workdir)["stdin"] == ""
    assert not runner.busy()
    if failure == "fail_join":
        [created] = containment.killed
        assert containment.removed == [created]


def test_c58_finished_run_with_a_populated_cgroup_keeps_the_runner_busy(tmp_path: Path) -> None:
    """A detached job whose parent exited is still in the cgroup: busy, and /stop kills it."""
    containment = _cgroups(tmp_path)
    runner, _ = _runner(tmp_path, containment)
    containment.held = True  # a background job left in the cgroup
    assert runner.run(_request()).exit_code == 0
    [(cgroup, _pid)] = containment.joined
    assert runner.busy()
    assert runner.kill_all() == 1
    assert containment.signalled == [(cgroup, signal.SIGTERM)]
    assert containment.killed == [cgroup]
    containment.held = False
    assert not runner.busy()
    assert containment.removed == [cgroup]


def test_c58_stop_mid_run_kills_the_cgroup_and_marks_the_run_killed(tmp_path: Path) -> None:
    containment = _cgroups(tmp_path)
    runner, workdir = _runner(tmp_path, containment, sleep=60.0)
    outcomes: list[RunOutcome] = []
    worker = threading.Thread(target=lambda: outcomes.append(runner.run(_request())))
    worker.start()
    deadline = threading.Event()
    while not (workdir / "record.json").exists():
        assert not deadline.wait(0.02) and worker.is_alive()
    assert runner.busy()
    assert runner.kill_all(epoch=1) == 1
    worker.join(15)
    assert not worker.is_alive() and outcomes[0].killed
    assert len(containment.killed) == 1
    assert not runner.busy()


def test_c58_run_timeout_kills_the_whole_cgroup(tmp_path: Path) -> None:
    containment = _cgroups(tmp_path)
    runner, _ = _runner(tmp_path, containment, sleep=60.0)
    runner._config = ClaudeCliConfig(
        claude_bin=runner._config.claude_bin,
        mcp_config=runner._config.mcp_config,
        settings=runner._config.settings,
        workdir=runner._config.workdir,
        run_timeout=0.5,
    )
    assert runner.run(_request()).timed_out
    assert len(containment.killed) == 1
    assert not runner.busy()


# --- RunCgroups on a tmp directory -------------------------------------------------------


def test_c58_run_cgroups_names_writes_and_reads_control_files(tmp_path: Path) -> None:
    cgroups = RunCgroups(tmp_path)
    first = cgroups.create(4242)
    second = cgroups.create(4242)  # same pid again: a fresh name, never a leftover
    assert (first.name, second.name) == ("run-1-4242", "run-2-4242")
    for name in ("cgroup.procs", "cgroup.kill", "cgroup.events"):
        (first / name).write_text("")
    cgroups.join(first, 4242)
    assert (first / "cgroup.procs").read_text() == "4242\n"
    cgroups.kill(first)
    assert (first / "cgroup.kill").read_text() == "1\n"
    (first / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    assert cgroups.populated(first)
    (first / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert not cgroups.populated(first)
    assert not cgroups.populated(tmp_path / "gone")
    assert cgroups.remove(second) and not second.exists()
    assert not cgroups.remove(second)


def test_c58_run_cgroups_never_create_or_follow_control_files(tmp_path: Path) -> None:
    cgroups = RunCgroups(tmp_path)
    cgroup = cgroups.create(7)
    with pytest.raises(OSError):
        cgroups.join(cgroup, 7)  # no cgroup.procs: an error, never a new file
    assert not (cgroup / "cgroup.procs").exists()
    target = tmp_path / "elsewhere"
    target.write_text("")
    (cgroup / "cgroup.procs").symlink_to(target)
    with pytest.raises(OSError):
        cgroups.join(cgroup, 7)
    assert target.read_text() == ""
    cgroups.kill(cgroup)  # missing cgroup.kill: logged, never raised


def test_c58_run_cgroups_signal_only_listed_members(tmp_path: Path) -> None:
    cgroups = RunCgroups(tmp_path)
    cgroup = cgroups.create(1)
    (cgroup / "cgroup.procs").write_text("0\n1\nnot-a-pid\n")
    cgroups.signal_all(cgroup, signal.SIGTERM)  # pid 0/1 and junk are skipped
    cgroups.signal_all(tmp_path / "gone", signal.SIGTERM)


# --- finding the delegated cgroup ----------------------------------------------------------


def _fs(tmp_path: Path, line: str, *, kill_file: bool = True) -> tuple[Path, Path]:
    proc = tmp_path / "cgroup"
    proc.write_text(f"12:cpu:/old\n{line}\n")
    fs = tmp_path / "fs"
    unit = fs / "system.slice" / "claudia-host.service"
    unit.mkdir(parents=True)
    if kill_file:
        (unit / "cgroup.kill").write_text("")
    return proc, fs


def test_c58_delegated_root_is_the_parent_of_the_host_leaf(tmp_path: Path) -> None:
    proc, fs = _fs(tmp_path, "0::/system.slice/claudia-host.service/host")
    root = delegated_cgroup_root(proc_self_cgroup=proc, cgroup_fs=fs)
    assert root == fs / "system.slice" / "claudia-host.service"


@pytest.mark.parametrize(
    "line",
    [
        "0::/system.slice/claudia-host.service",  # no DelegateSubgroup leaf
        "0::/host",  # never the cgroup root itself
        "0::/system.slice/../claudia-host.service/host",
        "0::/system.slice/claudia host.service/host",
        "0::relative/host",
        "1:name=systemd:/system.slice/claudia-host.service/host",  # cgroup v1 only
    ],
)
def test_c58_delegated_root_refuses_anything_else(tmp_path: Path, line: str) -> None:
    proc, fs = _fs(tmp_path, line)
    assert delegated_cgroup_root(proc_self_cgroup=proc, cgroup_fs=fs) is None


def test_c58_delegated_root_needs_cgroup_kill(tmp_path: Path) -> None:
    proc, fs = _fs(tmp_path, "0::/system.slice/claudia-host.service/host", kill_file=False)
    assert delegated_cgroup_root(proc_self_cgroup=proc, cgroup_fs=fs) is None
    assert delegated_cgroup_root(proc_self_cgroup=tmp_path / "missing", cgroup_fs=fs) is None


# --- host wiring ---------------------------------------------------------------------------


def _host_config(*, require: bool) -> HostConfig:
    argv = ["--claude-bin", "/usr/bin/claude"]
    return parse_args([*argv, "--require-run-cgroups"] if require else argv)


def test_c58_host_refuses_to_start_without_required_run_cgroups() -> None:
    config = _host_config(require=True)
    assert config.require_run_cgroups
    with pytest.raises(RunCgroupError):
        run_containment(config, lambda: None)


def test_c58_host_without_the_requirement_falls_back_to_process_groups(tmp_path: Path) -> None:
    config = _host_config(require=False)
    assert not config.require_run_cgroups
    assert run_containment(config, lambda: None) is None
    assert isinstance(run_containment(config, lambda: tmp_path), RunCgroups)
