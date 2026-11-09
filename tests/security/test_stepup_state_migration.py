"""Security tests for moving the step-up state into the admin-only claudia/ dir (F-C2b-3).

C47: the replay mark and lockout counters live in `<data_dir>/claudia/`
(0700, admin). The one-time move from the old data-dir location never
follows a symlink, refuses when both locations hold a file, keeps owner and
0600 mode, and a refused migration leaves everything untouched.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from preview_dashboard.adapters.stepup_state import (
    LOCK_FILE_NAME,
    STATE_FILE_NAME,
    StepUpStateError,
    migrate_legacy_state,
    open_stepup_state,
)
from preview_dashboard.domain.totp import StepUpState


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    root.mkdir(mode=0o750)
    os.chmod(root, 0o750)  # noqa: S103 - viewer-readable data dir
    (root / "claudia").mkdir(mode=0o700)
    os.chmod(root / "claudia", 0o700)
    return root


def _put(path: Path, text: str = "x", mode: int = 0o600) -> None:
    path.write_text(text)
    os.chmod(path, mode)


def test_old_file_and_lock_move_with_owner_and_mode(data_dir: Path) -> None:
    _put(data_dir / STATE_FILE_NAME, "state")
    _put(data_dir / LOCK_FILE_NAME, "")
    migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())
    assert not (data_dir / STATE_FILE_NAME).exists()
    assert not (data_dir / LOCK_FILE_NAME).exists()
    moved = data_dir / "claudia" / STATE_FILE_NAME
    assert moved.read_text() == "state"
    assert stat.S_IMODE(moved.stat().st_mode) == 0o600
    assert (data_dir / "claudia" / LOCK_FILE_NAME).exists()


def test_nothing_to_migrate_is_a_noop(data_dir: Path) -> None:
    migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())
    assert list((data_dir / "claudia").iterdir()) == []


def test_both_paths_present_is_refused_and_nothing_moves(data_dir: Path) -> None:
    _put(data_dir / STATE_FILE_NAME, "old")
    _put(data_dir / LOCK_FILE_NAME, "")
    _put(data_dir / "claudia" / STATE_FILE_NAME, "new")
    with pytest.raises(StepUpStateError, match="both"):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())
    assert (data_dir / STATE_FILE_NAME).read_text() == "old"
    assert (data_dir / "claudia" / STATE_FILE_NAME).read_text() == "new"
    assert (data_dir / LOCK_FILE_NAME).exists()
    assert not (data_dir / "claudia" / LOCK_FILE_NAME).exists()


def test_symlinked_old_file_is_refused_not_followed(data_dir: Path, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    _put(target, "secret")
    (data_dir / STATE_FILE_NAME).symlink_to(target)
    with pytest.raises(StepUpStateError):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())
    assert (data_dir / STATE_FILE_NAME).is_symlink()
    assert not (data_dir / "claudia" / STATE_FILE_NAME).exists()


def test_symlinked_claudia_dir_is_refused(data_dir: Path, tmp_path: Path) -> None:
    os.rmdir(data_dir / "claudia")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (data_dir / "claudia").symlink_to(elsewhere)
    _put(data_dir / STATE_FILE_NAME)
    with pytest.raises(StepUpStateError):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())
    assert list(elsewhere.iterdir()) == []


def test_loose_mode_or_hardlinked_old_file_is_refused(data_dir: Path, tmp_path: Path) -> None:
    _put(data_dir / STATE_FILE_NAME, mode=0o640)
    with pytest.raises(StepUpStateError):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())
    os.chmod(data_dir / STATE_FILE_NAME, 0o600)
    os.link(data_dir / STATE_FILE_NAME, tmp_path / "second-name")
    with pytest.raises(StepUpStateError):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())


def test_foreign_owner_is_refused(data_dir: Path) -> None:
    _put(data_dir / STATE_FILE_NAME)
    with pytest.raises(StepUpStateError):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid() + 1)


def test_group_accessible_claudia_dir_is_refused(data_dir: Path) -> None:
    os.chmod(data_dir / "claudia", 0o750)  # noqa: S103 - deliberately loose
    _put(data_dir / STATE_FILE_NAME)
    with pytest.raises(StepUpStateError):
        migrate_legacy_state(data_dir, "claudia", owner_uid=os.geteuid())


def test_open_stepup_state_migrates_then_loads_from_claudia(data_dir: Path) -> None:
    store = open_stepup_state(data_dir)
    store.save(StepUpState(last_step=7))
    assert (data_dir / "claudia" / STATE_FILE_NAME).exists()
    assert not (data_dir / STATE_FILE_NAME).exists()
    # A second start finds nothing to migrate and keeps the state.
    assert open_stepup_state(data_dir).load().last_step == 7


def test_open_stepup_state_without_claudia_dir_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(StepUpStateError):
        open_stepup_state(tmp_path)
