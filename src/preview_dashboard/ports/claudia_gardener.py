"""Ports of the weekly KB gardener (docs/security.md C54).

`KbGit` is the history of the knowledge-base repo (read changes, revert a
run); `GardenModel` runs the confined Haiku pass; `GardenReporter` publishes
the summary and sends the one alert. Implementations: `adapters/kb_git.py`,
`adapters/gardener_runner.py`, `interfaces/claudia/gardener.py`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ChangedFile:
    """One path changed between two commits; `status` is git's letter (A, M, D, T ...)."""

    status: str
    path: str


@dataclass(frozen=True, slots=True)
class GardenModelRun:
    """Outcome of the Haiku pass: success flag and its final text (never trusted)."""

    ok: bool
    text: str | None = None


class KbGit(Protocol):
    """History of the KB repo."""

    def head(self) -> str | None:
        """Full id of the current commit, None when the repo has none."""
        ...

    def tracked_files(self) -> list[str]:
        """Every tracked path, `/`-separated.

        Raises:
            StorageUnavailableError: git failed.
        """
        ...

    def changed_since(self, base: str) -> list[ChangedFile]:
        """Paths that differ between `base` and the current commit (no rename detection).

        Raises:
            StorageUnavailableError: git failed.
        """
        ...

    def revert_since(self, base: str) -> str | None:
        """Undo every commit after `base` with ONE new revert commit; its id, None if no change.

        Raises:
            StorageUnavailableError: git failed (e.g. a conflict).
        """
        ...

    def restore_worktree(self) -> None:
        """Drop uncommitted note changes: `*.md` back to HEAD, untracked `*.md` removed.

        Never touches `.git`, lock files or anything that is not a note.

        Raises:
            StorageUnavailableError: git failed.
        """
        ...


class GardenModel(Protocol):
    """The confined Haiku pass over the flagged notes."""

    def run(self, prompt: str) -> GardenModelRun:
        """Run once with `prompt` on stdin; failures are `ok=False`, never raised."""
        ...


class GardenReporter(Protocol):
    """Where the run's summary goes (a dashboard item + one alert)."""

    def report(self, title: str, markdown: str, *, ok: bool) -> None:
        """Publish `markdown` as a dashboard item and send one `done` (ok) / `failed` alert.

        Raises:
            StorageUnavailableError: the admin API could not be reached.
        """
        ...
