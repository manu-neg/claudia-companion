"""One gardener run: baseline commit, pre-pass, Haiku pass, verify, revert on violation (C54).

`Gardener` is framework-free and depends on ports only. The model is
untrusted: whatever it changed is re-checked by the host (file cap, layout,
caps, secret scan, `persona.md` untouched) and the whole run is reverted
with one commit on any violation or when the run itself failed.
"""

from __future__ import annotations

import contextlib
import datetime
import logging
import re
from collections import Counter
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from preview_dashboard.application.claudia.garden_rules import Finding, analyze
from preview_dashboard.application.claudia.kb import (
    KbRefusedError,
    NoteKind,
    check_note_rules,
    classify,
)
from preview_dashboard.application.notify import scan_texts
from preview_dashboard.domain.errors import SecretDetectedError, StorageUnavailableError
from preview_dashboard.ports.claudia_gardener import ChangedFile, GardenModel, GardenReporter, KbGit
from preview_dashboard.ports.claudia_kb import KbStore
from preview_dashboard.ports.scanner import ContentScanner

MAX_FILES: Final = 30
MAX_PROMPT_FINDINGS: Final = 60
_SAFE_PATH: Final = re.compile(r"[a-z0-9_./-]{1,200}")
logger = logging.getLogger(__name__)


class GardenStatus(StrEnum):
    """How a run ended."""

    NOTHING_TO_DO = "nothing-to-do"
    DONE = "done"
    REVERTED = "reverted"


@dataclass(frozen=True, slots=True)
class GardenReport:
    """What happened; contains paths, counts and rule labels only, never note text."""

    status: GardenStatus
    findings: tuple[Finding, ...] = ()
    changed: tuple[str, ...] = ()
    violations: tuple[str, ...] = field(default=())
    revert_commit: str | None = None

    def title(self, today: datetime.date) -> str:
        """Short one-line title (dashboard item and alert)."""
        label = {
            GardenStatus.NOTHING_TO_DO: "KB is tidy",
            GardenStatus.DONE: f"KB gardened ({len(self.changed)} files)",
            GardenStatus.REVERTED: "KB gardening reverted",
        }[self.status]
        return f"Claudia gardener {today.isoformat()}: {label}"

    def markdown(self, today: datetime.date) -> str:
        """Scannable summary for the dashboard item."""
        lines = [f"# {self.title(today)}", ""]
        counts = Counter(f.kind.value for f in self.findings)
        lines.append(f"**Findings:** {sum(counts.values())}")
        lines += [f"- {kind}: {n}" for kind, n in sorted(counts.items())]
        if self.changed:
            lines += ["", "## Changed files", *[f"- `{_clean(p)}`" for p in self.changed]]
        if self.violations:
            lines += ["", "## Violations (run reverted)", *[f"- {v}" for v in self.violations]]
            lines.append(f"\nRevert commit: `{self.revert_commit or 'none needed'}`")
        return "\n".join(lines) + "\n"


def _clean(path: str) -> str:
    return path if _SAFE_PATH.fullmatch(path) else "<odd path>"


class Gardener:
    """Runs the weekly pass.

    Args:
        store: the KB byte store (committing the baseline, reading changed files).
        git: history port (head, changes, revert).
        model: the confined Haiku pass.
        scanner: the C15 scanner for the re-check.
        reporter: summary + alert sink.
        today: day provider (injected for tests).
        max_files: cap on files one run may change.
        run_guard: context manager factory held for the whole run (the KB
            cross-process lock, kb-map-2); None means no guard.
    """

    def __init__(
        self,
        store: KbStore,
        git: KbGit,
        model: GardenModel,
        scanner: ContentScanner,
        reporter: GardenReporter,
        today: Callable[[], datetime.date],
        *,
        max_files: int = MAX_FILES,
        run_guard: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> None:
        self._run_guard = run_guard
        self._store = store
        self._git = git
        self._model = model
        self._scanner = scanner
        self._reporter = reporter
        self._today = today
        self._max_files = max_files

    def run(self) -> GardenReport:
        """Garden once and report; returns the report.

        Raises:
            StorageUnavailableError: git or the store failed before the model ran,
                the KB lock could not be taken, or the revert itself failed
                (a `failed` alert is attempted first; the KB then needs the owner).
        """
        with self._run_guard() if self._run_guard else contextlib.nullcontext():
            return self._run()

    def _run(self) -> GardenReport:
        today = self._today()
        self._store.commit("gardener: before")  # baseline: the revert target
        base = self._git.head()
        findings = tuple(analyze(self._read_all(), today)) if base is not None else ()
        if base is None or not findings:  # no commit means no notes either
            report = GardenReport(GardenStatus.NOTHING_TO_DO)
            self._send(report, today, ok=True)
            return report
        result = self._model_run(findings)
        violations: list[str] = []
        changed: list[ChangedFile] = []
        try:
            self._store.commit("gardener: run")  # catch anything the MCP server did not commit
            changed = self._git.changed_since(base)
            violations = self._violations(changed)
        except Exception as exc:  # fail closed: unverifiable output is a violation (kb-map-1)
            logger.error("gardener post-run check failed (%s)", type(exc).__name__)
            violations.append("the post-run check failed; output could not be verified")
            changed = []
        if not result:
            violations.append("the model run failed or hit its limit")
        paths = tuple(c.path for c in changed)
        if violations:
            # Always try the revert, even when the check itself failed: the MCP server
            # may already have committed unverified changes (kb-map-1). Restore the
            # work tree first: a failed post-run commit leaves the model's files
            # there, and the next commit would take them in unchecked.
            try:
                # Under `.lock` like every other KB git step (C53); inside the run
                # guard this also clears a stale index.lock (fixcheck-a-1).
                revert = self._store.run_locked(lambda: self._restore_and_revert(base))
            except Exception as exc:
                logger.error("gardener revert failed (%s)", type(exc).__name__)
                failed = GardenReport(
                    GardenStatus.REVERTED, findings, paths, (*violations, "the revert failed")
                )
                self._send(failed, today, ok=False)
                raise StorageUnavailableError("gardener revert failed") from exc
            report = GardenReport(GardenStatus.REVERTED, findings, paths, tuple(violations), revert)
        else:
            report = GardenReport(GardenStatus.DONE, findings, paths)
        self._send(report, today, ok=report.status is not GardenStatus.REVERTED)
        return report

    def _restore_and_revert(self, base: str) -> str | None:
        self._git.restore_worktree()
        return self._git.revert_since(base)

    def _read_all(self) -> dict[str, str]:
        notes: dict[str, str] = {}
        for path in self._git.tracked_files():
            try:
                classify(path)
                data = self._store.read(path)
            except (KbRefusedError, StorageUnavailableError):
                continue  # not ours or unreadable: the rules skip it
            if data is not None:
                notes[path] = data.decode("utf-8", "replace")
        return notes

    def _model_run(self, findings: tuple[Finding, ...]) -> bool:
        lines = [f"- {f.kind.value}: {f.path} ({f.detail})" for f in findings[:MAX_PROMPT_FINDINGS]]
        prompt = "Findings to fix (paths and rule labels only):\n" + "\n".join(lines) + "\n"
        try:
            return self._model.run(prompt).ok
        except Exception as exc:  # the model is untrusted: any failure just means "revert"
            logger.error("gardener model run failed (%s)", type(exc).__name__)
            return False

    def _violations(self, changed: list[ChangedFile]) -> list[str]:
        """Re-check every changed file; labels name paths and rules, never content."""
        out: list[str] = []
        if len(changed) > self._max_files:
            out.append(f"{len(changed)} files changed, max {self._max_files}")
        for entry in changed:
            label = _clean(entry.path)
            try:
                kind = classify(entry.path)
            except KbRefusedError:
                out.append(f"{label}: outside the KB layout")
                continue
            if kind is NoteKind.PERSONA:
                out.append("persona.md was changed")
            elif kind is NoteKind.GUIDE:
                out.append("guide.md was changed")
            elif entry.status == "D":
                if kind in (NoteKind.INDEX, NoteKind.NOW):
                    out.append(f"{label}: must not be deleted")
            elif entry.status not in ("A", "M"):
                out.append(f"{label}: unexpected change type")
            else:
                reason = self._check_file(entry.path)
                if reason:
                    out.append(f"{label}: {reason}")
        return out

    def _check_file(self, path: str) -> str | None:
        try:
            data = self._store.read(path)
        except StorageUnavailableError:
            return "not a plain readable file"
        if data is None:
            return "missing after commit"
        text = data.decode("utf-8", "replace")
        try:
            check_note_rules(path, text)
            scan_texts(self._scanner, [text])
        except KbRefusedError as exc:
            return str(exc)[:120]  # host-made rule text
        except SecretDetectedError:
            return "secret scan matched"
        return None

    def _send(self, report: GardenReport, today: datetime.date, *, ok: bool) -> None:
        try:
            self._reporter.report(report.title(today), report.markdown(today), ok=ok)
        except Exception as exc:  # the KB result stands even if the dashboard is down
            logger.error("gardener report failed (%s)", type(exc).__name__)
