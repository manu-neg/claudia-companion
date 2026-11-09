"""Free pre-pass of the weekly gardener: what in the KB needs tidying (docs/security.md C54).

Pure functions over `{relpath: text}`; no I/O and no model. Finds duplicates,
oversized notes, orphans, broken `[[links]]`, stale or unversioned source
pointers, `updated since` markers in `now.md` and journals older than 30
days. Haiku later touches only the notes named here, so the findings are the
whole attack surface a note's text can steer: their text fields are
rule-generated and sanitised (a note cannot smuggle sentences into them).
"""

from __future__ import annotations

import datetime
import hashlib
import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from preview_dashboard.application.claudia.kb import (
    KbRefusedError,
    NoteKind,
    check_note_rules,
    classify,
    parse_sources,
    split_frontmatter,
)

JOURNAL_FOLD_DAYS: Final = 30
STALE_DAYS: Final = 180
MIN_DUPLICATE_WORDS: Final = 8
_LINK_RE: Final = re.compile(r"\[\[([^\[\]\n]{1,200})\]\]")
_UPDATED_RE: Final = re.compile(r"updated:\s*(\d{4}-\d{2}-\d{2})\s*")
_UNSAFE_RE: Final = re.compile(r"[^A-Za-z0-9_./#-]")
_DETAIL_MAX: Final = 80


class FindingKind(StrEnum):
    """What the pre-pass flagged."""

    DUPLICATE = "duplicate"
    OVERSIZED = "oversized"
    ORPHAN = "orphan"
    BROKEN_LINK = "broken-link"
    STALE = "stale"
    UNVERSIONED_POINTER = "unversioned-pointer"
    UPDATED_SINCE = "updated-since"
    OLD_JOURNAL = "old-journal"


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing to fix: a layout path and a short, sanitised, rule-made detail."""

    kind: FindingKind
    path: str
    detail: str = ""


def _safe(text: str) -> str:
    """Strip a note-derived fragment to path-ish characters (no prose reaches the prompt)."""
    return _UNSAFE_RE.sub("?", text)[:_DETAIL_MAX]


def analyze(notes: Mapping[str, str], today: datetime.date) -> list[Finding]:
    """Run every rule over the notes; paths outside the layout are ignored.

    Args:
        notes: relpath -> text of every tracked note.
        today: reference day for staleness and journal age.

    Returns:
        Findings sorted by path then kind (stable for golden tests).
    """
    kinds: dict[str, NoteKind] = {}
    for path in notes:
        try:
            kinds[path] = classify(path)
        except KbRefusedError:
            continue
    findings: list[Finding] = []
    findings += _oversized(notes, kinds)
    findings += _duplicates(notes, kinds)
    findings += _links(notes, kinds)
    findings += _pointers(notes, kinds, today)
    findings += _journals(kinds, today)
    return sorted(findings, key=lambda f: (f.path, f.kind.value, f.detail))


def _oversized(notes: Mapping[str, str], kinds: Mapping[str, NoteKind]) -> list[Finding]:
    out: list[Finding] = []
    for path, kind in kinds.items():
        if kind is NoteKind.PERSONA:
            continue  # root's file: never ours to shorten
        try:
            check_note_rules(path, notes[path])
        except KbRefusedError as exc:
            # The rule text is host-made (counts and limits), never note content.
            out.append(Finding(FindingKind.OVERSIZED, path, str(exc)[:_DETAIL_MAX]))
    return out


def _body_key(text: str) -> str | None:
    _front, body = split_frontmatter(text)
    words = body.lower().split()
    if len(words) < MIN_DUPLICATE_WORDS:
        return None
    return hashlib.sha256(" ".join(words).encode()).hexdigest()


def _duplicates(notes: Mapping[str, str], kinds: Mapping[str, NoteKind]) -> list[Finding]:
    groups: dict[str, list[str]] = defaultdict(list)
    for path, kind in kinds.items():
        if kind in (NoteKind.NOTE, NoteKind.TOPIC) and (key := _body_key(notes[path])):
            groups[key].append(path)
    out: list[Finding] = []
    for paths in groups.values():
        first, *rest = sorted(paths)
        out += [Finding(FindingKind.DUPLICATE, p, f"same text as {first}") for p in rest]
    return out


def _resolver(kinds: Mapping[str, NoteKind]) -> dict[str, set[str]]:
    """Map every name a `[[link]]` may use onto the paths it denotes."""
    names: dict[str, set[str]] = defaultdict(set)
    for path, kind in kinds.items():
        stem = path.removesuffix(".md")
        names[stem].add(path)
        if kind is NoteKind.NOTE or kind is NoteKind.WORKLOG or kind is NoteKind.JOURNAL:
            names[stem.rsplit("/", 1)[-1]].add(path)
        elif kind is NoteKind.TOPIC:
            names[stem.split("/")[1]].add(path)  # [[category]] means its _topic.md
    return names


def _links(notes: Mapping[str, str], kinds: Mapping[str, NoteKind]) -> list[Finding]:
    names = _resolver(kinds)
    inbound: dict[str, set[str]] = defaultdict(set)
    out: list[Finding] = []
    for path in kinds:
        broken: set[str] = set()
        for raw in _LINK_RE.findall(notes[path]):
            target = raw.split("|", 1)[0].split("#", 1)[0].strip().removesuffix(".md")
            hits = names.get(target)
            if not hits:
                broken.add(target)
                continue
            for hit in hits:
                if hit != path:
                    inbound[hit].add(path)
        out += [Finding(FindingKind.BROKEN_LINK, path, f"[[{_safe(t)}]]") for t in sorted(broken)]
    for path, kind in kinds.items():
        if kind in (NoteKind.NOTE, NoteKind.TOPIC) and not inbound.get(path):
            out.append(Finding(FindingKind.ORPHAN, path, "no other note links here"))
    return out


def _pointers(
    notes: Mapping[str, str], kinds: Mapping[str, NoteKind], today: datetime.date
) -> list[Finding]:
    out: list[Finding] = []
    for path, kind in kinds.items():
        text = notes[path]
        if kind is NoteKind.NOW:
            marked = sum(1 for ln in text.split("\n") if "updated since" in ln.lower())
            if marked:
                out.append(Finding(FindingKind.UPDATED_SINCE, path, f"{marked} line(s) to resolve"))
        if kind is not NoteKind.NOTE:
            continue
        front, _body = split_frontmatter(text)
        if front is None:
            continue
        for line in front:
            m = _UPDATED_RE.fullmatch(line.strip())
            if m is None:
                continue
            try:
                age = (today - datetime.date.fromisoformat(m[1])).days
            except ValueError:
                break
            if age > STALE_DAYS:
                out.append(Finding(FindingKind.STALE, path, f"updated {age} days ago"))
            break
        unversioned = [s for s in parse_sources(front) if "@" not in s]
        if unversioned:
            out.append(
                Finding(FindingKind.UNVERSIONED_POINTER, path, f"{len(unversioned)} source(s)")
            )
    return out


def _journals(kinds: Mapping[str, NoteKind], today: datetime.date) -> list[Finding]:
    out: list[Finding] = []
    for path, kind in kinds.items():
        if kind is not NoteKind.JOURNAL:
            continue
        day = datetime.date.fromisoformat(path.split("/", 1)[1][:10])  # classify checked it
        age = (today - day).days
        if age > JOURNAL_FOLD_DAYS:
            out.append(Finding(FindingKind.OLD_JOURNAL, path, f"{age} days old: fold, then delete"))
    return out
