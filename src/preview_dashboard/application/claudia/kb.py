"""Claudia knowledge-base write rules: fixed layout, caps, secret scan (C53).

`KbService` is the only gate between model output and the KB files: every
call is checked against the fixed layout, the size caps and the C15 secret
scan before the `KbStore` port stores anything. Framework-free; the MCP
wrapper lives in `interfaces/claudia/kb_mcp.py`.
"""

from __future__ import annotations

import datetime
import re
import threading
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from typing import Final

from preview_dashboard.application.notify import scan_texts
from preview_dashboard.domain.errors import (
    NotFoundError,
    StorageUnavailableError,
    ValidationError,
)
from preview_dashboard.domain.unicode import (
    JOINERS,
    PRESENTATION_SELECTORS,
    is_default_ignorable,
    takes_joiner,
    takes_presentation_selector,
)
from preview_dashboard.ports.claudia_host import KbWorktree
from preview_dashboard.ports.claudia_kb import KbStats, KbStore
from preview_dashboard.ports.scanner import ContentScanner

MAX_NOW_LINES: Final = 40
MAX_TOPIC_WORDS: Final = 150
MAX_NOTE_WORDS: Final = 300
MAX_NOTE_BYTES: Final = 4096
MAX_JOURNAL_BULLETS: Final = 10
MAX_INDEX_LINES: Final = 100
MAX_INDEX_BYTES: Final = 8192
MAX_WORKLOG_BYTES: Final = 16384
MAX_NOTES: Final = 2000
MAX_TOTAL_BYTES: Final = 8 * 1024 * 1024
MAX_SOURCE_LEN: Final = 200
# Longer than a write's wait: a restore after a failed commit should outlast a short holder.
RESTORE_LOCK_WAIT_S: Final = 120.0

_SEG: Final = r"[a-z0-9-]{1,48}"
# ASCII-only on purpose: lower-case segments, so no look-alike or case-twin paths.
_PATH_RE: Final = re.compile(
    rf"""
    (?P<fixed>index|now|persona)\.md
    | topics/work-log/(?P<ym>\d{{4}}-\d{{2}})\.md
    | topics/(?P<tcat>{_SEG})/_topic\.md
    | topics/(?P<ncat>{_SEG})/(?P<note>{_SEG})\.md
    | journal/(?P<day>\d{{4}}-\d{{2}}-\d{{2}})-(?P<slug>{_SEG})\.md
    """,
    re.VERBOSE | re.ASCII,
)
_CALLER_RE: Final = re.compile(r"[a-z0-9-]{1,32}", re.ASCII)
_BULLET_RE: Final = re.compile(r"\s*[-*+]\s")
_SOURCE_LIST_ITEM: Final = re.compile(r"\s+-\s+(?P<v>.+)")
_PROMPT_COMMENT: Final = re.compile(r"\A\s*<!--.*?-->\s*", re.DOTALL)


class KbRefusedError(ValidationError):
    """A KB call broke a rule; the message says which, so she can fix it."""


class NoteKind(StrEnum):
    """What a layout path is; decides the caps that apply."""

    INDEX = "index"
    NOW = "now"
    PERSONA = "persona"
    TOPIC = "topic"
    NOTE = "note"
    WORKLOG = "work-log"
    JOURNAL = "journal"


@dataclass(frozen=True, slots=True)
class KbWriteResult:
    """What a successful write reports back (counts only, no content)."""

    path: str
    words: int
    size_bytes: int


def classify(relpath: str) -> NoteKind:
    """Map a relpath onto the fixed layout.

    Raises:
        KbRefusedError: the path is not exactly one of the layout shapes
            (traversal, odd segment, wrong extension, bad date ...).
    """
    m = _PATH_RE.fullmatch(relpath) if relpath.isascii() else None
    if m is None:
        raise KbRefusedError(
            "path is not in the layout: index.md, now.md, topics/<cat>/_topic.md, "
            "topics/<cat>/<note>.md, topics/work-log/YYYY-MM.md, journal/YYYY-MM-DD-<slug>.md "
            "(segments [a-z0-9-], 1..48 chars)"
        )
    if m["fixed"]:
        return NoteKind(m["fixed"])
    if m["ym"]:
        if not 1 <= int(m["ym"][5:]) <= 12:
            raise KbRefusedError("work-log month must be 01..12")
        return NoteKind.WORKLOG
    if m["tcat"]:
        return NoteKind.TOPIC
    if m["ncat"]:
        if m["ncat"] == "work-log":
            raise KbRefusedError("topics/work-log/ only holds YYYY-MM.md and _topic.md")
        return NoteKind.NOTE
    try:
        datetime.date.fromisoformat(m["day"])
    except ValueError as exc:
        raise KbRefusedError("journal date is not a real calendar day") from exc
    return NoteKind.JOURNAL


def split_frontmatter(text: str) -> tuple[list[str] | None, str]:
    """Split a leading `---` block off; returns (frontmatter lines or None, body)."""
    if not text.startswith("---\n"):
        return None, text
    rest = text[4:]
    end = rest.find("\n---\n")
    if end == -1:
        if rest.endswith("\n---"):
            return rest[:-4].split("\n"), ""
        return None, text
    return rest[:end].split("\n"), rest[end + 5 :]


def parse_sources(front: list[str]) -> list[str]:
    """Return the `sources:` entries of a frontmatter (inline list or `- ` block).

    Each entry names where a note came from, ideally as a versioned pointer
    `kind:ref@version` (dashboard revision / git commit or mtime / PR updated_at).
    """
    for i, line in enumerate(front):
        key, sep, value = line.partition(":")
        if not sep or key.strip() != "sources":
            continue
        value = value.strip()
        if value:
            inner = value.removeprefix("[").removesuffix("]")
            return [s.strip().strip("'\"") for s in inner.split(",") if s.strip().strip("'\"")]
        items: list[str] = []
        for nxt in front[i + 1 :]:
            m = _SOURCE_LIST_ITEM.fullmatch(nxt)
            if m is None:
                break
            items.append(m["v"].strip().strip("'\""))
        return items
    return []


def check_note_rules(relpath: str, content: str) -> NoteKind:
    """Check an existing note against layout + caps (what `write` enforces, minus the scan).

    Used by the gardener to find oversized notes and to re-check every file
    a run changed (C54).

    Raises:
        KbRefusedError: the path or the content breaks a rule.
    """
    kind = classify(relpath)
    _check_caps(kind, content, len(content.encode("utf-8", "replace")))
    return kind


def load_prompt(name: str) -> str:
    """Return a bundled prompt/seed text (`prompts/<name>`), header comment stripped."""
    raw = (resources.files("preview_dashboard.application.claudia") / "prompts" / name).read_text(
        encoding="utf-8"
    )
    return _PROMPT_COMMENT.sub("", raw, count=1)


class KbService:
    """Applies the KB write rules and forwards accepted writes to the store.

    Args:
        store: byte store (`adapters/kb_store.py`).
        scanner: the C15 content scanner (reused, not reimplemented).
        worktree: restores the work tree after a failed commit (host only);
            None = `restore_worktree` refuses.
        restore_wait_s: how long a restore / clean check waits for the KB locks.
    """

    def __init__(
        self,
        store: KbStore,
        scanner: ContentScanner,
        *,
        worktree: KbWorktree | None = None,
        restore_wait_s: float = RESTORE_LOCK_WAIT_S,
    ) -> None:
        self._store = store
        self._scanner = scanner
        self._worktree = worktree
        self._restore_wait = restore_wait_s
        self._lock = threading.Lock()  # one writer at a time: caps are check-then-write

    def read(self, relpath: str) -> str:
        """Return a note's text (any layout path, `persona.md` included).

        Raises:
            KbRefusedError: path not in the layout.
            NotFoundError: no such note.
            StorageUnavailableError: the file is not a plain file.
        """
        classify(relpath)
        data = self._store.read(relpath)
        if data is None:
            raise NotFoundError(f"no such note: {relpath}")
        return data.decode("utf-8", "replace")

    def write(self, relpath: str, content: str, *, caller: str) -> KbWriteResult:
        """Validate and store one note (create or replace).

        Args:
            relpath: layout path.
            content: complete new text of the note.
            caller: label of who writes (`claudia`, `recap`, `gardener`); it
                changes nothing about the rules, `persona.md` is refused to all.

        Raises:
            KbRefusedError: layout, cap, frontmatter or character rule broken.
            SecretDetectedError: the C15 scan matched (rule label only).
            StorageUnavailableError: the store refused or failed.
        """
        _check_caller(caller)
        kind = self._writable_kind(relpath)
        if not content.strip():
            raise KbRefusedError("empty note: use kb_delete to remove one")
        try:
            data = content.encode("utf-8")
        except UnicodeEncodeError as exc:  # lone surrogates cannot be stored
            raise KbRefusedError("note is not valid text") from exc
        words = _check_caps(kind, content, len(data))
        scan_texts(self._scanner, [content])

        def admit(old: int | None, stats: KbStats) -> None:
            if old is None and stats.files >= MAX_NOTES:
                raise KbRefusedError(f"knowledge base is full ({MAX_NOTES} notes): delete or merge")
            if stats.total_bytes - (old or 0) + len(data) > MAX_TOTAL_BYTES:
                raise KbRefusedError("knowledge base would exceed 8 MiB: shorten or delete notes")

        with self._lock:
            # fixcheck-a-3: the store runs the cap check under the same cross-process
            # lock hold as the write, so two KB processes can't both pass it.
            self._store.write_admitted(relpath, data, admit)
        return KbWriteResult(relpath, words, len(data))

    def delete(self, relpath: str, *, caller: str) -> None:
        """Delete one note.

        Raises:
            KbRefusedError: `persona.md` (every caller), `index.md`, `now.md`
                or a path outside the layout.
            NotFoundError: no such note.
        """
        _check_caller(caller)
        kind = self._writable_kind(relpath)
        if kind in (NoteKind.INDEX, NoteKind.NOW):
            raise KbRefusedError(f"{relpath} is always read at window start: rewrite it instead")
        with self._lock:
            if not self._store.delete(relpath):
                raise NotFoundError(f"no such note: {relpath}")

    def commit_run(self, message: str) -> str | None:
        """Commit the run's changes as ONE commit; None if nothing changed.

        Raises:
            KbBusyError: another process (e.g. a gardener run) held the KB locks.
            StorageUnavailableError: git failed.
        """
        with self._lock:
            return self._store.commit(message)

    def restore_worktree(self) -> None:
        """Drop uncommitted note changes (`*.md` only) after a failed `commit_run` (F-C2c).

        Left in place, the next run's commit would take them in unchecked.
        Runs under the store's cross-process locks (fixcheck-a-2), waiting up
        to `RESTORE_LOCK_WAIT_S`: never alongside a gardener run or a write.

        Raises:
            KbBusyError: the KB stayed locked for the whole wait.
            StorageUnavailableError: no work tree is configured, or git failed.
        """
        worktree = self._require_worktree()
        with self._lock:  # never between another writer's check and its write
            self._store.run_locked(worktree.restore_worktree, wait_s=self._restore_wait)

    def worktree_clean(self) -> bool:
        """True if no note differs from the last commit (checked under the KB locks).

        Raises:
            KbBusyError: the KB stayed locked for the whole wait.
            StorageUnavailableError: no work tree is configured, or git failed.
        """
        worktree = self._require_worktree()
        with self._lock:
            return self._store.run_locked(worktree.worktree_clean, wait_s=self._restore_wait)

    def _require_worktree(self) -> KbWorktree:
        if self._worktree is None:
            raise StorageUnavailableError("no knowledge base work tree to restore")
        return self._worktree

    def seed(self) -> list[str]:
        """Create `persona.md`, `index.md` and `now.md` from the bundled templates if missing.

        Goes straight to the store: `persona.md` is never writable via `write`.
        Returns the relpaths created.
        """
        created: list[str] = []
        with self._lock:
            for rel in ("persona.md", "index.md", "now.md"):
                if self._store.size(rel) is None:
                    self._store.write(rel, load_prompt(f"seed/{rel}").encode("utf-8"))
                    created.append(rel)
        return created

    def _writable_kind(self, relpath: str) -> NoteKind:
        kind = classify(relpath)
        # Checked for every caller: only root edits the persona by hand (C53).
        if kind is NoteKind.PERSONA:
            raise KbRefusedError("persona.md is read-only")
        return kind


def _check_caller(caller: str) -> None:
    if _CALLER_RE.fullmatch(caller) is None:
        raise KbRefusedError("invalid caller label")


def _check_characters(content: str) -> None:
    """Refuse control, format (bidi, zero-width, tag) and default-ignorable chars (kb-map-3).

    They hide text from the owner's review while Claudia still reads it. The
    only exceptions are joiners and emoji presentation selectors that sit next
    to a char they can legitimately modify (emoji, complex scripts).
    """
    for i, ch in enumerate(content):
        if ch in "\n\t":
            continue
        if ch == "\x7f" or unicodedata.category(ch) in ("Cc", "Cs"):
            raise KbRefusedError("control characters are not allowed in notes")
        if unicodedata.category(ch) == "Cf" or is_default_ignorable(ch):
            prev = content[i - 1] if i else ""
            nxt = content[i + 1] if i + 1 < len(content) else ""
            if ch in JOINERS and prev and takes_joiner(prev) and nxt:
                continue
            if ch in PRESENTATION_SELECTORS and prev and takes_presentation_selector(prev, nxt):
                continue
            raise KbRefusedError("invisible or direction-changing characters are not allowed")


def _check_caps(kind: NoteKind, content: str, size: int) -> int:
    """Enforce the per-kind caps and frontmatter; return the body word count."""
    _check_characters(content)
    front, body = split_frontmatter(content)
    words = len(body.split())
    lines = len(content.rstrip("\n").split("\n"))
    if kind is NoteKind.NOW:
        _cap(lines <= MAX_NOW_LINES, f"now.md has {lines} lines, max {MAX_NOW_LINES}: shorten")
        _cap(size <= MAX_NOTE_BYTES, f"now.md is {size} bytes, max {MAX_NOTE_BYTES}: shorten")
    elif kind is NoteKind.INDEX:
        _cap(lines <= MAX_INDEX_LINES, f"index.md has {lines} lines, max {MAX_INDEX_LINES}")
        _cap(size <= MAX_INDEX_BYTES, f"index.md is {size} bytes, max {MAX_INDEX_BYTES}")
    elif kind is NoteKind.TOPIC:
        _cap(words <= MAX_TOPIC_WORDS, f"_topic.md has {words} words, max {MAX_TOPIC_WORDS}")
        _cap(size <= MAX_NOTE_BYTES, f"_topic.md is {size} bytes, max {MAX_NOTE_BYTES}")
    elif kind is NoteKind.WORKLOG:
        _cap(size <= MAX_WORKLOG_BYTES, f"work-log is {size} bytes, max {MAX_WORKLOG_BYTES}")
        _require_sources(front)
    else:  # NOTE, JOURNAL
        _cap(size <= MAX_NOTE_BYTES, f"note is {size} bytes, max {MAX_NOTE_BYTES}: shorten")
        if kind is NoteKind.NOTE:
            _cap(words <= MAX_NOTE_WORDS, f"note has {words} words, max {MAX_NOTE_WORDS}")
        else:
            bullets = sum(1 for ln in body.split("\n") if _BULLET_RE.match(ln))
            _cap(
                bullets <= MAX_JOURNAL_BULLETS,
                f"journal has {bullets} bullets, max {MAX_JOURNAL_BULLETS}",
            )
        _require_sources(front)
    return words


def _require_sources(front: list[str] | None) -> None:
    """Every note names where it came from (notes are data with a recorded source)."""
    if front is None:
        raise KbRefusedError("frontmatter missing: start with --- and list tags, updated, sources")
    sources = parse_sources(front)
    if not sources:
        raise KbRefusedError("frontmatter needs a non-empty `sources:` (e.g. dashboard:<id>@rev3)")
    if any(len(s) > MAX_SOURCE_LEN for s in sources):
        raise KbRefusedError(f"a source entry is longer than {MAX_SOURCE_LEN} chars")


def _cap(ok: bool, reason: str) -> None:
    if not ok:
        raise KbRefusedError(reason)
