"""Knowledge map: builds the graph of the knowledge base and looks up one note (C57, I4).

The only parsing done on note text is a **bounded stdlib parser** that extracts
`[[links]]` and the frontmatter `tags` / `updated` keys (I4 amendment): no YAML
or Markdown library, no HTML. Bodies are returned as plain text for the browser
to render as untrusted. Notes are addressed by opaque ids: an HMAC of the
relative path under a per-process key, so an id names one note of the current
walk and is never a path (a forged id simply matches nothing).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from itertools import pairwise

from preview_dashboard.domain.errors import NotFoundError, ValidationError
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.kb_source import KbSource, KbWalk, RawNote

NOTE_ID_RE = re.compile(r"[0-9a-f]{32}")
RECENT_DAYS = 7
# Parser caps (I4): frontmatter is only looked for at the very top and is small.
MAX_FRONTMATTER_LINES = 40
MAX_FRONTMATTER_CHARS = 4096
MAX_TAGS = 20
MAX_LINKS_PER_NOTE = 200
MAX_TAG_GROUP = 200
MAX_EDGES = 20_000
_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_/-]{0,39}")
_CATEGORY_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
# `[[target]]`, `[[target#heading]]`, `[[target|shown text]]`; one line, bounded lengths.
_LINK_RE = re.compile(r"\[\[([^\[\]\n|#]{1,120})(?:#[^\[\]\n|]{0,120})?(?:\|[^\[\]\n]{0,120})?\]\]")
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_KEY_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]{0,31}):(.*)")
_CORE = "core"
_OTHER = "other"


@dataclass(frozen=True, slots=True)
class ParsedNote:
    """What the bounded parser takes from one note."""

    tags: tuple[str, ...]
    updated: date | None
    links: tuple[str, ...]  # raw link targets, in order, deduplicated
    body: str  # the text without its frontmatter block


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One note on the map. `updated` is the frontmatter date, else the file's mtime date."""

    id: str
    title: str
    category: str
    tags: tuple[str, ...]
    updated: date
    recent: bool
    degree: int


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """An undirected connection: a `[[link]]` (kind `link`) or a shared tag (kind `tag`)."""

    source: str
    target: str
    kind: str


@dataclass(frozen=True, slots=True)
class KbGraph:
    """The whole map of one walk."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    categories: tuple[tuple[str, int], ...]  # (name, note count), by name
    skipped: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class NoteLink:
    """A `[[link]]` in a note body: its raw target text and the note it resolves to (or None)."""

    target: str
    id: str | None


@dataclass(frozen=True, slots=True)
class NoteDetail:
    """One note for the side panel; `body` is untrusted plain text."""

    node: GraphNode
    body: str
    links: tuple[NoteLink, ...]
    backlinks: tuple[tuple[str, str], ...]  # (id, title) of notes linking here, by title


def _strip_value(raw: str) -> str:
    return raw.strip().strip("\"'").strip()


def _tags_from(values: list[str]) -> tuple[str, ...]:
    found: list[str] = []
    for value in values:
        tag = _strip_value(value).lstrip("#")
        if _TAG_RE.fullmatch(tag) and tag.casefold() not in {t.casefold() for t in found}:
            found.append(tag)
        if len(found) >= MAX_TAGS:
            break
    return tuple(found)


def _parse_date(raw: str) -> date | None:
    match = _DATE_RE.match(_strip_value(raw))
    if match is None:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def _split_frontmatter(text: str) -> tuple[list[str], str]:
    """(frontmatter lines, body). No frontmatter, or an unclosed/oversized one → ([], text)."""
    if not (text.startswith("---\n") or text.startswith("---\r\n")):
        return [], text
    head = text[: MAX_FRONTMATTER_CHARS + 8]
    lines = head.split("\n")
    for index in range(1, min(len(lines), MAX_FRONTMATTER_LINES + 2)):
        if lines[index].rstrip("\r") == "---":
            consumed = sum(len(line) + 1 for line in lines[: index + 1])
            return [line.rstrip("\r") for line in lines[1:index]], text[consumed:]
    return [], text


def _frontmatter_fields(lines: list[str]) -> tuple[tuple[str, ...], date | None]:
    """Only `tags` (inline list, comma list or `- item` block) and `updated`."""
    tags: tuple[str, ...] = ()
    updated: date | None = None
    index = 0
    while index < len(lines):
        match = _KEY_RE.fullmatch(lines[index])
        index += 1
        if match is None:
            continue
        key, value = match.group(1).casefold(), match.group(2).strip()
        if key == "updated":
            updated = _parse_date(value)
        elif key == "tags":
            if value.startswith("[") and value.endswith("]"):
                tags = _tags_from(value[1:-1].split(","))
            elif value:
                tags = _tags_from(value.split(","))
            else:
                items: list[str] = []
                while index < len(lines) and lines[index].lstrip().startswith("- "):
                    items.append(lines[index].lstrip()[2:])
                    index += 1
                tags = _tags_from(items)
    return tags, updated


def parse_note(text: str) -> ParsedNote:
    """Run the bounded parser on one note (I4): tags, updated, `[[link]]` targets, body."""
    lines, body = _split_frontmatter(text)
    tags, updated = _frontmatter_fields(lines)
    links: list[str] = []
    seen: set[str] = set()
    for match in _LINK_RE.finditer(body):
        target = match.group(1).strip()
        key = target.casefold()
        if target and key not in seen:
            seen.add(key)
            links.append(target)
            if len(links) >= MAX_LINKS_PER_NOTE:
                break
    return ParsedNote(tags=tags, updated=updated, links=tuple(links), body=body)


def category_of(relpath: str) -> str:
    """`topics/<cat>/…` → `<cat>`; top-level files → `core`; `journal/…` → `journal`."""
    parts = relpath.split("/")
    if len(parts) == 1:
        return _CORE
    name = parts[1] if parts[0] == "topics" and len(parts) >= 3 else parts[0]
    name = name.casefold()
    return name if _CATEGORY_RE.fullmatch(name) else _OTHER


def title_of(relpath: str, category: str) -> str:
    """A readable title from the file name (the parser reads nothing else of the body)."""
    stem = relpath.rsplit("/", 1)[-1].removesuffix(".md")
    if stem == "_topic":
        return f"{category.replace('-', ' ').capitalize()} overview"
    words = stem.replace("_", " ").replace("-", " ").strip() or stem
    return words[:1].upper() + words[1:]


def _link_keys(relpath: str) -> list[str]:
    """Every name a `[[link]]` may use for this note: each path suffix, without `.md`."""
    parts = relpath.removesuffix(".md").casefold().split("/")
    return ["/".join(parts[i:]) for i in range(len(parts))]


@dataclass(frozen=True, slots=True)
class _Indexed:
    note: RawNote
    id: str
    parsed: ParsedNote
    category: str
    title: str


class KbGraphService:
    """Knowledge-map use cases over a `KbSource` (fresh walk per call).

    Args:
        source: the read-only KB walker.
        clock: "now", for the recent-note glow.
        key: HMAC key for note ids; default a fresh random key per process.
    """

    def __init__(self, source: KbSource, clock: Clock, *, key: bytes | None = None) -> None:
        self._source = source
        self._clock = clock
        self._key = key if key is not None else secrets.token_bytes(32)

    def note_id(self, relpath: str) -> str:
        """The opaque id of `relpath` (stable for this process, meaningless outside it)."""
        return hmac.new(self._key, relpath.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def graph(self) -> KbGraph:
        """Walk the KB and build the whole map.

        Raises:
            StorageUnavailableError: the KB root is missing or unsafe (map off).
        """
        walk = self._source.walk()
        indexed = self._index(walk)
        resolved = self._resolver(indexed)
        edges = self._edges(indexed, resolved)
        degree: dict[str, int] = defaultdict(int)
        for edge in edges:
            degree[edge.source] += 1
            degree[edge.target] += 1
        nodes = tuple(self._node(entry, degree[entry.id]) for entry in indexed)
        counts: dict[str, int] = defaultdict(int)
        for entry in indexed:
            counts[entry.category] += 1
        return KbGraph(
            nodes=nodes,
            edges=tuple(edges),
            categories=tuple(sorted(counts.items())),
            skipped=walk.skipped,
            truncated=walk.truncated,
        )

    def note(self, note_id: str) -> NoteDetail:
        """One note by the id the map gave it, looked up in a fresh walk.

        Raises:
            ValidationError: `note_id` is not an id's shape.
            NotFoundError: no note of the current walk has this id.
            StorageUnavailableError: the KB root is missing or unsafe (map off).
        """
        if NOTE_ID_RE.fullmatch(note_id) is None:
            raise ValidationError("invalid note id")
        indexed = self._index(self._source.walk())
        by_id = {entry.id: entry for entry in indexed}
        entry = by_id.get(note_id)
        if entry is None:
            raise NotFoundError("no such note")
        resolved = self._resolver(indexed)
        edges = self._edges(indexed, resolved)
        degree = sum(1 for edge in edges if note_id in (edge.source, edge.target))
        links = tuple(
            NoteLink(target=target, id=resolved(target, entry)) for target in entry.parsed.links
        )
        backlinks = sorted(
            (
                (other.id, other.title)
                for other in indexed
                if other.id != note_id
                and any(resolved(target, other) == note_id for target in other.parsed.links)
            ),
            key=lambda pair: (pair[1].casefold(), pair[0]),
        )
        return NoteDetail(
            node=self._node(entry, degree),
            body=entry.parsed.body,
            links=links,
            backlinks=tuple(backlinks),
        )

    def _index(self, walk: KbWalk) -> list[_Indexed]:
        indexed = []
        for note in walk.notes:
            category = category_of(note.relpath)
            indexed.append(
                _Indexed(
                    note=note,
                    id=self.note_id(note.relpath),
                    parsed=parse_note(note.text),
                    category=category,
                    title=title_of(note.relpath, category),
                )
            )
        return indexed

    @staticmethod
    def _resolver(indexed: list[_Indexed]) -> _Resolve:
        keys: dict[str, list[_Indexed]] = defaultdict(list)
        for entry in indexed:
            for key in _link_keys(entry.note.relpath):
                keys[key].append(entry)
        return _Resolve(keys)

    @staticmethod
    def _edges(indexed: list[_Indexed], resolve: _Resolve) -> list[GraphEdge]:
        pairs: dict[tuple[str, str], str] = {}
        for entry in indexed:
            for target in entry.parsed.links:
                other = resolve(target, entry)
                if other is not None and other != entry.id:
                    pairs.setdefault((min(entry.id, other), max(entry.id, other)), "link")
        # Shared tags: chain each tag's notes (by title), so a tag adds n-1 edges, not n².
        groups: dict[str, list[_Indexed]] = defaultdict(list)
        for entry in indexed:
            for tag in entry.parsed.tags:
                groups[tag.casefold()].append(entry)
        for tag in sorted(groups):
            members = sorted(groups[tag], key=lambda e: (e.title.casefold(), e.id))[:MAX_TAG_GROUP]
            for left, right in pairwise(members):
                pairs.setdefault((min(left.id, right.id), max(left.id, right.id)), "tag")
        edges = [GraphEdge(source=a, target=b, kind=kind) for (a, b), kind in pairs.items()]
        return edges[:MAX_EDGES]

    def _node(self, entry: _Indexed, degree: int) -> GraphNode:
        updated = entry.parsed.updated or entry.note.modified.date()
        today = self._clock.now().date()
        recent = timedelta(0) <= today - updated <= timedelta(days=RECENT_DAYS)
        return GraphNode(
            id=entry.id,
            title=entry.title,
            category=entry.category,
            tags=entry.parsed.tags,
            updated=updated,
            recent=recent,
            degree=degree,
        )


class _Resolve:
    """Resolves a `[[target]]` the Obsidian way: by note name or any path suffix.

    An ambiguous name prefers a note in the linking note's own directory; otherwise it
    stays unresolved rather than guessing.
    """

    def __init__(self, keys: dict[str, list[_Indexed]]) -> None:
        self._keys = keys

    def __call__(self, target: str, origin: _Indexed) -> str | None:
        key = target.strip().casefold().removesuffix(".md").strip("/")
        candidates = self._keys.get(key, [])
        if len(candidates) == 1:
            return candidates[0].id
        folder = origin.note.relpath.rpartition("/")[0]
        local = [c for c in candidates if c.note.relpath.rpartition("/")[0] == folder]
        return local[0].id if len(local) == 1 else None


def iso_date(value: date | datetime) -> str:
    """`YYYY-MM-DD` for JSON."""
    return value.isoformat()[:10]
