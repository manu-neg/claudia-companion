"""Content-kind registry: the Registry + Strategy pattern for preview kinds.

`ContentKind` is the strategy interface; each concrete kind (image, html,
video, ...) is a small stateless class in its own module. `KindRegistry`
is the registry: it holds the registered kinds, decides which one a set of
file paths belongs to, and is the frontend's single source of truth via
`describe()` (served as `GET /api/kinds`). `default_registry()` is the only
place that lists every built-in kind — adding a kind means adding one file
plus one line there (see docs/extending.md).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Protocol

from preview_dashboard.domain.errors import UnsupportedContentError
from preview_dashboard.domain.models import validate_kind


class PreviewMode(StrEnum):
    """How the viewer renders an item of a given kind.

    - SANDBOXED: HTML, rendered in a sandboxed iframe from the preview origin.
    - MEDIA: an img/video/audio element pointing at the preview origin.
    - DOCUMENT: opened natively from the preview origin (PDF); no sandbox,
      but a strict CSP, because Chrome refuses to render PDFs under a
      `sandbox` CSP (docs/security.md C5).
    - TEXT: fetched as text and rendered client-side by a renderer
      (markdown/code/json/csv/text/diff); truncated at the render cap.
    - DOWNLOAD: no preview, download only.
    """

    SANDBOXED = "sandboxed"
    MEDIA = "media"
    DOCUMENT = "document"
    TEXT = "text"
    DOWNLOAD = "download"


class ContentKind(Protocol):
    """A strategy for one content kind: identification, typing and preview.

    Attributes:
        name: registry key; matches `domain.models.validate_kind`'s syntax.
        label: human-readable name for the UI.
        renderer: id of the frontend renderer module that draws this kind.
        preview_mode: how the viewer previews items of this kind.
        extensions: lowercase file extensions (with leading dot) this kind
            claims, e.g. `{".png", ".jpg"}`. Empty for a kind that never
            claims an extension (only the `file` fallback does this).
        render_capped: whether TEXT previews of this kind are truncated at
            the render cap (true for every TEXT kind).
    """

    name: str
    label: str
    renderer: str
    preview_mode: PreviewMode
    extensions: frozenset[str]
    render_capped: bool

    def media_type(self, relpath: str) -> str:
        """Return the `type/subtype` Content-Type for a file of this kind.

        Lowercase, no parameters — must satisfy `ItemFile`'s media-type
        validation (docs/security.md C8: type comes from the registry only).
        """
        ...

    def detect(self, relpaths: Sequence[str]) -> int:
        """Return this kind's confidence (0..100) that it owns these files.

        0 means "not mine". Confidence is used to pick a kind for content
        that wasn't given an explicit kind hint at publish time.
        """
        ...

    def entry_file(self, relpaths: Sequence[str]) -> str:
        """Return which of `relpaths` the viewer should open/preview first.

        For an HTML bundle (kind `html`, more than one file) this must be
        a root `index.html`. For a single-file item it is that file.
        """
        ...


def extension_of(relpath: str) -> str:
    """Return the lowercase extension (with dot) of a relpath's final segment.

    Matching is case-insensitive and looks only at the last `/`-separated
    segment, so `a/x.HTML.png` is `.png`. A dotfile with no further dot
    (`.env`) and a segment with no dot at all both have no extension ("").
    """
    name = relpath.rsplit("/", 1)[-1]
    dot = name.rfind(".")
    if dot <= 0:  # no dot, or the only dot is a leading dotfile marker
        return ""
    return name[dot:].lower()


class SimpleExtensionKind:
    """Base for kinds identified purely by file extension (every kind but
    `html`, which needs an `index.html` bundle rule, and `file`, the
    always-matches fallback).

    Confidence is all-or-nothing: 100 if *every* file's extension is in
    `extensions`, else 0. That keeps a mixed-type bundle (e.g. one image
    plus one text file) from being claimed by either kind by chance — it
    falls through to `file` instead (docs/architecture.md, "Content kinds").

    Subclasses set the `ContentKind` attributes and `_media_types`; a
    subclass with no per-extension variance may instead set
    `_default_media_type` (e.g. `kinds/code.py`, which serves every
    extension as `text/plain` so nothing it holds is ever executable).
    """

    name: str
    label: str
    renderer: str
    preview_mode: PreviewMode
    extensions: frozenset[str]
    render_capped: bool = False
    _media_types: Mapping[str, str] = {}
    _default_media_type: str = "application/octet-stream"

    def media_type(self, relpath: str) -> str:
        return self._media_types.get(extension_of(relpath), self._default_media_type)

    def detect(self, relpaths: Sequence[str]) -> int:
        if not relpaths:
            return 0
        return 100 if all(extension_of(r) in self.extensions for r in relpaths) else 0

    def entry_file(self, relpaths: Sequence[str]) -> str:
        # Previewing more than one file of the same kind (e.g. an image
        # gallery) is not built yet; the lexicographically-first file keeps
        # this deterministic until it is (docs/extending.md).
        return min(relpaths)


class KindRegistry:
    """Holds every registered `ContentKind` and answers lookups against them."""

    def __init__(self) -> None:
        self._by_name: dict[str, ContentKind] = {}
        self._order: list[ContentKind] = []

    def register(self, kind: ContentKind) -> None:
        """Add `kind` to the registry.

        Raises:
            ValidationError: `kind.name` doesn't match the domain kind syntax.
            ValueError: a kind with this name is already registered.
        """
        validate_kind(kind.name)
        if kind.name in self._by_name:
            raise ValueError(f"kind {kind.name!r} is already registered")
        self._by_name[kind.name] = kind
        self._order.append(kind)

    def get(self, name: str) -> ContentKind:
        """Return the registered kind named `name`.

        Raises:
            UnsupportedContentError: no kind with this name is registered.
        """
        try:
            return self._by_name[name]
        except KeyError:
            raise UnsupportedContentError(f"unknown content kind {name!r}") from None

    def all(self) -> tuple[ContentKind, ...]:
        """Return every registered kind, in registration order (stable)."""
        return tuple(self._order)

    def detect(self, relpaths: Sequence[str], hint: str | None = None) -> ContentKind:
        """Pick the kind for a set of bundle-relative file paths.

        Args:
            relpaths: the item's file paths (at least one).
            hint: an explicit kind name requested by the publisher. It must
                be compatible (its own `detect()` > 0) or the whole call
                fails, rather than silently falling back to autodetection.

        Returns:
            The requested kind if `hint` is given and compatible; otherwise
            the kind with the highest `detect()` confidence, ties broken by
            registration order (first registered wins).

        Raises:
            UnsupportedContentError: `hint` is unknown or incompatible, or
                (with no hint) no registered kind claims these files. The
                `file` kind, if registered, always claims non-empty input,
                so this only happens with an empty `relpaths` or a registry
                missing the fallback.
        """
        if hint is not None:
            kind = self.get(hint)
            if kind.detect(relpaths) <= 0:
                raise UnsupportedContentError(f"content does not match requested kind {hint!r}")
            return kind
        best: ContentKind | None = None
        best_confidence = 0
        for kind in self._order:
            confidence = kind.detect(relpaths)
            if confidence > best_confidence:
                best_confidence = confidence
                best = kind
        if best is None:
            raise UnsupportedContentError("content does not match any registered kind")
        return best

    def media_type_for(self, relpath: str) -> str:
        """Return the Content-Type for `relpath` from the global extension map.

        Only for top-level hints/detection where no item kind is known yet;
        **never** use it to assign `ItemFile.media_type` — that is always
        the item's own kind's `media_type(relpath)`, applied to every file
        (`application/publish.py`; docs/security.md C8). Like every type
        decision here it never depends on client-supplied type information
        or on content sniffing. Unknown extensions get
        `application/octet-stream`.
        """
        ext = extension_of(relpath)
        for kind in self._order:
            if ext in kind.extensions:
                return kind.media_type(relpath)
        return "application/octet-stream"

    def describe(self) -> tuple[dict[str, object], ...]:
        """Return plain-dict descriptions of every kind, for `GET /api/kinds`.

        This is the frontend's single source of truth for which kinds exist,
        their labels, renderers, preview modes, extensions and whether TEXT
        previews are cut at the server-side render cap (`render_capped`).
        """
        return tuple(
            {
                "name": kind.name,
                "label": kind.label,
                "renderer": kind.renderer,
                "preview_mode": str(kind.preview_mode),
                "extensions": sorted(kind.extensions),
                "render_capped": bool(kind.render_capped),
            }
            for kind in self._order
        )
