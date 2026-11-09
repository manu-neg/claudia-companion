"""Unit tests for `KindRegistry`: registration, detect(), media_type_for(), describe()."""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from preview_dashboard.domain.errors import UnsupportedContentError, ValidationError
from preview_dashboard.domain.models import ItemFile
from preview_dashboard.kinds import PreviewMode, default_registry
from preview_dashboard.kinds.base import KindRegistry
from tests.builders import make_file

pytestmark = pytest.mark.unit


class _StubKind:
    """Minimal ContentKind double for registry-only tests."""

    def __init__(self, name: str, confidence: int = 0) -> None:
        self.name = name
        self.label = name.title()
        self.renderer = name
        self.preview_mode = PreviewMode.DOWNLOAD
        self.extensions: frozenset[str] = frozenset()
        self.render_capped = False
        self._confidence = confidence

    def media_type(self, relpath: str) -> str:
        return "application/octet-stream"

    def detect(self, relpaths: Sequence[str]) -> int:
        return self._confidence

    def entry_file(self, relpaths: Sequence[str]) -> str:
        return relpaths[0]


# --- register() ----------------------------------------------------------------


def test_register_rejects_duplicate_name() -> None:
    registry = KindRegistry()
    registry.register(_StubKind("dup"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_StubKind("dup"))


def test_register_rejects_invalid_name_syntax() -> None:
    registry = KindRegistry()
    with pytest.raises(ValidationError):
        registry.register(_StubKind("Not_Valid!"))


def test_all_returns_stable_registration_order() -> None:
    registry = KindRegistry()
    kinds = [_StubKind("c"), _StubKind("a"), _StubKind("b")]
    for kind in kinds:
        registry.register(kind)
    assert [k.name for k in registry.all()] == ["c", "a", "b"]


# --- get() -----------------------------------------------------------------------


def test_get_unknown_kind_raises_unsupported_content_error() -> None:
    registry = default_registry()
    with pytest.raises(UnsupportedContentError):
        registry.get("nope")


def test_get_known_kind_returns_it() -> None:
    registry = default_registry()
    assert registry.get("image").name == "image"


# --- detect() ----------------------------------------------------------------------


def test_detect_picks_highest_confidence() -> None:
    registry = default_registry()
    kind = registry.detect(["photo.png"])
    assert kind.name == "image"


def test_detect_falls_back_to_file_for_unknown_extension() -> None:
    registry = default_registry()
    kind = registry.detect(["thing.zzz-unknown"])
    assert kind.name == "file"


def test_detect_mixed_bundle_falls_back_to_file() -> None:
    registry = default_registry()
    # One image, one code file: neither kind claims a mixed bundle, so it
    # falls through to the opaque fallback (docs/architecture.md).
    kind = registry.detect(["a.png", "b.py"])
    assert kind.name == "file"


def test_detect_empty_relpaths_raises() -> None:
    registry = default_registry()
    with pytest.raises(UnsupportedContentError):
        registry.detect([])


def test_detect_ties_break_by_registration_order() -> None:
    registry = KindRegistry()
    registry.register(_StubKind("first", confidence=50))
    registry.register(_StubKind("second", confidence=50))
    assert registry.detect(["x"]).name == "first"


def test_detect_hint_compatible_returns_requested_kind() -> None:
    registry = default_registry()
    kind = registry.detect(["a.txt"], hint="text")
    assert kind.name == "text"


def test_detect_hint_incompatible_raises() -> None:
    registry = default_registry()
    with pytest.raises(UnsupportedContentError):
        registry.detect(["a.txt"], hint="image")


def test_detect_hint_unknown_kind_raises() -> None:
    registry = default_registry()
    with pytest.raises(UnsupportedContentError):
        registry.detect(["a.txt"], hint="not-a-kind")


def test_detect_hint_overrides_would_be_default_autodetection() -> None:
    # A mixed bundle would default to `file`; an explicit, compatible hint
    # is honored instead of autodetection when it's a match.
    registry = default_registry()
    kind = registry.detect(["index.html", "notes.txt"], hint="html")
    assert kind.name == "html"


# --- media_type_for() --------------------------------------------------------------


def test_media_type_for_known_extension() -> None:
    registry = default_registry()
    assert registry.media_type_for("a/b/photo.png") == "image/png"


def test_media_type_for_unknown_extension_is_octet_stream() -> None:
    registry = default_registry()
    assert registry.media_type_for("thing.zzz-unknown") == "application/octet-stream"


def test_media_type_for_no_extension_is_octet_stream() -> None:
    registry = default_registry()
    assert registry.media_type_for("README") == "application/octet-stream"


# --- describe() ----------------------------------------------------------------------


def test_describe_shape_and_content() -> None:
    registry = default_registry()
    described = registry.describe()
    assert len(described) == len(registry.all())
    names = [d["name"] for d in described]
    assert names == [k.name for k in registry.all()]
    image = next(d for d in described if d["name"] == "image")
    assert image == {
        "name": "image",
        "label": "Image",
        "renderer": "image",
        "preview_mode": "media",
        "extensions": [".avif", ".gif", ".jpeg", ".jpg", ".png", ".webp"],
        "render_capped": False,
    }


def test_describe_render_capped_matches_every_kind() -> None:
    registry = default_registry()
    by_name = {d["name"]: d["render_capped"] for d in registry.describe()}
    assert by_name == {k.name: k.render_capped for k in registry.all()}
    # Every TEXT kind is capped server-side; nothing else is.
    for kind in registry.all():
        assert kind.render_capped is (kind.preview_mode is PreviewMode.TEXT)


def test_describe_entries_are_plain_json_safe_dicts() -> None:
    import json

    registry = default_registry()
    # Must round-trip through json.dumps with no custom encoder.
    json.dumps(registry.describe())


# --- every emitted media type satisfies ItemFile's validation --------------------


def test_every_registry_media_type_satisfies_item_file_validation() -> None:
    registry = default_registry()
    for kind in registry.all():
        for ext in sorted(kind.extensions) or [""]:
            relpath = f"sample{ext}" if ext else "sample.bin"
            media_type = registry.media_type_for(relpath) if ext else kind.media_type(relpath)
            # Would raise ValidationError if the media type didn't match
            # ItemFile's 'type/subtype' regex (docs/security.md C8).
            make_file(relpath="x", media_type=media_type)
    # And the global unknown-extension fallback:
    assert isinstance(make_file(relpath="x", media_type="application/octet-stream"), ItemFile)
