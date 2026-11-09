"""Unit tests for the `progress` kind and its schema v1 validator (ADR 0029).

Kind: selected only by an explicit hint, exactly one `progress.json`.
Schema: every limit, unknown keys, bad states, bar/phase references, text
cleaning, the strict (stored) form and the advertised JSON Schema.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from preview_dashboard.domain.errors import UnsupportedContentError, ValidationError
from preview_dashboard.kinds import default_registry
from preview_dashboard.kinds.progress import (
    MAX_BARS,
    MAX_LANES,
    MAX_PHASES,
    MAX_PROGRESS_BYTES,
    MAX_UNITS,
    ProgressKind,
    decode_progress,
    encode_progress,
    format_updated_at,
    normalize_progress,
    parse_progress,
    progress_json_schema,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 30, 9, 15, 7, 123456, tzinfo=UTC)
STAMP = "2026-09-30T09:15:07Z"


def _status(**overrides: Any) -> dict[str, Any]:
    status: dict[str, Any] = {
        "title": "Progress tool",
        "note": "P2 starts once the schema lands.",
        "phases": ["Build", "Review", "Merge"],
        "units": [
            {"id": "P1", "name": "kind + tools", "who": "dev", "state": "running", "detail": "x"},
            {"id": "P2", "name": "renderer", "state": "waiting"},
        ],
        "timeline": [
            {"lane": "developer", "model": "Opus", "bars": [{"unit": "P1", "from": 0, "to": 1}]},
            {"lane": "frontend", "bars": [{"unit": "P2", "from": 0, "to": 3, "label": "P2"}]},
        ],
    }
    status.update(overrides)
    return status


def _norm(status: object) -> dict[str, Any]:
    return dict(normalize_progress(status, updated_at=NOW))


def _rejects(status: object, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        normalize_progress(status, updated_at=NOW)


# --- kind -------------------------------------------------------------------------


def test_kind_is_registered_and_never_auto_detected() -> None:
    registry = default_registry()
    assert registry.get("progress").name == "progress"
    assert registry.detect(["progress.json"]).name == "json"
    assert registry.detect(["progress.json"], hint="progress").name == "progress"
    assert registry.media_type_for("progress.json") == "application/json"


@pytest.mark.parametrize(
    "relpaths",
    [[], ["other.json"], ["progress.json", "x.json"], ["sub/progress.json"], ["PROGRESS.JSON"]],
)
def test_hint_refused_for_anything_but_one_progress_json(relpaths: list[str]) -> None:
    with pytest.raises(UnsupportedContentError):
        default_registry().detect(relpaths, hint="progress")
    with pytest.raises(UnsupportedContentError):
        ProgressKind().entry_file(relpaths)


def test_kind_media_type_and_entry_file() -> None:
    kind = ProgressKind()
    assert kind.media_type("progress.json") == "application/json"
    assert kind.media_type("x.html") == "application/octet-stream"
    assert kind.entry_file(["progress.json"]) == "progress.json"
    assert kind.extensions == frozenset()


# --- happy path -------------------------------------------------------------------


def test_normalize_fills_defaults_and_stamps() -> None:
    doc = _norm({"title": "T"})
    assert doc == {
        "version": 1,
        "title": "T",
        "note": "",
        "updated_at": STAMP,
        "phases": [],
        "units": [],
        "timeline": [],
    }


def test_normalize_full_status_keeps_order_and_fills_optional_keys() -> None:
    doc = _norm(_status())
    assert list(doc) == ["version", "title", "note", "updated_at", "phases", "units", "timeline"]
    assert doc["units"][1] == {
        "id": "P2",
        "name": "renderer",
        "who": "",
        "state": "waiting",
        "detail": "",
    }
    assert doc["timeline"][0]["bars"][0] == {"unit": "P1", "from": 0, "to": 1, "label": ""}
    assert doc["timeline"][1]["model"] == ""


def test_caller_updated_at_is_replaced_and_version_1_accepted() -> None:
    doc = _norm(_status(updated_at="1999-01-01T00:00:00Z", version=1))
    assert doc["updated_at"] == STAMP


def test_updated_at_is_utc_whole_seconds() -> None:
    other = NOW.astimezone(timezone(timedelta(hours=2)))
    assert format_updated_at(other) == STAMP
    with pytest.raises(ValidationError):
        format_updated_at(datetime(2026, 1, 1))


def test_round_trip_encode_decode_is_strict_and_stable() -> None:
    doc = normalize_progress(_status(), updated_at=NOW)
    data = encode_progress(doc)
    assert decode_progress(data) == doc
    assert json.loads(data) == doc
    assert encode_progress(decode_progress(data)) == data


def test_strings_are_cleaned_to_single_line_text() -> None:
    doc = _norm(_status(title="  A\u202eB\u200b\nC\t ", note="x\r\ny"))
    assert doc["title"] == "AB C"
    assert doc["note"] == "x y"
    assert _norm(_status(note="   "))["note"] == ""


def test_markup_is_kept_as_plain_text() -> None:
    doc = _norm(_status(title="<b>*x*</b>"))
    assert doc["title"] == "<b>*x*</b>"  # no meaning: the renderer uses textContent


# --- limits -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "limit"),
    [
        (("title",), 120),
        (("note",), 500),
        (("units", 0, "name"), 120),
        (("units", 0, "who"), 80),
        (("units", 0, "detail"), 600),
        (("phases", 0), 40),
        (("timeline", 0, "lane"), 60),
        (("timeline", 0, "model"), 40),
        (("timeline", 0, "bars", 0, "label"), 60),
    ],
)
def test_every_text_limit(path: tuple[str | int, ...], limit: int) -> None:
    for length, ok in ((limit, True), (limit + 1, False)):
        status = _status()
        target: Any = status
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = "x" * length
        if ok:
            _norm(status)
        else:
            _rejects(status, f"must be 1..{limit}")


def _unit(i: int) -> dict[str, str]:
    return {"id": f"u{i}", "name": f"unit {i}", "state": "done"}


@pytest.mark.parametrize(
    ("key", "make", "limit"),
    [
        ("units", _unit, MAX_UNITS),
        ("phases", lambda i: f"p{i}", MAX_PHASES),
        ("timeline", lambda i: {"lane": f"l{i}"}, MAX_LANES),
    ],
)
def test_every_list_limit(key: str, make: Any, limit: int) -> None:
    base = {"title": "T"}
    _norm({**base, key: [make(i) for i in range(limit)]})
    _rejects({**base, key: [make(i) for i in range(limit + 1)]}, f"<= {limit} entries")


def test_bar_limit() -> None:
    bar = {"unit": "P1", "from": 0, "to": 1}
    status = _status()
    status["timeline"][0]["bars"] = [dict(bar) for _ in range(MAX_BARS)]
    _norm(status)
    status["timeline"][0]["bars"].append(dict(bar))
    _rejects(status, f"<= {MAX_BARS} entries")


def test_encoded_size_limit() -> None:
    # 40 units x (120 + 80 + 600) chars of 4-byte emoji-free CJK text > 64 KiB.
    wide = "漢"  # 3 bytes in UTF-8
    units = [
        {"id": f"u{i}", "name": wide * 120, "who": wide * 80, "state": "done", "detail": wide * 600}
        for i in range(MAX_UNITS)
    ]
    doc = normalize_progress({"title": "T", "units": units}, updated_at=NOW)
    with pytest.raises(ValidationError, match=str(MAX_PROGRESS_BYTES)):
        encode_progress(doc)
    with pytest.raises(ValidationError, match=str(MAX_PROGRESS_BYTES)):
        decode_progress(b" " * (MAX_PROGRESS_BYTES + 1))


# --- shape errors -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "match"),
    [
        ([], "status must be an object"),
        ({"note": "no title"}, "missing title"),
        ({"title": ""}, "title must be 1..120"),
        ({"title": "\u200b"}, "title must be 1..120"),
        ({"title": 5}, "title must be a string"),
        ({"title": "T", "extra": 1}, "unknown key 'extra'"),
        ({"title": "T", "version": 2}, "version must be 1"),
        ({"title": "T", "version": True}, "version must be 1"),
        ({"title": "T", "updated_at": 5}, "updated_at must be a string"),
        ({"title": "T", "phases": "a"}, "phases must be a list"),
        ({"title": "T", "phases": [""]}, r"phases\[0\] must be 1..40"),
        ({"title": "T", "units": [{"id": "a", "name": "n"}]}, r"units\[0\] is missing state"),
        ({"title": "T", "units": [{**_unit(0), "x": 1}]}, r"units\[0\] has unknown key 'x'"),
        ({"title": "T", "units": [_unit(0), _unit(0)]}, "must be unique"),
        ({"title": "T", "timeline": [{"lane": "l", "bars": {}}]}, "bars must be a list"),
        ({"title": "T", "timeline": [{"model": "m"}]}, "missing lane"),
    ],
)
def test_shape_errors(status: object, match: str) -> None:
    _rejects(status, match)


@pytest.mark.parametrize("state", ["Done", "finished", "", None, 1, "running "])
def test_bad_states(state: object) -> None:
    _rejects({"title": "T", "units": [{"id": "a", "name": "n", "state": state}]}, "state must be")


@pytest.mark.parametrize("uid", ["", "x" * 13, "a b", "a_b", "é", "a\n", 7, None])
def test_bad_unit_ids(uid: object) -> None:
    _rejects({"title": "T", "units": [{"id": uid, "name": "n", "state": "done"}]}, "id must match")


@pytest.mark.parametrize(
    ("bar", "match"),
    [
        ({"unit": "nope", "from": 0, "to": 1}, "must be the id of an entry"),
        ({"unit": "p1", "from": 0, "to": 1}, "must be the id of an entry"),  # exact match
        ({"unit": "P1", "from": 1, "to": 1}, "0 <= from < to <= 3"),
        ({"unit": "P1", "from": 2, "to": 1}, "0 <= from < to <= 3"),
        ({"unit": "P1", "from": -1, "to": 1}, "0 <= from < to <= 3"),
        ({"unit": "P1", "from": 0, "to": 4}, "0 <= from < to <= 3"),
        ({"unit": "P1", "from": False, "to": 1}, "must be integers"),
        ({"unit": "P1", "from": 0, "to": 1.0}, "must be integers"),
        ({"unit": "P1", "from": 0}, "missing to"),
        ({"unit": "P1", "from": 0, "to": 1, "color": "red"}, "unknown key 'color'"),
    ],
)
def test_bar_refs_and_ranges(bar: dict[str, Any], match: str) -> None:
    status = _status()
    status["timeline"][0]["bars"] = [bar]
    _rejects(status, match)


def test_bars_need_phases() -> None:
    status = _status(phases=[])
    _rejects(status, "0 <= from < to <= 0")


def test_unknown_key_echo_is_bounded() -> None:
    with pytest.raises(ValidationError) as info:
        normalize_progress({"title": "T", "k" * 5000: 1}, updated_at=NOW)
    assert len(str(info.value)) < 200


# --- strict (stored) form -----------------------------------------------------------


def test_parse_requires_every_key_and_a_valid_stamp() -> None:
    doc = dict(normalize_progress(_status(), updated_at=NOW))
    assert parse_progress(doc) == doc
    for key in doc:
        partial = {k: v for k, v in doc.items() if k != key}
        with pytest.raises(ValidationError, match="missing"):
            parse_progress(partial)
    unit_missing: Any = json.loads(json.dumps(doc))
    del unit_missing["units"][1]["who"]
    with pytest.raises(ValidationError, match="missing who"):
        parse_progress(unit_missing)
    for stamp in ("2026-09-30T09:15:07", "2026-13-01T00:00:00Z", "2026-09-30 09:15:07Z", 5):
        with pytest.raises(ValidationError, match="updated_at"):
            parse_progress({**doc, "updated_at": stamp})


@pytest.mark.parametrize("data", [b"\xff\xfe", b"{", b"[]", b'{"title":"T"}'])
def test_decode_rejects_non_documents(data: bytes) -> None:
    with pytest.raises(ValidationError):
        decode_progress(data)


# --- advertised JSON Schema ---------------------------------------------------------


def test_json_schema_is_closed_and_matches_limits() -> None:
    schema = progress_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["title"]
    props: Any = schema["properties"]
    assert props["title"]["maxLength"] == 120
    assert props["units"]["maxItems"] == MAX_UNITS
    unit = props["units"]["items"]
    assert unit["additionalProperties"] is False
    assert unit["properties"]["state"]["enum"] == ["done", "running", "waiting", "blocked"]
    bar = props["timeline"]["items"]["properties"]["bars"]["items"]
    assert bar["additionalProperties"] is False
    assert "updated_at" not in props  # set by the tool, never by the caller
    json.dumps(schema)  # plain JSON
