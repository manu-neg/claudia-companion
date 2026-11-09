"""Progress content kind: a live work tracker, one `progress.json` (ADR 0029).

`ProgressKind` claims exactly one file named `progress.json` but only with
the lowest confidence, so it is selected by an explicit `kind="progress"`
hint only (plain `.json` files stay `json`). The strict schema v1 validator
lives here too, as pure stdlib code: the MCP progress tools run it before
anything is written; the admin server never parses content (I4).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Final, TypedDict

from preview_dashboard.domain.errors import UnsupportedContentError, ValidationError
from preview_dashboard.domain.text import sanitize_line
from preview_dashboard.kinds.base import PreviewMode

PROGRESS_FILE: Final = "progress.json"
PROGRESS_MEDIA_TYPE: Final = "application/json"
SCHEMA_VERSION: Final = 1
MAX_PROGRESS_BYTES: Final = 64 * 1024

TITLE_MAX: Final = 120
NOTE_MAX: Final = 500
MAX_UNITS: Final = 40
UNIT_NAME_MAX: Final = 120
UNIT_WHO_MAX: Final = 80
UNIT_DETAIL_MAX: Final = 600
MAX_PHASES: Final = 12
PHASE_MAX: Final = 40
MAX_LANES: Final = 16
LANE_MAX: Final = 60
MODEL_MAX: Final = 40
MAX_BARS: Final = 12
BAR_LABEL_MAX: Final = 60
STATES: Final = ("done", "running", "waiting", "blocked")

UNIT_ID_PATTERN: Final = r"^[A-Za-z0-9-]{1,12}$"
_UNIT_ID_RE: Final = re.compile(r"[A-Za-z0-9-]{1,12}")
_UPDATED_AT_FORMAT: Final = "%Y-%m-%dT%H:%M:%SZ"
_UPDATED_AT_RE: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
# Unknown-key messages echo at most this much of one caller-supplied key.
_KEY_ECHO_MAX: Final = 40


class ProgressUnit(TypedDict):
    """One unit of work (schema v1)."""

    id: str
    name: str
    who: str
    state: str
    detail: str


# Functional syntax: `from` is a Python keyword.
ProgressBar = TypedDict("ProgressBar", {"unit": str, "from": int, "to": int, "label": str})


class ProgressLane(TypedDict):
    """One timeline row: who runs which unit in which phase columns."""

    lane: str
    model: str
    bars: list[ProgressBar]


class ProgressDoc(TypedDict):
    """A complete, validated `progress.json` document (schema v1, ADR 0029)."""

    version: int
    title: str
    note: str
    updated_at: str
    phases: list[str]
    units: list[ProgressUnit]
    timeline: list[ProgressLane]


class ProgressKind:
    """Live work tracker: exactly one `progress.json`, never auto-detected."""

    name = "progress"
    label = "Progress"
    renderer = "progress"
    preview_mode = PreviewMode.TEXT
    # No extensions: `.json` stays owned by `json` in media_type_for/detection.
    extensions: frozenset[str] = frozenset()
    render_capped = True

    def media_type(self, relpath: str) -> str:
        return PROGRESS_MEDIA_TYPE if relpath == PROGRESS_FILE else "application/octet-stream"

    def detect(self, relpaths: Sequence[str]) -> int:
        # 1 = lowest positive confidence: `json` (100) always wins autodetection,
        # so only an explicit hint picks this kind (ADR 0029).
        return 1 if list(relpaths) == [PROGRESS_FILE] else 0

    def entry_file(self, relpaths: Sequence[str]) -> str:
        """Return `progress.json`.

        Raises:
            UnsupportedContentError: the item is not exactly `progress.json`.
        """
        if list(relpaths) != [PROGRESS_FILE]:
            raise UnsupportedContentError(f"a progress item is exactly one {PROGRESS_FILE}")
        return PROGRESS_FILE


# --- schema v1 ------------------------------------------------------------------


def format_updated_at(at: datetime) -> str:
    """Return `at` as the schema's `updated_at` string (UTC, whole seconds).

    Raises:
        ValidationError: `at` is naive.
    """
    if at.tzinfo is None or at.utcoffset() is None:
        raise ValidationError("updated_at must be timezone-aware")
    return at.astimezone(UTC).strftime(_UPDATED_AT_FORMAT)


def normalize_progress(raw: object, *, updated_at: datetime) -> ProgressDoc:
    """Validate a caller-supplied status and return the canonical document.

    Optional keys may be omitted (defaults: "" / []); `version`, if given,
    must be 1; a given `updated_at` is replaced by `updated_at`. Strings are
    cleaned to single-line display text (`domain.text.sanitize_line`).

    Raises:
        ValidationError: any schema violation (message names the field).
    """
    return _parse(raw, strict=False, updated_at=format_updated_at(updated_at))


def parse_progress(raw: object) -> ProgressDoc:
    """Validate an already-canonical document (every key present, `updated_at` included).

    Raises:
        ValidationError: any schema violation.
    """
    return _parse(raw, strict=True, updated_at=None)


def encode_progress(doc: ProgressDoc) -> bytes:
    """Serialize a validated document as the canonical `progress.json` bytes.

    Raises:
        ValidationError: the encoding exceeds `MAX_PROGRESS_BYTES`.
    """
    data = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_PROGRESS_BYTES:
        raise ValidationError(f"progress.json must be <= {MAX_PROGRESS_BYTES} bytes")
    return data


def decode_progress(data: bytes) -> ProgressDoc:
    """Parse and strictly validate `progress.json` bytes.

    Raises:
        ValidationError: too large, not UTF-8 JSON, or not schema v1.
    """
    if len(data) > MAX_PROGRESS_BYTES:
        raise ValidationError(f"progress.json must be <= {MAX_PROGRESS_BYTES} bytes")
    try:
        value: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValidationError("progress.json is not UTF-8 JSON") from None
    return parse_progress(value)


def _parse(raw: object, *, strict: bool, updated_at: str | None) -> ProgressDoc:
    top = _object(
        raw,
        "status",
        required=("title",),
        optional=("version", "note", "updated_at", "phases", "units", "timeline"),
        strict=strict,
    )
    version = top.get("version", SCHEMA_VERSION)
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValidationError(f"status.version must be {SCHEMA_VERSION}")
    if strict or updated_at is None:
        stamp = _updated_at(top.get("updated_at"))
    else:
        # Caller input: the tool owns the stamp, a given one is only type-checked.
        if not isinstance(top.get("updated_at", ""), str):
            raise ValidationError("status.updated_at must be a string")
        stamp = updated_at
    phases = [
        clean_text(p, f"phases[{i}]", PHASE_MAX, required=True)
        for i, p in enumerate(_array(top.get("phases", []), "phases", MAX_PHASES))
    ]
    units = [
        _unit(u, f"units[{i}]", strict=strict)
        for i, u in enumerate(_array(top.get("units", []), "units", MAX_UNITS))
    ]
    ids = [u["id"] for u in units]
    if len(set(ids)) != len(ids):
        raise ValidationError("units[].id must be unique")
    timeline = [
        _lane(lane, f"timeline[{i}]", strict=strict, unit_ids=frozenset(ids), phases=len(phases))
        for i, lane in enumerate(_array(top.get("timeline", []), "timeline", MAX_LANES))
    ]
    return {
        "version": SCHEMA_VERSION,
        "title": clean_text(top["title"], "title", TITLE_MAX, required=True),
        "note": clean_text(top.get("note", ""), "note", NOTE_MAX, required=False),
        "updated_at": stamp,
        "phases": phases,
        "units": units,
        "timeline": timeline,
    }


def _unit(raw: object, where: str, *, strict: bool) -> ProgressUnit:
    obj = _object(
        raw,
        where,
        required=("id", "name", "state"),
        optional=("who", "detail"),
        strict=strict,
    )
    return {
        "id": unit_id(obj["id"], f"{where}.id"),
        "name": clean_text(obj["name"], f"{where}.name", UNIT_NAME_MAX, required=True),
        "who": clean_text(obj.get("who", ""), f"{where}.who", UNIT_WHO_MAX, required=False),
        "state": unit_state(obj["state"], f"{where}.state"),
        "detail": clean_text(
            obj.get("detail", ""), f"{where}.detail", UNIT_DETAIL_MAX, required=False
        ),
    }


def _lane(
    raw: object, where: str, *, strict: bool, unit_ids: frozenset[str], phases: int
) -> ProgressLane:
    obj = _object(raw, where, required=("lane",), optional=("model", "bars"), strict=strict)
    bars = [
        _bar(b, f"{where}.bars[{i}]", strict=strict, unit_ids=unit_ids, phases=phases)
        for i, b in enumerate(_array(obj.get("bars", []), f"{where}.bars", MAX_BARS))
    ]
    return {
        "lane": clean_text(obj["lane"], f"{where}.lane", LANE_MAX, required=True),
        "model": clean_text(obj.get("model", ""), f"{where}.model", MODEL_MAX, required=False),
        "bars": bars,
    }


def _bar(
    raw: object, where: str, *, strict: bool, unit_ids: frozenset[str], phases: int
) -> ProgressBar:
    obj = _object(raw, where, required=("unit", "from", "to"), optional=("label",), strict=strict)
    ref = obj["unit"]
    if not isinstance(ref, str) or ref not in unit_ids:
        raise ValidationError(f"{where}.unit must be the id of an entry in units")
    start, end = obj["from"], obj["to"]
    # bool is an int subclass; true/false are not phase indexes.
    if type(start) is not int or type(end) is not int:
        raise ValidationError(f"{where}.from/to must be integers")
    if not 0 <= start < end <= phases:
        raise ValidationError(f"{where} needs 0 <= from < to <= {phases} (the number of phases)")
    return {
        "unit": ref,
        "from": start,
        "to": end,
        "label": clean_text(obj.get("label", ""), f"{where}.label", BAR_LABEL_MAX, required=False),
    }


def unit_id(raw: object, where: str = "unit_id") -> str:
    """Validate a unit id (`[A-Za-z0-9-]{1,12}`).

    Raises:
        ValidationError: not a string of that shape.
    """
    if not isinstance(raw, str) or _UNIT_ID_RE.fullmatch(raw) is None:
        raise ValidationError(f"{where} must match {UNIT_ID_PATTERN}")
    return raw


def unit_state(raw: object, where: str = "state") -> str:
    """Validate a unit state (one of `STATES`).

    Raises:
        ValidationError: not one of `STATES`.
    """
    if not isinstance(raw, str) or raw not in STATES:
        raise ValidationError(f"{where} must be one of {', '.join(STATES)}")
    return raw


def clean_text(raw: object, where: str, max_chars: int, *, required: bool) -> str:
    """Clean one schema string field (single line, invisible chars removed).

    An optional field may be "" (or whitespace only, stored as "").

    Raises:
        ValidationError: not a string, too long, or (required) empty.
    """
    if not isinstance(raw, str):
        raise ValidationError(f"{where} must be a string")
    if not required and not raw.strip():
        return ""
    return sanitize_line(raw, name=where, max_chars=max_chars)


def _updated_at(raw: object) -> str:
    if not isinstance(raw, str) or _UPDATED_AT_RE.fullmatch(raw) is None:
        raise ValidationError("status.updated_at must be UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(raw, _UPDATED_AT_FORMAT)  # format check only; 'Z' is literal UTC
    except ValueError:
        raise ValidationError("status.updated_at is not a valid date/time") from None
    return raw


def _array(raw: object, where: str, max_len: int) -> list[object]:
    if not isinstance(raw, list):
        raise ValidationError(f"{where} must be a list")
    if len(raw) > max_len:
        raise ValidationError(f"{where} must have <= {max_len} entries")
    return raw


def _object(
    raw: object,
    where: str,
    *,
    required: tuple[str, ...],
    optional: tuple[str, ...],
    strict: bool,
) -> Mapping[str, object]:
    if not isinstance(raw, dict):
        raise ValidationError(f"{where} must be an object")
    unknown = sorted(str(k) for k in raw if k not in required and k not in optional)
    if unknown:
        shown = unknown[0][:_KEY_ECHO_MAX]
        allowed = ", ".join(required + optional)
        raise ValidationError(f"{where} has unknown key {shown!r} (allowed: {allowed})")
    # Canonical documents carry every key; caller input may omit optional ones.
    needed = required + optional if strict else required
    missing = [k for k in needed if k not in raw]
    if missing:
        raise ValidationError(f"{where} is missing {', '.join(missing)}")
    return raw


# --- JSON Schema (advertised to MCP clients) -------------------------------------


def _string(max_chars: int, *, min_chars: int = 0) -> dict[str, object]:
    return {"type": "string", "minLength": min_chars, "maxLength": max_chars}


def progress_json_schema() -> dict[str, object]:
    """JSON Schema of the caller-supplied status (input form of schema v1).

    Advertised on `dashboard_progress_set` so the caller sees the shape;
    `normalize_progress` stays the authority (cross-field rules like bar
    refs and phase ranges are not expressible here).
    """
    bar = {
        "type": "object",
        "additionalProperties": False,
        "required": ["unit", "from", "to"],
        "properties": {
            "unit": {"type": "string", "description": "id of a unit in units"},
            "from": {"type": "integer", "minimum": 0, "description": "first phase index"},
            "to": {"type": "integer", "minimum": 1, "description": "end phase index (exclusive)"},
            "label": _string(BAR_LABEL_MAX),
        },
    }
    lane = {
        "type": "object",
        "additionalProperties": False,
        "required": ["lane"],
        "properties": {
            "lane": _string(LANE_MAX, min_chars=1),
            "model": _string(MODEL_MAX),
            "bars": {"type": "array", "maxItems": MAX_BARS, "items": bar},
        },
    }
    unit = {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "name", "state"],
        "properties": {
            "id": {"type": "string", "pattern": UNIT_ID_PATTERN},
            "name": _string(UNIT_NAME_MAX, min_chars=1),
            "who": _string(UNIT_WHO_MAX),
            "state": {"type": "string", "enum": list(STATES)},
            "detail": _string(UNIT_DETAIL_MAX),
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["title"],
        "properties": {
            "version": {"type": "integer", "enum": [SCHEMA_VERSION]},
            "title": _string(TITLE_MAX, min_chars=1),
            "note": _string(NOTE_MAX),
            "phases": {
                "type": "array",
                "maxItems": MAX_PHASES,
                "items": _string(PHASE_MAX, min_chars=1),
            },
            "units": {"type": "array", "maxItems": MAX_UNITS, "items": unit},
            "timeline": {"type": "array", "maxItems": MAX_LANES, "items": lane},
        },
    }
