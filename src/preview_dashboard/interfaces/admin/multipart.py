"""Streaming multipart intake for `POST /v1/items` and `POST /v1/items/{id}/revisions`.

The body is parsed incrementally (python-multipart's push parser) and each
file part's bytes are handed to `PublishService.publish` (or
`publish_revision`), running in a worker thread, through a small bounded
channel: no file is ever buffered whole in memory or spooled to a temp
file. Form fields (publish: title, description, kind_hint, pinned,
folder_id, manifest; revision: kind_hint, expected_revision, manifest) must precede
the file parts, because the service needs every relpath before the first
byte (kind detection, count).

Limits (C18/C26): Content-Type, part count, field sizes, header sizes,
total body bytes counted on the stream (never trusting Content-Length),
a per-read stall timeout and a total deadline (slowloris, C11).
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from dataclasses import dataclass
from typing import Any, Final

import anyio
import anyio.from_thread
import anyio.to_thread
from anyio.abc import TaskGroup
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from python_multipart.exceptions import FormParserError
from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.requests import ClientDisconnect, Request

from preview_dashboard.application import IncomingFile, PublishCommand, RevisionCommand
from preview_dashboard.config import Settings
from preview_dashboard.domain.errors import LimitExceededError, ValidationError
from preview_dashboard.domain.models import Item
from preview_dashboard.domain.paths import MAX_PATH_BYTES
from preview_dashboard.interfaces.admin.errors import (
    ClientDisconnectedError,
    RequestTimeoutError,
    UnsupportedMediaTypeError,
)

_KIB: Final = 1024
MAX_FIELD_BYTES: Final = 16 * _KIB
MAX_PART_HEADER_BYTES: Final = 4 * _KIB
MAX_PART_HEADERS: Final = 4
READ_TIMEOUT_SECONDS: Final = 30.0
FIELD_NAMES: Final = frozenset(
    {"title", "description", "kind_hint", "pinned", "folder_id", "manifest"}
)
REVISION_FIELD_NAMES: Final = frozenset({"kind_hint", "expected_revision", "manifest"})
FILE_FIELD: Final = "file"
# Bounded channel between the event loop and the publish thread: at most
# this many body chunks (each <= one ASGI receive, ~64 KiB) are in memory.
_CHANNEL_CHUNKS: Final = 8
_MAX_BOUNDARY_CHARS: Final = 70  # RFC 2046
# JSON escapes can triple a relpath's UTF-8 size (e.g. \\ud83d\\ude00 for 4 bytes).
_MANIFEST_BYTES_PER_PATH: Final = 3 * MAX_PATH_BYTES + 4
_PINNED_VALUES: Final = {"true": True, "1": True, "false": False, "0": False, "": False}
# ASCII digits only (str.isdigit() also accepts "²"); 10 digits cover 2**31-1.
_REVISION_RE: Final = re.compile(r"[1-9][0-9]{0,9}")


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishFormLimits:
    """Bounds on one publish request (derived from `Settings` by `for_settings`)."""

    max_files: int
    max_parts: int
    max_field_bytes: int
    max_manifest_bytes: int
    max_body_bytes: int
    read_timeout: float
    total_timeout: float

    @classmethod
    def for_settings(cls, settings: Settings) -> PublishFormLimits:
        """Derive the limits: parts = files + fields, body = item bytes + overhead."""
        max_parts = settings.max_files + len(FIELD_NAMES)
        max_manifest = settings.max_files * _MANIFEST_BYTES_PER_PATH + 2
        # Part headers + boundaries per part, plus every field at its cap.
        # Every field but the manifest may use MAX_FIELD_BYTES.
        fields = (len(FIELD_NAMES) - 1) * MAX_FIELD_BYTES
        overhead = max_parts * (MAX_PART_HEADER_BYTES + 256) + fields + max_manifest
        return cls(
            max_files=settings.max_files,
            max_parts=max_parts,
            max_field_bytes=MAX_FIELD_BYTES,
            max_manifest_bytes=max_manifest,
            max_body_bytes=settings.max_item_bytes + overhead,
            read_timeout=READ_TIMEOUT_SECONDS,
            total_timeout=float(settings.publish_timeout_seconds),
        )


# --- parser events ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _PartStart:
    name: str
    filename: str | None


@dataclass(frozen=True, slots=True)
class _PartData:
    data: bytes


@dataclass(frozen=True, slots=True)
class _PartEnd:
    pass


@dataclass(frozen=True, slots=True)
class _BodyEnd:
    pass


_Event = _PartStart | _PartData | _PartEnd | _BodyEnd


def _utf8(raw: bytes, what: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError(f"{what} is not valid UTF-8") from None


class _EventCollector:
    """python-multipart callbacks → a list of events, drained after each write."""

    def __init__(self) -> None:
        self.events: list[_Event] = []
        self._field = bytearray()
        self._value = bytearray()
        self._headers: dict[bytes, bytes] = {}

    def drain(self) -> list[_Event]:
        events, self.events = self.events, []
        return events

    def on_part_begin(self) -> None:
        self._headers = {}

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._field += data[start:end]

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._value += data[start:end]

    def on_header_end(self) -> None:
        name = bytes(self._field).strip().lower()
        if name in self._headers:
            raise ValidationError("duplicate header in a form part")
        self._headers[name] = bytes(self._value).strip()
        self._field.clear()
        self._value.clear()

    def on_headers_finished(self) -> None:
        if b"content-transfer-encoding" in self._headers:
            # We never decode transfer encodings; bytes are stored exactly as sent.
            raise ValidationError("Content-Transfer-Encoding is not supported")
        disposition, params = parse_options_header(self._headers.get(b"content-disposition"))
        if disposition != b"form-data" or b"name" not in params:
            raise ValidationError("every form part needs Content-Disposition: form-data; name=")
        name = _utf8(params[b"name"], "form part name")
        raw_filename = params.get(b"filename")
        filename = None if raw_filename is None else _utf8(raw_filename, "file name")
        self.events.append(_PartStart(name=name, filename=filename))

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        if end > start:
            self.events.append(_PartData(bytes(data[start:end])))

    def on_part_end(self) -> None:
        self.events.append(_PartEnd())

    def on_end(self) -> None:
        self.events.append(_BodyEnd())


def _boundary(content_type: str | None) -> bytes:
    """Return the multipart boundary, or raise 415 for any other content type."""
    ctype, params = parse_options_header(content_type)
    boundary = params.get(b"boundary", b"")
    if ctype != b"multipart/form-data" or not 0 < len(boundary) <= _MAX_BOUNDARY_CHARS:
        raise UnsupportedMediaTypeError("expected multipart/form-data with a boundary")
    return boundary


# --- thread bridge -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Chunk:
    """Message to the publish thread: bytes of file `index`, or its end (data=None)."""

    index: int
    data: bytes | None


class _UploadAbortedError(ValidationError):
    """The upload ended before a file was complete (the real cause is reported instead)."""


class _FileChunks:
    """Iterable of one file's chunks, pulled by the publish thread from the channel."""

    def __init__(self, receive: MemoryObjectReceiveStream[_Chunk], index: int) -> None:
        self._receive = receive
        self._index = index

    def __iter__(self) -> Iterator[bytes]:
        while True:
            try:
                msg = anyio.from_thread.run(self._receive.receive)
            except (anyio.EndOfStream, anyio.ClosedResourceError):
                raise _UploadAbortedError("upload ended early") from None
            # Any other file's bytes mean the consumer and the upload disagree
            # on where we are (e.g. a file not read to its end): abort rather
            # than silently skip bytes and store something else than was sent.
            if msg.index != self._index:
                raise _UploadAbortedError("upload out of order")
            if msg.data is None:
                return
            yield msg.data


# --- form specs ------------------------------------------------------------------------

FieldText = Callable[[str], str | None]
"""Returns a form field's UTF-8 text, or None if the field was not sent."""


@dataclass(frozen=True, slots=True)
class FormSpec[C]:
    """Which fields a streamed form accepts and how they become a service command.

    Attributes:
        fields: allowed (non-file) field names; anything else is a 400.
        build: turns the fields and the manifest's `IncomingFile`s into the
            command handed to the service (raises `ValidationError`).
    """

    fields: frozenset[str]
    build: Callable[[FieldText, list[IncomingFile]], C]


def _publish_command(text: FieldText, files: list[IncomingFile]) -> PublishCommand:
    title = text("title")
    if title is None:
        raise ValidationError("the title field is required")
    pinned_raw = (text("pinned") or "").strip().lower()
    if pinned_raw not in _PINNED_VALUES:
        raise ValidationError("pinned must be true or false")
    return PublishCommand(
        title=title,
        description=text("description") or "",
        kind_hint=text("kind_hint") or None,
        pinned=_PINNED_VALUES[pinned_raw],
        files=files,
        # Validated (ULID, must exist) by the service before any byte moves.
        folder_id=text("folder_id") or None,
    )


def _revision_builder(item_id: str) -> Callable[[FieldText, list[IncomingFile]], RevisionCommand]:
    def build(text: FieldText, files: list[IncomingFile]) -> RevisionCommand:
        raw = text("expected_revision") or ""
        if raw and _REVISION_RE.fullmatch(raw) is None:
            raise ValidationError("expected_revision must be a positive integer")
        return RevisionCommand(
            item_id=item_id,
            files=files,
            kind_hint=text("kind_hint") or None,
            expected_revision=int(raw) if raw else None,
        )

    return build


PUBLISH_FORM: Final = FormSpec(fields=FIELD_NAMES, build=_publish_command)


def revision_form(item_id: str) -> FormSpec[RevisionCommand]:
    """The form of `POST /v1/items/{item_id}/revisions` (fields: see `REVISION_FIELD_NAMES`)."""
    return FormSpec(fields=REVISION_FIELD_NAMES, build=_revision_builder(item_id))


# --- the request pump ------------------------------------------------------------------


class _PublishUpload[C]:
    """State machine for one streamed form: fields → manifest → file parts."""

    def __init__(
        self,
        limits: PublishFormLimits,
        send: MemoryObjectSendStream[_Chunk],
        receive: MemoryObjectReceiveStream[_Chunk],
        start_publish: Callable[[C], None],
        spec: FormSpec[C],
    ) -> None:
        self._spec = spec
        self._limits = limits
        self._send = send
        self._receive = receive
        self._start_publish = start_publish
        self._fields: dict[str, bytearray] = {}
        self._manifest: list[str] | None = None
        self._current: _PartStart | None = None
        self._parts = 0
        self._files_done = 0
        self._pending_last_end: _Chunk | None = None
        self._ended = False

    async def handle(self, event: _Event) -> None:
        """Apply one parser event (may send bytes to the publish thread)."""
        if isinstance(event, _PartStart):
            self._begin_part(event)
        elif isinstance(event, _PartData):
            await self._part_data(event.data)
        elif isinstance(event, _PartEnd):
            await self._end_part()
        else:
            self._ended = True

    def _begin_part(self, part: _PartStart) -> None:
        self._parts += 1
        if self._parts > self._limits.max_parts:
            raise LimitExceededError(f"too many form parts (max {self._limits.max_parts})")
        if part.filename is None:
            if self._manifest is not None:
                raise ValidationError("form fields must come before file parts")
            if part.name not in self._spec.fields:
                raise ValidationError("unknown form field")
            if part.name in self._fields:
                raise ValidationError("duplicate form field")
            self._fields[part.name] = bytearray()
        else:
            if part.name != FILE_FIELD:
                raise ValidationError(f"file parts must be named {FILE_FIELD!r}")
            if self._manifest is None:
                self._manifest = self._parse_manifest()
                self._start_publish(self._command(self._manifest))
            index = self._files_done
            if index >= len(self._manifest) or part.filename != self._manifest[index]:
                raise ValidationError(
                    f"file part {index + 1} does not match manifest entry {index + 1}"
                )
        self._current = part

    async def _part_data(self, data: bytes) -> None:
        part = self._current
        if part is None:  # pragma: no cover - the parser never emits data outside a part
            raise ValidationError("malformed multipart body")
        if part.filename is not None:
            await self._send.send(_Chunk(self._files_done, data))
            return
        buffer = self._fields[part.name]
        cap = (
            self._limits.max_manifest_bytes
            if part.name == "manifest"
            else self._limits.max_field_bytes
        )
        if len(buffer) + len(data) > cap:
            raise LimitExceededError(f"form field is over {cap} bytes")
        buffer += data

    async def _end_part(self) -> None:
        part, self._current = self._current, None
        if part is None or part.filename is None:
            return
        end = _Chunk(self._files_done, None)
        self._files_done += 1
        if self._manifest is not None and self._files_done == len(self._manifest):
            # Hold the last end marker until the body is fully, validly parsed:
            # the publish can't commit before the request is known to be whole.
            self._pending_last_end = end
        else:
            await self._send.send(end)

    async def finish(self) -> None:
        """After the body is parsed: check completeness, release the last file."""
        if not self._ended:
            raise ValidationError("multipart body is incomplete")
        if self._manifest is None:
            raise ValidationError("at least one file part is required")
        if self._files_done != len(self._manifest) or self._pending_last_end is None:
            raise ValidationError("file parts do not match the manifest")
        await self._send.send(self._pending_last_end)

    def _text(self, name: str) -> str | None:
        raw = self._fields.get(name)
        return None if raw is None else _utf8(bytes(raw), f"field {name!r}")

    def _parse_manifest(self) -> list[str]:
        raw = self._text("manifest")
        if raw is None:
            raise ValidationError("the manifest field is required before file parts")
        try:
            manifest = json.loads(raw)
        except (ValueError, RecursionError):  # RecursionError: absurdly deep nesting
            raise ValidationError("manifest must be a JSON array of relpaths") from None
        if not isinstance(manifest, list) or not all(isinstance(p, str) for p in manifest):
            raise ValidationError("manifest must be a JSON array of relpaths")
        if not manifest:
            raise ValidationError("manifest must list at least one file")
        if len(manifest) > self._limits.max_files:
            raise LimitExceededError(f"too many files (max {self._limits.max_files})")
        return manifest

    def _command(self, manifest: list[str]) -> C:
        files = [
            IncomingFile(relpath=relpath, chunks=_FileChunks(self._receive, index))
            for index, relpath in enumerate(manifest)
        ]
        return self._spec.build(self._text, files)


async def _timed_chunks(request: Request, limits: PublishFormLimits) -> AsyncIterator[bytes]:
    """Yield body chunks; stall or total-deadline overrun → `RequestTimeoutError`."""
    deadline = time.monotonic() + limits.total_timeout
    stream = request.stream().__aiter__()
    while True:
        budget = min(limits.read_timeout, deadline - time.monotonic())
        try:
            with anyio.fail_after(max(budget, 0.0)):
                chunk = await stream.__anext__()
        except StopAsyncIteration:
            return
        except TimeoutError:
            raise RequestTimeoutError("request body stalled or took too long") from None
        yield chunk


async def publish_multipart(
    request: Request,
    *,
    limits: PublishFormLimits,
    publish: Callable[[PublishCommand], Item],
) -> Item:
    """Stream a multipart publish request into `publish`; see `stream_form`."""
    return await stream_form(request, limits=limits, spec=PUBLISH_FORM, run=publish)


async def stream_form[C](
    request: Request,
    *,
    limits: PublishFormLimits,
    spec: FormSpec[C],
    run: Callable[[C], Item],
) -> Item:
    """Stream a manifest-first multipart request into `run` (in a worker thread).

    Returns:
        The committed item.

    Raises:
        UnsupportedMediaTypeError: not `multipart/form-data` with a boundary.
        LimitExceededError: body, part count, field or manifest size limit.
        RequestTimeoutError: the body stalled or exceeded the total deadline.
        ClientDisconnectedError: the client went away mid-upload.
        ValidationError: malformed body, unknown/duplicate/misordered parts,
            bad manifest, or file parts not matching the manifest.
        Any error `run` raises (its own validation, limits, secret scan).
    """
    boundary = _boundary(request.headers.get("content-type"))
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limits.max_body_bytes:
        raise LimitExceededError("request body too large")  # fast path; real count below
    send, receive = anyio.create_memory_object_stream[_Chunk](max_buffer_size=_CHANNEL_CHUNKS)
    results: list[Item] = []
    thread_errors: list[Exception] = []

    async def run_publish(cmd: C) -> None:
        try:
            results.append(await anyio.to_thread.run_sync(run, cmd))
        except Exception as exc:
            thread_errors.append(exc)
        finally:
            # Unblocks the pump: further sends raise BrokenResourceError.
            receive.close()

    upload_error: Exception | None = None
    async with anyio.create_task_group() as group:
        upload = _PublishUpload(limits, send, receive, _starter(group, run_publish), spec)
        try:
            await _pump(request, limits, boundary, upload)
        except anyio.BrokenResourceError:
            pass  # the publish already finished (failed); its error is reported
        except ClientDisconnect:
            # Expected event, not a bug: one quiet log line, no traceback.
            upload_error = ClientDisconnectedError("client disconnected mid-upload; rolled back")
        except Exception as exc:  # parse and limit errors
            upload_error = exc
        finally:
            # Without the last end marker the publish thread aborts and rolls back.
            send.close()
    if upload_error is not None:
        raise upload_error from None
    if thread_errors:
        raise thread_errors[0]
    if not results:  # pragma: no cover - finish() guarantees a started publish
        raise ValidationError("nothing was published")
    return results[0]


def _starter[C](
    group: TaskGroup, run: Callable[[C], Coroutine[Any, Any, None]]
) -> Callable[[C], None]:
    def start(cmd: C) -> None:
        group.start_soon(run, cmd)

    return start


async def _pump[C](
    request: Request, limits: PublishFormLimits, boundary: bytes, upload: _PublishUpload[C]
) -> None:
    collector = _EventCollector()
    parser = MultipartParser(
        boundary,
        callbacks={
            "on_part_begin": collector.on_part_begin,
            "on_part_data": collector.on_part_data,
            "on_part_end": collector.on_part_end,
            "on_header_field": collector.on_header_field,
            "on_header_value": collector.on_header_value,
            "on_header_end": collector.on_header_end,
            "on_headers_finished": collector.on_headers_finished,
            "on_end": collector.on_end,
        },
        max_size=math.inf,  # counted below on the raw stream instead
        max_header_count=MAX_PART_HEADERS,
        max_header_size=MAX_PART_HEADER_BYTES,
    )
    received = 0
    async for chunk in _timed_chunks(request, limits):
        received += len(chunk)
        if received > limits.max_body_bytes:
            raise LimitExceededError("request body too large")
        _write(parser, chunk)
        for event in collector.drain():
            await upload.handle(event)
    try:
        parser.finalize()
    except FormParserError:
        raise ValidationError("malformed multipart body") from None
    for event in collector.drain():
        await upload.handle(event)
    await upload.finish()


def _write(parser: MultipartParser, chunk: bytes) -> None:
    try:
        parser.write(chunk)
    except FormParserError:
        raise ValidationError("malformed multipart body") from None
