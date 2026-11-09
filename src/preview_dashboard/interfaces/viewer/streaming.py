"""Streaming responses for item bytes: blob files (with ranges) and ZIP archives.

Both close their source deterministically when the response ends, fails or
the client disconnects. Any failure after the headers went out is
**raised**, never swallowed: the server then drops the connection without
a clean end-of-body, so a truncated or tampered file can't look complete
(docs/security.md C9; unit 4 obligation).
"""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator, Generator, Mapping
from typing import BinaryIO

import anyio.to_thread
from starlette.responses import StreamingResponse
from starlette.types import Receive, Scope, Send

CHUNK_SIZE = 64 * 1024


class StoredBytesMismatchError(Exception):
    """A blob's bytes don't match its manifest (size or SHA-256) while streaming."""


class BlobStreamResponse(StreamingResponse):
    """Stream `length` bytes of an open blob starting at `start`, then close it.

    For a full-file response (`expected_sha256` given) the exact size (one
    extra-byte read) and SHA-256 are verified before the final chunk is
    yielded, so a mismatch aborts the connection with fewer bytes on the
    wire than `Content-Length` — the client can never see a complete body.
    The first chunk is read before the headers are sent, so an empty or
    single-chunk file that fails verification becomes a plain 500. Range
    responses are only checked for a short blob, not hashed.
    """

    def __init__(
        self,
        stream: BinaryIO,
        *,
        start: int,
        length: int,
        status_code: int,
        headers: Mapping[str, str],
        expected_sha256: str | None = None,
    ) -> None:
        self._stream = stream
        self._body = self._chunks(start, length, expected_sha256)
        super().__init__(self._body, status_code=status_code, headers=headers)

    async def _chunks(
        self, start: int, length: int, expected_sha256: str | None
    ) -> AsyncIterator[bytes]:
        digest = hashlib.sha256()
        await anyio.to_thread.run_sync(self._stream.seek, start)
        remaining = length
        if expected_sha256 is not None and remaining == 0:
            await self._verify_end(digest.hexdigest(), expected_sha256)
        while remaining > 0:
            chunk = await anyio.to_thread.run_sync(self._stream.read, min(CHUNK_SIZE, remaining))
            if not chunk:
                raise StoredBytesMismatchError("blob shorter than its manifest")
            remaining -= len(chunk)
            if expected_sha256 is not None:
                digest.update(chunk)
                if remaining == 0:
                    # Verify *before* the last bytes go out: once the client has
                    # all Content-Length bytes, a later abort can't undo a
                    # "complete" (but tampered) download.
                    await self._verify_end(digest.hexdigest(), expected_sha256)
            yield chunk

    async def _verify_end(self, actual_sha256: str, expected_sha256: str) -> None:
        """Raise unless the blob ends here and its digest matches the manifest."""
        extra = await anyio.to_thread.run_sync(self._stream.read, 1)
        if extra or actual_sha256 != expected_sha256:
            raise StoredBytesMismatchError("blob does not match its manifest")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await self._prime()
            await super().__call__(scope, receive, send)
        finally:
            self._stream.close()

    async def _prime(self) -> None:
        """Read the first chunk before the headers go out.

        An empty or single-chunk file is then fully verified while an error
        can still become a clean 500: once a 200 with `Content-Length: 0`
        (or the whole one-chunk body) is sent, nothing can be taken back.
        """
        chunks = self._body
        try:
            first = await anext(chunks)
        except StopAsyncIteration:
            self.body_iterator = _no_chunks()
            return
        self.body_iterator = _prepend(first, chunks)


class ZipStreamResponse(StreamingResponse):
    """Stream a ZIP generator (`ArchiveService.stream_zip`), closing it at the end.

    Each `next()` runs in a worker thread (blob reads + DEFLATE). Errors
    from the generator propagate, aborting the connection mid-body.
    """

    def __init__(
        self, archive: Generator[bytes, None, None], *, headers: Mapping[str, str]
    ) -> None:
        self._archive = archive
        super().__init__(self._chunks(), status_code=200, headers=headers)

    async def _chunks(self) -> AsyncIterator[bytes]:
        while True:
            chunk = await anyio.to_thread.run_sync(_next_or_none, self._archive)
            if chunk is None:
                return
            if chunk:
                yield chunk

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            self._archive.close()  # closes any blob the archive still holds open


async def _prepend(first: bytes, rest: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    yield first
    async for chunk in rest:
        yield chunk


async def _no_chunks() -> AsyncIterator[bytes]:
    return
    yield  # an async generator that yields nothing


def _next_or_none(gen: Generator[bytes, None, None]) -> bytes | None:
    """`next(gen)`, with exhaustion as None (StopIteration can't cross threads)."""
    try:
        return next(gen)
    except StopIteration:
        return None
