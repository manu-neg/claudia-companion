"""HTTP client for the admin API over its Unix socket (MCP server and root CLI commands).

`AdminClient` sends the admin bearer token (read once from the private token
file, C12) on every request, streams publish uploads as manifest-first
multipart (ADR 0014) straight from intake file descriptors without buffering
whole files, organises folders (ADR 0027), asks/reads/cancels questions and
sends alerts (ADR 0021; it can never answer: that route needs the notifier
token, C34), and maps admin
error bodies to typed `AdminClientError`s carrying only caller-safe text. It
never logs or echoes the token or file contents.
"""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Collection, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Final, Protocol, Self

import httpx

from preview_dashboard.config import Settings
from preview_dashboard.domain.folders import UNFILED
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.interfaces.mcp.errors import safe_display
from preview_dashboard.interfaces.token_file import load_admin_token

logger = logging.getLogger("preview_dashboard.mcp")

# Socket-local HTTP: connect/pool are instant unless the admin is down or
# saturated. Read covers the server-side commit after a large upload.
DEFAULT_TIMEOUT: Final = httpx.Timeout(connect=5.0, read=120.0, write=60.0, pool=10.0)
DEFAULT_CHUNK_BYTES: Final = 64 * 1024
# Admin responses are small JSON; anything bigger is refused, not buffered.
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
_BASE_URL: Final = "http://admin.local"
_MAX_LIST_LIMIT: Final = 200
# Server-side cap of `GET /v1/questions/{id}?wait=`; the read timeout above
# (120 s) leaves room for it.
MAX_QUESTION_WAIT_SECONDS: Final = 60
# Characters that could break out of the quoted multipart `filename="..."`.
_HEADER_UNSAFE: Final = frozenset('"\\\r\n\x00')
# `GET /v1/items?folder=unfiled`: items in no folder (domain `UNFILED`).
UNFILED_FILTER: Final = UNFILED.value


class UploadFile(Protocol):
    """One file to upload: a bundle relpath, its exact size, and a chunk reader.

    `intake.IntakeFile` implements this; the reader must yield exactly `size`
    bytes (or raise).
    """

    @property
    def relpath(self) -> str: ...

    @property
    def size(self) -> int: ...

    def open_reader(self, chunk_size: int = ...) -> AbstractContextManager[Iterator[bytes]]: ...


# --- errors -----------------------------------------------------------------------


class AdminClientError(Exception):
    """A request to the admin API failed. `str()` is safe to show the agent.

    Attributes:
        status: HTTP status, or None if no response was received.
        code: admin error code (`invalid_input`, `not_found`, ...) or a
            client-side one (`unavailable`, `bad_response`, `upload_changed`).
        request_id: admin request id for correlating with its log, if any.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str = "error",
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id


class AdminUnavailableError(AdminClientError):
    """The admin API could not be reached, timed out, or answered unintelligibly."""


class AdminInputError(AdminClientError):
    """The request was malformed or failed validation (400/415, or checked locally)."""


class AdminAuthError(AdminClientError):
    """The admin API refused our credentials (401) or our peer uid (403)."""


class AdminNotFoundError(AdminClientError):
    """No such item (404)."""


class AdminConflictError(AdminClientError):
    """The item's state forbids the change, or it changed concurrently (409)."""


class AdminLimitError(AdminClientError):
    """A size, count, quota, disk, time (408/413) or rate (429) limit was hit.

    Attributes:
        retry_after: seconds to wait before retrying (429 only), if given.
    """

    retry_after: int | None = None


class AdminRejectedError(AdminClientError):
    """The content was refused (422): a secret-scan hit or a kind mismatch.

    Attributes:
        rule: neutral secret-scan rule label (never the matched bytes), if any.
        relpath: the offending file, if any.
    """

    rule: str | None = None
    relpath: str | None = None


class AdminServerError(AdminClientError):
    """The admin API failed internally (5xx) or returned an unexpected status."""


_STATUS_ERRORS: Final[dict[int, type[AdminClientError]]] = {
    400: AdminInputError,
    401: AdminAuthError,
    403: AdminAuthError,
    404: AdminNotFoundError,
    408: AdminLimitError,
    409: AdminConflictError,
    413: AdminLimitError,
    415: AdminInputError,
    422: AdminRejectedError,
    429: AdminLimitError,
}
_STATUS_LABELS: Final[dict[int, str]] = {
    401: "the admin API rejected the MCP server's token (check admin_token_file)",
    403: "the admin API refused this process (peer uid not allowed)",
    404: "not found",
    408: "the upload was too slow and timed out",
    429: "rate limit reached; try again later",
}


def _text(value: object) -> str | None:
    return safe_display(value) if isinstance(value, str) and value else None


def error_from_response(status: int, body: object) -> AdminClientError:
    """Build the typed error for an admin error response.

    Only the admin's caller-safe fields are used (`error`, `message`,
    `rule`, `relpath`, `request_id`), escaped and length-bounded.
    """
    fields = body if isinstance(body, dict) else {}
    code = _text(fields.get("error")) or f"http_{status}"
    detail = _text(fields.get("message")) or _STATUS_LABELS.get(status, "request failed")
    request_id = _text(fields.get("request_id"))
    message = f"admin API {status} {code}: {detail}"
    cls = _STATUS_ERRORS.get(status, AdminServerError)
    rule, relpath = _text(fields.get("rule")), _text(fields.get("relpath"))
    if cls is AdminRejectedError and rule is not None:
        where = f" in '{relpath}'" if relpath else ""
        message = (
            f"admin API refused the content: it looks like a secret (rule {rule}){where}. "
            "Nothing was published; remove the secret and publish again."
        )
    error = cls(message, status=status, code=code, request_id=request_id)
    if isinstance(error, AdminRejectedError):
        error.rule, error.relpath = rule, relpath
    return error


# --- multipart ----------------------------------------------------------------------


class _PublishBody:
    """A manifest-first multipart body streamed from upload readers (ADR 0014).

    Part order: `title`, `description`, `kind_hint`, `pinned`, `manifest`,
    then one `file` part per upload whose filename equals the next manifest
    entry. Its exact length is known up front, so no chunked encoding.
    """

    def __init__(
        self,
        files: Sequence[UploadFile],
        fields: Sequence[tuple[str, str]],
        chunk_size: int,
    ) -> None:
        if not files:
            raise AdminInputError("nothing to publish", code="invalid_input")
        for f in files:
            if not f.relpath or any(ch in _HEADER_UNSAFE for ch in f.relpath):
                raise AdminInputError(
                    f"file name '{safe_display(f.relpath)}' cannot be sent", code="invalid_input"
                )
        # 128 random bits: the chance of this appearing in file content is nil.
        self.boundary = f"pdash-{secrets.token_hex(16)}"
        self._files = tuple(files)
        self._chunk_size = chunk_size
        manifest = json.dumps([f.relpath for f in files], ensure_ascii=False)
        self._head = b"".join(
            self._field(name, value) for name, value in (*fields, ("manifest", manifest))
        )
        self._file_heads = tuple(self._file_head(f.relpath) for f in self._files)
        self._tail = f"--{self.boundary}--\r\n".encode("ascii")

    @property
    def content_type(self) -> str:
        """The request `Content-Type`, including the boundary."""
        return f"multipart/form-data; boundary={self.boundary}"

    def _field(self, name: str, value: str) -> bytes:
        return (
            f'--{self.boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value.encode("utf-8")
            + b"\r\n"
        )

    def _file_head(self, relpath: str) -> bytes:
        return (
            f"--{self.boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{relpath}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()

    def __len__(self) -> int:
        files = sum(len(h) + f.size + 2 for h, f in zip(self._file_heads, self._files, strict=True))
        return len(self._head) + files + len(self._tail)

    def __iter__(self) -> Iterator[bytes]:
        yield self._head
        for head, f in zip(self._file_heads, self._files, strict=True):
            yield head
            sent = 0
            with f.open_reader(self._chunk_size) as chunks:
                for chunk in chunks:
                    sent += len(chunk)
                    if sent > f.size:
                        break
                    yield chunk
            # Never send more or fewer bytes than announced: the body length
            # and the admin's per-file accounting depend on it.
            if sent != f.size:
                raise AdminInputError(
                    f"'{safe_display(f.relpath)}' changed size while uploading; publish aborted",
                    code="upload_changed",
                )
            yield b"\r\n"
        yield self._tail


# --- client -------------------------------------------------------------------------


class AdminClient:
    """Typed, synchronous client of the admin API (docs/api.md) over its Unix socket.

    Args:
        socket_path: the admin Unix socket.
        token: the bearer token (from `load_admin_token`); kept only in the
            client's default headers, never logged or repr'd.
        timeout: httpx timeouts (defaults to `DEFAULT_TIMEOUT`).
        transport: override the transport (tests); default is httpx over UDS.
    """

    def __init__(
        self,
        socket_path: Path,
        token: bytes,
        *,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._http = httpx.Client(
            # trust_env on the transport too: the client's flag doesn't reach it.
            transport=transport or httpx.HTTPTransport(uds=str(socket_path), trust_env=False),
            base_url=_BASE_URL,
            timeout=timeout,
            headers={
                b"Authorization": b"Bearer " + token,
                # The admin API never compresses (small JSON, a local
                # socket); asking for identity keeps the response bytes
                # this client parses exactly what `MAX_RESPONSE_BYTES` (and
                # the eye) sees, with no decompression step to get wrong.
                b"Accept-Encoding": b"identity",
            },
            follow_redirects=False,
            trust_env=False,  # no proxies/netrc from env: talk to the socket only
        )

    @classmethod
    def from_settings(cls, settings: Settings, *, token_gids: Collection[int] = ()) -> AdminClient:
        """Load the token file (same C12 checks as the admin side) and connect lazily.

        Args:
            settings: provides `admin_token_file` and `admin_socket`.
            token_gids: extra groups allowed to own the token file (e.g. the
                admin service group of a `root:pdash-admin` 0640 file).

        Raises:
            TokenFileError: the token file is unsafe or unreadable.
        """
        token = load_admin_token(settings.admin_token_file, trusted_gids=token_gids)
        return cls(settings.admin_socket, token)

    def __repr__(self) -> str:
        return "AdminClient()"  # never expose headers (the token)

    def close(self) -> None:
        """Close the connection pool. Idempotent."""
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # --- requests ---------------------------------------------------------------

    def _send(self, request: httpx.Request) -> dict[str, object]:
        try:
            response = self._http.send(request, stream=True)
        except httpx.TimeoutException:
            raise AdminUnavailableError("admin API timed out", code="unavailable") from None
        except httpx.TransportError as exc:
            # Class name only: transport messages may include socket paths, never needed.
            raise AdminUnavailableError(
                f"admin API unreachable ({type(exc).__name__}); "
                "is preview-dashboard-admin running?",
                code="unavailable",
            ) from None
        try:
            body = self._read_json(response)
        finally:
            response.close()
        if response.status_code in (200, 201):
            if not isinstance(body, dict):
                raise AdminUnavailableError(
                    "admin API returned a malformed body", code="bad_response"
                )
            return body
        return self._raise(response, body)

    def _raise(self, response: httpx.Response, body: object) -> dict[str, object]:
        error = error_from_response(response.status_code, body)
        if isinstance(error, AdminLimitError) and response.status_code == 429:
            raw = response.headers.get("retry-after", "")
            error.retry_after = int(raw) if raw.isdigit() and len(raw) < 7 else None
        logger.info(
            "admin request failed: status=%d code=%s request_id=%s",
            response.status_code,
            error.code,
            error.request_id,
        )
        raise error

    @staticmethod
    def _read_json(response: httpx.Response) -> object:
        raw = bytearray()
        try:
            for chunk in response.iter_bytes():
                raw += chunk
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise AdminUnavailableError("admin API response too large", code="bad_response")
        except httpx.HTTPError:
            raise AdminUnavailableError(
                "admin API connection failed mid-response", code="unavailable"
            ) from None
        try:
            return json.loads(bytes(raw)) if raw else None
        except ValueError:
            return None
        except RecursionError:
            # Absurdly nested JSON (e.g. thousands of "[") exhausts the
            # decoder's recursion budget rather than raising ValueError;
            # treated the same as any other malformed body.
            return None

    @staticmethod
    def _question_path(question_id: str, action: str = "") -> str:
        # Validated before building the URL, like item ids.
        if not is_ulid(question_id):
            raise AdminInputError(
                "question_id must be a 26-character question id (as returned by ask)",
                code="invalid_input",
            )
        return f"/v1/questions/{question_id}{action}"

    @staticmethod
    def _item_path(item_id: str, action: str = "") -> str:
        # Checked before building the URL: an id like "../kinds" must never
        # address a different route.
        if not is_ulid(item_id):
            raise AdminInputError(
                "item_id must be a 26-character item id (as returned by publish/list)",
                code="invalid_input",
            )
        return f"/v1/items/{item_id}{action}"

    @staticmethod
    def _folder_path(folder_id: str) -> str:
        # Same rule as item ids: only a canonical ULID ever reaches the URL.
        if not is_ulid(folder_id):
            raise AdminInputError(
                "folder_id must be a 26-character folder id (as returned by folder_create/list)",
                code="invalid_input",
            )
        return f"/v1/folders/{folder_id}"

    # --- API ------------------------------------------------------------------------

    def health(self) -> dict[str, object]:
        """`GET /v1/health` — checks the socket and the token."""
        return self._send(self._http.build_request("GET", "/v1/health"))

    def kinds(self) -> dict[str, object]:
        """`GET /v1/kinds` — `{"kinds": [...]}`, the content-kind registry."""
        return self._send(self._http.build_request("GET", "/v1/kinds"))

    def list_items(
        self,
        *,
        state: str = "active",
        kind: str | None = None,
        limit: int = 20,
        cursor: str | None = None,
        folder: str | None = None,
    ) -> dict[str, object]:
        """`GET /v1/items` — `{"items": [...], "next_cursor": str | None}`.

        `folder`: a folder id or `unfiled` (None: every item).
        """
        if not 1 <= limit <= _MAX_LIST_LIMIT:
            raise AdminInputError(f"limit must be 1..{_MAX_LIST_LIMIT}", code="invalid_input")
        if folder is not None and folder != UNFILED_FILTER and not is_ulid(folder):
            raise AdminInputError(
                f"folder must be a folder id or '{UNFILED_FILTER}'", code="invalid_input"
            )
        params: dict[str, str] = {"state": state, "limit": str(limit)}
        if kind:
            params["kind"] = kind
        if cursor:
            params["cursor"] = cursor
        if folder is not None:
            params["folder"] = folder
        return self._send(self._http.build_request("GET", "/v1/items", params=params))

    def get_item(self, item_id: str) -> dict[str, object]:
        """`GET /v1/items/{id}` — one item in any state."""
        return self._send(self._http.build_request("GET", self._item_path(item_id)))

    def update_item(
        self,
        item_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        pinned: bool | None = None,
    ) -> dict[str, object]:
        """`PATCH /v1/items/{id}` — only the given fields change."""
        body: dict[str, object] = {}
        if title is not None:
            body["title"] = title
        if description is not None:
            body["description"] = description
        if pinned is not None:
            body["pinned"] = pinned
        if not body:
            raise AdminInputError(
                "nothing to update: give title, description and/or pinned", code="invalid_input"
            )
        request = self._http.build_request("PATCH", self._item_path(item_id), json=body)
        return self._send(request)

    def trash_item(self, item_id: str) -> dict[str, object]:
        """`POST /v1/items/{id}/trash` (idempotent)."""
        return self._send(self._http.build_request("POST", self._item_path(item_id, "/trash")))

    def restore_item(self, item_id: str) -> dict[str, object]:
        """`POST /v1/items/{id}/restore` (idempotent)."""
        return self._send(self._http.build_request("POST", self._item_path(item_id, "/restore")))

    def move_item(self, item_id: str, folder_id: str | None) -> dict[str, object]:
        """`POST /v1/items/{id}/move` — file the item in `folder_id` (None: unfiled); any state."""
        if folder_id is not None:
            self._folder_path(folder_id)  # validate locally, like the item id
        request = self._http.build_request(
            "POST", self._item_path(item_id, "/move"), json={"folder_id": folder_id}
        )
        return self._send(request)

    # --- permanent deletes (ADR 0030) ------------------------------------------------------

    def prune_revisions(
        self, item_id: str, *, keep: int = 1, expected_revision: int | None = None
    ) -> dict[str, object]:
        """`POST /v1/items/{id}/revisions/prune` — `{"item", "revisions_removed", "bytes_freed"}`.

        Permanent: the dropped revisions and their files are deleted.
        """
        body: dict[str, object] = {"keep": keep}
        if expected_revision is not None:
            body["expected_revision"] = expected_revision
        request = self._http.build_request(
            "POST", self._item_path(item_id, "/revisions/prune"), json=body
        )
        return self._send(request)

    def empty_trash(self) -> dict[str, object]:
        """`POST /v1/trash/empty` — `{"items_purged", "blobs_deleted"}`. Permanent."""
        return self._send(self._http.build_request("POST", "/v1/trash/empty"))

    # --- folders (ADR 0027) -------------------------------------------------------------

    def list_folders(self) -> dict[str, object]:
        """`GET /v1/folders` — `{"folders": [...], "unfiled_count", "unfiled_trashed_count"}`."""
        return self._send(self._http.build_request("GET", "/v1/folders"))

    def create_folder(self, name: str) -> dict[str, object]:
        """`POST /v1/folders` — the new folder `{id, name, created_at, updated_at}`."""
        return self._send(self._http.build_request("POST", "/v1/folders", json={"name": name}))

    def rename_folder(self, folder_id: str, name: str) -> dict[str, object]:
        """`PATCH /v1/folders/{id}` — the renamed folder."""
        request = self._http.build_request(
            "PATCH", self._folder_path(folder_id), json={"name": name}
        )
        return self._send(request)

    def delete_folder(self, folder_id: str) -> dict[str, object]:
        """`DELETE /v1/folders/{id}` — `{"id", "deleted": true}`; 409 unless empty."""
        return self._send(self._http.build_request("DELETE", self._folder_path(folder_id)))

    def publish(
        self,
        files: Sequence[UploadFile],
        *,
        title: str,
        description: str = "",
        kind_hint: str | None = None,
        pinned: bool = False,
        folder_id: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_BYTES,
    ) -> dict[str, object]:
        """`POST /v1/items` — stream `files` as one new item; returns the item JSON.

        `folder_id` files the new item in that folder (None: unfiled).

        Bytes are read chunk by chunk from each file's reader while the
        request is sent (memory stays bounded by `chunk_size`).

        Raises:
            AdminClientError: a typed admin error, or `upload_changed` if a
                file delivered a different number of bytes than its size.
            IntakeError: propagated from an intake reader (file changed).
        """
        fields: list[tuple[str, str]] = [("title", title)]
        if description:
            fields.append(("description", description))
        if kind_hint:
            fields.append(("kind_hint", kind_hint))
        fields.append(("pinned", "true" if pinned else "false"))
        if folder_id is not None:
            self._folder_path(folder_id)  # validate locally before any upload
            fields.append(("folder_id", folder_id))
        body = _PublishBody(files, fields, chunk_size)
        request = self._http.build_request(
            "POST",
            "/v1/items",
            content=iter(body),
            headers={"Content-Type": body.content_type, "Content-Length": str(len(body))},
        )
        return self._send(request)

    def publish_revision(
        self,
        item_id: str,
        files: Sequence[UploadFile],
        *,
        kind_hint: str | None = None,
        expected_revision: int | None = None,
        chunk_size: int = DEFAULT_CHUNK_BYTES,
    ) -> dict[str, object]:
        """`POST /v1/items/{id}/revisions` — replace `item_id`'s content with a new head revision.

        Same manifest-first streaming as `publish` (ADR 0019); the item
        keeps its id, title, description and pin. `expected_revision`, if
        given, makes the update apply only while it is still the head
        revision number (else `AdminConflictError`).

        Raises:
            AdminClientError: a typed admin error (404 unknown item, 409
                `invalid_state`/`conflict`, ...), or `upload_changed` if a
                file delivered a different number of bytes than its size.
            IntakeError: propagated from an intake reader (file changed).
        """
        fields: list[tuple[str, str]] = []
        if kind_hint:
            fields.append(("kind_hint", kind_hint))
        if expected_revision is not None:
            fields.append(("expected_revision", str(expected_revision)))
        body = _PublishBody(files, fields, chunk_size)
        request = self._http.build_request(
            "POST",
            self._item_path(item_id, "/revisions"),
            content=iter(body),
            headers={"Content-Type": body.content_type, "Content-Length": str(len(body))},
        )
        return self._send(request)

    # --- questions and alerts (ADR 0021) ----------------------------------------------

    def ask_question(self, body: Mapping[str, object]) -> dict[str, object]:
        """`POST /v1/questions` — returns `{"question": {...}}` (see docs/api.md).

        `body`: `prompt`, `options` ([{key, label}]), `session_label`, and
        optionally `default_key`, `item_id`, `expires_in_s`. Validated by
        the admin API (400 with a caller-safe message).
        """
        request = self._http.build_request("POST", "/v1/questions", json=dict(body))
        return self._send(request)

    def get_question(self, question_id: str, *, wait: int = 0) -> dict[str, object]:
        """`GET /v1/questions/{id}?wait=` — `{"question": {...}}`, held up to `wait` s (0..60)."""
        if isinstance(wait, bool) or not 0 <= wait <= MAX_QUESTION_WAIT_SECONDS:
            raise AdminInputError(
                f"wait must be 0..{MAX_QUESTION_WAIT_SECONDS}", code="invalid_input"
            )
        request = self._http.build_request(
            "GET", self._question_path(question_id), params={"wait": str(wait)}
        )
        return self._send(request)

    def cancel_question(self, question_id: str) -> dict[str, object]:
        """`POST /v1/questions/{id}/cancel` (idempotent) — `{"question": {...}}`."""
        return self._send(
            self._http.build_request("POST", self._question_path(question_id, "/cancel"))
        )

    def notify(self, event: str, title: str, item_id: str | None = None) -> dict[str, object]:
        """`POST /v1/notifications` — a `done`/`failed` alert; `{"notification": {...}}`."""
        body: dict[str, object] = {"event": event, "title": title}
        if item_id is not None:
            body["item_id"] = item_id
        return self._send(self._http.build_request("POST", "/v1/notifications", json=body))
