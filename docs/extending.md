**TL;DR:** Supported extension points: a new **content kind** (one backend file + one frontend renderer), a new **storage adapter** (one file implementing a port), and for notifications (ADR 0021) a new **channel**, **event type** or **answer source** (one file each). None requires touching unrelated code. The ports and contract suites exist (unit 2); the kind registry and 13 built-in kinds exist (unit 3, `src/preview_dashboard/kinds/`); the event registry and its 3 built-in types exist (N1, `src/preview_dashboard/events/`).

**TL;DR:** Two supported extension points: a new **content kind** (one backend file + one frontend renderer) and a new **storage adapter** (one file implementing a port). Neither requires touching unrelated code. The ports and contract suites exist (unit 2); the kind registry and 13 built-in kinds exist (unit 3, `src/preview_dashboard/kinds/`).

## Adding a content kind

A "kind" (image, html, video, markdown, ...) is a self-contained strategy
registered once in `kinds/__init__.py`'s `default_registry()`, which
`GET /api/kinds` (via `KindRegistry.describe()`) exposes as the frontend's
single source of truth. See `docs/architecture.md`, "Content kinds", for
the full table of built-in kinds and how detection works.

1. Add `src/preview_dashboard/kinds/<your_kind>.py` with a class implementing the `ContentKind` protocol from `kinds/base.py`: `name`, `label`, `renderer`, `preview_mode` (`PreviewMode.MEDIA`/`SANDBOXED`/`DOCUMENT`/`TEXT`/`DOWNLOAD`), `extensions`, `render_capped`, and `media_type()`/`detect()`/`entry_file()`. If your kind is identified purely by extension (most are), subclass `SimpleExtensionKind` instead of writing `detect()`/`entry_file()`/`media_type()` yourself — see the example below.
2. Register one instance of it in `kinds/__init__.py`'s `default_registry()` (one line — order only affects tie-breaking, so append it before `FileKind()`, which must stay last).
3. Add a matching renderer module in `static/renderers/<your_kind>.js` (vanilla ES module, no build step) that the frontend picks up via the `/api/kinds` registry response.
4. Add table-driven tests: extend `tests/unit/test_kinds.py`'s `KIND_TABLE` with your kind's extensions/media types/preview mode (this is also what proves it's wired into `default_registry()`), plus any kind-specific edge cases. If it can emit a `text/*` or otherwise sensitive media type, add a case to `tests/security/test_kinds.py`.
5. Update the "Content kinds" table in `docs/architecture.md`.
6. No edits to `application/`, `interfaces/`, or other kinds.

### Example: a minimal extension-only kind

A kind whose files are identified purely by extension (the common case)
needs no custom `detect()`/`entry_file()`/`media_type()` — `SimpleExtensionKind`
already implements them (all-or-nothing confidence: 100 only if every file
in the item matches, else 0; `entry_file()` picks the first file
deterministically). This is the entirety of `kinds/json.py`:

```python
"""JSON content kind: fetched as text and pretty-printed client-side."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {".json": "application/json"}


class JsonKind(SimpleExtensionKind):
    """json, fetched as text and pretty-printed client-side."""

    name = "json"
    label = "JSON"
    renderer = "json"
    preview_mode = PreviewMode.TEXT
    extensions = frozenset(_MEDIA_TYPES)
    render_capped = True
    _media_types = _MEDIA_TYPES
```

...plus one line in `kinds/__init__.py`'s `default_registry()`:
`JsonKind(),` in the tuple passed to `registry.register(...)`.

A kind that needs custom logic — a different detection rule, or a
multi-file entry-point rule like `html`'s "root `index.html` required" —
implements `ContentKind` directly instead of subclassing
`SimpleExtensionKind`; see `kinds/html.py` or the always-matches fallback
`kinds/file.py`.

## Adding a storage backend

Storage is behind two ports: `ItemRepository` (metadata/state) and `BlobStore` (file bytes), plus `FolderRepository` (ADR 0027), which shares the item repository's store (items reference folders, so a new item backend brings its folder repository too). Application services depend only on these Protocols.

1. Implement the port from `ports/repository.py` or `ports/blobstore.py` in a new file under `adapters/` (e.g. `adapters/s3_blobstore.py`).
2. Run the **shared port-contract test suite** against your new adapter — the same suite that runs against the in-memory fakes (and the SQLite/filesystem adapters). This is what proves the new adapter is a drop-in replacement. Subclass the contract and override one fixture:

   ```python
   # tests/integration/test_s3_blobstore.py
   import pytest

   # For a repository: tests.contracts.item_repository.ItemRepositoryContract (fixtures
   # `repo` + `folders`) and tests.contracts.folder_repository.FolderRepositoryContract
   from tests.contracts.blob_store import BlobStoreContract

   pytestmark = pytest.mark.integration


   class TestS3BlobStore(BlobStoreContract):
       @pytest.fixture
       def store(self, tmp_path):  # `repo` for ItemRepositoryContract
           return S3BlobStore(...)  # fresh, empty instance per test
   ```

   Add adapter-specific tests (permissions, crash recovery, concurrency) in the same module. If a contract test seems wrong for your adapter, the port contract is what needs discussing — don't skip the test.
3. Wire it in `bootstrap.py` (the composition root) behind a config flag if it should be selectable at runtime, or swap the import if it's a hard replacement.
4. No edits to `domain/` or `application/` — if you find yourself needing to change either, the port's contract is probably incomplete; fix the Protocol first, then update every adapter and fake to match.

## Adding a notification channel (ntfy, email, Signal, ...)

A channel delivers channel-neutral `MessageContent` (plain text ≤ 300
chars, answer buttons, optional dashboard link) inside the notifier
process. The core never changes.

1. Add `src/preview_dashboard/adapters/<channel>/` implementing
   `ports/notify.py`'s `NotificationChannel`: a `name` (`[a-z][a-z0-9-]{0,31}`),
   `send(payload) -> message_ref | None` (≤ 64 visible ASCII; None if the
   channel can't edit messages later) and `resolve(message_ref, payload)`
   (replace the message with the outcome, drop its buttons). Raise on any
   failure: the task is retried with backoff (5 s × 4ⁿ, 8 tries).
2. Security (docs/security.md C35/C36): plain text only (no markup/parse
   modes), never log payloads, URLs or credentials, no env proxies, fixed
   base URL, credentials from a root-owned file.
3. Answer buttons: if the channel can report taps, also implement
   `AnswerSource` (below); otherwise render `payload.content.buttons` as text
   or drop them.
4. Enable it: add its name to the enabled channels in `bootstrap.py`
   (admin side creates one SEND/RESOLVE task per enabled channel) and pass
   the instance to `DeliveryService(channels=[...])` in the notifier.
5. Tests: the `FakeNotificationChannel` in `tests/fakes.py` shows the
   expected behavior; `tests/unit/test_delivery_service.py` shows how the
   service drives a channel.

## Adding a notification event type (digest, reminder, ...)

Event types mirror content kinds: a Registry + Strategy in `events/`.

1. Add `src/preview_dashboard/events/<name>.py` with a class implementing
   `events/base.py`'s `EventType`: `name`, `emoji`, `actionable` (only
   questions carry buttons) and `render(ctx: RenderContext) -> MessageContent`.
   Use `compose_text(emoji, title, extra_lines)` so the text always fits.
2. Register one instance in `events/__init__.py`'s `default_event_registry()`.
3. Non-actionable types are sent with `NotifyService.notify(<name>, title,
   item_id)`; the admin API/MCP tool may need to accept the new name (N3's
   allow-list).
4. Tests: extend `tests/unit/test_event_registry.py`.

```python
"""The `reminder` event type: a nudge with a dashboard link, no buttons."""

from preview_dashboard.domain.notifications import MessageContent
from preview_dashboard.events.base import RenderContext, compose_text


class ReminderEventType:
    name = "reminder"
    emoji = "⏰"
    actionable = False

    def render(self, ctx: RenderContext) -> MessageContent:
        return MessageContent(text=compose_text(self.emoji, ctx.title), link=ctx.link)
```

## Adding an answer source (dashboard buttons = N6, ntfy actions, ...)

1. Notifier-side source: implement `AnswerSource` (`name`, `poll(timeout)
   -> [AnswerEvent]`, `ack(handle, text)`) and drop anything not from the
   configured owner **before** returning it (C34). `DeliveryService`
   submits each tap and acks the result.
2. Admin-side source (e.g. a viewer route): call
   `QuestionService.answer(question_id, key, source="<name>")` behind that
   interface's own owner checks (C2/C4 for the viewer). Never give the
   admin token (Claude) a way to answer.
3. Free-text answers are out of scope: they change the trust model and
   need a new ADR.

## General rules (from CLAUDE.md)

- Every new file gets a 2-4 line header comment: what it contains, what it's responsible for.
- Full type hints; the file must pass `mypy --strict`.
- `domain/` and `application/` never import frameworks (no FastAPI, sqlite3, httpx, mcp).
- Write tests alongside the code, not after: happy path, edge cases, and (for anything security-relevant) a test tied to a control in `docs/security.md`.
- Update the relevant doc (this file, `docs/architecture.md`'s module map, `docs/api.md`) in the same change.
