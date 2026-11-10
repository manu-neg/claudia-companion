"""In-memory fakes for every port (repository, folders, blob store, clock, ids,
scanner, questions, notification outbox, wake-ups, notifier channel/source/queue,
Claudia's owner-message inbox and approval store).

They implement the full port contracts (errors, ordering, atomicity) and are
held to them by the shared suites in `tests/contracts/`, so unit tests of
the application layer can trust them as drop-in replacements for adapters.
"""

from __future__ import annotations

import asyncio
import builtins
import hashlib
import io
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import BinaryIO

from preview_dashboard.application.notify import OutboxService
from preview_dashboard.application.questions import QuestionService
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalRequest,
    ApprovalState,
    WindowId,
    check_successor,
)
from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    ConflictError,
    LimitExceededError,
    NotFoundError,
    SecretDetectedError,
    ValidationError,
)
from preview_dashboard.domain.folders import Folder, FolderId
from preview_dashboard.domain.models import BlobRef, Item, ItemId, ItemState, ensure_utc, is_ulid
from preview_dashboard.domain.notifications import (
    DeliveryAction,
    DeliveryPayload,
    DeliveryState,
    DeliveryTask,
    MessageContent,
    Notification,
    NotificationId,
    PendingTask,
    TaskId,
    approval_outcome_content,
    validate_message_ref,
)
from preview_dashboard.domain.owner_messages import InboxState, OwnerMessage, OwnerMessageId
from preview_dashboard.domain.query import ItemQuery, Page, paginate
from preview_dashboard.domain.questions import AnswerResult, Question, QuestionId, QuestionState
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.folders import FolderCounts
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.notify import AnswerEvent
from preview_dashboard.ports.owner_messages import MAX_UNHANDLED_LIMIT
from preview_dashboard.ports.repository import RepositoryUsage

DEFAULT_START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class FixedClock:
    """Clock that only moves when told to (`advance` / `set`)."""

    def __init__(self, start: datetime = DEFAULT_START) -> None:
        self._now = ensure_utc(start, "start")

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> datetime:
        """Move time forward (or back, with a negative delta); return the new now."""
        self._now += delta
        return self._now

    def set(self, value: datetime) -> None:
        self._now = ensure_utc(value, "value")


class SequentialIdGenerator:
    """Deterministic ids: '000...0001', '000...0002', ... (valid canonical ULIDs).

    Item and blob ids share one counter, so no id is ever handed out twice.
    """

    def __init__(self, start: int = 1) -> None:
        self._next = start

    def _take(self) -> str:
        value = f"{self._next:026d}"
        self._next += 1
        return value

    def new_item_id(self) -> ItemId:
        return ItemId(self._take())

    def new_blob_id(self) -> str:
        return self._take()


class InMemoryItemRepository:
    """ItemRepository backed by a dict; ordering/paging via `domain.query.paginate`.

    Folder references are checked against the `InMemoryFolderRepository`
    attached to it (none attached = no folder exists), like SQLite's
    foreign key: filing into a missing folder is `NotFoundError`.
    """

    def __init__(self) -> None:
        self._items: dict[ItemId, Item] = {}
        self._folders: InMemoryFolderRepository | None = None

    def attach_folders(self, folders: InMemoryFolderRepository) -> None:
        """Share one store with a folder repository (done by its constructor)."""
        self._folders = folders

    def _check_folder(self, item: Item) -> None:
        if item.folder_id is not None and (
            self._folders is None or not self._folders.exists(item.folder_id)
        ):
            raise NotFoundError("folder not found")

    def add(self, item: Item) -> None:
        self._check_folder(item)
        if item.id in self._items:
            raise AlreadyExistsError("item already exists")
        self._items[item.id] = item

    def get(self, item_id: ItemId) -> Item:
        try:
            return self._items[item_id]
        except KeyError:
            raise NotFoundError("item not found") from None

    def list(self, query: ItemQuery) -> Page[Item]:
        return paginate(self._items.values(), query)

    def save(self, item: Item, *, expected_updated_at: datetime) -> None:
        expected = ensure_utc(expected_updated_at, "expected_updated_at")
        current = self._items.get(item.id)
        if current is None:
            raise NotFoundError("item not found")
        # Single-threaded dict: compare-and-swap is atomic by construction.
        if current.updated_at != expected:
            raise ConflictError("item was changed concurrently")
        self._check_folder(item)
        self._items[item.id] = item

    def delete(self, item_id: ItemId) -> bool:
        return self._items.pop(item_id, None) is not None

    def delete_if_purgeable(self, item_id: ItemId, cutoff: datetime) -> Item | None:
        # Single-threaded dict: check-and-delete is atomic by construction.
        item = self._items.get(item_id)
        if (
            item is None
            or item.state is not ItemState.TRASHED
            or item.trashed_at is None
            or item.trashed_at > ensure_utc(cutoff, "cutoff")
        ):
            return None
        del self._items[item_id]
        return item

    def list_purgeable(self, now: datetime, retention: timedelta) -> builtins.list[Item]:
        due = [i for i in self._items.values() if i.is_purgeable(now, retention)]
        # trashed_at is always set for purgeable items; `or now` only satisfies typing.
        return sorted(due, key=lambda i: (i.trashed_at or now, i.id))

    def all_blob_ids(self) -> set[str]:
        # Every kept revision, not just the head (ADR 0019).
        return {f.blob_id for i in self._items.values() for f in i.all_files}

    def usage(self) -> RepositoryUsage:
        return RepositoryUsage(
            item_count=len(self._items),
            total_bytes=sum(i.stored_size for i in self._items.values()),
        )

    def count(self, state: ItemState | None = None) -> int:
        """Test helper: number of stored items, optionally in one state."""
        return sum(1 for i in self._items.values() if state is None or i.state is state)

    def snapshot(self) -> builtins.list[Item]:
        """Test helper (and the folder fake's view): every stored item, any state."""
        return list(self._items.values())


class InMemoryFolderRepository:
    """FolderRepository over a dict, sharing its store with an `InMemoryItemRepository`.

    Single-threaded, so every check-then-write is atomic by construction.
    `corrupt_folder` simulates a tampered row (SQLite: `name_key` rewritten
    to disagree with `name`, or similar); `get` fails closed on it, `list`
    skips it, like `SqliteFolderRepository`.
    """

    def __init__(self, items: InMemoryItemRepository | None = None) -> None:
        self._folders: dict[FolderId, Folder] = {}
        self._corrupt: set[FolderId] = set()
        self._items = items if items is not None else InMemoryItemRepository()
        self._items.attach_folders(self)

    @property
    def items(self) -> InMemoryItemRepository:
        """The item repository sharing this store."""
        return self._items

    def exists(self, folder_id: FolderId) -> bool:
        """Test helper (and the item fake's foreign-key check)."""
        return folder_id in self._folders

    def corrupt_folder(self, folder_id: FolderId) -> None:
        """Test hook: from now on this folder's row fails re-validation (tampered row)."""
        self._corrupt.add(folder_id)

    def _name_taken(self, folder: Folder) -> bool:
        return any(
            f.name_key == folder.name_key and f.id != folder.id for f in self._folders.values()
        )

    def add(self, folder: Folder, *, max_folders: int) -> None:
        if len(self._folders) >= max_folders:
            raise LimitExceededError("folder quota reached")
        if folder.id in self._folders:
            raise AlreadyExistsError("folder already exists")
        if self._name_taken(folder):
            raise AlreadyExistsError("a folder with that name already exists")
        self._folders[folder.id] = folder

    def get(self, folder_id: FolderId) -> Folder:
        try:
            folder = self._folders[folder_id]
        except KeyError:
            raise NotFoundError("folder not found") from None
        if folder_id in self._corrupt:
            raise ValidationError("invalid folder in stored row")
        return folder

    def list(self) -> builtins.list[Folder]:
        # A corrupt row is skipped, not raised (docs/security.md C39).
        good = (f for f in self._folders.values() if f.id not in self._corrupt)
        return sorted(good, key=lambda f: (f.name_key, f.id))

    def rename(self, folder: Folder, *, expected_updated_at: datetime) -> None:
        current = self.get(folder.id)
        expected = ensure_utc(expected_updated_at, "expected_updated_at")
        # Single-threaded dict: compare-and-swap is atomic by construction.
        if current.updated_at != expected:
            raise ConflictError("folder was changed concurrently")
        if self._name_taken(folder):
            raise AlreadyExistsError("a folder with that name already exists")
        # Only the name and its timestamp are written (as the SQLite adapter).
        self._folders[folder.id] = Folder(
            id=current.id,
            name=folder.name,
            created_at=current.created_at,
            updated_at=folder.updated_at,
        )

    def delete_if_empty(self, folder_id: FolderId) -> None:
        self.get(folder_id)
        if any(i.folder_id == folder_id for i in self._items.snapshot()):
            raise ConflictError("folder is not empty")
        del self._folders[folder_id]

    def counts(self, state: ItemState) -> FolderCounts:
        by_folder = dict.fromkeys(self._folders, 0)
        unfiled = 0
        for item in self._items.snapshot():
            if item.state is not state:
                continue
            if item.folder_id is None:
                unfiled += 1
            else:
                by_folder[item.folder_id] += 1
        return FolderCounts(by_folder=by_folder, unfiled=unfiled)


class InMemoryBlobStore:
    """BlobStore backed by a dict of bytes, with a configurable capacity.

    `capacity_bytes` models the disk: a `put` that would exceed it fails
    with `LimitExceededError` and stores nothing (the disk-full contract).
    """

    def __init__(
        self,
        *,
        capacity_bytes: int = 10 * 1024**3,
        clock: Clock | None = None,
        ids: IdGenerator | None = None,
    ) -> None:
        self._capacity = capacity_bytes
        self._clock: Clock = clock or FixedClock()
        # Offset keeps fake blob ids visibly distinct from item ids in tests.
        self._ids: IdGenerator = ids or SequentialIdGenerator(start=10**20)
        self._blobs: dict[str, tuple[bytes, datetime]] = {}

    def put(self, chunks: Iterable[bytes], max_bytes: int) -> BlobRef:
        if max_bytes < 0:
            raise ValueError("max_bytes must be >= 0")
        buf = bytearray()
        digest = hashlib.sha256()
        free = self.free_bytes()
        for chunk in chunks:
            if len(buf) + len(chunk) > max_bytes:
                raise LimitExceededError("blob exceeds the size limit")
            # Simulates disk full (ENOSPC): fail mid-stream, keep nothing.
            if len(buf) + len(chunk) > free:
                raise LimitExceededError("blob storage is full")
            buf += chunk
            digest.update(chunk)
        blob_id = self._ids.new_blob_id()
        self._blobs[blob_id] = (bytes(buf), self._clock.now())
        return BlobRef(blob_id=blob_id, size=len(buf), sha256=digest.hexdigest())

    def open(self, blob_id: str) -> BinaryIO:
        if not is_ulid(blob_id) or blob_id not in self._blobs:
            raise NotFoundError("blob not found")
        return io.BytesIO(self._blobs[blob_id][0])

    def delete(self, blob_id: str) -> None:
        self._blobs.pop(blob_id, None)

    def list_ids(self, created_before: datetime | None = None) -> set[str]:
        if created_before is None:
            return set(self._blobs)
        cutoff = ensure_utc(created_before, "created_before")
        return {b for b, (_, created) in self._blobs.items() if created < cutoff}

    def free_bytes(self) -> int:
        used = sum(len(data) for data, _ in self._blobs.values())
        return max(0, self._capacity - used)


FAKE_SECRET = b"FAKE-SECRET-MARKER"
"""Bytes the default `FakeContentScanner` treats as a secret (label `fake secret marker`)."""


class FakeScanSession:
    """Buffers the whole stream (tests are small) so split markers are found."""

    def __init__(self, markers: Mapping[bytes, str], owner: FakeContentScanner) -> None:
        self._markers = markers
        self._owner = owner
        self._buf = bytearray()

    def _check(self) -> None:
        for marker, rule in self._markers.items():
            if marker in self._buf:
                raise SecretDetectedError(rule)

    def feed(self, chunk: bytes) -> None:
        self._buf += chunk
        self._owner.fed_bytes += len(chunk)
        self._check()

    def finish(self) -> None:
        self._owner.finished += 1
        self._check()


class FakeContentScanner:
    """ContentScanner that flags fixed marker byte strings.

    `sessions`, `fed_bytes` and `finished` let tests assert that every byte
    (and every stream) went through the scanner.
    """

    def __init__(self, markers: Mapping[bytes, str] | None = None) -> None:
        self._markers = (
            dict(markers) if markers is not None else {FAKE_SECRET: "fake secret marker"}
        )
        self.sessions = 0
        self.fed_bytes = 0
        self.finished = 0

    def new_session(self) -> FakeScanSession:
        self.sessions += 1
        return FakeScanSession(self._markers, self)


# --- questions + notifications (ADR 0021) ---------------------------------------

MAX_OUTBOX_PENDING_LIMIT = 100


class InMemoryNotificationOutbox:
    """NotificationOutbox backed by dicts; the reference for the outbox delivery rules.

    `InMemoryQuestionRepository` writes question notifications and RESOLVE
    tasks into the same dicts, which models the shared SQLite store, and
    sets `question_lookup` so stale SENDs can be recognized. `corrupt_task`
    models a tampered row: it fails re-validation on every read.
    """

    def __init__(self) -> None:
        self.notifications: dict[NotificationId, Notification] = {}
        self.tasks: dict[TaskId, DeliveryTask] = {}
        self.question_lookup: Callable[[QuestionId], Question | None] = lambda _qid: None
        # Like SQLite's LEFT JOIN: an unknown (or deleted) request makes its prompt stale.
        self.approval_lookup: Callable[[ApprovalId], ApprovalRequest | None] = lambda _aid: None
        self._corrupt: set[TaskId] = set()

    def corrupt_task(self, task_id: TaskId) -> None:
        """Test hook: from now on this task's row fails re-validation (like a tampered row)."""
        self._corrupt.add(task_id)

    # --- helpers shared with the question repository ------------------------

    def check_new(self, notification: Notification | None, tasks: Sequence[DeliveryTask]) -> None:
        """Raise unless `notification` (if given) and `tasks` can be inserted as a unit.

        Like SQLite's unique index: at most one SEND per notification and channel.
        """
        if notification is not None and notification.id in self.notifications:
            raise AlreadyExistsError("notification already exists")
        ids = [t.id for t in tasks]
        if len(set(ids)) != len(ids) or any(i in self.tasks for i in ids):
            raise AlreadyExistsError("delivery task already exists")
        sends = [(t.notification_id, t.channel) for t in tasks if t.action is DeliveryAction.SEND]
        if len(set(sends)) != len(sends) or any(self._send_for(n, c) for n, c in sends):
            raise AlreadyExistsError("delivery task already exists")

    def insert(self, notification: Notification | None, tasks: Sequence[DeliveryTask]) -> None:
        """Store rows already checked by `check_new` (single-threaded: atomic)."""
        if notification is not None:
            self.notifications[notification.id] = notification
        for task in tasks:
            self.tasks[task.id] = task

    def _send_for(self, notification_id: NotificationId, channel: str) -> DeliveryTask | None:
        return next(
            (
                t
                for t in self.tasks.values()
                if t.notification_id == notification_id
                and t.channel == channel
                and t.action is DeliveryAction.SEND
            ),
            None,
        )

    # --- port ------------------------------------------------------------------

    def add(self, notification: Notification, tasks: Sequence[DeliveryTask]) -> None:
        if notification.question_id is not None:
            raise ValidationError("question notifications are added with their question")
        if any(t.notification_id != notification.id for t in tasks):
            raise ValidationError("task belongs to another notification")
        self.check_new(notification, tasks)
        self.insert(notification, tasks)

    def pending(self, now: datetime, limit: int) -> builtins.list[PendingTask]:
        if not 1 <= limit <= MAX_OUTBOX_PENDING_LIMIT:
            raise ValidationError("limit must be 1..100")
        at = ensure_utc(now, "now")
        due = sorted(
            (
                t
                for t in self.tasks.values()
                if t.state is DeliveryState.PENDING and t.next_attempt_at <= at
            ),
            key=lambda t: (t.next_attempt_at, t.created_at, t.id),
        )
        out: builtins.list[PendingTask] = []
        # Settled after the loop, like SQLite's read snapshot + short write.
        settled: dict[TaskId, DeliveryTask] = {}
        for task in due:
            if len(out) >= limit:
                break
            handed = self._classify(task, settled, at)
            if handed is not None:
                out.append(handed)
        self.tasks.update(settled)
        return out

    def _classify(
        self, task: DeliveryTask, settled: dict[TaskId, DeliveryTask], now: datetime
    ) -> PendingTask | None:
        """Hand a due task out, hold it (None) or settle it unsent (None, into `settled`)."""
        if task.id in self._corrupt:
            settled[task.id] = task.dropped()  # a poison row: failed by id, no delivery
            return None
        notification = self.notifications[task.notification_id]
        question = (
            None
            if notification.question_id is None
            else self.question_lookup(notification.question_id)
        )
        if task.action is DeliveryAction.SEND and question and question.state.is_terminal:
            settled[task.id] = task.done(None)  # stale: the question is already resolved
            return None
        content = task.content
        outcome: ApprovalState | None = None
        if notification.approval_id is not None:
            request = self.approval_lookup(notification.approval_id)
            if task.action is DeliveryAction.RESOLVE:
                if request is None:
                    settled[task.id] = task.dropped()  # no request: nothing true to show
                    return None
                if request.state in (ApprovalState.PENDING, ApprovalState.TAPPED):
                    settled[task.id] = task.dropped()  # forged edit of an undecided request
                    return None
                # F-CL5, like SQLite: the fixed text of the stored state, never the row's.
                outcome = request.state
                content = approval_outcome_content(outcome)
            elif (
                request is None
                or request.state is not ApprovalState.PENDING
                or request.is_expired(now)
            ):
                settled[task.id] = task.done(None)  # buttons for a live PENDING request only
                return None
            else:
                # Like SQLite: the shown text is the request's, never the task row's (C46).
                content = MessageContent(text=request.action_text)
        ref: str | None = None
        if task.action is DeliveryAction.RESOLVE:
            send = self._send_for(task.notification_id, task.channel)
            if send is not None and send.id in self._corrupt:
                settled[task.id] = task.dropped()  # its SEND row fails re-validation
                return None
            if send is not None and send.state is DeliveryState.PENDING:
                return None  # the message isn't out yet: wait for it
            if send is None or send.state is DeliveryState.FAILED or send.message_ref is None:
                settled[task.id] = task.dropped()  # nothing to edit, ever
                return None
            ref = send.message_ref
        return PendingTask(
            id=task.id,
            channel=task.channel,
            action=task.action,
            payload=DeliveryPayload(
                content=content,
                question_id=notification.question_id,
                final_state=None if notification.approval_id is not None else task.final_state,
                approval_id=notification.approval_id,
                approval_outcome=outcome,
            ),
            message_ref=ref,
        )

    def add_approval_resolves(
        self,
        approval_id: ApprovalId,
        *,
        content: MessageContent,
        final_state: QuestionState,
        now: datetime,
        new_task_id: Callable[[], TaskId],
    ) -> int:
        """`ApprovalResolveOutbox`: one RESOLVE per channel whose prompt SEND can be edited."""
        if content.buttons or content.link is not None:
            raise ValidationError("an approval outcome has no buttons or link")
        prompts = [n for n in self.notifications.values() if n.approval_id == approval_id]
        if len(prompts) != 1:
            return 0
        sends = sorted(
            (
                t
                for t in self.tasks.values()
                if t.notification_id == prompts[0].id
                and t.action is DeliveryAction.SEND
                and (
                    t.state is DeliveryState.PENDING
                    or (t.state is DeliveryState.DONE and t.message_ref is not None)
                )
            ),
            key=lambda t: t.channel,
        )
        tasks = [
            DeliveryTask.new_resolve(
                id=new_task_id(),
                notification_id=prompts[0].id,
                channel=send.channel,
                content=content,
                final_state=final_state,
                now=now,
            )
            for send in sends
        ]
        self.check_new(None, tasks)
        self.insert(None, tasks)
        return len(tasks)

    def get_task(self, task_id: TaskId) -> DeliveryTask:
        try:
            task = self.tasks[task_id]
        except KeyError:
            raise NotFoundError("delivery task not found") from None
        if task_id in self._corrupt:
            raise ValidationError("invalid delivery task in stored row")
        return task

    def mark_done(self, task_id: TaskId, message_ref: str | None) -> DeliveryTask:
        if message_ref is not None:
            validate_message_ref(message_ref)
        task = self.get_task(task_id)
        if task.state is not DeliveryState.PENDING:
            return task
        self.tasks[task_id] = task.done(message_ref)
        return self.tasks[task_id]

    def mark_failed(self, task_id: TaskId, *, now: datetime) -> DeliveryTask:
        task = self.get_task(task_id)
        if task.state is not DeliveryState.PENDING:
            return task
        self.tasks[task_id] = task.failed_attempt(now)
        return self.tasks[task_id]

    def notification_for_question(self, question_id: QuestionId) -> Notification | None:
        return next((n for n in self.notifications.values() if n.question_id == question_id), None)

    def message_ref_for(self, question_id: QuestionId, channel: str) -> str | None:
        notification = self.notification_for_question(question_id)
        if notification is None:
            return None
        send = self._send_for(notification.id, channel)
        if send is None or send.state is not DeliveryState.DONE:
            return None
        return send.message_ref

    def delete_before(self, cutoff: datetime) -> int:
        limit = ensure_utc(cutoff, "cutoff")
        doomed = {n.id for n in self.notifications.values() if n.created_at < limit}
        for notification_id in doomed:
            del self.notifications[notification_id]
        self.tasks = {k: t for k, t in self.tasks.items() if t.notification_id not in doomed}
        return len(doomed)

    def tasks_of(self, notification_id: NotificationId) -> builtins.list[DeliveryTask]:
        """Test helper: every task of one notification, in creation order."""
        found = [t for t in self.tasks.values() if t.notification_id == notification_id]
        return sorted(found, key=lambda t: (t.created_at, t.id))


class InMemoryQuestionRepository:
    """QuestionRepository sharing its store with an `InMemoryNotificationOutbox`."""

    def __init__(self, outbox: InMemoryNotificationOutbox | None = None) -> None:
        self.outbox = outbox if outbox is not None else InMemoryNotificationOutbox()
        self._questions: dict[QuestionId, Question] = {}
        self._corrupt: set[QuestionId] = set()
        self.outbox.question_lookup = self._questions.get

    def corrupt_question(self, question_id: QuestionId) -> None:
        """Test hook: from now on this question's row fails re-validation (tampered row)."""
        self._corrupt.add(question_id)

    def add_with_notification(
        self, question: Question, notification: Notification, tasks: Sequence[DeliveryTask]
    ) -> None:
        if question.id in self._questions:
            raise AlreadyExistsError("question already exists")
        if notification.question_id != question.id:
            raise ValidationError("notification belongs to another question")
        if any(t.notification_id != notification.id for t in tasks):
            raise ValidationError("task belongs to another notification")
        self.outbox.check_new(notification, tasks)
        self._questions[question.id] = question
        self.outbox.insert(notification, tasks)

    def get(self, question_id: QuestionId) -> Question:
        try:
            question = self._questions[question_id]
        except KeyError:
            raise NotFoundError("question not found") from None
        if question_id in self._corrupt:
            raise ValidationError("invalid question in stored row")
        return question

    def save(
        self,
        question: Question,
        *,
        expected_updated_at: datetime,
        tasks: Sequence[DeliveryTask] = (),
    ) -> None:
        expected = ensure_utc(expected_updated_at, "expected_updated_at")
        # Like SQLite's conditional UPDATE: the stored row is compared, not re-validated.
        current = self._questions.get(question.id)
        if current is None:
            raise NotFoundError("question not found")
        if current.updated_at != expected:
            raise ConflictError("question was changed concurrently")
        for task in tasks:
            owner = self.outbox.notifications.get(task.notification_id)
            if owner is None or owner.question_id != question.id:
                raise ValidationError("task does not belong to this question's notification")
        self.outbox.check_new(None, tasks)
        self._questions[question.id] = question
        self.outbox.insert(None, tasks)

    def list_expirable(self, now: datetime) -> builtins.list[Question]:
        at = ensure_utc(now, "now")
        due = [
            q
            for q in self._questions.values()
            if q.state is QuestionState.OPEN and q.expires_at <= at and q.id not in self._corrupt
        ]
        return sorted(due, key=lambda q: (q.expires_at, q.id))

    def delete_resolved_before(self, cutoff: datetime) -> int:
        limit = ensure_utc(cutoff, "cutoff")
        doomed = [
            q.id
            for q in self._questions.values()
            if q.state.is_terminal and q.resolved_at is not None and q.resolved_at < limit
        ]
        for question_id in doomed:
            del self._questions[question_id]
        return len(doomed)

    def count(self) -> int:
        """Test helper: number of stored questions."""
        return len(self._questions)


class FakeQuestionEvents:
    """QuestionEvents that records notifications; `wait` works inside one event loop."""

    def __init__(self) -> None:
        self.notified: builtins.list[QuestionId] = []
        self._waiters: dict[QuestionId, builtins.list[asyncio.Event]] = {}

    def notify(self, question_id: QuestionId) -> None:
        self.notified.append(question_id)
        for event in self._waiters.pop(question_id, []):
            event.set()

    async def wait(self, question_id: QuestionId, timeout: float) -> bool:
        event = asyncio.Event()
        self._waiters.setdefault(question_id, []).append(event)
        try:
            await asyncio.wait_for(event.wait(), timeout)
        except TimeoutError:
            return False
        finally:
            waiters = self._waiters.get(question_id, [])
            if event in waiters:
                waiters.remove(event)
        return True


class FakeOutboxEvents:
    """OutboxEvents that counts notifications; `wait` works inside one event loop."""

    def __init__(self) -> None:
        self.notified = 0
        self._waiters: builtins.list[asyncio.Event] = []

    def notify(self) -> None:
        self.notified += 1
        waiters, self._waiters = self._waiters, []
        for event in waiters:
            event.set()

    async def wait(self, timeout: float) -> bool:
        event = asyncio.Event()
        self._waiters.append(event)
        try:
            await asyncio.wait_for(event.wait(), timeout)
        except TimeoutError:
            return False
        finally:
            if event in self._waiters:
                self._waiters.remove(event)
        return True


class FakeChannelError(ConnectionError):
    """What `FakeNotificationChannel` raises while told to fail."""


class FakeNotificationChannel:
    """NotificationChannel that records messages; fails the next `fail_times` calls.

    `send` returns `msg-1`, `msg-2`, ... (or None with `refs=False`).
    """

    def __init__(self, name: str = "fake", *, fail_times: int = 0, refs: bool = True) -> None:
        self.name = name
        self.fail_times = fail_times
        self._refs = refs
        self._count = 0
        self.sent: builtins.list[DeliveryPayload] = []
        self.resolved: builtins.list[tuple[str, DeliveryPayload]] = []

    def _maybe_fail(self) -> None:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise FakeChannelError("fake channel down")

    def send(self, payload: DeliveryPayload) -> str | None:
        self._maybe_fail()
        self._count += 1
        self.sent.append(payload)
        return f"msg-{self._count}" if self._refs else None

    def resolve(self, message_ref: str, payload: DeliveryPayload) -> None:
        self._maybe_fail()
        self.resolved.append((message_ref, payload))


class FakeAnswerSource:
    """AnswerSource fed by `push`; records poll timeouts and acks."""

    def __init__(self, name: str = "fake") -> None:
        self.name = name
        self.inbox: builtins.list[AnswerEvent] = []
        self.polls: builtins.list[float] = []
        self.acks: builtins.list[tuple[str, str]] = []

    def push(self, *events: AnswerEvent) -> None:
        self.inbox.extend(events)

    def poll(self, timeout: float) -> builtins.list[AnswerEvent]:
        self.polls.append(timeout)
        events, self.inbox = self.inbox, []
        return events

    def ack(self, handle: str, text: str) -> None:
        self.acks.append((handle, text))


class InProcessDeliveryQueue:
    """DeliveryQueue calling the admin-side services directly (no HTTP, no tokens).

    Wires the notifier-side `DeliveryService` to a real in-memory core, so a
    test can follow a question from `ask` to the edited message. `down=True`
    makes every call raise, like an unreachable admin socket.
    """

    def __init__(
        self, *, outbox: OutboxService, questions: QuestionService, limit: int = 20
    ) -> None:
        self._outbox = outbox
        self._questions = questions
        self._limit = limit
        self.waits: builtins.list[float] = []
        self.submitted: builtins.list[tuple[str, str, str, str]] = []
        self.down = False

    def _check_up(self) -> None:
        if self.down:
            raise ConnectionError("admin socket unreachable")

    def pending(self, wait: float) -> builtins.list[PendingTask]:
        self._check_up()
        self.waits.append(wait)
        return self._outbox.pending(self._limit)

    def done(self, task_id: TaskId, message_ref: str | None) -> None:
        self._check_up()
        self._outbox.done(task_id, message_ref)

    def failed(self, task_id: TaskId) -> None:
        self._check_up()
        self._outbox.failed(task_id)

    def submit_answer(
        self, question_id: str, key: str, source: str, actor_ref: str
    ) -> AnswerResult:
        self._check_up()
        self.submitted.append((question_id, key, source, actor_ref))
        return self._questions.answer(question_id, key, source)


class InMemoryOwnerMessageStore:
    """OwnerMessageStore (C44): idempotent on the Telegram update, CAS handled mark."""

    def __init__(self) -> None:
        self._messages: dict[OwnerMessageId, OwnerMessage] = {}
        self._corrupt: set[OwnerMessageId] = set()

    def corrupt_message(self, message_id: OwnerMessageId) -> None:
        """Test hook: from now on this message's row fails re-validation (tampered row)."""
        self._corrupt.add(message_id)

    def _checked(self, message: OwnerMessage) -> OwnerMessage:
        if message.id in self._corrupt:
            raise ValidationError("invalid owner message in stored row")
        return message

    def add(self, message: OwnerMessage) -> OwnerMessage:
        if message.state is not InboxState.RECEIVED:
            raise ValidationError("only a received message can be added")
        for stored in self._messages.values():
            if (stored.update_id, stored.telegram_message_id) == (
                message.update_id,
                message.telegram_message_id,
            ):
                return self._checked(stored)
        if message.id in self._messages:
            raise AlreadyExistsError("owner message already exists")
        self._messages[message.id] = message
        return message

    def get(self, message_id: OwnerMessageId) -> OwnerMessage:
        try:
            message = self._messages[message_id]
        except KeyError:
            raise NotFoundError("owner message not found") from None
        return self._checked(message)

    def list_unhandled(self, limit: int) -> builtins.list[OwnerMessage]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValidationError("limit must be an int")
        if not 1 <= limit <= MAX_UNHANDLED_LIMIT:
            raise ValidationError(f"limit must be 1..{MAX_UNHANDLED_LIMIT}")
        due = sorted(
            (m for m in self._messages.values() if m.state is InboxState.RECEIVED),
            key=lambda m: (m.received_at, m.id),
        )[:limit]
        # Like SQLite: the limit applies to rows, then tampered ones are skipped.
        return [m for m in due if m.id not in self._corrupt]

    def mark_handled(self, message_id: OwnerMessageId, at: datetime) -> OwnerMessage:
        at = ensure_utc(at, "at")
        handled = self.get(message_id).handled(at)
        self._messages[message_id] = handled
        return handled

    def delete_received_before(self, cutoff: datetime) -> int:
        limit = ensure_utc(cutoff, "cutoff")
        doomed = [m.id for m in self._messages.values() if m.received_at < limit]
        for message_id in doomed:
            del self._messages[message_id]
        return len(doomed)

    def count(self) -> int:
        """Test helper: number of stored messages."""
        return len(self._messages)


class InMemoryApprovalStore:
    """ApprovalStore (C46): PENDING-only add, one open request per window, CAS + successor."""

    def __init__(self) -> None:
        self._requests: dict[ApprovalId, ApprovalRequest] = {}
        self._corrupt: set[ApprovalId] = set()

    def corrupt_request(self, approval_id: ApprovalId) -> None:
        """Test hook: from now on this request's row fails re-validation (tampered row)."""
        self._corrupt.add(approval_id)

    def _valid(self) -> builtins.list[ApprovalRequest]:
        return [r for r in self._requests.values() if r.id not in self._corrupt]

    def add(self, request: ApprovalRequest) -> None:
        if request.state is not ApprovalState.PENDING:
            raise ValidationError("approval requests are created only as pending")
        # Raw rows, like SQLite's check: a tampered open row still blocks.
        if any(
            r.window_id == request.window_id
            and r.state.is_open
            and r.expires_at > request.created_at
            for r in self._requests.values()
        ):
            raise ConflictError("this window already has an open approval request")
        if request.id in self._requests:
            raise AlreadyExistsError("approval request already exists")
        self._requests[request.id] = request

    def get(self, approval_id: ApprovalId) -> ApprovalRequest:
        try:
            request = self._requests[approval_id]
        except KeyError:
            raise NotFoundError("approval request not found") from None
        if approval_id in self._corrupt:
            raise ValidationError("invalid approval request in stored row")
        return request

    def save(self, request: ApprovalRequest, *, expected_updated_at: datetime) -> None:
        expected = ensure_utc(expected_updated_at, "expected_updated_at")
        stored = self.get(request.id)
        if stored.updated_at != expected:
            raise ConflictError("approval request was changed concurrently")
        check_successor(stored, request)
        self._requests[request.id] = request

    def find_consumed(
        self,
        window_id: WindowId,
        action_kind: ActionKind,
        action_target: str,
        *,
        consumed_since: datetime,
    ) -> ApprovalRequest | None:
        since = ensure_utc(consumed_since, "consumed_since")
        if not isinstance(action_kind, ActionKind):
            raise ValidationError("action_kind must be an ActionKind")
        found = [
            r
            for r in self._valid()
            if r.window_id == window_id
            and r.covers(action_kind, action_target)
            and r.resolved_at is not None
            and r.resolved_at >= since
        ]
        found.sort(key=lambda r: (r.resolved_at or since, r.id), reverse=True)
        return found[0] if found else None

    def list_open(self, window_id: WindowId | None = None) -> builtins.list[ApprovalRequest]:
        found = [
            r
            for r in self._valid()
            if r.state.is_open and (window_id is None or r.window_id == window_id)
        ]
        return sorted(found, key=lambda r: (r.created_at, r.id))

    def list_expirable(self, now: datetime) -> builtins.list[ApprovalRequest]:
        at = ensure_utc(now, "now")
        found = [r for r in self._valid() if r.state.is_open and r.expires_at <= at]
        return sorted(found, key=lambda r: (r.expires_at, r.id))

    def delete_expired_before(self, cutoff: datetime) -> int:
        limit = ensure_utc(cutoff, "cutoff")
        doomed = [r.id for r in self._requests.values() if r.expires_at < limit]
        for approval_id in doomed:
            del self._requests[approval_id]
        return len(doomed)

    def count(self) -> int:
        """Test helper: number of stored requests."""
        return len(self._requests)
