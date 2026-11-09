"""Runs the shared port contract suites against the in-memory fakes.

Proves `tests/fakes.py` behaves like a real adapter, so application unit
tests built on the fakes are trustworthy.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from tests.contracts.approval_store import ApprovalStoreContract, ApprovalStoreHandle
from tests.contracts.blob_store import BlobStoreContract
from tests.contracts.folder_repository import FolderRepositoryContract, FolderStore
from tests.contracts.item_repository import ItemRepositoryContract
from tests.contracts.owner_message_store import MessageStore, OwnerMessageStoreContract
from tests.contracts.question_store import (
    NotificationOutboxContract,
    NotifyStore,
    QuestionRepositoryContract,
)
from tests.fakes import (
    InMemoryApprovalStore,
    InMemoryBlobStore,
    InMemoryFolderRepository,
    InMemoryItemRepository,
    InMemoryNotificationOutbox,
    InMemoryOwnerMessageStore,
    InMemoryQuestionRepository,
)

pytestmark = pytest.mark.unit


class TestInMemoryItemRepository(ItemRepositoryContract):
    @pytest.fixture
    def repo(self) -> InMemoryItemRepository:
        return InMemoryItemRepository()

    @pytest.fixture
    def folders(self, repo: InMemoryItemRepository) -> InMemoryFolderRepository:
        return InMemoryFolderRepository(repo)


class TestInMemoryFolderRepository(FolderRepositoryContract):
    @pytest.fixture
    def store(self) -> FolderStore:
        folders = InMemoryFolderRepository()
        return FolderStore(
            items=folders.items, folders=folders, corrupt_folder=folders.corrupt_folder
        )


class TestInMemoryBlobStore(BlobStoreContract):
    @pytest.fixture
    def store(self) -> InMemoryBlobStore:
        return InMemoryBlobStore()

    @pytest.fixture
    def store_with_capacity(self) -> Callable[[int], InMemoryBlobStore]:
        return lambda capacity: InMemoryBlobStore(capacity_bytes=capacity)


def _fake_notify_store() -> NotifyStore:
    outbox = InMemoryNotificationOutbox()
    repo = InMemoryQuestionRepository(outbox)
    return NotifyStore(
        repo=repo,
        outbox=outbox,
        corrupt_task=outbox.corrupt_task,
        corrupt_question=repo.corrupt_question,
    )


class TestInMemoryQuestionRepository(QuestionRepositoryContract):
    @pytest.fixture
    def store(self) -> NotifyStore:
        return _fake_notify_store()


class TestInMemoryNotificationOutbox(NotificationOutboxContract):
    @pytest.fixture
    def store(self) -> NotifyStore:
        return _fake_notify_store()


class TestInMemoryOwnerMessageStore(OwnerMessageStoreContract):
    @pytest.fixture
    def ms(self) -> MessageStore:
        store = InMemoryOwnerMessageStore()
        return MessageStore(store=store, corrupt=store.corrupt_message)


class TestInMemoryApprovalStore(ApprovalStoreContract):
    @pytest.fixture
    def aps(self) -> ApprovalStoreHandle:
        store = InMemoryApprovalStore()
        return ApprovalStoreHandle(store=store, corrupt=store.corrupt_request)
