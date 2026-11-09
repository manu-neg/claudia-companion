"""adapters.sqlite package: the SQLite item, question and outbox adapters.

`connection.connect` validates the DB location (shared-group model) and
builds hardened, migrated connections;
`migrations.migrate` owns the versioned schema; `repository.SqliteItemRepository`
implements `ports.repository.ItemRepository` over them, and `questions`
implements `QuestionRepository` + `NotificationOutbox` (one shared store, ADR 0021),
`folders` implements `FolderRepository` (same database as the items, ADR 0027),
`owner_messages` / `approvals` implement Claudia's inbox and approval stores (ADR 0031)
over the separate, admin-only database of `claudia_db` (S-C1 S1).
"""

from __future__ import annotations

from preview_dashboard.adapters.sqlite.approvals import SqliteApprovalStore
from preview_dashboard.adapters.sqlite.claudia_db import (
    CLAUDIA_DB_FILENAME,
    CLAUDIA_DIR_MODE,
    CLAUDIA_FILE_MODE,
    CLAUDIA_SCHEMA_VERSION,
    CLAUDIA_SUBDIR,
    connect_claudia,
    default_claudia_db_path,
)
from preview_dashboard.adapters.sqlite.connection import (
    DB_DIR_MODE,
    DB_FILE_MODE,
    DB_FILENAME,
    DB_SUBDIR,
    DatabaseSetupError,
    UnsafeDatabasePathError,
    connect,
    default_db_path,
)
from preview_dashboard.adapters.sqlite.folders import SqliteFolderRepository
from preview_dashboard.adapters.sqlite.migrations import CURRENT_VERSION, migrate
from preview_dashboard.adapters.sqlite.owner_messages import SqliteOwnerMessageStore
from preview_dashboard.adapters.sqlite.questions import (
    SqliteNotificationOutbox,
    SqliteQuestionRepository,
)
from preview_dashboard.adapters.sqlite.repository import ConnectionFactory, SqliteItemRepository

__all__ = [
    "CLAUDIA_DB_FILENAME",
    "CLAUDIA_DIR_MODE",
    "CLAUDIA_FILE_MODE",
    "CLAUDIA_SCHEMA_VERSION",
    "CLAUDIA_SUBDIR",
    "CURRENT_VERSION",
    "DB_DIR_MODE",
    "DB_FILENAME",
    "DB_FILE_MODE",
    "DB_SUBDIR",
    "ConnectionFactory",
    "DatabaseSetupError",
    "SqliteApprovalStore",
    "SqliteFolderRepository",
    "SqliteItemRepository",
    "SqliteNotificationOutbox",
    "SqliteOwnerMessageStore",
    "SqliteQuestionRepository",
    "UnsafeDatabasePathError",
    "connect",
    "connect_claudia",
    "default_claudia_db_path",
    "default_db_path",
    "migrate",
]
