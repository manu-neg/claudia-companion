"""Application layer: use-case services (command handlers) over ports.

Pure core — stdlib, `domain`, `ports` and `kinds` only; collaborators are
injected by `bootstrap.py`. Services: publish (+ revisions), history (prune old
revisions, ADR 0030), queries, lifecycle, purge (+ empty trash),
archive (+ the publish rate limiter), folders (ADR 0027), questions,
notify/outbox and the notifier's delivery loop (ADR 0021). See docs/architecture.md.
"""

from __future__ import annotations

from preview_dashboard.application.archive import ArchiveService, download_filename
from preview_dashboard.application.delivery import DeliveryService
from preview_dashboard.application.folders import FolderEntry, FolderListing, FolderService
from preview_dashboard.application.history import HistoryService, PruneResult
from preview_dashboard.application.lifecycle import LifecycleService
from preview_dashboard.application.notify import NotifyService, OutboxService
from preview_dashboard.application.publish import (
    IncomingFile,
    PublishCommand,
    PublishLimits,
    PublishService,
    RevisionCommand,
)
from preview_dashboard.application.purge import (
    MaintenanceHook,
    PostPurgeHook,
    PurgeReport,
    PurgeService,
    QuestionHousekeeping,
)
from preview_dashboard.application.queries import OpenedFile, QueryService
from preview_dashboard.application.questions import AskCommand, QuestionService
from preview_dashboard.application.ratelimit import RateLimiter, SlidingWindowRateLimiter

__all__ = [
    "ArchiveService",
    "AskCommand",
    "DeliveryService",
    "FolderEntry",
    "FolderListing",
    "FolderService",
    "HistoryService",
    "IncomingFile",
    "LifecycleService",
    "MaintenanceHook",
    "NotifyService",
    "OpenedFile",
    "OutboxService",
    "PostPurgeHook",
    "PruneResult",
    "PublishCommand",
    "PublishLimits",
    "PublishService",
    "PurgeReport",
    "PurgeService",
    "QueryService",
    "QuestionHousekeeping",
    "QuestionService",
    "RateLimiter",
    "RevisionCommand",
    "SlidingWindowRateLimiter",
    "download_filename",
]
