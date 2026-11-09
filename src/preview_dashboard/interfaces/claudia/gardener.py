"""Entry point of the weekly KB gardener (systemd timer, unit M9; docs/security.md C54).

Refuses to start with any API credential variable set (C49) or a run env
that would load the owner's CLAUDE.md / auto memory (F-CL1), commits the KB
as baseline, runs the free pre-pass and, only if it found something, the
confined Haiku pass (`application/claudia/garden.py`). Afterwards it posts one
dashboard summary item and one `done`/`failed` alert through the admin API.
Exit codes: 0 done or nothing to do, 1 reverted/failed, 2 refused to start.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import logging
import os
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Final

from preview_dashboard.adapters.claude_cli import (
    ApiCredentialError,
    RunIsolationError,
    check_run_isolation,
    child_env,
    refuse_api_credentials,
)
from preview_dashboard.adapters.gardener_runner import ClaudeGardenModel
from preview_dashboard.adapters.kb_git import GitKbHistory
from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia.garden import Gardener, GardenStatus
from preview_dashboard.application.claudia.kb import load_prompt
from preview_dashboard.domain.errors import StorageUnavailableError
from preview_dashboard.interfaces.claudia.settings import KB_ROOT
from preview_dashboard.interfaces.mcp.admin_socket import AdminSocketTrustError, verify_admin_socket
from preview_dashboard.interfaces.mcp.client import AdminClient
from preview_dashboard.interfaces.token_file import TokenFileError, load_admin_token

EXIT_OK: Final = 0
EXIT_FAILED: Final = 1
EXIT_REFUSED: Final = 2
_log = logging.getLogger("preview_dashboard.claudia.gardener")


class _MemoryUpload:
    """A tiny in-memory `UploadFile` for the summary (a few KiB of Markdown)."""

    def __init__(self, relpath: str, data: bytes) -> None:
        self.relpath = relpath
        self.size = len(data)
        self._data = data

    def open_reader(self, chunk_size: int = 65536) -> AbstractContextManager[Iterator[bytes]]:
        """Yield the bytes in `chunk_size` pieces."""
        data = self._data
        return contextlib.nullcontext(
            iter([data[i : i + chunk_size] for i in range(0, len(data), chunk_size)])
        )


class AdminGardenReporter:
    """`GardenReporter` over the admin API (admin token, publish + notify)."""

    def __init__(self, client: AdminClient) -> None:
        self._client = client

    def report(self, title: str, markdown: str, *, ok: bool) -> None:
        """Publish the summary item, then send the single alert that references it.

        Raises:
            AdminClientError: the admin API refused or was unreachable.
        """
        item = self._client.publish(
            [_MemoryUpload("gardener-summary.md", markdown.encode("utf-8"))],
            title=title,
            kind_hint="markdown",
        )
        item_id = item.get("id")
        self._client.notify(
            "done" if ok else "failed", title, item_id if isinstance(item_id, str) else None
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Command line of the gardener service."""
    p = argparse.ArgumentParser(prog="claudia-gardener", description=__doc__)
    p.add_argument("--kb-root", type=Path, default=Path(KB_ROOT))
    p.add_argument("--claude-bin", type=Path, default=Path("/usr/local/bin/claude"))
    p.add_argument("--socket", type=Path, default=Path("/run/preview-dashboard/admin.sock"))
    p.add_argument("--token-file", type=Path, default=Path("/etc/preview-dashboard/admin.token"))
    p.add_argument("--viewer-gid", type=int, default=None, help="group for files created")
    return p.parse_args(argv)


def build_gardener(
    args: argparse.Namespace,
    environ: Mapping[str, str],
    client: AdminClient,
    today: Callable[[], datetime.date],
) -> Gardener:
    """Wire the real adapters (the only place that does)."""
    store = FsKbStore(args.kb_root, group_id=args.viewer_gid, exempt_run_lock=True)
    model = ClaudeGardenModel(args.claude_bin, args.kb_root, load_prompt("gardener.md"), environ)
    return Gardener(
        store,
        GitKbHistory(args.kb_root),
        model,
        RegexSecretScanner(),
        AdminGardenReporter(client),
        today,
        run_guard=store.exclusive_run,
    )


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    """Run one gardening pass; returns the process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    env = dict(os.environ if environ is None else environ)
    args = parse_args(argv)
    try:
        refuse_api_credentials(env)  # before anything else: D15/C49
        check_run_isolation(child_env(env))  # F-CL1: no CLAUDE.md / auto memory in runs
        gid = verify_admin_socket(args.socket)
        token = load_admin_token(args.token_file, trusted_gids=(gid,))
    except (ApiCredentialError, RunIsolationError, AdminSocketTrustError, TokenFileError) as exc:
        _log.error("refusing to start: %s", exc)  # names a variable or file, never a value
        return EXIT_REFUSED
    client = AdminClient(args.socket, token)
    try:
        today = lambda: datetime.datetime.now(datetime.UTC).date()  # noqa: E731
        report = build_gardener(args, env, client, today).run()
    except StorageUnavailableError as exc:
        _log.error("gardener failed: %s", exc)
        return EXIT_FAILED
    finally:
        client.close()
    _log.info("gardener finished: %s", report.status.value)
    return EXIT_FAILED if report.status is GardenStatus.REVERTED else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
