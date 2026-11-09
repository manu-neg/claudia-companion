"""Haiku pass of the weekly gardener over the `claude` CLI (docs/security.md C54).

The model gets exactly one tool family, the `claudia-kb` MCP server pinned
to the KB root with `--caller gardener` (so `persona.md` is refused): no
built-in tools (`--tools ""`), no other MCP servers (`--strict-mcp-config`),
no settings sources, no session file, at most `MAX_TURNS` turns, subscription
login only (the allowlisted `child_env`; API-key refusal is the caller's).
When the run ends its process group gets SIGTERM, a ≤ 5 s grace, then SIGKILL.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import subprocess  # nosec B404 - fixed argv list, no shell (C54)
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from preview_dashboard.adapters.claude_cli import child_env, parse_run_output
from preview_dashboard.ports.claudia_gardener import GardenModelRun

MAX_TURNS: Final = 20
MODEL: Final = "haiku"
KB_SERVER: Final = "claudia-kb"
KB_TOOLS: Final = tuple(f"mcp__{KB_SERVER}__{t}" for t in ("kb_read", "kb_write", "kb_delete"))
RUN_TIMEOUT_S: Final = 20 * 60.0
MAX_OUTPUT_BYTES: Final = 1024 * 1024
_KILL_REAP_S: Final = 5.0
# SIGTERM -> SIGKILL grace: long enough for the MCP child's exit commit, bounded (≤ 5 s).
KILL_GRACE_S: Final = 5.0
_POLL_S: Final = 0.05
logger = logging.getLogger(__name__)


def kb_mcp_config(kb_root: Path, python: str = sys.executable) -> dict[str, object]:
    """The only MCP config the gardener sees: `claudia-kb` on `kb_root`, caller `gardener`."""
    return {
        "mcpServers": {
            KB_SERVER: {
                "command": python,
                "args": [
                    "-I",  # isolated: cwd and PYTHON* never reach sys.path (like the units)
                    "-m",
                    "preview_dashboard.interfaces.claudia.kb_mcp",
                    "--root",
                    str(kb_root),
                    "--caller",
                    "gardener",
                ],
            }
        }
    }


def gardener_argv(claude_bin: str, mcp_config: Path, system_prompt: str) -> list[str]:
    """The fixed gardener argv (golden-tested); the findings go to stdin, not argv."""
    return [
        claude_bin,
        "-p",
        "--model",
        MODEL,
        "--output-format",
        "json",
        "--tools",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_config),
        f"--allowedTools={','.join(KB_TOOLS)}",
        "--max-turns",
        str(MAX_TURNS),
        "--setting-sources",
        "",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--system-prompt",
        system_prompt,
    ]


class ClaudeGardenModel:
    """`GardenModel` running `claude -p --model haiku` with only the KB tool.

    Args:
        claude_bin: absolute path of the CLI.
        kb_root: the KB directory the MCP server is pinned to.
        system_prompt: the gardener's fixed instructions.
        environ: source environment, filtered through `child_env` per run.
        timeout_s: wall-clock limit; the process group is killed after it.
        kill_grace_s: SIGTERM -> SIGKILL grace for the group (0 < grace ≤ 5 s).

    Raises (constructor):
        ValueError: a relative path or a grace outside (0, 5].
    """

    def __init__(
        self,
        claude_bin: Path,
        kb_root: Path,
        system_prompt: str,
        environ: Mapping[str, str],
        *,
        timeout_s: float = RUN_TIMEOUT_S,
        kill_grace_s: float = KILL_GRACE_S,
    ) -> None:
        if not claude_bin.is_absolute() or not kb_root.is_absolute():
            raise ValueError("claude_bin and kb_root must be absolute paths")
        if not 0 < kill_grace_s <= KILL_GRACE_S:
            raise ValueError("kill_grace_s must be in (0, 5]")
        self._grace = kill_grace_s
        self._bin = claude_bin
        self._root = kb_root
        self._system = system_prompt
        self._env = child_env(environ)
        self._timeout = timeout_s

    def run(self, prompt: str) -> GardenModelRun:
        """Run once; every failure (spawn, timeout, error result) is `ok=False`."""
        prefix = "claudia-gardener-"
        with tempfile.TemporaryDirectory(prefix=prefix, ignore_cleanup_errors=True) as d:
            work = Path(d)
            os.chmod(work, 0o700)
            config = work / "mcp.json"
            config.write_text(json.dumps(kb_mcp_config(self._root)), encoding="utf-8")
            return self._spawn(gardener_argv(str(self._bin), config, self._system), prompt, work)

    def _spawn(self, argv: list[str], prompt: str, cwd: Path) -> GardenModelRun:
        with tempfile.TemporaryFile() as out:
            try:
                proc = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, no shell
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=out,
                    stderr=subprocess.DEVNULL,  # may echo note text: never kept
                    cwd=cwd,
                    env=self._env,
                    start_new_session=True,
                    close_fds=True,
                )
            except OSError as exc:
                logger.error("gardener claude could not start (%s)", type(exc).__name__)
                return GardenModelRun(ok=False)
            try:
                proc.communicate(prompt.encode("utf-8", "replace"), timeout=self._timeout)
            except subprocess.TimeoutExpired:
                logger.error("gardener run exceeded %.0f s; killing it", self._timeout)
                self._kill(proc)
                return GardenModelRun(ok=False)
            except BaseException:
                self._kill(proc)
                raise
            # Reap leftovers (the MCP child) so none can race the post-run commit
            # (kb-map-1); the gardener's own commit covers what it did not commit.
            self._kill(proc)
            out.seek(0)
            raw = out.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            return GardenModelRun(ok=False)
        outcome = parse_run_output(raw, proc.returncode)
        return GardenModelRun(ok=not outcome.is_error, text=outcome.result_text)

    def _kill(self, proc: subprocess.Popen[bytes]) -> None:
        """SIGTERM the run's process group, wait up to the grace, then SIGKILL (fixcheck-a-1).

        SIGTERM first: the MCP child commits on SIGTERM and git removes its
        own `index.lock` on SIGTERM, while a SIGKILL mid-commit leaves a stale
        lock that blocks every later git call (cleared under the run lock).
        """
        pgid = proc.pid
        _signal_group(pgid, signal.SIGTERM)
        deadline = time.monotonic() + self._grace
        while time.monotonic() < deadline and _group_alive(pgid, proc):
            time.sleep(_POLL_S)
        if _group_alive(pgid, proc):
            logger.warning("gardener run group still alive after %.1f s; killing it", self._grace)
            _signal_group(pgid, signal.SIGKILL)
            with contextlib.suppress(OSError):
                proc.kill()  # the leader, if it already left its group
        try:
            proc.wait(timeout=_KILL_REAP_S)
        except subprocess.TimeoutExpired:
            logger.error("gardener child did not exit after kill: pid=%d", proc.pid)


def _signal_group(pgid: int, sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, sig)


def _group_alive(pgid: int, leader: subprocess.Popen[bytes]) -> bool:
    """True while the leader or any process of its group is alive.

    The pgid stays ours while the leader is unreaped or the group has members,
    so polling it never reaches an unrelated process.
    """
    if leader.poll() is None:
        return True
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
