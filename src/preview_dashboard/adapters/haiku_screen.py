"""HaikuScreenRunner: runs the strict Haiku screen as a `claude -p` child process (C48, C49).

The argv is a fixed template with no tools, no MCP servers, no settings
sources and no session persistence; the message goes on stdin, never argv.
Each run gets a fresh empty 0700 temp dir as cwd (no project context) and
an environment built from an allowlist (never the inherited one, so no API
key or token path reaches it). The child runs in its own process group,
killed whole on timeout. Never raises for a failed run; logs no text.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess  # nosec B404  # the claude CLI; fixed argv, never a shell
import tempfile
from collections.abc import Mapping

from preview_dashboard.domain.screen_rules import (
    MAX_MODEL_OUTPUT_CHARS,
    ModelRun,
    ModelRunStatus,
)

logger = logging.getLogger("preview_dashboard.claudia.haiku_screen")

SCREEN_MODEL = "haiku"
# C49: only these variables reach the child (HOME locates the subscription
# login; locale/time vars keep output stable). Everything else is dropped.
ENV_ALLOWLIST: tuple[str, ...] = (
    "HOME",
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TZ",
    "USER",
    "LOGNAME",
)
# Bound on reading the child's stdout after a kill, so a hung pipe can't block the host.
_DRAIN_TIMEOUT_S = 5.0


def screen_argv(claude_bin: str, system_prompt: str) -> list[str]:
    """The fixed screen argv (golden-tested): no tools, no MCP, no settings, no persistence."""
    return [
        claude_bin,
        "-p",
        "--model",
        SCREEN_MODEL,
        "--output-format",
        "json",
        "--tools",
        "",
        "--strict-mcp-config",
        "--setting-sources",
        "",
        "--no-session-persistence",
        "--disable-slash-commands",
        "--system-prompt",
        system_prompt,
    ]


def child_env(source: Mapping[str, str]) -> dict[str, str]:
    """Allowlisted copy of `source` (C49): only `ENV_ALLOWLIST` names, nothing inherited."""
    return {name: source[name] for name in ENV_ALLOWLIST if name in source}


class HaikuScreenRunner:
    """Implements `ScreenModelRunner` with the real `claude` CLI.

    Args:
        claude_bin: absolute path to the CLI, or a bare name resolved on the
            allowlisted `PATH` at each run (missing -> `UNAVAILABLE`).
        environ: environment to filter (default: the process environment).
    """

    def __init__(
        self, *, claude_bin: str = "claude", environ: Mapping[str, str] | None = None
    ) -> None:
        self._claude_bin = claude_bin
        self._environ = environ

    def run(self, *, system_prompt: str, stdin_text: str, timeout_s: float) -> ModelRun:
        """Run one screen classification; see `ScreenModelRunner.run`."""
        env = child_env(os.environ if self._environ is None else self._environ)
        binary = self._resolve(env)
        if binary is None:
            logger.warning("screen CLI unavailable")
            return ModelRun(status=ModelRunStatus.UNAVAILABLE)
        with tempfile.TemporaryDirectory(
            prefix="claudia-screen-", ignore_cleanup_errors=True
        ) as cwd:
            os.chmod(cwd, 0o700)  # mkdtemp already uses 0700; asserted, not assumed
            return self._run_in(binary, system_prompt, stdin_text, timeout_s, cwd, env)

    def _resolve(self, env: Mapping[str, str]) -> str | None:
        if os.path.isabs(self._claude_bin):
            ok = os.path.isfile(self._claude_bin) and os.access(self._claude_bin, os.X_OK)
            return self._claude_bin if ok else None
        return shutil.which(self._claude_bin, path=env.get("PATH", ""))

    def _run_in(
        self,
        binary: str,
        system_prompt: str,
        stdin_text: str,
        timeout_s: float,
        cwd: str,
        env: dict[str, str],
    ) -> ModelRun:
        try:
            # Fixed argv list, shell=False; the message goes on stdin only.
            proc = subprocess.Popen(  # noqa: S603  # nosec B603
                screen_argv(binary, system_prompt),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # stderr may echo message text: never read or logged.
                stderr=subprocess.DEVNULL,
                cwd=cwd,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,
            )
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            logger.warning("screen CLI unavailable")
            return ModelRun(status=ModelRunStatus.UNAVAILABLE)
        try:
            stdout, _ = proc.communicate(stdin_text, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self._kill_group(proc)
            return ModelRun(status=ModelRunStatus.TIMEOUT)
        except BaseException:
            self._kill_group(proc)
            raise
        code = proc.returncode
        if code != 0:
            return ModelRun(status=ModelRunStatus.FAILED, exit_code=code)
        if len(stdout) > MAX_MODEL_OUTPUT_CHARS:
            # Oversized output is no verdict; keep it out of memory downstream.
            return ModelRun(status=ModelRunStatus.COMPLETED, stdout="", exit_code=code)
        return ModelRun(status=ModelRunStatus.COMPLETED, stdout=stdout, exit_code=code)

    @staticmethod
    def _kill_group(proc: subprocess.Popen[str]) -> None:
        """SIGKILL the child's whole process group, then reap it (bounded)."""
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            proc.communicate(timeout=_DRAIN_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            logger.error("screen child did not exit after kill: pid=%d", proc.pid)
