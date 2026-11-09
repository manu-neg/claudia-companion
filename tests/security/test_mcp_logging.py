"""Security tests for the MCP server's output hygiene (docs/security.md C12, C27, C29, C30).

stdout is the MCP protocol channel: the real `preview-dashboard-mcp` process
(run as a subprocess against a real admin API) must write nothing there but
JSON-RPC messages, even while tools fail. Logs go to stderr and never contain
the admin token or published file contents; startup failures are one line.
"""

from __future__ import annotations

import json
import logging
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from preview_dashboard.interfaces.mcp.server import DashboardTools, build_server
from tests.mcp_support import LiveAdmin, fake_aws_key, live_admin, strip_pdash_env, write_file

pytestmark = pytest.mark.security

CONTENT_MARKER = "CONTENT-MARKER-7f3a9c-never-logged"
# Caller-supplied names that only ever appear in tool *error* text (C29).
NAME_MARKER = "NAME-MARKER-2c8e41"
UNIT_MARKER = "Q7ZUNITX9"


def _write_config(tmp_path: Path, admin: LiveAdmin) -> Path:
    """A root-owned 0600 TOML config in a 0700 dir (passes the C16 checks)."""
    settings = admin.settings
    conf_dir = tmp_path / "conf"
    conf_dir.mkdir(mode=0o700)
    config = conf_dir / "config.toml"
    config.write_text(
        "\n".join(
            [
                f'data_dir = "{settings.data_dir}"',
                f'admin_socket = "{settings.admin_socket}"',
                f'admin_token_file = "{settings.admin_token_file}"',
                f'intake_allowed_roots = ["{admin.outbox}"]',
                'allowed_hosts = ["dash.example.ts.net"]',
                "max_file_bytes = 65536",
                "max_item_bytes = 262144",
                "",
            ]
        )
    )
    os.chmod(config, 0o600)
    return config


class _McpProcess:
    """The real MCP server as a subprocess, spoken to in raw JSON-RPC over stdio."""

    def __init__(self, config: Path) -> None:
        env = {**strip_pdash_env(), "PDASH_CONFIG": str(config), "PYTHONUNBUFFERED": "1"}
        self.proc = subprocess.Popen(  # fixed argv: our own module
            [sys.executable, "-m", "preview_dashboard.interfaces.mcp.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        self.stdout_lines: list[bytes] = []
        self._next_id = 0
        self._stderr = bytearray()
        # Drain stderr concurrently so a chatty log can never fill the pipe and stall.
        self._drain = threading.Thread(target=self._read_stderr, daemon=True)
        self._drain.start()

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        stream = self.proc.stderr
        while chunk := stream.read1(65536):  # type: ignore[attr-defined]  # a BufferedReader
            self._stderr += chunk

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message).encode() + b"\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        wanted = self._next_id
        self.send({"jsonrpc": "2.0", "id": wanted, "method": method, "params": params})
        assert self.proc.stdout is not None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.proc.stdout], [], [], 1)
            if not ready:
                continue
            line = self.proc.stdout.readline()
            if not line:
                raise AssertionError("MCP server closed stdout")
            self.stdout_lines.append(line)
            message = json.loads(line)
            if message.get("id") == wanted:
                return dict(message)
        raise AssertionError(f"no response to {method}")

    def call(self, tool: str, **args: Any) -> dict[str, Any]:
        response = self.request("tools/call", {"name": tool, "arguments": args})
        return dict(response["result"])

    def finish(self) -> tuple[bytes, bytes]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.close()
        self.stdout_lines.extend(self.proc.stdout.read().splitlines(keepends=True))
        self.proc.wait(timeout=30)
        self._drain.join(timeout=30)
        return b"".join(self.stdout_lines), bytes(self._stderr)


def _handshake(mcp: _McpProcess) -> None:
    init = mcp.request(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "preview-dashboard"
    mcp.send({"jsonrpc": "2.0", "method": "notifications/initialized"})


def test_stdout_is_protocol_only_and_token_never_logged(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        config = _write_config(tmp_path, admin)
        good = write_file(admin.outbox / "page.html", f"<p>{CONTENT_MARKER}</p>")
        denied = write_file(admin.outbox / "id_rsa", CONTENT_MARKER)
        denied_named = write_file(admin.outbox / f"{NAME_MARKER}.pem", CONTENT_MARKER)
        leaky = write_file(admin.outbox / "leak.txt", f"{CONTENT_MARKER} {fake_aws_key()}")
        mcp = _McpProcess(config)
        try:
            _handshake(mcp)
            tools = mcp.request("tools/list", {})["result"]["tools"]
            names = {t["name"] for t in tools}
            assert len(tools) == 21
            assert {
                "dashboard_prune_revisions",
                "dashboard_empty_trash",
                "dashboard_progress_set",
                "dashboard_progress_update",
                "dashboard_ask",
                "dashboard_wait_answer",
                "dashboard_notify",
                "dashboard_cancel_question",
            } <= names
            asked = mcp.call(
                "dashboard_ask",
                prompt=f"Pick one {CONTENT_MARKER}",
                options=[{"key": "a", "label": "Alpha"}, {"key": "b", "label": "Beta"}],
                session_label="logging test",
            )
            assert not asked.get("isError"), asked
            question = json.loads(asked["content"][0]["text"])["question"]
            cancelled = mcp.call("dashboard_cancel_question", question_id=question["id"])
            assert json.loads(cancelled["content"][0]["text"])["question"]["state"] == "cancelled"
            ok = mcp.call("dashboard_publish", paths=[str(good)], title="Page")
            assert not ok.get("isError"), ok
            item = json.loads(ok["content"][0]["text"])
            assert item["kind"] == "html" and item["viewer_url"]
            for result in (
                mcp.call("dashboard_publish", paths=[str(denied)], title="key"),
                mcp.call("dashboard_publish", paths=[str(denied_named)], title="named"),
                mcp.call("dashboard_publish", paths=[str(leaky)], title="leak"),
                mcp.call("dashboard_get", item_id="01J0000000000000000000000Z"),
                mcp.call("dashboard_get", item_id="not-an-id"),
                mcp.call("dashboard_update", item_id=item["id"]),
            ):
                assert result.get("isError") is True
                assert "Traceback" not in result["content"][0]["text"]
            assert mcp.call("dashboard_trash", item_id=item["id"]).get("isError") is not True
            # Progress trackers: status text (content) never reaches the log either.
            tracker = mcp.call(
                "dashboard_progress_set",
                status={
                    "title": f"Tracker {CONTENT_MARKER}",
                    "units": [{"id": "U1", "name": CONTENT_MARKER, "state": "running"}],
                },
            )
            assert not tracker.get("isError"), tracker
            tracker_id = json.loads(tracker["content"][0]["text"])["id"]
            patched = mcp.call(
                "dashboard_progress_update", item_id=tracker_id, unit_id="U1", state="done"
            )
            assert not patched.get("isError"), patched
            leaked = mcp.call("dashboard_progress_update", item_id=tracker_id, note=fake_aws_key())
            assert leaked.get("isError") is True
            unknown = mcp.call(
                "dashboard_progress_update", item_id=tracker_id, unit_id=UNIT_MARKER, state="done"
            )
            assert unknown.get("isError") is True
            assert UNIT_MARKER in unknown["content"][0]["text"]  # the caller does see it
            # main() wires the publish-only denylist: the state dir is never published.
            state = admin.outbox / "progress-state" / tracker_id / "state.json"
            refused = mcp.call("dashboard_publish", paths=[str(state)], title="state")
            assert refused.get("isError") is True
            assert "intake refused (denied)" in refused["content"][0]["text"]
        finally:
            stdout, stderr = mcp.finish()

    assert mcp.proc.returncode == 0
    # Every stdout line is a JSON-RPC message: nothing else ever reaches it.
    for line in stdout.splitlines():
        message = json.loads(line)
        assert message.get("jsonrpc") == "2.0", line
    token = admin.token.encode()
    assert token not in stdout
    assert token not in stderr
    assert CONTENT_MARKER.encode() not in stderr
    assert fake_aws_key().encode() not in stderr
    assert fake_aws_key().encode() not in stdout
    assert b"Traceback" not in stderr
    # The SDK's "Tool ... failed: <text>" records are capped away: a refused
    # file's name and an unknown unit id reach the caller, never the log.
    assert NAME_MARKER.encode() not in stderr
    assert UNIT_MARKER.encode() not in stderr
    assert b"refused by intake: denied" in stderr  # our own record: the code only
    assert b"publish ok" in stderr  # logging does work, on stderr


def test_startup_failure_is_one_clean_stderr_message(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        config = _write_config(tmp_path, admin)
        os.chmod(admin.settings.admin_token_file, 0o644)  # C12: must refuse
        env = {**strip_pdash_env(), "PDASH_CONFIG": str(config)}
        proc = subprocess.run(  # fixed argv: our own module
            [sys.executable, "-m", "preview_dashboard.interfaces.mcp.server"],
            input=b"",
            capture_output=True,
            env=env,
            timeout=60,
            check=False,
        )
    assert proc.returncode == 1
    assert proc.stdout == b""
    assert b"TokenFileError" in proc.stderr
    assert b"Traceback" not in proc.stderr
    assert admin.token.encode() not in proc.stderr


def test_insecure_config_file_refused(tmp_path: Path) -> None:
    with live_admin(tmp_path) as admin:
        config = _write_config(tmp_path, admin)
        os.chmod(config, 0o620)  # C16: group-writable config must be refused
        env = {**strip_pdash_env(), "PDASH_CONFIG": str(config)}
        proc = subprocess.run(  # fixed argv: our own module
            [sys.executable, "-m", "preview_dashboard.interfaces.mcp.server"],
            input=b"",
            capture_output=True,
            env=env,
            timeout=60,
            check=False,
        )
    assert proc.returncode == 1
    assert proc.stdout == b""
    assert b"ConfigError" in proc.stderr


def test_refuses_to_start_when_the_named_config_file_is_missing(tmp_path: Path) -> None:
    """I6: an explicit PDASH_CONFIG that doesn't exist must not mean "use defaults"."""
    missing = tmp_path / "conf" / "config.toml"
    env = {**strip_pdash_env(), "PDASH_CONFIG": str(missing)}
    proc = subprocess.run(  # fixed argv: our own module
        [sys.executable, "-m", "preview_dashboard.interfaces.mcp.server"],
        input=b"",
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 1
    assert proc.stdout == b""
    assert b"ConfigError" in proc.stderr
    assert b"does not exist" in proc.stderr
    assert b"Traceback" not in proc.stderr


def test_refuses_to_start_with_a_stray_pdash_env_var(tmp_path: Path) -> None:
    """C30/ADR 0016: the registration must carry no env; PDASH_CONFIG is the one exception."""
    with live_admin(tmp_path) as admin:
        config = _write_config(tmp_path, admin)
        env = {**strip_pdash_env(), "PDASH_CONFIG": str(config), "PDASH_MAX_ITEMS": "1"}
        proc = subprocess.run(  # fixed argv: our own module
            [sys.executable, "-m", "preview_dashboard.interfaces.mcp.server"],
            input=b"",
            capture_output=True,
            env=env,
            timeout=60,
            check=False,
        )
    assert proc.returncode == 1
    assert proc.stdout == b""
    assert b"PDASH_MAX_ITEMS" in proc.stderr
    # One clean line: no traceback, and PDASH_CONFIG (the allowed exception) isn't blamed.
    assert b"Traceback" not in proc.stderr
    assert b"PDASH_CONFIG" not in proc.stderr
    assert len([line for line in proc.stderr.splitlines() if line.strip()]) == 1


def test_refuses_to_start_when_admin_socket_is_untrusted(tmp_path: Path) -> None:
    """M1: the socket is checked before the token is ever read, let alone sent."""
    with live_admin(tmp_path) as admin:
        settings = admin.settings
        # A regular file where the admin socket should be: never a real
        # Unix socket admin.sock could actually be.
        bogus_socket = tmp_path / "not-a-socket"
        bogus_socket.write_text("nope")
        conf_dir = tmp_path / "conf2"
        conf_dir.mkdir(mode=0o700)
        config = conf_dir / "config.toml"
        config.write_text(
            "\n".join(
                [
                    f'data_dir = "{settings.data_dir}"',
                    f'admin_socket = "{bogus_socket}"',
                    f'admin_token_file = "{settings.admin_token_file}"',
                    f'intake_allowed_roots = ["{admin.outbox}"]',
                    'allowed_hosts = ["dash.example.ts.net"]',
                    "max_file_bytes = 65536",
                    "max_item_bytes = 262144",
                    "",
                ]
            )
        )
        os.chmod(config, 0o600)
        env = {**strip_pdash_env(), "PDASH_CONFIG": str(config)}
        proc = subprocess.run(  # fixed argv: our own module
            [sys.executable, "-m", "preview_dashboard.interfaces.mcp.server"],
            input=b"",
            capture_output=True,
            env=env,
            timeout=60,
            check=False,
        )
    assert proc.returncode == 1
    assert proc.stdout == b""
    assert b"AdminSocketTrustError" in proc.stderr
    assert admin.token.encode() not in proc.stderr


async def test_in_process_logs_never_contain_token_or_contents(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    # Worst case: every logger (incl. httpx/httpcore) at DEBUG.
    caplog.set_level(logging.DEBUG)
    for name in ("httpx", "httpcore", "mcp", "preview_dashboard"):
        caplog.set_level(logging.DEBUG, logger=name)
    with live_admin(tmp_path) as admin, admin.client() as http:
        good = write_file(admin.outbox / "a.md", f"# {CONTENT_MARKER}")
        leaky = write_file(admin.outbox / "b.txt", f"{CONTENT_MARKER} {fake_aws_key()}")
        server = build_server(DashboardTools(intake=admin.intake(), admin=http))
        async with Client(server) as client:
            ok = await client.call_tool("dashboard_publish", {"paths": [str(good)], "title": "A"})
            assert not ok.is_error
            bad = await client.call_tool("dashboard_publish", {"paths": [str(leaky)], "title": "B"})
            assert bad.is_error
            await client.call_tool("dashboard_list", {})
    text = caplog.text
    assert admin.token not in text
    assert f"Bearer {admin.token}" not in text
    assert CONTENT_MARKER not in text
    assert fake_aws_key() not in text
    assert capsys.readouterr().out == ""
