"""F-CL1 items 2 + 3: the hook blocks dashboard bypasses and lets read-only `gh api` through.

Item 2 (C51/C59): Bash that runs the dashboard MCP server, the
`preview-dashboard` CLI, the install's venv or the admin socket, and
Edit/Write content that scripts them, are denied as `dashboard_bypass`
(audited, never approvable); repo slugs and ordinary commands are not.
Item 3 (C59): `gh api <path>` as a plain GET (globbed `?query`, a quoted
`--jq` holding `|`) is no decision; every mutating or unreadable form stays
`unknown`.
"""

from __future__ import annotations

import json

import pytest

from preview_dashboard.application.claudia.approval_flow import DenialRecorder
from preview_dashboard.application.claudia.hook_gate import (
    REASON_DASHBOARD_BYPASS,
    HookGate,
    HookVerdict,
)
from preview_dashboard.domain import risky_actions as ra
from preview_dashboard.domain.dashboard_bypass import (
    DASHBOARD_BYPASS_LABEL,
    REFERENCE_PATTERN,
    WRITES_REFERENCE_KEY,
    bash_bypasses_dashboard,
    content_bypasses_dashboard,
    is_dashboard_bypass,
)
from preview_dashboard.interfaces.claudia import hook as hook_cmd
from preview_dashboard.interfaces.claudia.hook import _REASON_RE
from tests.claudia_host_support import WINDOW_A, FakeAuditLog
from tests.fakes import FixedClock

pytestmark = pytest.mark.security

CWD = "/var/lib/claudia-host/work"

# --- item 2: dashboard bypass ------------------------------------------------------------

BYPASS_COMMANDS = [
    "/opt/preview-dashboard/.venv/bin/preview-dashboard-mcp",
    "python3 work/notify.py | /opt/preview-dashboard/.venv/bin/preview-dashboard-mcp",
    "preview-dashboard notify failed 'x'",
    "preview-dashboard question wait 01J",
    "/opt/preview-dashboard/.venv/bin/preview-dashboard notify done x",
    "sudo -u root preview-dashboard notify done x",
    "env A=1 preview-dashboard notify done x",
    "X=1 preview-dashboard list",
    "nohup preview-dashboard notify done x &",
    "python3 /usr/local/bin/preview-dashboard notify done x",
    "./preview-dashboard notify x",
    'cd /tmp; preview-dash""board notify x',
    "sh -c 'preview-dashboard notify done x'",
    'bash -c "/opt/preview-dashboard/.venv/bin/python -m preview_dashboard.interfaces.mcp"',
    "python3 -c \"import subprocess; subprocess.run(['preview-dashboard', 'notify', 'x'])\"",
    "python3 -c 'import preview_dashboard'",
    "python3 -m preview_dashboard.interfaces.mcp.server",
    "curl --unix-socket /run/preview-dashboard/admin.sock http://x/v1/notify",
    "socat - UNIX-CONNECT:/run/preview-dashboard/admin.sock",
    "cat /etc/preview-dashboard/admin.token",
    "ls /opt/preview-dashboard/.venv/bin",
    'echo \'{"method":"tools/call","params":{"name":"dashboard_notify"}}\' | x',
    "uv run preview-dashboard notify done x",
]

NOT_BYPASS_COMMANDS = [
    "gh api repos/example-org/preview-dashboard/commits?per_page=5",
    "gh repo view example-org/preview-dashboard",
    "git clone https://github.com/example-org/preview-dashboard",
    "cd preview-dashboard",
    "ls -la",
    "git log --oneline -5",
    "echo hola",
    "cat notes/preview-dashboard-ideas.md",
]


@pytest.mark.parametrize("command", BYPASS_COMMANDS)
def test_fcl1_bash_dashboard_bypass_detected(command: str) -> None:
    assert bash_bypasses_dashboard(command), command


@pytest.mark.parametrize("command", NOT_BYPASS_COMMANDS)
def test_fcl1_ordinary_commands_are_not_a_bypass(command: str) -> None:
    assert not bash_bypasses_dashboard(command), command


NOTIFY_SCRIPT = (
    "import json, subprocess\n"
    "p = subprocess.Popen(['/opt/preview-dashboard/.venv/bin/preview-dashboard-mcp'])\n"
)


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Write", {"file_path": "/w/notify.py", "content": NOTIFY_SCRIPT}),
        ("Write", {"file_path": "/w/a.sh", "content": "preview-dashboard notify failed x\n"}),
        ("Write", {"file_path": "/w/a.py", "content": "call('dashboard_notify', {})"}),
        ("Write", {"file_path": "/w/a.py", "content": "s.connect('/run/preview-dashboard/x')"}),
        ("Write", {"file_path": "/w/a.py", "content": "open('/etc/preview-dashboard/t.token')"}),
        ("Edit", {"file_path": "/w/a.py", "old_string": "x", "new_string": "admin.sock"}),
        ("MultiEdit", {"file_path": "/w/a", "edits": [{"new_string": "preview-dashboard-mcp"}]}),
        ("NotebookEdit", {"notebook_path": "/w/n.ipynb", "new_source": "import preview_dashboard"}),
    ],
)
def test_fcl1_written_content_bypass_detected(tool: str, tool_input: dict[str, object]) -> None:
    assert content_bypasses_dashboard(tool, tool_input)
    assert is_dashboard_bypass(tool, tool_input)


def test_fcl1_ordinary_content_is_not_a_bypass() -> None:
    tool_input = {"file_path": "/w/notes.md", "content": "The preview dashboard shows items.\n"}
    assert not is_dashboard_bypass("Write", tool_input)


def _gate() -> tuple[HookGate, FakeAuditLog, DenialRecorder]:
    log = FakeAuditLog()
    recorder = DenialRecorder(log)
    gate = HookGate(recorder, FixedClock())
    gate.begin_run(WINDOW_A)
    return gate, log, recorder


def _call(tool: str, tool_input: dict[str, object]) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": WINDOW_A,
        "cwd": CWD,
        "tool_name": tool,
        "tool_input": tool_input,
    }


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Bash", {"command": "python3 notify.py; preview-dashboard notify failed x"}),
        ("Bash", {"command": "/opt/preview-dashboard/.venv/bin/preview-dashboard-mcp"}),
        ("Write", {"file_path": f"{CWD}/notify.py", "content": NOTIFY_SCRIPT}),
    ],
)
def test_fcl1_gate_denies_bypass_audited_and_not_approvable(
    tool: str, tool_input: dict[str, object]
) -> None:
    gate, log, recorder = _gate()
    decision = gate.decide(_call(tool, tool_input))
    assert decision.verdict is HookVerdict.DENY
    assert decision.reason == REASON_DASHBOARD_BYPASS
    assert log.entries[-1]["action_kind"] == DASHBOARD_BYPASS_LABEL
    assert log.entries[-1]["action_target"] is None
    # Not approvable: the approval flow never asks for it.
    assert recorder.last(WINDOW_A) is None
    # No command or file text in the audit entry (C52, C59).
    assert "notify" not in str(log.entries[-1]).replace("dashboard_bypass", "")


def test_fcl1_bypass_reason_fits_the_hook_output_rule() -> None:
    assert _REASON_RE.fullmatch(REASON_DASHBOARD_BYPASS)
    assert "reply" in REASON_DASHBOARD_BYPASS


def test_fcl1_gate_leaves_ordinary_calls_to_the_guard() -> None:
    gate, _log, _recorder = _gate()
    decision = gate.decide(_call("Bash", {"command": "gh repo view example-org/preview-dashboard"}))
    assert decision.verdict is HookVerdict.NO_DECISION


def test_fcl1_hook_pattern_equals_the_domain_pattern() -> None:
    # The hook stays stdlib-only, so it carries a copy: the two must never drift.
    assert hook_cmd.CONTENT_REFERENCE_PATTERN == REFERENCE_PATTERN
    assert hook_cmd.WRITES_REFERENCE_KEY == WRITES_REFERENCE_KEY


def _hook_input(tool: str, tool_input: dict[str, object]) -> bytes:
    return json.dumps(_call(tool, tool_input)).encode("utf-8")


@pytest.mark.parametrize(
    ("tool", "tool_input"),
    [
        ("Write", {"file_path": f"{CWD}/notify.py", "content": NOTIFY_SCRIPT}),
        ("Edit", {"file_path": f"{CWD}/a.py", "old_string": "x", "new_string": "admin.sock"}),
        ("MultiEdit", {"file_path": f"{CWD}/a", "edits": [{"new_string": "dashboard_ask"}]}),
        ("NotebookEdit", {"notebook_path": f"{CWD}/n.ipynb", "new_source": "-m preview_dashboard"}),
    ],
)
def test_fcl1_hook_forwards_the_verdict_never_the_content(
    tool: str, tool_input: dict[str, object]
) -> None:
    call = hook_cmd.trim_call(_hook_input(tool, tool_input))
    forwarded = call["tool_input"]
    assert isinstance(forwarded, dict)
    assert forwarded[WRITES_REFERENCE_KEY] is True
    assert not {"content", "new_string", "new_source", "edits"} & forwarded.keys()
    # End to end through the gate: denied as a bypass.
    gate, _log, _recorder = _gate()
    decision = gate.decide(call)
    assert decision.verdict is HookVerdict.DENY
    assert decision.reason == REASON_DASHBOARD_BYPASS


def test_fcl1_hook_ignores_a_model_supplied_verdict() -> None:
    tool_input: dict[str, object] = {
        "file_path": f"{CWD}/notify.py",
        "content": NOTIFY_SCRIPT,
        WRITES_REFERENCE_KEY: False,
    }
    forwarded = hook_cmd.trim_call(_hook_input("Write", tool_input))["tool_input"]
    assert isinstance(forwarded, dict)
    assert forwarded[WRITES_REFERENCE_KEY] is True


def test_fcl1_hook_plain_write_carries_no_verdict() -> None:
    tool_input = {"file_path": f"{CWD}/notes.md", "content": "hola", WRITES_REFERENCE_KEY: True}
    forwarded = hook_cmd.trim_call(_hook_input("Write", tool_input))["tool_input"]
    assert isinstance(forwarded, dict)
    assert WRITES_REFERENCE_KEY not in forwarded


# --- item 3: read-only gh api ------------------------------------------------------------

READ_ONLY_GH_API = [
    # The evidence form (window 31134ad8): a globbed query and a quoted jq pipe.
    'gh api repos/example-org/preview-dashboard/commits?per_page=5 --jq ".[] | .sha"',
    "gh api 'repos/o/r/commits?per_page=5' --jq '.[] | {sha: .sha, msg: .commit.message}'",
    "gh api repos/o/r/pulls --paginate --jq '.[].number'",
    "gh api -X GET repos/o/r -q '.name | ascii_downcase'",
    "gh api repos/o/r -H 'Accept: application/vnd.github+json'",
    "gh api --method GET /repos/o/r/actions/runs --jq .total_count",
    "gh api repos/o/r/commits?per_page=5 -q .[0].sha",
    "gh api -i repos/o/r",
    "gh api -iq .name repos/o/r",
    "gh api repos/o/r --template '{{.name}}'",
    "gh api --hostname github.com repos/o/r --cache 1h",
    "gh api repos/o/r/commits?per_page=5 --jq '.[] | .sha' | head -3",
]

STILL_UNKNOWN_GH_API = [
    "gh api -X POST repos/o/r/pulls/1/merge --jq '.[] | .x'",
    "gh api -iXPOST repos/o/r/pulls/1/merge",
    "gh api -iX PUT repos/o/r/pulls/1/merge",
    "gh api repos/o/r/issues -f title=x --jq '.a | .b'",
    "gh api repos/o/r/issues -iF title=x",
    "gh api repos/o/r/issues --input body.json",
    "gh api graphql --jq '.data | .x'",
    "gh api /graphql",
    "gh api graphq? --jq .x",
    "gh api * --jq .x",
    "gh api repos/o/r/pulls/1/merge -H 'X-HTTP-Method-Override: PUT'",
    'gh api repos/o/r --jq "$Q"',
    "gh api $EP",
    "gh api repos/o/r repos/o/s",
    "gh api repos/o/r --unknown-opt=1",
    "gh api repos/o/r -Z",
    "gh api repos/o/r --jq",
]


@pytest.mark.parametrize("command", READ_ONLY_GH_API)
def test_fcl1_read_only_gh_api_has_no_decision(command: str) -> None:
    assert ra.classify_bash(command, CWD) is None, command


@pytest.mark.parametrize("command", STILL_UNKNOWN_GH_API)
def test_fcl1_mutating_or_unreadable_gh_api_stays_unknown(command: str) -> None:
    action = ra.classify_bash(command, CWD)
    assert action is not None, command
    assert action.label == ra.UNKNOWN_LABEL, command


def test_fcl1_gate_lets_the_evidence_gh_api_call_through() -> None:
    gate, _log, _recorder = _gate()
    command = 'gh api repos/example-org/preview-dashboard/commits?per_page=5 --jq ".[] | .sha"'
    assert gate.decide(_call("Bash", {"command": command})).verdict is HookVerdict.NO_DECISION
