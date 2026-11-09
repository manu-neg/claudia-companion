"""C59: the risky-action hook (classifier, gate, hook command, control socket).

Table-driven classifier cases (one per risky form and bypass form), the
gate's cover rules (exact kind + target, single use, ends with the run,
never `flagged_message`, never `unknown`), and the hook process: it prints
only `deny` or nothing, and every failure path (host down, timeout, odd
reply, bad input, untrusted socket) denies with exit 2.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.application.claudia.hook_gate import (
    REASON_MALFORMED,
    REASON_NO_RUN,
    REASON_UNKNOWN_TOOL,
    HookDecision,
    HookGate,
    HookVerdict,
)
from preview_dashboard.application.claudia.runs import TELEGRAM_TOOLS, TOOL_SETS
from preview_dashboard.domain import risky_actions as ra
from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    WindowId,
)
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_messages import OwnerMessageId
from preview_dashboard.interfaces.claudia import hook as hook_cmd
from preview_dashboard.interfaces.claudia.control_socket import (
    ControlSocketError,
    ControlSocketServer,
)
from preview_dashboard.interfaces.claudia.settings import (
    HOOK_COMMAND,
    HOST_SETTINGS_PATH,
    MANAGED_SETTINGS,
    MANAGED_SETTINGS_DIR,
    REQUIRED_DENY,
    HostSettingsError,
    check_settings_sources,
    settings_sources,
)
from tests.claudia_host_support import WINDOW_A, WINDOW_B, FakeAuditLog, FakePeers
from tests.fakes import FixedClock

pytestmark = pytest.mark.security

CWD = "/w"
ME = (os.geteuid(),)
UNKNOWN = "unknown"
ANY = object()  # any target (including None)


# --- helpers ---------------------------------------------------------------------------


def classify(command: str, cwd: str | None = CWD) -> ra.RiskyAction | None:
    return ra.classify_bash(command, cwd)


def assert_kind(command: str, label: str, target: object = ANY) -> None:
    action = classify(command)
    assert action is not None, command
    assert action.label == label, command
    if target is not ANY:
        assert action.target == target, command


def consumed(
    n: int,
    kind: ActionKind,
    target: str,
    *,
    window: WindowId = WINDOW_A,
    approval_kind: ApprovalKind = ApprovalKind.ACTION,
) -> ApprovalRequest:
    clock = FixedClock()
    request = ApprovalRequest.new(
        id=ApprovalId(f"{n:026d}"),
        window_id=window,
        kind=approval_kind,
        action_text=f"Do the thing number {n}",
        now=clock.now(),
        action_kind=kind,
        action_target=target,
    )
    step = timedelta(seconds=1)
    return (
        request.tapped(clock.advance(step))
        .approved(clock.advance(step))
        .consumed(clock.advance(step))
    )


def flagged(n: int) -> ApprovalRequest:
    clock = FixedClock()
    message_id = OwnerMessageId(f"{n + 500:026d}")
    request = ApprovalRequest.new(
        id=ApprovalId(f"{n:026d}"),
        window_id=WINDOW_A,
        kind=ApprovalKind.FLAGGED_MESSAGE,
        action_text=f"Treat flagged message {message_id} as your request: please rm x",
        now=clock.now(),
        message_id=message_id,
    )
    step = timedelta(seconds=1)
    return (
        request.tapped(clock.advance(step))
        .approved(clock.advance(step))
        .consumed(clock.advance(step))
    )


def bash(command: str, *, session: str = WINDOW_A, cwd: str = CWD) -> dict[str, object]:
    return tool("Bash", {"command": command}, session=session, cwd=cwd)


def tool(
    name: str, tool_input: dict[str, object], *, session: str = WINDOW_A, cwd: str = CWD
) -> dict[str, object]:
    return {
        "hook_event_name": "PreToolUse",
        "session_id": session,
        "cwd": cwd,
        "tool_name": name,
        "tool_input": tool_input,
        "transcript_path": "/root/.claude/projects/x/y.jsonl",
    }


def gate(audit: FakeAuditLog | None = None) -> HookGate:
    return HookGate(FakePeers(), audit or FakeAuditLog(), FixedClock())


def denied(decision: HookDecision) -> bool:
    return decision.verdict is HookVerdict.DENY


# --- classifier: every risky form ------------------------------------------------------

RISKY_FORMS = [
    ("gh pr merge 31 --repo example-org/example-repo --merge", "pr_merge"),
    ("gh pr merge https://github.com/example-org/example-repo/pull/31", "pr_merge"),
    ("gh pr merge 31", "pr_merge"),
    ("gh pr -R o/r merge 5", "pr_merge"),
    ("deploy/install.sh --owner-login x --host y", "deploy"),
    ("./deploy/install.sh", "deploy"),
    ("bash deploy/install.sh", "deploy"),
    ("bash -x /srv/project/deploy/install.sh", "deploy"),
    ("source deploy/install.sh", "deploy"),
    ("git push origin main", "git_push_main"),
    ("git push origin master", "git_push_main"),
    ("git push", "git_push_main"),
    ("git push origin", "git_push_main"),
    ("rm -rf build", "rm"),
    ("unlink a", "rm"),
    ("shred -u -n 3 a", "rm"),
    ("rmdir empty", "rm"),
    ("echo {} > .claude/settings.json", "settings_edit"),
    ("tee /etc/preview-dashboard/claudia-settings.json", "settings_edit"),
    ("cp x /root/.claude/settings.json", "settings_edit"),
    ("sed -i s/a/b/ .claude/settings.local.json", "settings_edit"),
    ("dd of=/etc/claude-code/managed-settings.json", "settings_edit"),
    ("> /root/.claude/settings.json", "settings_edit"),
]

# Each risky form hidden in a chain, a substitution, a group or a shell string.
CONTEXTS = [
    "{}",
    "ls && {}",
    "true; {}",
    "false || {}",
    "cat f | {}",
    "ls\n{}",
    "echo $({})",
    "echo `{}`",
    "x=$({})",
    "({})",
    "{{ {}; }}",
    "if true; then {}; fi",
    "while true; do {}; done",
    "diff <({}) y",
    'echo "$({})"',
]


@pytest.mark.parametrize(("command", "label"), RISKY_FORMS)
@pytest.mark.parametrize("context", CONTEXTS)
def test_c59_risky_form_classified_everywhere(command: str, label: str, context: str) -> None:
    action = classify(context.format(command) if "{}" in context else context)
    assert action is not None
    assert action.label == label


@pytest.mark.parametrize(("command", "label"), RISKY_FORMS)
@pytest.mark.parametrize("wrap", ["{}", "ls; {}", "echo $({})", "sh -c '{}'"])
def test_c59_risky_form_denied_without_approval(command: str, label: str, wrap: str) -> None:
    g = gate()
    g.begin_run(WINDOW_A)
    decision = g.decide(bash(wrap.format(command)))
    assert denied(decision)
    assert decision.reason is not None
    assert decision.reason.startswith(label if "sh -c" not in wrap else UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "git status",
        "git commit -m \"$(cat <<'EOF'\nfix: don't break (it)\nEOF\n)\"",
        "git log --oneline | head -5",
        "gh pr view 3",
        "gh pr create --title x --body y",
        "gh api repos/o/r/pulls",
        "gh api -X GET repos/o/r",
        "gh api --method=get repos/o/r",
        "echo rm -rf /",
        "grep -r 'rm -rf' .",
        "cat .claude/settings.json",
        "uv run pytest",
        "make check",
        "[ -f x ] && echo y",
        "test -f x",
        "python3 script.py",
        "python3 -m pytest -q",
        "node app.js",
        "bash scripts/x.sh",
        "git push origin feature",
        "git push -u origin feat/x",
        "git push origin HEAD:feature",
        "git push origin v1.0:refs/tags/v1.0",
        "find . -name '*.py'",
        "find . -exec ls {} +",
        "command -v rm",
        "for f in a b; do echo $f; done",
        "cat <<EOF\nrm -rf / is just text here\nEOF",
        "awk '{print $1}' f",
        "# rm -rf / in a comment",
    ],
)
def test_c59_non_risky_commands_pass(command: str) -> None:
    assert classify(command) is None
    g = gate()
    g.begin_run(WINDOW_A)
    assert g.decide(bash(command)) == HookDecision.no_decision()


@pytest.mark.parametrize(
    ("command", "target"),
    [
        ("gh pr merge 31 --repo example-org/example-repo", "example-org/example-repo#31"),
        ("gh pr merge 31 -R example-org/example-repo", "example-org/example-repo#31"),
        ("gh pr merge --repo=o/r '#7'", "o/r#7"),
        ("gh pr merge https://github.com/o/r/pull/9/files", "o/r#9"),
        ("GH_REPO=o/r gh pr merge 5", "o/r#5"),
        ("gh pr -R o/r merge 5 --squash", "o/r#5"),
        ("gh pr merge 31", None),
        ("gh pr merge my-branch -R o/r", None),
        ("gh pr merge https://github.com/o/r/pull/9 -R x/y", None),
    ],
)
def test_c59_pr_merge_targets(command: str, target: str | None) -> None:
    assert_kind(command, "pr_merge", target)


def test_c59_deploy_and_push_targets() -> None:
    assert_kind("deploy/install.sh --x", "deploy", "/w/deploy/install.sh")
    assert_kind("/srv/project/deploy/install.sh", "deploy", "/srv/project/deploy/install.sh")
    assert_kind("git push origin main", "git_push_main", "/w origin")
    assert_kind("git push", "git_push_main", None)
    assert_kind("git push $R main", "git_push_main", None)
    assert_kind("git push https://evil.example/r main", "git_push_main", None)


# --- classifier: bypass forms ----------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "gh api -X POST repos/o/r/pulls/1/merge",
        "gh api -XPUT repos/o/r/pulls/1/merge",
        "gh api --method PUT repos/o/r/pulls/1/merge",
        "gh api --method=DELETE repos/o/r/git/refs/heads/x",
        "gh api repos/o/r/issues -f title=x",
        "gh api repos/o/r/issues -F title=x",
        "gh api repos/o/r/issues -ftitle=x",
        "gh api repos/o/r/issues --field title=x",
        "gh api repos/o/r/issues --raw-field title=x",
        "gh api repos/o/r/issues --input body.json",
        "gh api graphql -q x",
        "gh api /graphql",
        "gh alias set m 'pr merge'",
        "gh --bogus pr merge 1",
    ],
)
def test_c59_gh_api_mutation_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "sudo rm x",
        "sudo -u root rm x",
        "sudo --user root -E rm x",
        "sudo -Eu root rm x",
        "env rm x",
        "env FOO=1 BAR=2 rm x",
        "env -i rm x",
        "env -u HOME rm x",
        "FOO=1 rm x",
        "command rm x",
        "command -p rm x",
        "builtin command rm x",
        "nice rm x",
        "nice -n 5 rm x",
        "nice -5 rm x",
        "timeout 5 rm x",
        "timeout -s KILL 5 rm x",
        "timeout --signal=KILL -k 1 5 rm x",
        "/bin/rm x",
        "/usr/bin/rm x",
        "\\rm x",
        "r''m x",
        "'rm' x",
        "nohup rm x",
        "exec rm x",
        "time rm x",
        "time -p rm x",
        "stdbuf -o0 rm x",
        "ionice -c 3 rm x",
        "setsid rm x",
        "flock /tmp/l rm x",
        "sudo env timeout 3 nice /usr/bin/rm x",
        "! rm x",
        "coproc rm x",
        "pkexec rm x",
        "busybox rm x",
        'A="a b" rm x',
        "case $y in a) rm x;; esac",
        "f() { rm x; }; f",
        "rm x &",
    ],
)
def test_c59_wrappers_stripped(command: str) -> None:
    assert_kind(command, "rm", "/w/x")


@pytest.mark.parametrize(
    "command",
    [
        "xargs rm < list",
        "find . -print0 | xargs -0 rm",
        "xargs -I{} rm {}",
    ],
)
def test_c59_xargs_rm_has_no_exact_target(command: str) -> None:
    assert_kind(command, "rm", None)


@pytest.mark.parametrize(
    "command",
    [
        "sudo -s rm x",
        "sudo -i rm x",
        "sudo --frobnicate rm x",
        "env -S 'rm x'",
        "env --split-string='rm x'",
        "$CMD x",
        "${CMD} x",
        "$(echo rm) x",
        "`echo rm` x",
        "$'\\x72m' x",
        "r* x",
        "eval rm x",
        "eval 'gh pr merge 1'",
        "trap 'rm x' EXIT",
        "alias r=rm",
        "watch rm x",
        "su -c 'rm x'",
        "flock -c 'rm x' /tmp/l",
    ],
)
def test_c59_hidden_command_names_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    ("command", "target"),
    [
        ("git -C /repo push origin main", "/repo origin"),
        ("git -C sub push origin main", "/w/sub origin"),
        ("git -c user.name=x push origin main", "/w origin"),
        ("git -c color.ui=never -C /repo push origin main", "/repo origin"),
        ("git --no-pager push origin main", "/w origin"),
        ("git -P --no-optional-locks push origin main", "/w origin"),
        ("git --git-dir=/r/.git push origin main", None),
        ("git --git-dir /r/.git push origin main", None),
        ("git --work-tree /r push origin main", None),
        ("git --namespace=x push origin main", None),
        ("sudo git -C /repo push origin main", "/repo origin"),
    ],
)
def test_c59_git_global_options_stripped(command: str, target: str | None) -> None:
    assert_kind(command, "git_push_main", target)


@pytest.mark.parametrize(
    "command",
    [
        "git -c alias.p=push p origin main",
        "git -c 'alias.x=!rm y' x",
        "git --config-env=alias.p=ENV p",
        "git --bogus push origin main",
        "git $SUB origin main",
    ],
)
def test_c59_git_alias_and_unknown_options_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "git push --all origin",
        "git push --branches origin",
        "git push --mirror origin",
        "git push --delete origin feature",
        "git push -d origin feature",
        "git push --prune origin feature",
        "git push origin :feature",
        "git push origin +feature:main",
        "git push origin feature:refs/heads/master",
        "git push origin feature:heads/main",
        "git push origin HEAD",
        "git push origin @",
        "git push origin 'refs/heads/*:refs/heads/*'",
        "git push origin feature main",
        "git push origin $BRANCH",
        "git push origin a..b",
        "git push -f origin main",
        "git push --force-with-lease origin main",
        "git push -o ci.skip origin main",
    ],
)
def test_c59_push_all_mirror_delete_refspec(command: str) -> None:
    assert_kind(command, "git_push_main")


@pytest.mark.parametrize(
    ("command", "label"),
    [
        ("find . -delete", "rm"),
        ("find /tmp -name '*.o' -delete", "rm"),
        ("find . -exec rm {} \\;", "rm"),
        ("find . -exec rm -f {} +", "rm"),
        ("find . -execdir /bin/rm {} ';'", "rm"),
        ("find . -ok rm {} \\;", "rm"),
        ("find . -exec sh -c 'rm $1' _ {} \\;", UNKNOWN),
        ("find . -exec python3 -c x \\;", UNKNOWN),
    ],
)
def test_c59_find_delete_exec_rm(command: str, label: str) -> None:
    assert_kind(command, label, None)


@pytest.mark.parametrize(
    "command",
    [
        "python -c 'import os'",
        "python3 -c x",
        "python3.12 -Ic x",
        "python3 -Bc x",
        "pypy3 -c x",
        "node -e x",
        "node --eval x",
        "node --eval=x",
        "node -p x",
        "nodejs -e x",
        "bun -e x",
        "deno eval x",
        "perl -e x",
        "perl -ne x",
        "perl -E x",
        "ruby -e x",
        "php -r x",
        "lua -e x",
        "bash -c x",
        "bash -lc x",
        "sh -c x",
        "zsh -c x",
        "dash -c x",
        "bash --command x",
        "echo x | python3",
        "echo rm x | sh",
        "echo rm x | bash -s",
        "python3 - <<EOF\nprint(1)\nEOF",
        "bash <<'EOF'\nrm x\nEOF",
        "bash <<< 'rm x'",
        "sh < script.txt",
        "claude -p hello",
        "/root/.local/bin/claude --resume x",
        "awk 'BEGIN{system(\"rm x\")}'",
        "awk '{print | \"sh\"}' f",
    ],
)
def test_c59_inline_interpreters_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "echo 'unterminated",
        'echo "unterminated',
        "echo $(ls",
        "echo `ls",
        "echo ${x",
        "cat <<EOF\nno end",
        "rm x \\",
        "echo $'x",
        "ls >",
        "a" * (300 * 1024),
        "echo $(" * 40 + ")" * 40,
    ],
)
def test_c59_unparseable_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)
    g = gate()
    g.begin_run(WINDOW_A)
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/x")])
    assert denied(g.decide(bash(command)))


@pytest.mark.parametrize(
    ("command", "target"),
    [
        ("rm x", "/w/x"),
        ("rm -rf ./x/", "/w/x"),
        ("rm b a", "/w/a /w/b"),
        ("rm a a", "/w/a"),
        ("rm -- -weird", "/w/-weird"),
        ("rm '/tmp/a b'", "'/tmp/a b'"),
        ("rm /abs/x", "/abs/x"),
        ("rm a; rm b", "/w/a /w/b"),
        ("rm a && unlink b", "/w/a /w/b"),
        ("cd /tmp && rm /abs/x", "/abs/x"),
        ("rm x/../y", None),
        ("rm *.log", None),
        ("rm ~/x", None),
        ("rm $X", None),
        ("rm {a,b}", None),
        ("rm", None),
        ("cd /tmp && rm a", None),
        ("rm a; (cd b; rm c)", None),
        ("env -C /tmp rm a", None),
    ],
)
def test_c59_rm_target_exact_resolved_set(command: str, target: str | None) -> None:
    assert_kind(command, "rm", target)


def test_c59_rm_relative_without_cwd_has_no_target() -> None:
    action = classify("rm x", cwd=None)
    assert action is not None
    assert action.kind is ActionKind.RM
    assert action.target is None


def test_c59_rm_approval_covers_exact_set_only() -> None:
    g = gate()
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/a /w/b")])
    assert denied(g.decide(bash("rm a")))  # a subset is another set
    assert denied(g.decide(bash("rm a b c")))
    assert g.decide(bash("rm b a")) == HookDecision.no_decision()


def test_c59_two_different_risky_actions_unknown() -> None:
    assert_kind("rm a && gh pr merge 1 -R o/r", UNKNOWN)
    assert_kind("git push origin main; deploy/install.sh", UNKNOWN)


# --- S-C2b review bypass forms (each one passed the classifier before F-C2b-1) ----------


@pytest.mark.parametrize(
    ("command", "label", "target"),
    [
        # hook-1: xargs appends arguments at run time, so nothing is exact.
        ("xargs rm /tmp/ok < list", "rm", None),
        ("xargs -0 rm -f /w/a < list", "rm", None),
        ("echo main | xargs git push origin feature", "git_push_main", None),
        ("xargs git < args", UNKNOWN, None),
        ("xargs -0 sudo < cmds", UNKNOWN, None),
        ("xargs env < cmds", UNKNOWN, None),
        ("xargs -I % % x < cmds", UNKNOWN, None),
        ("xargs gh pr < args", UNKNOWN, None),
        ("xargs gh api < args", UNKNOWN, None),
        ("xargs tee < files", "settings_edit", None),
        ("xargs cp /tmp/h < dests", "settings_edit", None),
        ("xargs gh pr merge 5 -R o/r < more", "pr_merge", None),
    ],
)
def test_c59_xargs_adds_runtime_arguments(command: str, label: str, target: str | None) -> None:
    assert_kind(command, label, target)


@pytest.mark.parametrize(
    ("command", "label"),
    [
        # hook-2: a cd after a keyword, assignment or wrapper still moves the cwd.
        ("{ cd /x; rm a; }", "rm"),
        ("if true; then cd /x; fi; rm a", "rm"),
        ("while true; do cd /x; done; rm a", "rm"),
        ("builtin cd /x; rm a", "rm"),
        ("command cd /x; rm a", "rm"),
        ("X=1 cd /x; rm a", "rm"),
        ("! cd /x; rm a", "rm"),
        ("time pushd /x; rm a", "rm"),
        ("{ cd /other; git push origin main; }", "git_push_main"),
    ],
)
def test_c59_hidden_cd_unresolves_relative_targets(command: str, label: str) -> None:
    assert_kind(command, label, None)


@pytest.mark.parametrize(
    "command",
    [
        # hook-3: config or env from the call can re-point a remote or run code.
        "git -c remote.origin.url=/other push origin main",
        "git -c remote.origin.pushurl=/other push origin feature:main",
        "git -c core.pager='gh pr merge 5' -p log",
        "git -c core.sshCommand='rm x' fetch",
        "git -c core.fsmonitor='rm x' status",
        "git --config-env=core.pager=X log",
        "git --config-env core.pager=X log",
        "GIT_DIR=/r/.git git push origin main",
        "GIT_WORK_TREE=/r git status",
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0=push git p origin main",
        "env GIT_DIR=/r/.git git push origin main",
        "sudo GIT_SSH_COMMAND='rm x' git fetch",
        "export GIT_DIR=/r/.git; git push origin main",
        "GIT_DIR=/r/.git; export GIT_DIR; git push origin main",
        "PAGER='gh pr merge 5' git -p log",
        "GIT_PAGER=$P git log",
        "HOME=/tmp/h git push origin feature",
        "XDG_CONFIG_HOME=/tmp/c git status",
        "git --exec-path=/tmp/x push origin main",
    ],
)
def test_c59_git_config_and_env_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "git -c user.name=x -c user.email=y commit -m z",
        "git -c color.ui=never log",
        "GIT_PAGER=cat git log",
        "GIT_TERMINAL_PROMPT=0 git fetch",
        "git --exec-path",
    ],
)
def test_c59_harmless_git_config_passes(command: str) -> None:
    assert classify(command) is None


@pytest.mark.parametrize(
    "command",
    [
        # hook-4: non-literal targets may name a settings source or the hook.
        "cp x ~/.claude/settings.json",
        "echo {} > ~/.claude/settings.local.json",
        "echo {} > $HOME/.claude/settings.json",
        'echo {} >> "${HOME}/.claude/settings.json"',
        'tee "$F" < x',
        "ln -sf /tmp/x ~/.claude/settings.json",
        "mv /tmp/x ~/.claude/settings.json",
        "touch ~/.claude/settings.json",
        "chmod 777 ~/.claude/settings.json",
        "sed -i s/a/b/ ~/.claude/settings.json",
        "dd of=$HOME/.claude/settings.json",
        "cp -t ~/.claude x",
        "cp x /tmp/*/settings.json",
        # ... and after a cd, by name (unknown cwd) or by the cd target.
        "cd /root/.claude && echo {} > settings.json",
        "cd /opt/preview-dashboard/.venv/bin; cp /tmp/h preview-dashboard-claudia-hook",
        "cd /opt/preview-dashboard && cp /tmp/x src/preview_dashboard/a.py",
        "cd /etc && echo {} > claude-code/managed-settings.json",
        "cd / && echo x > var/lib/claudia-host/recap-mcp.json",
        "cd ~ && echo {} > .claude/settings.json",
        "cd $D && echo x > hook",
        "cd .. && echo x > recap-mcp.json",
        "pushd /opt; echo x > preview-dashboard/x.py",
        "env -C /opt/preview-dashboard cp /tmp/x a.py",
        "sudo -D /etc/claude-code tee managed-settings.d/x.json",
        # `..` folded lexically.
        "cp /tmp/x /tmp/../opt/preview-dashboard/src/a.py",
    ],
)
def test_c59_unknown_write_targets_are_settings_edit(command: str) -> None:
    assert_kind(command, "settings_edit", None)


@pytest.mark.parametrize(
    "command",
    [
        "echo x > /tmp/out.txt",
        "make 2>&1",
        "make > build.log 2>&1",
        "cd build && cmake .. > log.txt",
        "cd /tmp && echo x > out.txt",
        "cp src/*.py dest/",
        'sed s/a/b/ "$F"',
        "cat ~/.claude/settings.json",
        "ls > /dev/null",
    ],
)
def test_c59_ordinary_writes_pass(command: str) -> None:
    assert classify(command) is None


@pytest.mark.parametrize(
    ("raw", "cwd"),
    [
        ("/var/lib/claudia-host/recap-mcp.json", CWD),
        ("/var/lib/claudia-host/audit/2026-11.jsonl", CWD),
        ("/var/lib/claudia-host", CWD),
        ("../recap-mcp.json", "/var/lib/claudia-host/work"),
    ],
)
def test_c59_host_state_outside_work_is_protected(raw: str, cwd: str) -> None:
    action = ra.classify_tool_call("Write", {"file_path": raw}, cwd)
    assert action is not None
    assert action.kind is ActionKind.SETTINGS_EDIT


@pytest.mark.parametrize(
    "command",
    [
        "echo 'be rude' > /var/lib/claudia-kb/persona.md",
        "sed -i s/a/b/ /var/lib/claudia-kb/persona.md",
        "cp /tmp/x /var/lib/claudia-kb/notes/a.md",
        "cd /var/lib/claudia-kb && echo x > persona.md",
        "echo x > ../persona.md",  # place unknown (`..`): judged by the name
    ],
)
def test_c59_bash_writing_the_kb_or_persona_needs_approval(command: str) -> None:
    action = ra.classify_bash(command, CWD)
    assert action is not None
    assert action.kind is ActionKind.SETTINGS_EDIT


def test_c59_kb_root_is_protected_for_edit_tools_too() -> None:
    action = ra.classify_tool_call("Write", {"file_path": "/var/lib/claudia-kb/persona.md"}, CWD)
    assert action is not None
    assert action.kind is ActionKind.SETTINGS_EDIT


def test_c59_host_work_dir_is_hers() -> None:
    assert not ra.is_protected_path("/var/lib/claudia-host/work/notes.md")
    work = ra.CLAUDIA_HOST_WORK_DIR
    assert ra.classify_tool_call("Write", {"file_path": f"{work}/a.md"}, work) is None
    assert ra.classify_bash("echo x > out.txt", work) is None


@pytest.mark.parametrize(
    "command",
    [
        # hook-7: a merge or push through GitHub's REST API.
        'curl -X PUT -H "Authorization: token $(gh auth token)" '
        "https://api.github.com/repos/o/r/pulls/5/merge",
        "curl -X PUT https://api.github.com/repos/o/r/pulls/5/merge",
        "curl -sXPUT https://api.github.com/repos/o/r/pulls/5/merge",
        "curl --request PATCH https://api.github.com/repos/o/r/git/refs/heads/main",
        "curl -d '{}' https://api.github.com/repos/o/r/merges",
        "curl --json '{}' https://API.GITHUB.COM/repos/o/r/merges",
        "curl -F a=b https://api.github.com/x",
        "curl -X POST $URL",
        "curl -K req.cfg",
        "wget --method=PUT https://api.github.com/repos/o/r/pulls/5/merge",
        "wget --post-data=x https://api.github.com/repos/o/r/merges",
        "http PUT api.github.com/repos/o/r/pulls/5/merge",
        "http api.github.com/repos/o/r/issues title=x",
        "xh POST https://api.github.com/x",
        "xargs curl -X POST < urls",
    ],
)
def test_c59_github_api_mutations_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "curl https://api.github.com/repos/o/r",
        "curl -sSL https://example.com/x -o x.tar.gz",
        "curl -X POST http://localhost:8080/x",
        "curl -I https://api.github.com",
        "wget https://api.github.com/repos/o/r",
        "http GET api.github.com/repos/o/r",
    ],
)
def test_c59_http_reads_pass(command: str) -> None:
    assert classify(command) is None


@pytest.mark.parametrize("command", ["gh repo sync", "gh repo sync o/fork --branch main"])
def test_c59_gh_repo_sync_is_a_push(command: str) -> None:
    # hook-7: updates a default branch on GitHub; no exact target.
    assert_kind(command, "git_push_main", None)


# --- S-C3 review bypass forms (each one passed the classifier before F-C3-1) -------------


@pytest.mark.parametrize(
    "command",
    [
        # fixcheck-b-1: runners that hide the real command (now opaque) ...
        "strace -f gh pr merge 5 -R o/r",
        "systemd-run --wait gh pr merge 5",
        "run0 gh pr merge 5",
        "setpriv --reuid=0 gh pr merge 5",
        "unshare -m gh pr merge 5",
        "nsenter -t 1 -m gh pr merge 5",
        "chroot / gh pr merge 5",
        "tmux new -d 'gh pr merge 5'",
        "screen -dm gh pr merge 5",
        "ssh localhost gh pr merge 5",
        "at now",
        "batch",
        "ltrace rm x",
        "gdb -batch -ex run --args rm x",
        "valgrind rm x",
        "firejail rm x",
        "bwrap --bind / / rm x",
        "proot rm x",
        "fakeroot rm x",
        "sg root -c 'rm x'",
        # ... and any unlisted command carrying a risky program name.
        "chronic gh pr merge 5 -R o/r",
        "numactl -N 0 rm x",
        "faketime now git push origin main",
        "catchsegv /usr/bin/gh pr merge 5",
        "foo --exec=rm x",
        "sed -n '1e gh pr merge 5' f",
        "rsync -e 'sh -c x' a b:",
        "uv run python -c x",
        "docker run img sh",
    ],
)
def test_c59_unlisted_wrappers_with_risky_names_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "grep -r gh docs",
        "echo git push origin main",
        "which gh",
        "type rm",
        "ls /usr/bin/git",
        "cat install.sh",
        "pip install requests",
        "npm run build",
        "uv run pytest -q",
        "make check",
        "docker ps",
    ],
)
def test_c59_risky_names_as_plain_text_pass(command: str) -> None:
    assert classify(command) is None


@pytest.mark.parametrize(
    "command",
    [
        # fixcheck-b-2: persistent git config (aliases, pager, push refspec, URL) ...
        "git config --global alias.m '!gh pr merge 5'",
        "git config --global core.pager 'gh pr merge 5'",
        "git config remote.origin.push refs/heads/feature:refs/heads/main",
        "git config remote.origin.pushurl /other",
        "git config --add include.path /tmp/x",
        "git config set alias.m x",
        "git config -e",
        "git config --unset core.pager",
        "git config",
        # ... and options or sub-commands that run a command.
        "git push --receive-pack='gh pr merge 5' /tmp/r feature",
        "git push --exec=x /tmp/r feature",
        "git fetch --upload-pack='rm x' origin",
        "git clone -u 'rm x' /tmp/r",
        "git ls-remote --upload-pack=x origin",
        "git archive --exec=x --remote=r HEAD",
        "git rebase -x 'gh pr merge 5' main",
        "git rebase --exec='rm x' main",
        "git rebase -ix x main",
        "git submodule foreach 'gh pr merge 5'",
        "git submodule --quiet foreach x",
        "git bisect run ./t.sh",
        "git difftool -x 'rm x'",
        "git difftool --extcmd=x",
        "git filter-branch --tree-filter x",
        "git clone --template=/tmp/t /tmp/r",
        "git init --template=/tmp/t",
        "xargs git fetch < args",
    ],
)
def test_c59_git_config_writes_and_command_options_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "git config user.name",
        "git config --get remote.origin.url",
        "git config --global --list",
        "git config -l --show-origin",
        "git config get user.email",
        "git config --get-regexp alias",
        "git submodule update --init",
        "git bisect start",
        "git rebase main",
        "git cherry-pick -x abc",
        "git push -u origin feature",
        "git apply --check p.diff",
        "git fetch origin",
    ],
)
def test_c59_git_reads_and_plain_sub_commands_pass(command: str) -> None:
    assert classify(command) is None


@pytest.mark.parametrize(
    "command",
    [
        # fixcheck-b-3: a directory destination holding a protected path ...
        "cp /tmp/settings.json /root/.claude/",
        "cp /tmp/managed-settings.json /etc/claude-code/",
        "cp /tmp/x.json /etc/claude-code/managed-settings.d/",
        "install /tmp/h /opt/preview-dashboard/.venv/bin/",
        "cp /tmp/* /root/.claude/",
        "cp -t /root/.claude /tmp/settings.json",
        # ... whole trees onto or above a loaded `.claude` dir ...
        "cp -r /tmp/home/.claude /root/",
        "cp -a /tmp/r/. /root",
        "rsync -a /tmp/r/ /root/",
        "mv /tmp/c /root/.claude",
        # ... links into a protected tree ...
        "ln -s /opt o",
        "ln -s /root r",
        "ln -s /etc/claude-code m",
        "ln -s $D o",
        # ... CDPATH ...
        "CDPATH=/opt/preview-dashboard/src; cd preview_dashboard; cp /tmp/x a.py",
        "export CDPATH=/opt; cd preview-dashboard; touch x",
        # ... and writers that take their targets from their input.
        "tar -xf /tmp/a.tar -C /root",
        "tar xfC /tmp/a.tar out",
        "tar -xPf /tmp/a.tar",
        "tar --extract --file=/tmp/a.tar --directory=/etc",
        "tar -cf /root/.claude/settings.json x",
        "unzip a.zip -d /root",
        "unzip -: a.zip",
        "cpio -idv < a.cpio",
        "cpio -p /root < list",
        "patch -p1 < x.diff",
        "sort -o /root/.claude/settings.json x",
        "sort --output=/etc/preview-dashboard/claudia-settings.json x",
        "git apply p.diff",
        "git am < m.mbox",
    ],
)
def test_c59_dir_tree_link_and_archive_writes_are_settings_edit(command: str) -> None:
    assert_kind(command, "settings_edit")


@pytest.mark.parametrize(
    "command",
    [
        "tar -I 'gh pr merge 5' -xf a.tar",
        "tar --to-command='rm x' -xf a.tar",
        "tar --use-compress=x -cf a.tar b",
        "tar -xf $A",
        "cpio --rsh-command=x -i < a",
    ],
)
def test_c59_archive_options_that_run_code_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command",
    [
        "tar -xf a.tar -C out",
        "tar -czf out.tgz src",
        "tar -tf a.tar",
        "unzip -l a.zip",
        "unzip a.zip -d out",
        "patch --dry-run -p1 < x.diff",
        "sort -o out.txt in.txt",
        "cp /tmp/notes.txt /root/.claude/",
        "cp -r src dest",
        "cp a.txt /root/",
        "ln -s /tmp/foo x",
        "cd sub; cp /tmp/x a.py",
    ],
)
def test_c59_ordinary_dir_and_archive_writes_pass(command: str) -> None:
    assert classify(command) is None


@pytest.mark.parametrize(
    "command",
    ["tar -xf /tmp/a.tar", "cp -r /tmp/x .", "unzip /tmp/a.zip", "rsync -a /tmp/r/ ./"],
)
def test_c59_tree_into_her_cwd_may_plant_project_settings(command: str) -> None:
    # Her cwd holds the project `.claude/settings*.json` a run loads.
    work = ra.CLAUDIA_HOST_WORK_DIR
    action = ra.classify_bash(command, work)
    assert action is not None
    assert action.kind is ActionKind.SETTINGS_EDIT
    assert ra.classify_bash("tar -xf /tmp/a.tar -C out", work) is None


def _fake_realpath(path: str) -> str:
    # `/w/o` is a symlink to `/opt` (made by an earlier call).
    return "/opt" + path.removeprefix("/w/o") if path.startswith("/w/o/") else path


@pytest.mark.parametrize(
    "command",
    [
        "cp /tmp/h o/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook",
        "echo x > o/preview-dashboard/src/a.py",
        "cp /tmp/h o/preview-dashboard/",
    ],
)
def test_c59_bash_writes_resolve_symlinks(command: str) -> None:
    assert classify(command) is None  # lexically harmless ...
    action = ra.classify_bash(command, CWD, realpath=_fake_realpath)
    assert action is not None  # ... but it resolves into the install
    assert action.kind is ActionKind.SETTINGS_EDIT
    g = HookGate(FakePeers(), FakeAuditLog(), FixedClock(), realpath=_fake_realpath)
    g.begin_run(WINDOW_A)
    assert denied(g.decide(bash(command)))


@pytest.mark.parametrize(
    "command",
    [
        # fixcheck-b-4: setters other than `NAME=` (exported under `set -a`) ...
        "set -a; read GIT_DIR <<< /x; git push origin main",
        "set -o allexport; printf -v GIT_DIR /x; git push origin main",
        "set -a; mapfile GIT_DIR < f; git push origin main",
        "readarray GIT_CONFIG_GLOBAL < f; git push origin main",
        "for GIT_DIR in /x; do git push origin main; done",
        # ... and gh config from another place.
        "GH_CONFIG_DIR=/tmp/g gh m",
        "export GH_CONFIG_DIR=/tmp/g; gh pr merge 5 -R o/r",
        "GH_HOST=evil.example gh pr merge 5 -R o/r",
        "read GH_CONFIG_DIR < f; gh m",
        "XDG_CONFIG_HOME=/tmp/c gh pr view 3",
    ],
)
def test_c59_env_setters_and_gh_config_unknown(command: str) -> None:
    assert_kind(command, UNKNOWN)


@pytest.mark.parametrize(
    "command", ["GH_PAGER=cat gh pr view 3", "set -a; read X; git status", "read GIT; gh pr view"]
)
def test_c59_harmless_setters_pass(command: str) -> None:
    assert classify(command) is None


# --- host-flow-3: the hook sees every tool; the gate denies the ones it doesn't know ------


@pytest.mark.parametrize(
    ("name", "tool_input"),
    [
        ("Monitor", {"command": "gh pr merge 5 -R o/r"}),
        ("PowerShell", {"command": "gh pr merge 5"}),
        ("BashOutput", {}),
        ("mcp__other__run", {}),
        ("mcp__preview-dashboard__dashboard_notify", {"title": "x"}),
        ("mcp__preview-dashboard__dashboard_ask", {}),
        ("mcp__claudia-kb__kb_admin", {}),
        ("bash", {"command": "ls"}),
    ],
)
def test_c59_unknown_tool_denied(name: str, tool_input: dict[str, object]) -> None:
    assert ra.classify_tool_call(name, tool_input, CWD) == ra.UNKNOWN
    audit = FakeAuditLog()
    g = gate(audit)
    every_kind = [
        consumed(i + 1, k, "x") for i, k in enumerate(ActionKind) if k.value != "peer_message"
    ]
    g.begin_run(WINDOW_A, every_kind)
    assert g.decide(tool(name, tool_input)) == HookDecision.deny(REASON_UNKNOWN_TOOL)
    assert audit.entries[-1]["action_kind"] == UNKNOWN


def test_c59_every_tool_of_every_set_is_known() -> None:
    # The gate must know each tool the runs offer, or it denies it (C51 tool sets).
    for tool_set in TOOL_SETS.values():
        for name in tool_set.allowed:
            assert ra.is_known_tool(name), name
    for name in TELEGRAM_TOOLS:
        assert not ra.is_known_tool(name), name


@pytest.mark.parametrize(
    "name",
    [
        "Read",
        "Grep",
        "Glob",
        "TodoWrite",
        "WebFetch",
        "WebSearch",
        "Agent",
        "Task",
        "mcp__claudia-kb__kb_read",
        "mcp__claudia-kb__kb_write",
    ],
)
def test_c59_known_non_risky_tool_no_decision(name: str) -> None:
    g = gate()
    g.begin_run(WINDOW_A)
    assert g.decide(tool(name, {"file_path": "/w/a"})) == HookDecision.no_decision()


# --- classifier: edits and dashboard tools ------------------------------------------------


@pytest.mark.parametrize(
    ("name", "key", "path"),
    [
        ("Edit", "file_path", "/srv/project/.claude/settings.json"),
        ("Write", "file_path", "/root/.claude/settings.local.json"),
        ("MultiEdit", "file_path", "/x/.CLAUDE/Settings.JSON"),
        ("Write", "file_path", ".claude/settings.json"),
        ("Edit", "file_path", "/etc/preview-dashboard/claudia-settings.json"),
        ("Write", "file_path", "/opt/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook"),
        ("Edit", "file_path", "/opt/preview-dashboard/src/preview_dashboard/x.py"),
        ("Write", "file_path", "/etc/claude-code/managed-settings.json"),
        ("Write", "file_path", "/etc/claude-code/managed-settings.d/10-x.json"),
        ("Edit", "file_path", "/srv/project/deploy/claudia/settings.json"),
        ("NotebookEdit", "notebook_path", "/root/.claude/settings.json"),
    ],
)
def test_c59_settings_edits_classified(name: str, key: str, path: str) -> None:
    action = ra.classify_tool_call(name, {key: path}, CWD)
    assert action is not None
    assert action.kind is ActionKind.SETTINGS_EDIT


def test_c59_settings_edit_through_symlink() -> None:
    links = {"/w/innocent.json": "/root/.claude/settings.json"}
    action = ra.classify_tool_call(
        "Write", {"file_path": "/w/innocent.json"}, CWD, realpath=lambda p: links.get(p, p)
    )
    assert action == ra.RiskyAction(ActionKind.SETTINGS_EDIT, "/w/innocent.json")

    def broken(path: str) -> str:
        raise OSError("loop")

    action = ra.classify_tool_call("Write", {"file_path": "/w/a.json"}, CWD, realpath=broken)
    assert action is not None
    assert action.kind is ActionKind.SETTINGS_EDIT


@pytest.mark.parametrize(
    "path", ["/w/src/app.py", "/w/.claude/commands/dev.md", "/root/.claude/projects/x/notes.md"]
)
def test_c59_ordinary_edits_pass(path: str) -> None:
    assert ra.classify_tool_call("Edit", {"file_path": path}, CWD) is None


@pytest.mark.parametrize("tool_input", [{}, {"file_path": 3}, {"file_path": ""}])
def test_c59_edit_without_path_unknown(tool_input: dict[str, object]) -> None:
    assert ra.classify_tool_call("Write", tool_input, CWD) == ra.UNKNOWN


ITEM = "01" + "A" * 24
DASH = ra.DASHBOARD_TOOL_PREFIX


@pytest.mark.parametrize(
    ("name", "tool_input", "target"),
    [
        ("dashboard_trash", {"item_id": ITEM}, f"trash:{ITEM}"),
        ("dashboard_prune_revisions", {"item_id": ITEM, "keep": 3}, f"prune:{ITEM}:keep=3"),
        # The MCP tool's default keep=1 is part of the target too.
        ("dashboard_prune_revisions", {"item_id": ITEM}, f"prune:{ITEM}:keep=1"),
        ("dashboard_empty_trash", {}, "empty:trash"),
        ("dashboard_trash", {"item_id": "x"}, None),
        ("dashboard_prune_revisions", {"item_id": ITEM, "keep": True}, None),
        ("dashboard_prune_revisions", {"item_id": ITEM, "keep": "2"}, None),
        ("dashboard_prune_revisions", {"item_id": ITEM, "keep": 0}, None),
    ],
)
def test_c59_dashboard_delete_targets_name_the_tool(
    name: str, tool_input: dict[str, object], target: str | None
) -> None:
    action = ra.classify_tool_call(f"{DASH}{name}", tool_input, CWD)
    assert action == ra.RiskyAction(ActionKind.DASHBOARD_DELETE, target)


def test_c59_dashboard_other_tools() -> None:
    assert ra.classify_tool_call(f"{DASH}dashboard_list", {}, CWD) is None
    assert ra.classify_tool_call("Read", {"file_path": "/x"}, CWD) is None


def test_c59_trash_approval_never_covers_a_prune() -> None:
    # hook-6: trashing is undoable, pruning revisions is not.
    g = gate()
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.DASHBOARD_DELETE, f"trash:{ITEM}")])
    prune = tool(f"{DASH}dashboard_prune_revisions", {"item_id": ITEM, "keep": 1})
    assert denied(g.decide(prune))
    assert g.decide(tool(f"{DASH}dashboard_trash", {"item_id": ITEM})) == HookDecision.no_decision()


def test_c59_bash_without_command_unknown() -> None:
    assert ra.classify_tool_call("Bash", {}, CWD) == ra.UNKNOWN
    assert ra.classify_tool_call("Bash", {"command": 1}, CWD) == ra.UNKNOWN


# --- gate: covers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("call", "kind", "target"),
    [
        (bash("gh pr merge 31 -R o/r"), ActionKind.PR_MERGE, "o/r#31"),
        (bash("deploy/install.sh"), ActionKind.DEPLOY, "/w/deploy/install.sh"),
        (bash("git push origin main"), ActionKind.GIT_PUSH_MAIN, "/w origin"),
        (bash("rm -rf x"), ActionKind.RM, "/w/x"),
        (
            tool("mcp__preview-dashboard__dashboard_empty_trash", {}),
            ActionKind.DASHBOARD_DELETE,
            "empty:trash",
        ),
        (
            tool("Edit", {"file_path": "/w/.claude/settings.json"}),
            ActionKind.SETTINGS_EDIT,
            "/w/.claude/settings.json",
        ),
    ],
)
def test_c59_matching_approval_gives_no_decision(
    call: dict[str, object], kind: ActionKind, target: str
) -> None:
    audit = FakeAuditLog()
    g = gate(audit)
    g.begin_run(WINDOW_A, [consumed(1, kind, target)])
    assert g.decide(call) == HookDecision.no_decision()
    assert audit.entries[-1]["event"] == "hook_cover_used"
    assert audit.entries[-1]["approval"] == f"{1:026d}"


def test_c59_other_target_or_kind_denied() -> None:
    g = gate()
    g.begin_run(
        WINDOW_A,
        [consumed(1, ActionKind.PR_MERGE, "o/r#30"), consumed(2, ActionKind.DEPLOY, "o/r#31")],
    )
    decision = g.decide(bash("gh pr merge 31 -R o/r"))
    assert denied(decision)
    assert decision.reason is not None
    assert decision.reason.startswith("pr_merge")


def test_c59_one_approval_covers_one_call() -> None:
    g = gate()
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/x")])
    assert g.decide(bash("rm x")) == HookDecision.no_decision()
    assert denied(g.decide(bash("rm x")))


def test_c59_cover_ends_with_the_run() -> None:
    g = gate()
    approval = consumed(1, ActionKind.RM, "/w/x")
    g.begin_run(WINDOW_A, [approval])
    g.end_run()
    assert g.decide(bash("rm x")).reason == REASON_NO_RUN
    g.begin_run(WINDOW_A)  # the next run of the same window has no cover
    assert denied(g.decide(bash("rm x")))


def test_c59_unknown_session_denied() -> None:
    g = gate()
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/x")])
    assert g.decide(bash("ls", session=WINDOW_B)).reason == REASON_NO_RUN
    assert g.decide(bash("rm x", session=WINDOW_B)).reason == REASON_NO_RUN
    no_run = gate()
    assert no_run.decide(bash("ls")).reason == REASON_NO_RUN


def test_c59_cover_from_another_window_refused() -> None:
    with pytest.raises(ValidationError):
        gate().begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/x", window=WINDOW_B)])


def test_c59_flagged_message_never_covers() -> None:
    request = flagged(1)
    assert not request.covers(ActionKind.RM, "/w/x")
    with pytest.raises(ValidationError):
        gate().begin_run(WINDOW_A, [request])


def test_c59_unconsumed_approval_refused_as_cover() -> None:
    clock = FixedClock()
    pending = ApprovalRequest.new(
        id=ApprovalId(f"{1:026d}"),
        window_id=WINDOW_A,
        kind=ApprovalKind.ACTION,
        action_text="Remove x",
        now=clock.now(),
        action_kind=ActionKind.RM,
        action_target="/w/x",
    )
    approved = pending.tapped(clock.advance(timedelta(seconds=1))).approved(
        clock.advance(timedelta(seconds=1))
    )
    for request in (pending, approved):
        with pytest.raises(ValidationError):
            gate().begin_run(WINDOW_A, [request])


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "text",
        [],
        {},
        {**bash("ls"), "hook_event_name": "PostToolUse"},
        {**bash("ls"), "session_id": "not-a-uuid"},
        {**bash("ls"), "session_id": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
        {**bash("ls"), "cwd": "relative"},
        {**bash("ls"), "cwd": 3},
        {**bash("ls"), "tool_name": ""},
        {**bash("ls"), "tool_name": 5},
        {**bash("ls"), "tool_input": "rm x"},
    ],
)
def test_c59_malformed_input_denied(raw: object) -> None:
    g = gate()
    g.begin_run(WINDOW_A)
    assert g.decide(raw).reason == REASON_MALFORMED


def test_c59_deny_without_approval_not_locked() -> None:
    g = gate()
    g.begin_run(WINDOW_A)
    assert denied(g.decide(bash("rm x")))
    assert denied(g.decide(bash("rm x")))
    # After the owner approves, the same action goes through: nothing was locked.
    g.end_run()
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/x")])
    assert g.decide(bash("rm x")) == HookDecision.no_decision()


def test_c59_unknown_never_stored_or_approvable() -> None:
    assert UNKNOWN not in {k.value for k in ActionKind}
    assert not ra.UNKNOWN.approvable
    assert ra.UNKNOWN.label == UNKNOWN
    with pytest.raises(ValidationError):
        ApprovalRequest.new(
            id=ApprovalId(f"{1:026d}"),
            window_id=WINDOW_A,
            kind=ApprovalKind.ACTION,
            action_text="Run something",
            now=FixedClock().now(),
            action_kind=UNKNOWN,  # type: ignore[arg-type]
            action_target="x",
        )
    g = gate()
    every_kind = [
        consumed(i + 1, k, "x") for i, k in enumerate(ActionKind) if k.value != "peer_message"
    ]
    g.begin_run(WINDOW_A, every_kind)
    assert denied(g.decide(bash("eval x")))


def test_c59_no_command_text_logged(caplog: pytest.LogCaptureFixture) -> None:
    marker = "marker-text-4711"  # stands in for command text that must not leak
    audit = FakeAuditLog()
    g = gate(audit)
    g.begin_run(WINDOW_A)
    caplog.set_level("DEBUG")
    for command in (f"rm x # {marker}", f"eval {marker}", f"gh pr merge 1 -b {marker}"):
        decision = g.decide(bash(command))
        assert denied(decision)
        assert marker not in (decision.reason or "")
    assert marker not in caplog.text
    assert marker not in json.dumps(audit.entries)
    assert all(
        set(e) <= {"event", "at", "window", "action_kind", "action_target"} for e in audit.entries
    )


def test_c59_gate_errors_deny() -> None:
    class Exploding(FakeAuditLog):
        def record(self, entry: object) -> None:
            raise RuntimeError("disk full")

    g = HookGate(FakePeers(), Exploding(), FixedClock())
    g.begin_run(WINDOW_A)
    assert denied(g.decide(bash("rm x")))


# --- settings: the hook can't be switched off ------------------------------------------------


@pytest.mark.parametrize("content", [{"disableAllHooks": True}, {"allowManagedHooksOnly": True}])
@pytest.mark.parametrize("source", ["user", "user_local", "project", "project_local", "managed"])
def test_c59_disable_all_hooks_refuses_run(source: str, content: object, tmp_path: Path) -> None:
    home, work = tmp_path / "home", tmp_path / "work"
    paths = {
        "user": home / ".claude" / "settings.json",
        "user_local": home / ".claude" / "settings.local.json",
        "project": work / ".claude" / "settings.json",
        "project_local": work / ".claude" / "settings.local.json",
        "managed": tmp_path / "managed-settings.json",
    }
    sources = settings_sources(home, work)
    assert MANAGED_SETTINGS in sources  # the real managed file is always checked
    checked = [p for p in sources if p != MANAGED_SETTINGS] + [paths["managed"]]
    target = paths[source]
    assert target in checked
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(content), encoding="utf-8")
    with pytest.raises(HostSettingsError):
        check_settings_sources(checked)
    target.write_text(
        json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": []}]}}), encoding="utf-8"
    )
    with pytest.raises(HostSettingsError):
        check_settings_sources(checked)


def test_c59_hook_paths_in_deny_and_settings_edit() -> None:
    assert ra.HOOK_SCRIPT == HOOK_COMMAND
    assert HOST_SETTINGS_PATH.as_posix() == ra.HOST_SETTINGS_FILE
    assert MANAGED_SETTINGS.as_posix() == ra.MANAGED_SETTINGS_FILE
    assert MANAGED_SETTINGS_DIR.as_posix() == ra.MANAGED_SETTINGS_DIR
    for path in (HOOK_COMMAND, HOST_SETTINGS_PATH.as_posix()):
        assert f"Edit(/{path})" in REQUIRED_DENY
        assert f"Write(/{path})" in REQUIRED_DENY
        for name in ("Edit", "Write"):
            action = ra.classify_tool_call(name, {"file_path": path}, CWD)
            assert action == ra.RiskyAction(ActionKind.SETTINGS_EDIT, path)
        assert_kind(f"echo x > {path}", "settings_edit", path)
        assert_kind(f"cp /tmp/x {path}", "settings_edit", path)


def test_c59_shipped_hook_matches_every_hooked_tool() -> None:
    deploy = Path(__file__).resolve().parents[2] / "deploy" / "claudia" / "settings.json"
    entry = json.loads(deploy.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]
    assert entry["hooks"][0]["command"] == ra.HOOK_SCRIPT
    # The hook's own deadline must beat Claude Code's timeout (a timeout fails open).
    assert entry["hooks"][0]["timeout"] > hook_cmd.ALARM_SECONDS
    assert hook_cmd.TIMEOUT_SECONDS < hook_cmd.ALARM_SECONDS
    pyproject = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text("utf-8")
    assert (
        'preview-dashboard-claudia-hook = "preview_dashboard.interfaces.claudia.hook:main"'
        in pyproject
    )


# --- the hook process + control socket ---------------------------------------------------------


@pytest.fixture
def sock_dir() -> Iterator[Path]:
    # AF_UNIX paths are limited to ~108 bytes: keep it short.
    path = Path(tempfile.mkdtemp(prefix="hk", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def served(sock_dir: Path) -> Iterator[tuple[HookGate, Path]]:
    g = gate()
    server = ControlSocketServer(g, sock_dir / "hook.sock", trusted_uids=ME, timeout=2.0)
    server.start()
    try:
        yield g, server.path
    finally:
        server.close()


def run_hook(payload: object, path: Path, *, timeout: float = 2.0) -> tuple[int, str, str]:
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    out, err = io.StringIO(), io.StringIO()
    code = hook_cmd.run(
        io.BytesIO(raw), out, err, socket_path=path, trusted_uids=ME, timeout=timeout
    )
    return code, out.getvalue(), err.getvalue()


def assert_hook_denied(result: tuple[int, str, str]) -> str:
    code, out, err = result
    assert code == hook_cmd.EXIT_DENY
    body = json.loads(out)
    decision = body["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert err.startswith("Claudia hook: ")
    reason = decision["permissionDecisionReason"]
    assert isinstance(reason, str)
    return reason


def test_c59_hook_never_allows(served: tuple[HookGate, Path]) -> None:
    source = Path(hook_cmd.__file__).read_text(encoding="utf-8")
    assert "allow" not in source.casefold()
    g, path = served
    g.begin_run(WINDOW_A, [consumed(1, ActionKind.RM, "/w/x")])
    assert run_hook(bash("rm x"), path) == (0, "", "")  # match: no decision, no output
    assert run_hook(bash("ls"), path) == (0, "", "")
    assert "rm" in assert_hook_denied(run_hook(bash("rm x"), path))  # cover used up


def test_c59_hook_end_to_end_deny(served: tuple[HookGate, Path]) -> None:
    g, path = served
    g.begin_run(WINDOW_A)
    reason = assert_hook_denied(run_hook(bash("gh pr merge 1 -R o/r"), path))
    assert "pr_merge" in reason
    assert "gh pr" not in reason  # no command text


def test_c59_hook_forwards_large_writes_trimmed(served: tuple[HookGate, Path]) -> None:
    g, path = served
    g.begin_run(WINDOW_A)
    big = tool("Write", {"file_path": "/w/a.txt", "content": "x" * (2 * 1024 * 1024)})
    assert run_hook(big, path) == (0, "", "")


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'{"tool_name": "Bash"}',
        b'{"tool_input": {"command": ["rm", "x"]}}',
        b'{"tool_input": {"command": true}}',
    ],
)
def test_c59_hook_bad_input_denies(payload: bytes, served: tuple[HookGate, Path]) -> None:
    g, path = served
    g.begin_run(WINDOW_A)
    assert_hook_denied(run_hook(payload, path))


def test_c59_hook_oversized_command_denies(served: tuple[HookGate, Path]) -> None:
    g, path = served
    g.begin_run(WINDOW_A)
    assert_hook_denied(run_hook(bash("echo " + "a" * (hook_cmd.MAX_COMMAND_CHARS + 1)), path))


def test_c59_host_down_denies(sock_dir: Path) -> None:
    reason = assert_hook_denied(run_hook(bash("ls"), sock_dir / "missing.sock"))
    assert reason.endswith(hook_cmd.REASON_HOST_DOWN)


def test_c59_host_timeout_denies(sock_dir: Path) -> None:
    path = sock_dir / "slow.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(1)  # accepts, never answers
        reason = assert_hook_denied(run_hook(bash("ls"), path, timeout=0.3))
    assert reason.endswith(hook_cmd.REASON_HOST_DOWN)


@pytest.mark.parametrize(
    "reply",
    [
        b"garbage\n",
        b'{"decision": "allow"}\n',
        b'{"decision": "no_decision", "extra": 1}\n',
        b'{"decision": "deny"}\n',
        b'{"decision": "deny", "reason": "<script>"}\n',
        b'{"decision": "no_decision"}',  # no newline: incomplete
        b"",
    ],
)
def test_c59_odd_host_reply_denies(reply: bytes, sock_dir: Path) -> None:
    path = sock_dir / "odd.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o600)
    listener.listen(1)

    def answer() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(65536)
            conn.sendall(reply)

    worker = threading.Thread(target=answer, daemon=True)
    worker.start()
    try:
        reason = assert_hook_denied(run_hook(bash("ls"), path))
    finally:
        worker.join(timeout=2)
        listener.close()
    assert reason.endswith(hook_cmd.REASON_BAD_REPLY) or reason.endswith(hook_cmd.REASON_HOST_DOWN)


def test_c59_untrusted_socket_denies(served: tuple[HookGate, Path]) -> None:
    g, path = served
    g.begin_run(WINDOW_A)
    os.chmod(path, 0o666)  # noqa: S103 - the hook must refuse a world-accessible socket
    assert_hook_denied(run_hook(bash("ls"), path))
    os.chmod(path, 0o600)
    out, err = io.StringIO(), io.StringIO()
    code = hook_cmd.run(
        io.BytesIO(json.dumps(bash("ls")).encode()), out, err, socket_path=path, trusted_uids=(-1,)
    )
    assert code == hook_cmd.EXIT_DENY


def test_c59_hook_crash_denies(monkeypatch: pytest.MonkeyPatch, sock_dir: Path) -> None:
    def boom(*_args: object, **_kwargs: object) -> bytes:
        raise MemoryError

    monkeypatch.setattr(hook_cmd, "ask_host", boom)
    reason = assert_hook_denied(run_hook(bash("ls"), sock_dir / "x.sock"))
    assert reason.endswith(hook_cmd.REASON_CRASH)


def test_c59_hook_process_denies_on_failure(sock_dir: Path) -> None:
    done = subprocess.run(  # noqa: S603 - fixed argv, test interpreter
        [
            sys.executable,
            "-m",
            "preview_dashboard.interfaces.claudia.hook",
            "--socket",
            str(sock_dir / "none.sock"),
        ],
        input=json.dumps(bash("ls")).encode(),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == hook_cmd.EXIT_DENY
    assert json.loads(done.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    bad_args = subprocess.run(
        [sys.executable, "-m", "preview_dashboard.interfaces.claudia.hook", "--frob"],
        input=b"{}",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert bad_args.returncode == hook_cmd.EXIT_DENY


def test_c59_socket_is_0600_root_only(served: tuple[HookGate, Path]) -> None:
    _g, path = served
    st = path.stat()
    assert st.st_mode & 0o777 == 0o600
    assert st.st_uid == os.geteuid()


def test_c59_socket_refuses_untrusted_directory(sock_dir: Path) -> None:
    open_dir = sock_dir / "open"
    open_dir.mkdir()
    open_dir.chmod(0o777)
    with pytest.raises(ControlSocketError):
        ControlSocketServer(gate(), open_dir / "hook.sock", trusted_uids=ME).start()
    with pytest.raises(ControlSocketError):
        ControlSocketServer(gate(), sock_dir / "missing" / "hook.sock", trusted_uids=ME).start()
    with pytest.raises(ControlSocketError):
        ControlSocketServer(gate(), sock_dir / "hook.sock", trusted_uids=(-1,)).start()
    squatter = sock_dir / "hook.sock"
    squatter.write_text("x", encoding="utf-8")
    with pytest.raises(ControlSocketError):
        ControlSocketServer(gate(), squatter, trusted_uids=ME).start()


def test_c59_socket_refuses_untrusted_peer(sock_dir: Path) -> None:
    g = gate()
    g.begin_run(WINDOW_A)
    server = ControlSocketServer(g, sock_dir / "hook.sock", trusted_uids=(-1,))
    # The directory check uses the same uids: start with ours, then serve only uid -1.
    server._trusted = frozenset(ME)
    server.start()
    server._trusted = frozenset({-1})
    try:
        assert_hook_denied(run_hook(bash("ls"), server.path))
    finally:
        server.close()


@pytest.mark.parametrize(
    "line",
    [
        b"garbage\n",
        b'{"v": 2, "call": {}}\n',
        b'{"call": {}}\n',
        b'{"v": 1, "call": {}, "x": 1}\n',
        b"[1]\n",
    ],
)
def test_c59_socket_malformed_request_denied(line: bytes, served: tuple[HookGate, Path]) -> None:
    _g, path = served
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3)
        conn.connect(str(path))
        conn.sendall(line)
        reply = conn.recv(4096)
    assert json.loads(reply)["decision"] == "deny"


def test_c59_socket_slow_peer_gets_no_answer(sock_dir: Path) -> None:
    server = ControlSocketServer(gate(), sock_dir / "hook.sock", trusted_uids=ME, timeout=0.3)
    server.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(str(server.path))
            conn.sendall(b'{"v": 1,')  # never finishes the line
            reply = conn.recv(4096)
            # Closed (or denied) after the budget; the hook denies either way.
            assert reply == b"" or json.loads(reply)["decision"] == "deny"
    finally:
        server.close()
    assert not server.path.exists()
