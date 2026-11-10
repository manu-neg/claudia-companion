"""Pure classifier of Claudia's tool calls into the fixed risky set (docs/security.md C59, C60).

`classify_tool_call` maps one PreToolUse call (tool name, tool input, cwd)
to `None` (not risky) or a `RiskyAction`: a canonical `ActionKind` plus the
exact target an approval must name, or kind `unknown` (no approval can
cover it). A tool it does not know is `unknown` (the hook sees every tool).
Bash commands are lexed by `domain.shell_lex` (chains, pipes, `$(…)`,
backticks, heredocs) and every simple command is checked after a closed
list of wrappers (`sudo`, `env`, `xargs`, …) and git global options are
stripped; a command outside every list that carries a risky program name
(`strace gh …`) is `unknown`. Anything it cannot read for sure is
`unknown` (fail closed). No I/O: the caller may pass `realpath` to also
check symlink targets of edited and Bash-written files.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from preview_dashboard.domain.approvals import ActionKind, normalize_action_target
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.models import is_ulid
from preview_dashboard.domain.shell_lex import (
    OUTPUT_REDIRECTS,
    ShellSyntaxError,
    SimpleCommand,
    Word,
    parse_script,
)

UNKNOWN_LABEL: Final = "unknown"
PEER_MESSAGE_PREFIX: Final = "From Claudia (owner's companion):"
SEND_MESSAGE_TOOL: Final = "SendMessage"
DASHBOARD_TOOL_PREFIX: Final = "mcp__preview-dashboard__"
TRASH_TOOL: Final = "dashboard_trash"
PRUNE_TOOL: Final = "dashboard_prune_revisions"
EMPTY_TRASH_TOOL: Final = "dashboard_empty_trash"
DASHBOARD_DELETE_TOOLS: Final = frozenset({TRASH_TOOL, PRUNE_TOOL, EMPTY_TRASH_TOOL})
# The tool is part of the target (hook-6): an approval to trash an item
# (undoable) must not cover pruning its revisions (permanent).
EMPTY_TRASH_TARGET: Final = "empty:trash"
# Mirrors the `keep` default of `dashboard_prune_revisions` (interfaces/mcp/server.py).
PRUNE_DEFAULT_KEEP: Final = 1
# Dashboard tools Claudia's runs may call; the Telegram ones are left out on
# purpose (only the host talks to the owner, C51): the gate denies them.
DASHBOARD_KNOWN_TOOLS: Final = frozenset(
    {
        "dashboard_list",
        "dashboard_get",
        "dashboard_kinds",
        "dashboard_folder_list",
        "dashboard_publish",
        "dashboard_update_content",
        "dashboard_update",
        "dashboard_restore",
        "dashboard_move",
        "dashboard_folder_create",
        "dashboard_folder_rename",
        "dashboard_folder_delete",
        "dashboard_progress_set",
        "dashboard_progress_update",
        *DASHBOARD_DELETE_TOOLS,
    }
)
KB_TOOL_PREFIX: Final = "mcp__claudia-kb__"
# `request_approval` (F-CL3) only opens a PENDING request through the host, and
# `cancel_approval` (F-CL5) only closes one of hers: no decision for either.
KB_KNOWN_TOOLS: Final = frozenset(
    {"kb_read", "kb_write", "kb_delete", "request_approval", "cancel_approval"}
)
# Built-ins outside the risky set: no decision (the permission guard decides).
NO_DECISION_BUILTINS: Final = frozenset(
    {
        "Read",
        "Grep",
        "Glob",
        "ListAgents",
        "ToolSearch",
        "TodoWrite",
        "Agent",
        "Task",
        "WebFetch",
        "WebSearch",
    }
)
EDIT_TOOLS: Final = {
    "Edit": "file_path",
    "MultiEdit": "file_path",
    "Write": "file_path",
    "NotebookEdit": "notebook_path",
}

# Fixed host paths that count as `settings_edit` (C50, C59); kept equal to
# `interfaces/claudia/settings.py` by tests/security/test_risky_hook.py.
HOST_SETTINGS_FILE: Final = "/etc/preview-dashboard/claudia-settings.json"
HOOK_SCRIPT: Final = "/opt/preview-dashboard/.venv/bin/preview-dashboard-claudia-hook"
MANAGED_SETTINGS_FILE: Final = "/etc/claude-code/managed-settings.json"
MANAGED_SETTINGS_DIR: Final = "/etc/claude-code/managed-settings.d"
# The installed hook's own code lives here: editing it switches the hook off.
INSTALL_ROOT: Final = "/opt/preview-dashboard"
# The host's own state (recap MCP config, audit evidence); only `work/`
# (her cwd) is hers to write (host-flow-1).
CLAUDIA_HOST_STATE_DIR: Final = "/var/lib/claudia-host"
CLAUDIA_HOST_WORK_DIR: Final = "/var/lib/claudia-host/work"
REPO_HOST_SETTINGS_SUFFIX: Final = "/deploy/claudia/settings.json"
# The KB holds `persona.md`, which steers every run (F-CL2b): a shell or file tool
# writing there needs approval; her own KB writes go through the KB MCP tools.
KB_ROOT: Final = "/var/lib/claudia-kb"
KB_PERSONA_NAME: Final = "persona.md"
_PROTECTED_ROOTS: Final = (
    KB_ROOT,
    HOST_SETTINGS_FILE,
    HOOK_SCRIPT,
    MANAGED_SETTINGS_FILE,
    MANAGED_SETTINGS_DIR,
    INSTALL_ROOT,
    CLAUDIA_HOST_STATE_DIR,
)
_PROTECTED_NAMES: Final = frozenset(
    posixpath.basename(p) for p in (HOST_SETTINGS_FILE, HOOK_SCRIPT, MANAGED_SETTINGS_FILE)
)
# The `.claude` dirs whose settings files her runs load (user, project in
# her cwd): a whole tree copied onto or above them may plant one (fixcheck-b-3).
_LOADED_SETTINGS_DIRS: Final = ("/root/.claude", CLAUDIA_HOST_WORK_DIR + "/.claude")

_MAX_WRAPPERS: Final = 32
_MAX_DEPTH: Final = 8
_NAME_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REPO_RE: Final = re.compile(r"([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})")
_PR_URL_RE: Final = re.compile(
    r"https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})/pull/([0-9]{1,9})"
    r"(?:[/?#].*)?"
)
_PR_NUMBER_RE: Final = re.compile(r"#?([0-9]{1,9})")
_REMOTE_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
_SAFE_REF_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
_MAIN_REFS: Final = frozenset({"main", "master"})
_VERSIONED_RE: Final = re.compile(r"(python|pypy|perl|ruby|php|lua|node)[0-9.]*")


@dataclass(frozen=True, slots=True)
class RiskyAction:
    """A risky tool call: `kind` None means `unknown` (never approvable, C59).

    `target` is the normalized `action_target` an approval must equal
    exactly; None when it cannot be known for sure (then no approval covers it).
    """

    kind: ActionKind | None
    target: str | None = None

    @property
    def label(self) -> str:
        """The kind as shown in a deny reason (`unknown` for None)."""
        return UNKNOWN_LABEL if self.kind is None else str(self.kind)

    @property
    def approvable(self) -> bool:
        """True if an approval with this kind + target could cover the call."""
        return self.kind is not None and self.target is not None


UNKNOWN: Final = RiskyAction(None)


@dataclass(frozen=True, slots=True)
class _Found:
    kind: ActionKind | None
    target: str | None = None
    # rm only: the resolved path set (None = not knowable).
    paths: frozenset[str] | None = None


_UNKNOWN: Final = _Found(None)


def _target(raw: str | None) -> str | None:
    if raw is None:
        return None
    try:
        return normalize_action_target(raw)
    except ValidationError:
        return None  # not representable as an approval target: never covered


def rm_target(paths: Iterable[str]) -> str | None:
    """The `action_target` of an `rm` of exactly these resolved paths (C59).

    Sorted unique absolute paths, shell-quoted and space-joined (one
    unambiguous spelling); None if empty or not a valid target.
    """
    unique = sorted(set(paths))
    return _target(shlex.join(unique)) if unique else None


def push_target(repo_dir: str, remote: str) -> str | None:
    """The `action_target` of a `git push` to main/master: `<repo dir> <remote>`."""
    return _target(shlex.join([repo_dir, remote]))


def pr_target(owner: str, repo: str, number: int) -> str | None:
    """The `action_target` of `gh pr merge`: `owner/repo#N`."""
    return _target(f"{owner}/{repo}#{number}")


# --- paths ---------------------------------------------------------------------------


def resolve_path(raw: str, cwd: str | None) -> str | None:
    """Lexically resolve `raw` against `cwd`; None if not knowable for sure.

    `..` components are refused: through a symlinked directory the real
    path differs from the lexical one, so an exact match could mislead.
    """
    if not raw or "\x00" in raw:
        return None
    if not raw.startswith("/"):
        if cwd is None or not cwd.startswith("/"):
            return None
        raw = posixpath.join(cwd, raw)
    if ".." in raw.split("/"):
        return None
    return "/" + posixpath.normpath(raw).lstrip("/")


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def is_protected_path(path: str) -> bool:
    """True for every settings source, the host settings file, the hook's code and the
    host's state outside `work/` (C50, C59)."""
    folded = path.casefold()
    parent, name = posixpath.split(folded)
    if posixpath.basename(parent) == ".claude" and name.startswith("settings"):
        return name.endswith(".json")
    if folded in {HOST_SETTINGS_FILE, HOOK_SCRIPT, MANAGED_SETTINGS_FILE, MANAGED_SETTINGS_DIR}:
        return True
    if any(_under(folded, root) for root in (MANAGED_SETTINGS_DIR, INSTALL_ROOT, KB_ROOT)):
        return True
    if _under(folded, CLAUDIA_HOST_STATE_DIR) and not _under(folded, CLAUDIA_HOST_WORK_DIR):
        return True
    return folded.endswith(REPO_HOST_SETTINGS_SUFFIX)


def _name_protected(raw: str) -> bool:
    """Judge a path we can't place by its name: `settings*.json` or a fixed protected file."""
    name = posixpath.basename(raw.rstrip("/")).casefold()
    return (
        (name.startswith("settings") and name.endswith(".json"))
        or name in _PROTECTED_NAMES
        or name == KB_PERSONA_NAME
    )


def _dir_may_hold_protected(path: str) -> bool:
    """True if relative names under `path` may reach a protected file (it is one, or above one)."""
    folded = path.casefold()
    if is_protected_path(folded):
        return True
    prefix = folded.rstrip("/") + "/"
    return any(root.startswith(prefix) for root in _PROTECTED_ROOTS)


def _dir_may_receive_protected(path: str) -> bool:
    """A destination dir where a file of unknown name may become protected (`.claude`, above)."""
    return _dir_may_hold_protected(path) or posixpath.basename(path.rstrip("/")) == ".claude"


def _tree_may_hold_protected(path: str) -> bool:
    """A whole tree landing at `path` may contain a protected file (fixcheck-b-3).

    True for `_dir_may_receive_protected` and for any dir at, under or above a
    loaded `.claude` dir (`cp -r x /root`, `tar -x` in her cwd).
    """
    folded = path.casefold().rstrip("/") or "/"
    if _dir_may_receive_protected(folded):
        return True
    return any(_under(d, folded) or _under(folded, d) for d in _LOADED_SETTINGS_DIRS)


def _protected(
    raw: str,
    cwd: str | None,
    realpath: Callable[[str], str] | None,
    *,
    unsafe_dir: bool = False,
    test: Callable[[str], bool] = is_protected_path,
) -> _Found | None:
    """`settings_edit` if `raw` may be a place `test` flags (lexical and resolved), else None.

    The target is exact only for `is_protected_path` itself; a dir or tree
    test can't name the file that will be written.
    """
    path = resolve_path(raw, cwd)
    if path is None:
        relative = not raw.startswith("/")
        # Unknown place (after a `cd`, or with `..`): judge the name; after a cd
        # into or above a protected dir, any relative name may be protected (hook-4).
        if _name_protected(raw) or (relative and unsafe_dir):
            return _Found(ActionKind.SETTINGS_EDIT)
        base = cwd if cwd is not None and cwd.startswith("/") else "/"
        lexical = "/" + posixpath.normpath(posixpath.join(base, raw)).lstrip("/")
        candidates = ["/" + raw.lstrip("/"), lexical]
    else:
        candidates = [path]
        if realpath is not None:
            try:
                candidates.append(realpath(path))
            except (OSError, ValueError):
                return _Found(ActionKind.SETTINGS_EDIT)  # cannot check the link: fail closed
    if any(test(c) for c in candidates):
        exact = test is is_protected_path
        return _Found(ActionKind.SETTINGS_EDIT, _target(path) if exact else None)
    return None


# --- option parsing ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Opts:
    """Options of a wrapper; anything not listed makes the call `unknown` (fail closed)."""

    flags: frozenset[str] = frozenset()
    values: frozenset[str] = frozenset()
    # Value only attached (`-i{}`, `--eof=x`), never the next word.
    attached: frozenset[str] = frozenset()
    opaque: frozenset[str] = frozenset()
    chdir: frozenset[str] = frozenset()
    # Changes the root directory: no path inside the command is knowable.
    chroot: frozenset[str] = frozenset()
    lookup_only: frozenset[str] = frozenset()
    # xargs `-I R`: words holding R are filled from stdin at run time.
    replace: frozenset[str] = frozenset()
    positionals: int = 0
    assignments: bool = False


def _o(*names: str) -> frozenset[str]:
    return frozenset(names)


_WRAPPERS: Final[dict[str, _Opts]] = {
    "sudo": _Opts(
        flags=_o(
            *["-A", "-b", "-E", "-H", "-K", "-k", "-n", "-P", "-S", "-B", "-N"],
            "--askpass",
            "--background",
        )
        | _o("--preserve-env", "--set-home", "--non-interactive", "--preserve-groups", "--stdin")
        | _o("--bell", "--reset-timestamp", "--remove-timestamp"),
        values=_o(
            *["-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-T", "-D", "-R"],
            "--user",
            "--group",
            "--host",
        )
        | _o("--close-from", "--prompt", "--role", "--type", "--other-user", "--chdir")
        | _o("--command-timeout", "--chroot"),
        attached=_o("--preserve-env"),
        # -s/-i run through a shell, -e edits files: no exact action.
        opaque=_o("-s", "-i", "-e", "--shell", "--login", "--edit", "-l", "--list", "-v"),
        chdir=_o("-D", "--chdir", "-R", "--chroot"),
        chroot=_o("-R", "--chroot"),
        assignments=True,
    ),
    "doas": _Opts(flags=_o("-n"), values=_o("-u", "-C"), opaque=_o("-s", "-L")),
    "env": _Opts(
        flags=_o("-i", "-0", "-v", "-", "--ignore-environment", "--null", "--debug"),
        values=_o("-u", "--unset", "-C", "--chdir"),
        attached=_o("--block-signal", "--default-signal", "--ignore-signal"),
        opaque=_o("-S", "--split-string"),
        chdir=_o("-C", "--chdir"),
        assignments=True,
    ),
    "xargs": _Opts(
        flags=_o("-0", "-r", "-t", "-p", "-x", "-o", "--null", "--no-run-if-empty", "--verbose")
        | _o("--interactive", "--exit", "--open-tty", "--show-limits"),
        values=_o(
            *["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"],
            "--arg-file",
            "--delimiter",
            "--max-args",
        )
        | _o("--max-lines", "--max-procs", "--max-chars", "--process-slot-var"),
        attached=_o("-i", "-e", "-l", "--replace", "--eof"),
        replace=_o("-I", "-i", "--replace"),
    ),
    "nice": _Opts(flags=_o(*(f"-{d}" for d in "0123456789")), values=_o("-n", "--adjustment")),
    "ionice": _Opts(
        flags=_o("-t", "--ignore"),
        values=_o("-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid"),
    ),
    "timeout": _Opts(
        flags=_o("-v", "--verbose", "--preserve-status", "--foreground"),
        values=_o("-s", "-k", "--signal", "--kill-after"),
        positionals=1,
    ),
    "stdbuf": _Opts(values=_o("-i", "-o", "-e", "--input", "--output", "--error")),
    "exec": _Opts(flags=_o("-c", "-l"), values=_o("-a")),
    "time": _Opts(
        flags=_o("-p", "-v", "-a", "-q", "--verbose", "--portability", "--append", "--quiet"),
        values=_o("-f", "-o", "--format", "--output"),
    ),
    "command": _Opts(flags=_o("-p"), lookup_only=_o("-v", "-V")),
    "builtin": _Opts(),
    "nohup": _Opts(),
    "setsid": _Opts(flags=_o("-c", "-f", "-w", "--ctty", "--fork", "--wait")),
    "unbuffer": _Opts(flags=_o("-p")),
    "busybox": _Opts(),
    "pkexec": _Opts(flags=_o("--disable-internal-agent", "--keep-cwd"), values=_o("--user")),
    "chrt": _Opts(
        flags=_o(*["-a", "-b", "-d", "-f", "-i", "-m", "-o", "-r", "-R", "-v", "-e"]), positionals=1
    ),
    "taskset": _Opts(flags=_o("-a", "-c", "--all-tasks", "--cpu-list"), positionals=1),
    "flock": _Opts(
        flags=_o(*["-s", "-x", "-u", "-n", "-o", "-F"], "--shared", "--exclusive", "--unlock")
        | _o("--nonblock", "--close", "--no-fork", "--verbose"),
        values=_o("-w", "-E", "--timeout", "--conflict-exit-code"),
        opaque=_o("-c", "--command"),
        positionals=1,
    ),
}


@dataclass(slots=True)
class _Ctx:
    cwd: str | None
    # Arguments are added at run time (xargs, find -exec): never an exact target.
    via_xargs: bool = False
    gh_repo: str | None = None
    # A `cd` (or `env -C`) went into or above a protected dir, or somewhere unknowable.
    unsafe_dir: bool = False
    # The script sets an env var git reads (GIT_*, PAGER, HOME, ...).
    git_env: bool = False
    # ... or one gh reads (GH_CONFIG_DIR: aliases from another file, fixcheck-b-4).
    gh_env: bool = False
    xargs_replace: str | None = None
    realpath: Callable[[str], str] | None = None

    def inner(self) -> _Ctx:
        """A fresh context for a command whose arguments come at run time (`find -exec`)."""
        return _Ctx(
            cwd=None,
            via_xargs=True,
            unsafe_dir=self.unsafe_dir,
            git_env=self.git_env,
            gh_env=self.gh_env,
            realpath=self.realpath,
        )


def _is_assignment(word: Word) -> bool:
    # Quoting is not checked: reading `'A=1' rm x` as an assignment only
    # makes us look at `rm` too (stricter), while `A="a b" rm x` must strip.
    name, eq, _ = word.text.partition("=")
    return bool(eq) and _NAME_RE.fullmatch(name) is not None


def _strip_wrapper(spec: _Opts, words: list[Word], ctx: _Ctx) -> list[Word] | None:
    """Remove one wrapper and its options; None if the rest can't be known (`unknown`)."""
    rest = words[1:]
    positionals = spec.positionals
    while rest:
        word = rest[0]
        text = word.text
        if word.dynamic:
            return None  # `sudo $OPTS rm x`: the options can't be read
        if spec.assignments and _is_assignment(word):
            rest.pop(0)
            continue
        if text == "--":
            rest.pop(0)
            break
        if text.startswith("-") and len(text) > 1:
            rest.pop(0)
            verdict = _option(spec, word, rest, ctx)
            if verdict == "unknown":
                return None
            if verdict == "no_command":
                return []
            continue
        if positionals:
            positionals -= 1
            rest.pop(0)
            continue
        break
    return rest


def _option(spec: _Opts, word: Word, rest: list[Word], ctx: _Ctx) -> str:
    """Consume one option word: `ok`, `no_command` (lookup only) or `unknown`."""
    text = word.text
    names: list[tuple[str, str | None]] = []  # (option, its value inside the word)
    if text.startswith("--") or text in spec.flags:
        long_name, eq, long_value = text.partition("=")
        names.append((long_name, long_value if eq else None))
    else:
        for k, ch in enumerate(text[1:], start=1):
            names.append((f"-{ch}", text[k + 1 :] or None))
            if f"-{ch}" in spec.values or f"-{ch}" in spec.attached:
                break
    for name, inline in names:
        if name in spec.opaque:
            return "unknown"
        if name in spec.lookup_only:
            return "no_command"
        value: Word | None = None
        if name in spec.values:
            if inline is None:
                if not rest:
                    return "unknown"
                value = rest.pop(0)
            else:
                value = Word(inline, word.dynamic, word.pattern)
        elif name in spec.attached:
            value = None if inline is None else Word(inline, word.dynamic, word.pattern)
        elif name not in spec.flags:
            return "unknown"  # an option we can't read: fail closed
        if name in spec.chdir:
            _note_chdir(ctx, value, chroot=name in spec.chroot)
        if name in spec.replace:
            ctx.xargs_replace = "{}" if value is None else value.text
    return "ok"


def _note_chdir(ctx: _Ctx, value: Word | None, *, chroot: bool) -> None:
    """`env -C DIR` / `sudo -D DIR`: relative paths are no longer knowable (and maybe protected)."""
    path = None if value is None or not value.literal else resolve_path(value.text, ctx.cwd)
    if chroot or path is None or _dir_may_hold_protected(path):
        ctx.unsafe_dir = True
    ctx.cwd = None


# --- the shell -----------------------------------------------------------------------

_KEYWORDS: Final = _o(
    "!",
    "{",
    "}",
    "if",
    "then",
    "elif",
    "else",
    "fi",
    "do",
    "done",
    "while",
    "until",
    "esac",
    "coproc",
)
_NON_COMMANDS: Final = _o("for", "case", "select", "function", "[[", "]]", "[", "in", "test")
_DIR_CHANGERS: Final = _o("cd", "pushd", "popd")
# They take a string of code, hide the real command, run it elsewhere
# (another cgroup, host, namespace, root or session) or define one for
# later: no exact action can be known (C59 `unknown`, fixcheck-b-1).
_OPAQUE: Final = _o(
    "eval", "trap", "alias", "watch", "su", "script", "parallel", "claude", "runuser", "expect"
) | _o(
    *["systemd-run", "run0", "tmux", "screen", "ssh", "at", "batch", "nsenter", "unshare"],
    *["chroot", "setpriv", "strace", "ltrace", "gdb", "valgrind", "firejail", "bwrap"],
    *["proot", "fakeroot", "sg"],
)
_SHELLS: Final = _o("bash", "sh", "dash", "zsh", "ksh", "mksh", "ash", "fish", "csh", "tcsh")
# Short-option letters that take inline code, per interpreter family.
_INLINE_SHORT: Final = {
    "shell": "c",
    "python": "c",
    "pypy": "c",
    "node": "ep",
    "perl": "eE",
    "ruby": "e",
    "php": "rR",
    "lua": "e",
}
_INLINE_LONG: Final = _o("--eval", "--print", "--command")
_AWK: Final = _o("awk", "gawk", "mawk", "nawk")
_RM: Final = _o("rm", "unlink", "shred", "rmdir")
_WRITERS: Final = _o(
    "tee", "cp", "mv", "ln", "install", "truncate", "touch", "chmod", "chown", "chgrp", "sed"
) | _o("rsync", "sort")
# Only the destination is written (sources are read; `ln` sources stay as they are).
_DEST_WRITERS: Final = _o("cp", "install", "ln", "rsync", "mv")
# Whole trees land under the destination (cp only with -r/-R/-a).
_TREE_WRITERS: Final = _o("rsync", "mv")
# Commands that never run a program named in their arguments: a risky name
# there is just text (`grep gh`, `echo rm`). Everything else not classified
# is checked for one (fixcheck-b-1). Not here on purpose: man/sort/rg/
# install/rsync/sed (pager, compress, preprocessor, strip, rsh, `e` hooks).
_NO_EXEC: Final = (
    _o(
        *["echo", "printf", "cat", "grep", "egrep", "fgrep", "ls", "which", "type", "whereis"],
        *["head", "tail", "wc", "file", "stat", "du", "df", "pwd", "true", "false", ":", "sleep"],
        *["date", "basename", "dirname", "realpath", "readlink", "mkdir", "ps", "id", "whoami"],
        *["uname", "cut", "tr", "jq", "tee", "cp", "mv", "ln", "truncate", "touch", "chmod"],
        *["chown", "chgrp", "dd", "set", "unset", "shift", "exit", "return", "wait", "read"],
        *["mapfile", "readarray", "getopts", "kill", "umask"],
    )
    | _DIR_CHANGERS
)
# Written into a word, these names may run a risky step through a command
# we don't model (`strace -f gh pr merge 5`, `foo --exec=rm x`).
_RISKY_PROGRAMS: Final = _o(
    *["gh", "git", "find", "install.sh", "eval", "xargs", "sudo", "doas", "env", "su"],
    *["ssh", "nohup", "setsid", "busybox", "pkexec", "flock", "exec", "systemd-run", "run0"],
    *["nsenter", "unshare", "chroot", "setpriv", "strace", "tmux", "claude", "runuser"],
    *["tee", "cp", "mv", "ln", "dd", "sed", "rsync", "tar", "unzip", "cpio", "truncate"],
)
_WORD_SPLIT_RE: Final = re.compile(r"[\s;&|()<>'\"`{}=,]+")
_HTTP_CLIENTS: Final = _o("curl", "wget", "http", "https", "xh", "xhs")
_READ_METHODS: Final = _o("GET", "HEAD")
# Env vars git reads that change where it pushes or what it runs (hook-3).
_GIT_ENV_NAMES: Final = _o("PAGER", "EDITOR", "VISUAL", "HOME", "XDG_CONFIG_HOME", "SSH_ASKPASS")
_SAFE_GIT_ENV: Final = _o(
    "GIT_PAGER=cat", "GIT_PAGER=", "PAGER=cat", "PAGER=", "GIT_TERMINAL_PROMPT=0", "GIT_EDITOR=true"
)
# Env vars gh reads for its config (aliases), host or the programs it runs (fixcheck-b-4).
_GH_ENV_NAMES: Final = _o(
    *["GH_CONFIG_DIR", "GH_HOST", "GH_PAGER", "GH_BROWSER", "GH_EDITOR", "BROWSER", "PAGER"],
    *["EDITOR", "VISUAL", "HOME", "XDG_CONFIG_HOME"],
)
_SAFE_GH_ENV: Final = _o("GH_PAGER=cat", "GH_PAGER=", "PAGER=cat", "PAGER=")
_DECLARERS: Final = _o("export", "declare", "typeset", "readonly", "local")
# Builtins that set a variable named by a later word (under `set -a` that
# also exports it): `read GIT_DIR`, `printf -v GIT_DIR`, `for GIT_DIR in`.
_VAR_SETTERS: Final = _DECLARERS | _o(
    "read", "mapfile", "readarray", "printf", "getopts", "for", "select"
)


def _basename(word: Word) -> str:
    return posixpath.basename(word.text)


def _strip_prefix(cmd: SimpleCommand, ctx: _Ctx) -> list[Word] | None:
    """Drop keywords and leading assignments; None if this is not a command at all."""
    words = list(cmd.words)
    while words:
        first = words[0]
        if first.text in _KEYWORDS and not first.quoted:
            words.pop(0)
        elif _is_assignment(first):
            name, _, value = first.text.partition("=")
            if name == "GH_REPO":
                ctx.gh_repo = value if first.literal else ""
            words.pop(0)
        else:
            break
    if not words or (words[0].text in _NON_COMMANDS and not words[0].quoted):
        return None
    return words


def _family(name: str) -> str | None:
    if name in _SHELLS:
        return "shell"
    if name in {"nodejs", "bun", "deno"}:
        return "node"
    match = _VERSIONED_RE.fullmatch(name)
    return match.group(1) if match else None


def _interpreter(family: str, words: list[Word], cmd: SimpleCommand, ctx: _Ctx) -> _Found | None:
    """Inline code (`-c`, `-e`, code on stdin) is `unknown`; a shell running install.sh deploys."""
    args = words[1:]
    letters = _INLINE_SHORT[family]
    script: Word | None = None
    module = False
    i = 0
    while i < len(args):
        word = args[i]
        text = word.text
        i += 1
        if not word.literal:
            return _UNKNOWN
        if text in {"-", "-s"} and family in {"shell", "python", "pypy"}:
            break  # code from stdin
        if text.startswith("--"):
            if text.partition("=")[0] in _INLINE_LONG:
                return _UNKNOWN
            continue
        if text.startswith(("-", "+")) and len(text) > 1:
            if any(ch in letters for ch in text[1:]):
                return _UNKNOWN
            if family in {"python", "pypy"} and text in {"-m", "-W", "-X", "-Q"}:
                module = module or text == "-m"
                i += 1  # value follows
            elif (family == "shell" and text in {"-o", "+o", "-O", "+O"}) or (
                family == "node" and text in {"-r", "--require"}
            ):
                i += 1
            continue
        script = word
        break
    if family == "node" and script is not None and script.text == "eval":
        return _UNKNOWN  # `deno eval '…'`
    if script is None and not module and (cmd.stdin_fed or ctx.via_xargs):
        return _UNKNOWN  # code from a pipe, heredoc, here-string or `<`
    if family == "shell":
        # Any argument, not only the script word: an option we skip may take a value.
        for word in args:
            if word.literal and posixpath.basename(word.text) == "install.sh":
                return _deploy(word, ctx)
    return None


def _deploy(script: Word, ctx: _Ctx) -> _Found:
    path = resolve_path(script.text, ctx.cwd) if script.literal else None
    return _Found(ActionKind.DEPLOY, _target(path))


def _rm(name: str, args: list[Word], ctx: _Ctx) -> _Found:
    value_opts = (
        {"-n", "-s", "--iterations", "--size", "--random-source"} if name == "shred" else set()
    )
    paths: list[str] = []
    knowable = not ctx.via_xargs
    options_done = False
    i = 0
    while i < len(args):
        word = args[i]
        i += 1
        if not options_done and word.text == "--":
            options_done = True
        elif not options_done and word.text.startswith("-") and len(word.text) > 1:
            i += 1 if word.text in value_opts else 0
        else:
            resolved = resolve_path(word.text, ctx.cwd) if word.literal else None
            knowable = knowable and resolved is not None
            if resolved is not None:
                paths.append(resolved)
    if not knowable or not paths:
        return _Found(ActionKind.RM)
    return _Found(ActionKind.RM, rm_target(paths), frozenset(paths))


def _find(args: list[Word], ctx: _Ctx, depth: int) -> _Found | None:
    """`find … -delete` is `rm` (no exact target); `-exec CMD … ;` is classified as CMD."""
    found: list[_Found | None] = []
    i = 0
    while i < len(args):
        text = args[i].text
        if text == "-delete":
            found.append(_Found(ActionKind.RM))
        elif text in {"-exec", "-execdir", "-ok", "-okdir"}:
            j = i + 1
            while j < len(args) and args[j].text not in {";", "+"}:
                j += 1
            sub = SimpleCommand(tuple(args[i + 1 : j]), (), True)
            inner = _command(sub, ctx.inner(), depth + 1)
            if inner is not None:
                # The files come from find at run time: never an exact target.
                found.append(_Found(inner.kind))
            i = j
        i += 1
    return _combine(found)


_GIT_FLAGS: Final = _o(
    "-p",
    "-P",
    "--paginate",
    "--no-pager",
    "--bare",
    "--no-replace-objects",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
    "--no-optional-locks",
    "--no-advice",
    "--no-lazy-fetch",
    "--exec-path",
)
_GIT_REPO_OPTS: Final = _o("--git-dir", "--work-tree", "--namespace", "--super-prefix")
# `-c` keys that neither run a command nor change where git pushes (hook-3).
_GIT_SAFE_CONFIG: Final = _o(
    "user.name",
    "user.email",
    "color.ui",
    "core.quotepath",
    "commit.gpgsign",
    "tag.gpgsign",
    "advice.detachedhead",
    "init.defaultbranch",
    "log.showsignature",
    "column.ui",
)


def _git(args: list[Word], ctx: _Ctx) -> _Found | None:
    """Strip git's global options (`-C`, `--git-dir`, …), then check `git push` (C59).

    Config from the call (`-c`, `--config-env`, GIT_* env) can point a remote
    elsewhere or run a command (`core.pager`, aliases): `unknown`, except a
    few harmless `-c` keys.
    """
    if ctx.git_env:
        return _UNKNOWN
    repo = ctx.cwd
    i = 0
    while i < len(args) and args[i].text.startswith("-"):
        word = args[i]
        if not word.literal:
            return _UNKNOWN
        opt, eq, _ = word.text.partition("=")
        nxt = args[i + 1] if i + 1 < len(args) else None
        if opt in {"-C", "-c"}:
            if nxt is None or not nxt.literal:
                return _UNKNOWN
            if opt == "-C":
                repo = resolve_path(nxt.text, repo)
            elif nxt.text.partition("=")[0].casefold() not in _GIT_SAFE_CONFIG:
                return _UNKNOWN
            i += 2
        elif opt == "--config-env":
            return _UNKNOWN  # the value comes from the environment
        elif opt in _GIT_REPO_OPTS:
            repo = None  # another repository: its path is not the cwd
            i += 1 if eq else 2
        elif opt in _GIT_FLAGS and not (eq and opt == "--exec-path"):
            i += 1  # `--exec-path=DIR` swaps git's own sub-commands: not here
        else:
            return _UNKNOWN  # an option we can't read: fail closed
    if i >= len(args):
        return _UNKNOWN if ctx.via_xargs else None  # `xargs git`: the sub-command is stdin
    if not args[i].literal:
        return _UNKNOWN
    sub, rest = args[i].text, args[i + 1 :]
    found = _git_sub(sub, rest, ctx)
    if found is not None or sub != "push":
        return found
    if ctx.via_xargs:
        return _Found(ActionKind.GIT_PUSH_MAIN)  # xargs appends refspecs at run time
    return _git_push(rest, repo)


# Options that name a program git runs (on this host, for push/fetch/clone/archive).
_GIT_EXEC_OPTS: Final = _o("--receive-pack", "--upload-pack", "--exec", "--extcmd")
# `-u` means --upload-pack only for these (push -u is --set-upstream).
_GIT_U_IS_UPLOAD: Final = _o("clone", "ls-remote")
# `-x` takes a command only for these (cherry-pick -x / clean -x don't).
_GIT_X_RUNS: Final = _o("rebase", "difftool")
# They can get an exec option or a sub-command from stdin under xargs
# (`xargs git push` is already `git_push_main` without a target: denied too).
_GIT_EXEC_CAPABLE: Final = _o(
    *["fetch", "pull", "clone", "ls-remote", "archive", "rebase", "difftool"],
    *["config", "submodule", "bisect", "apply", "am", "filter-branch", "init"],
)
# A sub-command (or the first word after it) that runs commands by design.
_GIT_RUNNERS: Final = {
    "filter-branch": None,
    "submodule": "foreach",
    "bisect": "run",
}
_GIT_PATCH_READS: Final = _o("--check", "--stat", "--numstat", "--summary")


def _git_sub(sub: str, args: list[Word], ctx: _Ctx) -> _Found | None:
    """fixcheck-b-2: git sub-commands that store config, run a command or write patched files.

    `git config` writes (an alias, `core.pager`, `remote.*.push` for a
    later call) and options that name a program are `unknown`; `git apply`
    / `am` write files named inside the patch: `settings_edit`, no target.
    """
    if ctx.via_xargs and sub in _GIT_EXEC_CAPABLE:
        return _UNKNOWN
    if sub == "config":
        return None if _git_config_reads(args) else _UNKNOWN
    if sub in _GIT_RUNNERS:
        runner = _GIT_RUNNERS[sub]
        positional = [w.text for w in args if not w.text.startswith("-")]
        if runner is None or runner in positional[:1] or not all(w.literal for w in args):
            return _UNKNOWN
    if sub in {"clone", "init"} and any(
        w.text.partition("=")[0] in {"--template", "-c", "--config"} for w in args
    ):
        return _UNKNOWN  # hooks from a template dir, config (aliases) for the new repo
    for word in args:
        if word.text == "--":
            break
        opt = word.text.partition("=")[0]
        cluster = _short_cluster(word.text)
        if opt in _GIT_EXEC_OPTS or (sub in _GIT_U_IS_UPLOAD and opt == "-u"):
            return _UNKNOWN
        if sub in _GIT_X_RUNS and "x" in cluster:
            return _UNKNOWN
    if sub == "am" or (sub == "apply" and not any(w.text in _GIT_PATCH_READS for w in args)):
        return _Found(ActionKind.SETTINGS_EDIT)  # the patch names the files it writes
    return None


_GIT_CONFIG_READ_OPTS: Final = _o(
    *["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color", "--get-colorbool"],
    *["-l", "--list"],
)
_GIT_CONFIG_NEUTRAL: Final = _o(
    *["--global", "--system", "--local", "--worktree", "--show-origin", "--show-scope"],
    *["--name-only", "-z", "--null", "--includes", "--no-includes", "--bool", "--int"],
    *["--bool-or-int", "--path", "--expiry-date"],
)
_GIT_CONFIG_VALUE_OPTS: Final = _o("-f", "--file", "--blob", "--type", "--default")
_GIT_CONFIG_WRITE_SUBS: Final = _o("set", "unset", "rename-section", "remove-section", "edit")


def _git_config_reads(args: list[Word]) -> bool:
    """True only for a `git config` that surely just reads (`--get`, `--list`, `get`, one name)."""
    read = False
    positionals: list[str] = []
    i = 0
    while i < len(args):
        word = args[i]
        i += 1
        if not word.literal:
            return False
        opt, eq, _ = word.text.partition("=")
        if word.text.startswith("-") and len(word.text) > 1:
            if opt in _GIT_CONFIG_READ_OPTS:
                read = True
            elif opt in _GIT_CONFIG_VALUE_OPTS:
                i += 0 if eq else 1
            elif opt not in _GIT_CONFIG_NEUTRAL:
                return False  # --add, --unset, --replace-all, -e, ...: a write
        else:
            positionals.append(word.text)
    if positionals[:1] in (["get"], ["list"]):
        return True
    if read:
        return True
    return len(positionals) == 1 and positionals[0] not in _GIT_CONFIG_WRITE_SUBS


_PUSH_MAIN_FLAGS: Final = _o("--all", "--branches", "--mirror", "--delete", "--prune")
_PUSH_VALUE_OPTS: Final = _o("-o", "--push-option", "--receive-pack", "--exec", "--repo")


def _git_push(args: list[Word], repo: str | None) -> _Found | None:
    to_main = False
    positionals: list[Word] = []
    remote: str | None = None
    options_done = False
    i = 0
    while i < len(args):
        word = args[i]
        text = word.text
        i += 1
        if options_done or not text.startswith("-") or text == "-":
            positionals.append(word)
        elif text == "--":
            options_done = True
        elif text.startswith("--"):
            opt, eq, value = text.partition("=")
            to_main = to_main or opt in _PUSH_MAIN_FLAGS
            if opt in _PUSH_VALUE_OPTS and not eq:
                value = args[i].text if i < len(args) else ""
                i += 1
            if opt == "--repo":
                remote = value
        else:
            cluster = text[1:]
            to_main = to_main or "d" in cluster  # -d = --delete
            if cluster.endswith("o"):
                i += 1
    refspecs = positionals[1:]
    if refspecs and not to_main and not any(_refspec_hits_main(r) for r in refspecs):
        return None
    if positionals:
        remote = positionals[0].text if positionals[0].literal else None
    if repo is None or remote is None or not _REMOTE_RE.fullmatch(remote):
        return _Found(ActionKind.GIT_PUSH_MAIN)
    return _Found(ActionKind.GIT_PUSH_MAIN, push_target(repo, remote))


def _ref_is_main(ref: str) -> bool:
    for prefix in ("refs/heads/", "heads/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix) :]
            break
    return ref in _MAIN_REFS


def _refspec_hits_main(word: Word) -> bool:
    """True unless the refspec's destination is surely a branch other than main/master."""
    if not word.literal:
        return True
    src, colon, dst = word.text.removeprefix("+").partition(":")
    if not colon:
        dst = src
        if src.startswith(("HEAD", "@")):
            return True  # the current branch may be main
    elif not src:
        return True  # `:ref` deletes the remote ref
    if not _SAFE_REF_RE.fullmatch(dst) or ".." in dst or dst.endswith("/"):
        return True
    return _ref_is_main(dst)


def _gh(args: list[Word], ctx: _Ctx) -> _Found | None:
    # Under xargs, a missing sub-command (or any `gh api` option) comes from stdin.
    if not args:
        return _UNKNOWN if ctx.via_xargs else None
    if not args[0].literal or args[0].text.startswith("-"):
        return _UNKNOWN if args[0].text not in {"--help", "--version"} else None
    head = args[0].text
    if head == "api":
        return _UNKNOWN if ctx.via_xargs else _gh_api(args[1:])
    if head == "alias":
        sub = args[1].text if len(args) > 1 else ""
        return _UNKNOWN if sub in {"set", "import"} else None
    if head == "repo":
        if len(args) < 2:
            return _UNKNOWN if ctx.via_xargs else None
        if not args[1].literal:
            return _UNKNOWN
        # `gh repo sync` updates a default branch on GitHub without `git push` (hook-7).
        return _Found(ActionKind.GIT_PUSH_MAIN) if args[1].text == "sync" else None
    if head != "pr":
        return None
    i = 1
    repo = ctx.gh_repo
    while i < len(args) and args[i].text.startswith("-"):
        text = args[i].text
        if not args[i].literal:
            return _UNKNOWN
        if text in {"-R", "--repo"}:
            repo = args[i + 1].text if i + 1 < len(args) and args[i + 1].literal else ""
            i += 2
        elif text.startswith(("--repo=", "-R")):
            repo = text.partition("=")[2] if text.startswith("--") else text[2:]
            i += 1
        elif text in {"--help", "-h"}:
            return None
        else:
            return _UNKNOWN
    if i < len(args) and not args[i].literal:
        return _UNKNOWN
    if i >= len(args):
        return _UNKNOWN if ctx.via_xargs else None
    if args[i].text != "merge":
        return None
    return _gh_merge(args[i + 1 :], repo)


# `gh api` options that take a value (`--jq`/`-q` and `--template`/`-t` only format the
# output); the method, field and body options are judged on their own.
_GH_API_VALUE_LONG: Final = _o(
    "--header", "--jq", "--template", "--hostname", "--preview", "--cache"
)
_GH_API_VALUE_SHORT: Final = "Hqtp"
_GH_API_FLAG_SHORT: Final = "ih"
_GH_API_BODY_LONG: Final = _o("--field", "--raw-field", "--input")
_GLOB_START: Final = "-~*?[{"
_GLOB_SPLIT_RE: Final = re.compile(r"[*?\[{]")


def _api_word_ok(word: Word, *, endpoint: bool = False) -> bool:
    """A `gh api` word whose run-time value can't become an option or another endpoint.

    `$…` never. An unquoted glob (`repos/o/r/commits?per_page=5`, F-CL1) only
    if its first char is literal and not `-`: every expansion keeps that
    char, so it can't turn into `-X POST`. An endpoint glob must also have a
    `/` before its first glob char, so it can't expand to `graphql`.
    """
    if word.dynamic:
        return False
    if not word.pattern:
        return True
    text = word.text
    if not text or text[0] in _GLOB_START:
        return False
    return not endpoint or "/" in _GLOB_SPLIT_RE.split(text, maxsplit=1)[0].strip("/")


def _gh_api_method_ok(method: Word | None) -> bool:
    return method is not None and method.literal and method.text.upper() == "GET"


def _gh_api_value(value: str, opt: str) -> bool:
    """False for a header that could switch the method (`X-HTTP-Method-Override`)."""
    return not (opt in {"-H", "--header"} and "method" in value.casefold())


def _gh_api(args: list[Word]) -> _Found | None:
    """`gh api` is read-only (no decision) only as a plain GET (C59, F-CL1 item 3).

    Any non-GET `-X`/`--method`, a field or body (`-f`/`-F`/`--field`/
    `--raw-field`/`--input`), GraphQL, a method-override header, an option
    or short cluster it can't read, a second operand or an expansion that
    could become an option is `unknown`. `--jq`/`-q` and `--template` only
    format the output: their value may hold `|` (quoted) or a glob.
    """
    endpoint: str | None = None
    options_done = False
    i = 0
    while i < len(args):
        word = args[i]
        text = word.text
        i += 1
        nxt = args[i] if i < len(args) else None
        if options_done or not text.startswith("-") or text == "-":
            if not _api_word_ok(word, endpoint=True) or endpoint is not None:
                return _UNKNOWN  # an expansion, or a second operand (gh takes one)
            endpoint = text
            continue
        if not word.literal:
            return _UNKNOWN
        if text == "--":
            options_done = True
            continue
        opt, eq, value = text.partition("=")
        if opt.startswith("--"):
            if opt in _GH_API_BODY_LONG:
                return _UNKNOWN
            if opt == "--method":
                if not _gh_api_method_ok(Word(value) if eq else nxt):
                    return _UNKNOWN
                i += 0 if eq else 1
            elif opt in _GH_API_VALUE_LONG:
                if not eq:
                    if nxt is None or not _api_word_ok(nxt):
                        return _UNKNOWN
                    value = nxt.text
                    i += 1
                if not _gh_api_value(value, opt):
                    return _UNKNOWN
            elif eq:
                return _UNKNOWN  # a long option with a value we don't know
            continue  # --paginate, --slurp, --silent, --verbose, --include, ...
        consumed = _gh_api_short(text, nxt)
        if consumed is None:
            return _UNKNOWN
        i += consumed
    if endpoint is not None and endpoint.strip("/").casefold() == "graphql":
        return _UNKNOWN
    return None


def _gh_api_short(text: str, nxt: Word | None) -> int | None:
    """Read one short-option cluster (`-i`, `-XGET`, `-q .x`, `-iq`); words used, None = unknown."""
    for k, ch in enumerate(text[1:], start=1):
        if ch in _GH_API_FLAG_SHORT:
            continue
        rest = text[k + 1 :]
        if ch in "fF":
            return None  # a field: the request gets a body (POST by default)
        if ch == "X":
            return (0 if rest else 1) if _gh_api_method_ok(Word(rest) if rest else nxt) else None
        if ch in _GH_API_VALUE_SHORT:
            if rest:
                return 0 if _gh_api_value(rest, f"-{ch}") else None
            if nxt is None or not _api_word_ok(nxt) or not _gh_api_value(nxt.text, f"-{ch}"):
                return None
            return 1
        return None  # a short option we don't know
    return 0


_MERGE_VALUE_OPTS: Final = _o(
    "-R", "--repo", "-t", "--subject", "-b", "--body", "-F", "--body-file", "-A"
) | _o("--author-email", "--match-head-commit")


def _gh_merge(args: list[Word], repo: str | None) -> _Found:
    selector: Word | None = None
    i = 0
    while i < len(args):
        word = args[i]
        text = word.text
        i += 1
        if not (text.startswith("-") and len(text) > 1):
            selector = selector or word
            continue
        opt, eq, value = text.partition("=")
        if opt in _MERGE_VALUE_OPTS and not eq:
            value = args[i].text if i < len(args) and args[i].literal else ""
            i += 1
        elif opt.startswith("-R") and not opt.startswith("--"):
            opt, value = "-R", text[2:]
        if opt in {"-R", "--repo"}:
            repo = value
    if selector is None or not selector.literal:
        return _Found(ActionKind.PR_MERGE)
    named = repo.removeprefix("github.com/") if repo else None
    url = _PR_URL_RE.fullmatch(selector.text)
    if url:
        owner, name, number = url.group(1), url.group(2), int(url.group(3))
        if named and named != f"{owner}/{name}":
            return _Found(ActionKind.PR_MERGE)  # conflicting repos: no exact target
        return _Found(ActionKind.PR_MERGE, pr_target(owner, name, number))
    num = _PR_NUMBER_RE.fullmatch(selector.text)
    match = _REPO_RE.fullmatch(named) if named else None
    if num is None or match is None:
        return _Found(ActionKind.PR_MERGE)  # a branch, or the repo comes from git config
    return _Found(ActionKind.PR_MERGE, pr_target(match.group(1), match.group(2), int(num.group(1))))


def _positionals(args: list[Word]) -> list[Word]:
    out: list[Word] = []
    for k, word in enumerate(args):
        if word.text == "--":
            return out + args[k + 1 :]
        if not (word.text.startswith("-") and len(word.text) > 1):
            out.append(word)
    return out


def _short_cluster(text: str) -> str:
    """The letters of a short-option word (`-rt` -> `rt`); empty for long options and operands."""
    return text[1:] if text.startswith("-") and not text.startswith("--") else ""


def _sed_in_place(args: list[Word]) -> bool:
    for word in args:
        if word.text == "--":
            break
        if word.text.startswith("--in-place"):
            return True
        for ch in _short_cluster(word.text):
            if ch == "i":
                return True
            if ch in "efl":
                break  # the rest of the word is that option's value
    return False


def _sed_script_option(args: list[Word]) -> bool:
    for word in args:
        if word.text.partition("=")[0] in {"--expression", "--file"}:
            return True
        for ch in _short_cluster(word.text):
            if ch in "ef":
                return True
            if ch in "il":
                break
    return False


def _target_dir(args: list[Word]) -> Word | None:
    """The `-t DIR` / `--target-directory=DIR` of cp, mv, ln, install."""
    for k, word in enumerate(args):
        text = word.text
        nxt = args[k + 1] if k + 1 < len(args) else Word("", dynamic=True)
        opt, eq, value = text.partition("=")
        if opt == "--target-directory":
            return Word(value, word.dynamic, word.pattern) if eq else nxt
        cluster = _short_cluster(text)
        if "t" in cluster:
            rest = cluster[cluster.index("t") + 1 :]
            return Word(rest, word.dynamic, word.pattern) if rest else nxt
    return None


@dataclass(frozen=True, slots=True)
class _Writes:
    """What a writer command may write, by role (fixcheck-b-3)."""

    # Judged by place and name (lexical and resolved).
    checked: tuple[Word, ...] = ()
    # Must be literal, else `settings_edit` (no target).
    written: tuple[Word, ...] = ()
    # Destinations that may be directories: `<dest>/<source name>` is written too.
    dests: tuple[Word, ...] = ()
    sources: tuple[Word, ...] = ()
    # Whole trees land at the destination (`cp -r`, `mv`, `rsync`).
    tree: bool = False
    # `ln` link targets: a link to a dir above a protected path is a way in.
    links: tuple[Word, ...] = ()
    by_args: bool = False


def _cp_recursive(args: list[Word]) -> bool:
    for word in args:
        if word.text == "--":
            break
        if word.text in {"--recursive", "--archive"} or any(
            c in "rRa" for c in _short_cluster(word.text)
        ):
            return True
    return False


def _sort_output(args: list[Word]) -> list[Word]:
    """`sort -o FILE` / `--output=FILE`: the file it writes."""
    outs: list[Word] = []
    for k, word in enumerate(args):
        opt, eq, value = word.text.partition("=")
        nxt = args[k + 1] if k + 1 < len(args) else Word("", dynamic=True)
        if opt == "--output":
            outs.append(Word(value, word.dynamic, word.pattern) if eq else nxt)
        cluster = _short_cluster(word.text)
        if "o" in cluster:
            rest = cluster[cluster.index("o") + 1 :]
            outs.append(Word(rest, word.dynamic, word.pattern) if rest else nxt)
    return outs


def _write_targets(name: str, args: list[Word]) -> _Writes:
    """The words a writer command may write, by role (see `_Writes`)."""
    if name == "dd":
        outs = tuple(
            Word(w.text[3:], w.dynamic, w.pattern) for w in args if w.text.startswith("of=")
        )
        return _Writes(checked=outs, written=outs, by_args=True)
    if name not in _WRITERS:
        return _Writes()
    positional = tuple(_positionals(args))
    if name == "sed":
        if not _sed_in_place(args):
            return _Writes(checked=positional)
        written = positional if _sed_script_option(args) else positional[1:]
        return _Writes(checked=positional, written=written, by_args=True)
    if name == "sort":
        outs = tuple(_sort_output(args))
        return _Writes(checked=outs, written=outs, by_args=bool(outs))
    if name in _DEST_WRITERS:
        target_dir = _target_dir(args)
        dests = (target_dir,) if target_dir is not None else positional[-1:]
        sources = positional if target_dir is not None else positional[:-1]
        # mv moves its sources away: a `~/...` source may be a settings file.
        written = (*dests, *sources) if name == "mv" else dests
        return _Writes(
            checked=positional,
            written=written,
            dests=dests,
            sources=sources,
            tree=name in _TREE_WRITERS or (name == "cp" and _cp_recursive(args)),
            links=sources if name == "ln" else (),
            by_args=True,
        )
    return _Writes(checked=positional, written=positional, by_args=True)  # tee, touch, chmod, ...


def _is_fd(word: Word) -> bool:
    return word.literal and (word.text.isdigit() or word.text == "-")


def _place(raw: str, ctx: _Ctx, test: Callable[[str], bool] = is_protected_path) -> _Found | None:
    return _protected(raw, ctx.cwd, ctx.realpath, unsafe_dir=ctx.unsafe_dir, test=test)


def _dest_writes(w: _Writes, ctx: _Ctx) -> _Found | None:
    """Directory destinations (`cp x /root/.claude/`), trees and `ln` targets (fixcheck-b-3)."""
    for dest in w.dests:
        names = [posixpath.basename(s.text.rstrip("/")) for s in w.sources if s.literal]
        joined = [posixpath.join(dest.text, n) for n in names if n]
        for raw in joined:
            found = _place(raw, ctx)
            if found is not None:
                return found
        if w.tree:
            places, test = [dest.text, *joined], _tree_may_hold_protected
        elif any(not s.literal for s in w.sources):
            places, test = [dest.text], _dir_may_receive_protected  # `cp /tmp/* dir/`
        else:
            continue
        for raw in places:
            found = _place(raw, ctx, test)
            if found is not None:
                return found
    for link in w.links:
        if not link.literal:
            return _Found(ActionKind.SETTINGS_EDIT)
        found = _place(link.text, ctx, _tree_may_hold_protected)
        if found is not None:
            return found
    return None


def _writes_protected(name: str, args: list[Word], cmd: SimpleCommand, ctx: _Ctx) -> _Found | None:
    """Bash writes to a settings source, the hook or host state (redirections, `tee`, `cp`, `dd`).

    A written word whose value is unknown here (`~`, `$HOME`, a glob, xargs
    input) may name a protected file: `settings_edit` without a target (hook-4).
    Paths are also checked through `ctx.realpath` (symlinks, fixcheck-b-3).
    """
    w = _write_targets(name, args)
    redirects = [
        out
        for op, out in cmd.redirects
        if op in OUTPUT_REDIRECTS and not (op == ">&" and _is_fd(out))
    ]
    if w.by_args and ctx.via_xargs:
        return _Found(ActionKind.SETTINGS_EDIT)  # the file names come from stdin
    if any(not word.literal for word in (*redirects, *w.written)):
        return _Found(ActionKind.SETTINGS_EDIT)
    for word in (*redirects, *w.checked):
        if word.literal:
            found = _place(word.text, ctx)
            if found is not None:
                return found
    return _dest_writes(w, ctx)


def _extract_place(dest: Word | None, ctx: _Ctx) -> _Found | None:
    """An archive extracted at `dest` (or the cwd) may plant a whole tree (fixcheck-b-3)."""
    if dest is not None and not dest.literal:
        return _Found(ActionKind.SETTINGS_EDIT)
    return _place("." if dest is None else dest.text, ctx, _tree_may_hold_protected)


# tar options that run a program (GNU long options may be abbreviated: prefixes count).
_TAR_EXEC: Final = (
    "--to-command",
    "--use-compress-program",
    "--checkpoint-action",
    "--rsh-command",
    "--rmt-command",
    "--info-script",
    "--new-volume-script",
)


def _long_prefix(opt: str, full: str, minimum: int = 4) -> bool:
    return len(opt) >= minimum and full.startswith(opt)


def _tar(args: list[Word], ctx: _Ctx) -> _Found | None:
    """`tar -x` writes the archive's tree under `-C DIR` / the cwd; `-I`/`--to-command` run code."""
    extract = absolute = False
    dest: Word | None = None
    archive: Word | None = None
    for k, word in enumerate(args):
        text = word.text
        nxt = args[k + 1] if k + 1 < len(args) else Word("", dynamic=True)
        if not word.literal:
            return _UNKNOWN  # may be an option that runs a program
        if text == "--":
            break
        if text.startswith("--"):
            opt, eq, value = text.partition("=")
            if any(_long_prefix(opt, full, 3) for full in _TAR_EXEC):
                return _UNKNOWN
            extract = extract or _long_prefix(opt, "--extract", 5) or opt == "--get"
            absolute = absolute or _long_prefix(opt, "--absolute-names", 5)
            if _long_prefix(opt, "--directory", 5):
                dest = Word(value) if eq else nxt
            elif _long_prefix(opt, "--file", 4):
                archive = Word(value) if eq else nxt
            continue
        old_style = k == 0 and not text.startswith("-")
        if not (old_style or (text.startswith("-") and len(text) > 1)):
            continue
        cluster = text.lstrip("-")
        if "I" in cluster or "F" in cluster:
            return _UNKNOWN  # -I PROG (compressor), -F SCRIPT (volume script)
        extract = extract or "x" in cluster
        absolute = absolute or "P" in cluster
        if "C" in cluster:
            rest = cluster[cluster.index("C") + 1 :]
            # Old-style letters take their values in order: not knowable here.
            dest = Word("", dynamic=True) if old_style else (Word(rest) if rest else nxt)
        if "f" in cluster:
            archive = args[1] if old_style and len(args) > 1 else nxt
    if not extract:
        return None if archive is None else _place(archive.text, ctx)
    if absolute:
        return _Found(ActionKind.SETTINGS_EDIT)  # -P keeps absolute member names
    return _extract_place(dest, ctx)


def _unzip(args: list[Word], ctx: _Ctx) -> _Found | None:
    dest: Word | None = None
    for k, word in enumerate(args):
        text = word.text
        if not word.literal:
            return _Found(ActionKind.SETTINGS_EDIT)
        cluster = _short_cluster(text)
        if text == "-d":
            dest = args[k + 1] if k + 1 < len(args) else Word("", dynamic=True)
        elif text.startswith("-d"):
            dest = Word(text[2:])
        elif any(c in "ltvpzZ" for c in cluster):
            return None  # list, test or pipe: nothing on disk
        elif ":" in cluster:
            return _Found(ActionKind.SETTINGS_EDIT)  # -: keeps `../` member names
    return _extract_place(dest, ctx)


def _cpio(args: list[Word]) -> _Found | None:
    """`cpio -i` / `-p` write files named in their input: no target (fail closed)."""
    for word in args:
        opt = word.text.partition("=")[0]
        if any(_long_prefix(opt, full, 3) for full in ("--rsh-command",)):
            return _UNKNOWN
        cluster = _short_cluster(word.text)
        if (
            not word.literal
            or "i" in cluster
            or "p" in cluster
            or _long_prefix(opt, "--extract", 5)
            or _long_prefix(opt, "--pass-through", 5)
        ):
            return _Found(ActionKind.SETTINGS_EDIT)
    return None


def _patch(args: list[Word]) -> _Found | None:
    """`patch` writes the files its input names (and may run `ed`): no target."""
    if any(w.text == "--dry-run" for w in args):
        return None
    return _Found(ActionKind.SETTINGS_EDIT)


_CURL_BODY: Final = _o(
    "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json"
) | _o("--form", "--form-string", "--upload-file")
_WGET_BODY: Final = ("--post-data", "--post-file", "--body-data", "--body-file")


def _curl_mutates(args: list[Word]) -> bool | None:
    """True for a non-GET method or a body; None if options come from a file (`-K`)."""
    mutates = False
    i = 0
    while i < len(args):
        text = args[i].text
        nxt = args[i + 1].text if i + 1 < len(args) else ""
        i += 1
        if text in {"-K", "--config"}:
            return None
        if text == "--request":
            mutates = mutates or nxt.upper() not in _READ_METHODS
            i += 1
        elif text in _CURL_BODY:
            mutates = True
        for k, ch in enumerate(_short_cluster(text)):
            rest = text[k + 2 :]
            if ch == "K":
                return None
            if ch == "X":
                method = rest or nxt
                mutates = mutates or method.upper() not in _READ_METHODS
                break
            if ch in "dFT":
                mutates = True
                break
    return mutates


def _wget_mutates(args: list[Word]) -> bool | None:
    mutates = False
    for k, word in enumerate(args):
        opt, eq, value = word.text.partition("=")
        if opt in {"-i", "--input-file"}:
            return None  # the URLs come from a file
        if opt == "--method":
            method = value if eq else (args[k + 1].text if k + 1 < len(args) else "")
            mutates = mutates or method.upper() not in _READ_METHODS
        mutates = mutates or opt in _WGET_BODY
    return mutates


def _httpie_mutates(args: list[Word]) -> bool:
    if any(w.text in {"-f", "--form", "--multipart"} or w.text.startswith("--raw") for w in args):
        return True
    positional = [w.text for w in args if not w.text.startswith("-")]
    if not positional or positional[0].upper() not in _READ_METHODS:
        return True  # no explicit GET: httpie sends data (incl. stdin) as POST
    items = positional[2:]
    return any(("=" in t and "==" not in t) or "@" in t for t in items)


def _http_client(name: str, args: list[Word], ctx: _Ctx) -> _Found | None:
    """A mutating HTTP call that may reach GitHub is `unknown` (hook-7: merge via the REST API)."""
    if name == "curl":
        mutates = _curl_mutates(args)
    elif name == "wget":
        mutates = _wget_mutates(args)
    else:
        mutates = _httpie_mutates(args)
    if mutates is False:
        return None
    if mutates is None or ctx.via_xargs:
        return _UNKNOWN
    if any(not w.literal or "github.com" in w.text.casefold() for w in args):
        return _UNKNOWN  # an unknown URL, or GitHub: no exact action
    return None


def _awk(args: list[Word]) -> _Found | None:
    program = next((w for w in args if not w.text.startswith("-")), None)
    if program is None or not program.literal or "system" in program.text or "|" in program.text:
        return _UNKNOWN  # awk can run commands from its program text
    return None


def _unwrap(cmd: SimpleCommand, ctx: _Ctx) -> list[Word] | None:
    """The words after keywords, assignments and wrappers.

    `[]` = nothing runs (only redirections, `for`, `[[ … ]]`, `command -v`);
    None = the real command can't be known (`unknown`).
    """
    words = _strip_prefix(cmd, ctx)
    if words is None:
        return []
    after_wrapper = False
    for _ in range(_MAX_WRAPPERS):
        if not words:
            # `xargs sudo`: the command itself comes from stdin at run time.
            return None if ctx.via_xargs and after_wrapper else []
        if not words[0].literal:
            return None  # `$CMD x`, `$(echo rm) x`, globbed or $'\x72m' names
        name = _basename(words[0])
        spec = _WRAPPERS.get(name)
        if spec is None:
            break
        stripped = _strip_wrapper(spec, words, ctx)
        if stripped is None:
            return None
        if name == "xargs":
            ctx.via_xargs = True  # hook-1: xargs appends arguments at run time
        after_wrapper = name != "xargs"
        words = stripped
    else:
        return None
    if ctx.xargs_replace and ctx.xargs_replace in words[0].text:
        return None  # `xargs -I % %`: the command name is stdin
    return words


def _command(cmd: SimpleCommand, ctx: _Ctx, depth: int) -> _Found | None:
    """Classify one simple command (after keywords, assignments and wrappers)."""
    if depth > _MAX_DEPTH:
        return _UNKNOWN
    words = _unwrap(cmd, ctx)
    if words is None:
        return _UNKNOWN
    if not words:
        return _writes_protected("", [], cmd, ctx)
    name = _basename(words[0])
    args = words[1:]
    found = _writes_protected(name, args, cmd, ctx) or _program(name, words, cmd, ctx, depth)
    if found is not None and ctx.via_xargs and found.target is not None:
        return _Found(found.kind)  # xargs adds arguments at run time: never exact
    return found


def _program(
    name: str, words: list[Word], cmd: SimpleCommand, ctx: _Ctx, depth: int
) -> _Found | None:
    args = words[1:]
    if name in _OPAQUE:
        return _UNKNOWN
    if name in {"source", "."}:
        if args and posixpath.basename(args[0].text) == "install.sh":
            return _deploy(args[0], ctx)
        return None
    if name == "install.sh":
        return _deploy(words[0], ctx)
    family = _family(name)
    if family is not None:
        return _interpreter(family, words, cmd, ctx)
    if name in _AWK:
        return _awk(args)
    if name in _RM:
        return _rm(name, args, ctx)
    if name == "find":
        return _find(args, ctx, depth)
    if name == "git":
        return _git(args, ctx)
    if name == "gh":
        return _UNKNOWN if ctx.gh_env else _gh(args, ctx)
    if name in _HTTP_CLIENTS:
        return _http_client(name, args, ctx)
    if name == "tar":
        return _tar(args, ctx)
    if name == "unzip":
        return _unzip(args, ctx)
    if name == "cpio":
        return _cpio(args)
    if name == "patch":
        return _patch(args)
    return _hidden_program(name, args)


def _is_risky_program(token: str) -> bool:
    name = posixpath.basename(token)
    return (
        name in _RISKY_PROGRAMS
        or name in _RM
        or name in _HTTP_CLIENTS
        or name in _AWK
        or _family(name) is not None
    )


def _hidden_program(name: str, args: list[Word]) -> _Found | None:
    """fixcheck-b-1: a command we don't model that names a risky program may run it.

    `strace -f gh pr merge 5`, `foo --exec=rm x`, `tmux new 'gh …'`: any
    literal word (split on blanks and shell punctuation) whose basename is a
    risky program makes the call `unknown`, except for `_NO_EXEC` commands.
    """
    if name in _NO_EXEC:
        return None
    for word in args:
        if word.literal and any(_is_risky_program(t) for t in _WORD_SPLIT_RE.split(word.text)):
            return _UNKNOWN
    return None


def _combine(found: Sequence[_Found | None]) -> _Found | None:
    """One call, one action: `rm`s merge their paths, equal ones collapse, else `unknown`."""
    risky = [f for f in found if f is not None]
    if not risky:
        return None
    if any(f.kind is None for f in risky):
        return _UNKNOWN
    if {f.kind for f in risky} == {ActionKind.RM}:
        sets = [f.paths for f in risky]
        if any(s is None for s in sets):
            return _Found(ActionKind.RM)
        paths = frozenset(p for s in sets if s is not None for p in s)
        return _Found(ActionKind.RM, rm_target(paths), paths)
    first = risky[0]
    if all(f.kind == first.kind and f.target == first.target for f in risky):
        return first
    return _UNKNOWN  # two different risky actions: one approval can't cover both


def _public(found: _Found | None) -> RiskyAction | None:
    return None if found is None else RiskyAction(found.kind, found.target)


def _safe_dir_change(words: list[Word], base: str | None) -> bool:
    """True if this `cd`/`pushd`/`popd` surely lands where no relative name is protected."""
    target: Word | None = None
    for word in words[1:]:
        text = word.text
        if text == "--":
            continue
        if word.literal and text.startswith(("-", "+")) and len(text) > 1:
            continue  # -L, -P, -e, -@, pushd +N / -N
        target = word
        break
    if target is None or not target.literal or target.text == "-":
        return False  # $HOME, $OLDPWD, the dir stack or an expansion: unknowable
    path = resolve_path(target.text, base)
    return path is not None and not _dir_may_hold_protected(path)


def _dir_changes(commands: Sequence[SimpleCommand], cwd: str | None) -> tuple[bool, bool]:
    """(a dir change anywhere, one of them may reach a protected dir) — hook-2, hook-4.

    Checked after keywords, assignments and wrappers (`{ cd`, `then cd`,
    `X=1 cd`, `builtin cd`), so none of them hides a `cd`.
    """
    changes: list[list[Word]] = []
    unsafe = False
    for cmd in commands:
        scratch = _Ctx(cwd=cwd)
        words = _unwrap(cmd, scratch)
        unsafe = unsafe or scratch.unsafe_dir
        if words and _basename(words[0]) in _DIR_CHANGERS:
            changes.append(words)
    # With two or more changes, a relative target's base is unknown.
    base = cwd if len(changes) == 1 else None
    unsafe = unsafe or any(not _safe_dir_change(words, base) for words in changes)
    return bool(changes), unsafe


def _setter_word(cmd: SimpleCommand) -> Word | None:
    """The first word after keywords and assignments, if it sets variables (`export`, `read`)."""
    for word in cmd.words:
        if (word.text in _KEYWORDS and not word.quoted) or _is_assignment(word):
            continue
        return word if word.text in _VAR_SETTERS and not word.quoted else None
    return None


def _sets_env(
    commands: Sequence[SimpleCommand], hit: Callable[[str], bool], safe: frozenset[str]
) -> bool:
    """True if the script assigns, exports or reads into a variable `hit` names (hook-3, b-4).

    `NAME=…` anywhere (unless in `safe`), and `NAME` after a setter: `export
    NAME`, `read NAME`, `printf -v NAME`, `mapfile NAME`, `for NAME in` (all
    exported under `set -a`, so `set -a` itself needs no special case).
    """
    for cmd in commands:
        setter = _setter_word(cmd)
        for word in cmd.words:
            name, eq, _ = word.text.partition("=")
            if not hit(name.partition("[")[0]):
                continue
            if eq and not (word.literal and word.text in safe):
                return True
            if not eq and setter is not None and word is not setter:
                return True
    return False


def _git_env_name(name: str) -> bool:
    return name.startswith("GIT_") or name in _GIT_ENV_NAMES


def classify_bash(
    command: str, cwd: str | None, *, realpath: Callable[[str], str] | None = None
) -> RiskyAction | None:
    """Classify a Bash tool command (C59); None if nothing in it is risky.

    `realpath` (optional, I/O by the caller) also checks the resolved path
    of every Bash-written file (symlinked dirs, fixcheck-b-3).
    """
    try:
        commands = parse_script(command)
    except ShellSyntaxError:
        return UNKNOWN
    # A `cd` anywhere makes relative paths ambiguous (subshells, order): resolve none.
    moves, unsafe_dir = _dir_changes(commands, cwd)
    # CDPATH sends a relative `cd` anywhere it lists (fixcheck-b-3).
    unsafe_dir = unsafe_dir or _sets_env(commands, lambda n: n == "CDPATH", frozenset())
    base = None if moves else cwd
    git_env = _sets_env(commands, _git_env_name, _SAFE_GIT_ENV)
    gh_env = _sets_env(commands, lambda n: n in _GH_ENV_NAMES, _SAFE_GH_ENV)

    def ctx() -> _Ctx:
        return _Ctx(
            cwd=base, unsafe_dir=unsafe_dir, git_env=git_env, gh_env=gh_env, realpath=realpath
        )

    return _public(_combine([_command(c, ctx(), 0) for c in commands]))


def classify_tool_call(
    tool_name: str,
    tool_input: Mapping[str, object],
    cwd: str | None,
    *,
    realpath: Callable[[str], str] | None = None,
) -> RiskyAction | None:
    """Map one PreToolUse call to its risky action, or None (C59).

    `SendMessage` is not classified here (the gate applies C60). A tool not
    in `is_known_tool` is `unknown` (host-flow-3: the hook sees every tool),
    and so is a missing or non-string field a rule needs.
    """
    if tool_name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            return UNKNOWN
        return classify_bash(command, cwd, realpath=realpath)
    if tool_name in EDIT_TOOLS:
        path = tool_input.get(EDIT_TOOLS[tool_name])
        if not isinstance(path, str) or not path:
            return UNKNOWN
        return _public(_protected(path, cwd, realpath))
    if tool_name.startswith(DASHBOARD_TOOL_PREFIX):
        return _dashboard(tool_name.removeprefix(DASHBOARD_TOOL_PREFIX), tool_input)
    if tool_name == SEND_MESSAGE_TOOL or is_known_tool(tool_name):
        return None
    return UNKNOWN


def is_known_tool(tool_name: str) -> bool:
    """True for a tool Claudia's runs may call: the hooked built-ins, the read-only and
    other non-risky built-ins, and the known dashboard + KB MCP tools."""
    if tool_name in NO_DECISION_BUILTINS or tool_name in EDIT_TOOLS:
        return True
    if tool_name in {"Bash", SEND_MESSAGE_TOOL}:
        return True
    if tool_name.startswith(DASHBOARD_TOOL_PREFIX):
        return tool_name.removeprefix(DASHBOARD_TOOL_PREFIX) in DASHBOARD_KNOWN_TOOLS
    if tool_name.startswith(KB_TOOL_PREFIX):
        return tool_name.removeprefix(KB_TOOL_PREFIX) in KB_KNOWN_TOOLS
    return False


def dashboard_delete_target(tool: str, tool_input: Mapping[str, object]) -> str | None:
    """The `action_target` of a dashboard delete: `trash:<id>`, `prune:<id>:keep=N` or
    `empty:trash` (hook-6); None if the item id or `keep` is not exact."""
    if tool == EMPTY_TRASH_TOOL:
        return EMPTY_TRASH_TARGET
    item = tool_input.get("item_id")
    if not is_ulid(item):
        return None
    if tool == TRASH_TOOL:
        return _target(f"trash:{item}")
    if tool != PRUNE_TOOL:
        return None
    keep = tool_input.get("keep", PRUNE_DEFAULT_KEEP)
    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        return None
    return _target(f"prune:{item}:keep={keep}")


def _dashboard(name: str, tool_input: Mapping[str, object]) -> RiskyAction | None:
    if name not in DASHBOARD_KNOWN_TOOLS:
        return UNKNOWN  # e.g. the Telegram tools: only the host talks to the owner
    if name not in DASHBOARD_DELETE_TOOLS:
        return None
    return RiskyAction(ActionKind.DASHBOARD_DELETE, dashboard_delete_target(name, tool_input))


def runs_any_code(program: str) -> bool:
    """True if `program` (a path or name) runs code or a command given to it (fixcheck-b-5).

    Shells, interpreters, awk, `find`, every stripped wrapper (`sudo`, `env`,
    `xargs`, …) and every opaque runner (`eval`, `ssh`, `systemd-run`, …): an
    allow rule for one of them pre-approves arbitrary code.
    """
    name = posixpath.basename(program)
    return (
        name in _SHELLS
        or name in _WRAPPERS
        or name in _OPAQUE
        or name in _AWK
        or name in {"find", "source", "."}
        or _family(name) is not None
    )


def has_peer_prefix(text: object) -> bool:
    """True if a `SendMessage` text starts with exactly the C52/C60 prefix."""
    return isinstance(text, str) and text.startswith(PEER_MESSAGE_PREFIX)


__all__ = [
    "CLAUDIA_HOST_STATE_DIR",
    "CLAUDIA_HOST_WORK_DIR",
    "DASHBOARD_KNOWN_TOOLS",
    "DASHBOARD_TOOL_PREFIX",
    "EMPTY_TRASH_TARGET",
    "KB_TOOL_PREFIX",
    "NO_DECISION_BUILTINS",
    "PEER_MESSAGE_PREFIX",
    "SEND_MESSAGE_TOOL",
    "UNKNOWN",
    "UNKNOWN_LABEL",
    "RiskyAction",
    "classify_bash",
    "classify_tool_call",
    "dashboard_delete_target",
    "has_peer_prefix",
    "is_known_tool",
    "is_protected_path",
    "pr_target",
    "push_target",
    "resolve_path",
    "rm_target",
    "runs_any_code",
]
