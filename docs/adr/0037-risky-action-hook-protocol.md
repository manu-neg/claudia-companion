# ADR 0037: Risky-action hook: thin stdlib hook, host-side gate, exit 2 on every deny

**TL;DR:** The PreToolUse hook command only forwards a trimmed call to the host over a root 0600 Unix socket and prints `deny` or nothing; the classifier and the approval check run in the host (`HookGate`). Every deny exits 2 (plus the deny JSON), and the hook has its own 8 s alarm, because a crash, a non-2 exit or a Claude Code hook timeout would let the call through. Unit M5a, C59/C60.

## Context
- Claude Code 2.1.x PreToolUse hooks: exit 0 + JSON `hookSpecificOutput.permissionDecision` decides; **exit 2** blocks (stderr is shown to the model, stdout ignored); any other exit, or the hook timing out, is a non-blocking error: the call runs (fail open).
- The approvals the run may use are known to the host (it consumes them through the admin API, C46) — not to the hook process, which has no token.
- A hook started before every tool call must be fast and must not break on a heavy or broken import.

## Decision
- `interfaces/claudia/hook.py` is stdlib-only: reads stdin (≤ 64 MiB), keeps `session_id`, `cwd`, `hook_event_name`, `tool_name` and fixed `tool_input` keys (`command` ≤ 256 KiB, `message` cut to its first 512 chars, file content never sent), asks the socket (5 s overall), accepts only `{"decision":"no_decision"}` or `{"decision":"deny","reason":<fixed charset>}`. Anything else, and any exception, is a deny. The word "allow" does not occur in its source (test).
- The host (`ControlSocketServer` + `HookGate`) does the rest: strict input check, session id = the run's window, `classify_tool_call`, C60 for `SendMessage`, single-use covers handed in by `begin_run(window, covers)`.
- Covers are passed explicitly per run instead of querying `ApprovalStore.find_consumed`: the host has no store, and "consumed for the run in progress" is then exact by construction; the first matching call uses a cover up (in memory; the run ends → gone).
- Deny = exit 2 + deny JSON on stdout + reason on stderr; no decision = exit 0, no output.

## Amendment (F-C2b-1, S-C2b review)
- **Matcher `*`** (was a named list): the hook sees every tool, so a built-in we never named (MultiEdit, Monitor, PowerShell, …) can't skip it (host-flow-3, hook-9).
- **Unknown tool = deny:** `HookGate` denies any tool outside `is_known_tool` (hooked built-ins, the non-risky built-ins of the C51 sets, the known dashboard and KB MCP tools); the Telegram dashboard tools stay unknown. A test checks every tool of every `TOOL_SETS` entry is known.
- **`dashboard_delete` targets name the tool:** `trash:<id>`, `prune:<id>:keep=N` (default 1), `empty:trash`, so an approval to trash (undoable) never covers a prune (permanent) (hook-6).
- **Preflight checks more:** the hook file and its `#!` interpreter (regular, root-owned, no g/o write, executable; a broken hook exits ≠ 2 = fails open, hook-5); other sources may not enable a plugin that ships hooks, set a broad allow rule or a bypass/accept-edits mode (hook-8), or set `env` / credential helpers (host-flow-4, C49).
- **Classifier hardening:** xargs and `find -exec` arguments are never exact; `cd` is found after keywords/assignments/wrappers; git with `-c` (beyond a few harmless keys), `--config-env` or git-read env (`GIT_*`, `PAGER`, `HOME`, …) is `unknown`; non-literal / post-`cd` write targets are `settings_edit` without a target; mutating curl/wget/httpie calls that may reach GitHub are `unknown`; `gh repo sync` is `git_push_main` (hook-1..4, hook-7).

## Amendment (F-C3-1, S-C3 review)
- **Unlisted commands fail closed on risky names:** the wrapper list stays closed (documented as such); runners that move or hide the command (`systemd-run`, `ssh`, `tmux`, `nsenter`, `strace`, …) are opaque, and any other command not modelled is `unknown` when a literal word (split on blanks and shell punctuation) names a risky program, unless it is in a short "never runs its arguments" list (`echo`, `grep`, `cat`, `cp`, …). Chosen over a longer wrapper list: new tools fail closed by default (fixcheck-b-1).
- **git:** only a `git config` that surely reads passes; command-running options and sub-commands are `unknown`; `git apply`/`am` are `settings_edit` (fixcheck-b-2).
- **Bash writes:** `realpath` from the gate also checks Bash targets; dir destinations are joined with each source name; trees (`cp -r`, `mv`, `rsync`, `tar -x`, `unzip`) at/above a loaded `.claude` dir or protected root, links to one, `cpio`, `patch` → `settings_edit`; `CDPATH` = unsafe dir (fixcheck-b-3).
- **Variable setters** (`read`, `printf -v`, `mapfile`, `for`) count like assignments without needing `set -a`; gh config/host env makes gh `unknown` (fixcheck-b-4).
- **Preflight:** broad allow = also a Bash rule for a shell/interpreter/wrapper/opaque runner, or Edit/Write over `/`, `/root`, `/etc`, `/opt` (fixcheck-b-5); managed drop-ins listed again each run, unlistable → refuse (newcode-3); the hook script + the package files it imports are pinned by SHA-256 at start (source only; not `__pycache__`/`.pth`, Known limitations).

## Amendment (F-CL1, Claudia permission problems 2026-11-09)
- **Context:** a run (root, same login as the owner's coding sessions) loaded the owner's `~/.claude/CLAUDE.md`, followed its "send a Telegram `failed` alert" rule and scripted the dashboard MCP server over stdio; a read-only `gh api …?per_page=5 --jq "…|…"` was `unknown`; her first reply got a 400.
- **Isolation, not the hook:** every `claude` child gets `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` + `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` (C49, start refused without them). Rejected: `--bare` (skips the OAuth subscription login), a separate `CLAUDE_CONFIG_DIR` (the credentials live in root's). Plus a fixed `--append-system-prompt` with the host rules (C51).
- **`dashboard_bypass` deny:** Bash naming the MCP server, the venv's programs, the admin socket, token files, the package or a CLI call, and file writes whose content does, are denied before classification with a fixed reason pointing her to the reply; no target, so never approvable. The hook command still never forwards file content: it scans it with a copy of the domain pattern (equality tested; the hook stays stdlib-only) and forwards one boolean it computes itself. Protected settings/hook paths stay `settings_edit`.
- **`gh api` read-only:** parsed option by option (value options, short clusters, `--`); an unquoted glob is accepted only where no expansion can start with `-` or turn the endpoint into `graphql`.
- **Consequence:** text matching is advisory against deliberate obfuscation (C59 already says so); false positives (a command that merely mentions the admin socket or token files) are denied, fail closed.

## Consequences
- A host that is down, slow or restarted denies every hooked call (including harmless ones) until it is back: availability traded for fail-closed.
- The host must call `begin_run`/`end_run` around every run (M5b); without it every hooked call is denied.
- Peer lookups must answer well inside the 5 s budget, or `SendMessage` is denied.
- The classifier is advisory against a capable injected agent (scripts written then run), as stated in C59.
- Fail-closed costs: writes to `"$VAR"`/`~`/glob targets and `find -exec`/`xargs` writers are denied without an approvable target; every new tool must be added to `is_known_tool` (and the `--tools` list) before runs can use it.
