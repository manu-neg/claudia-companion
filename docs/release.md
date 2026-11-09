# Cutting a shareable release

**TL;DR:** From a clean, up-to-date `main` checkout of the working repo: `uv run python scripts/export_release.py --out <new dir>`, review the tree, then commit it as **one release commit** in the separate release repo. The script refuses on any secret-scanner or personal-data hit and writes nothing; fix the source in the working repo, never the export.

## What the export does

| Step | Detail |
|---|---|
| File list | `git ls-files --cached --others --exclude-standard` (ignored files never) |
| Excluded | any path under `.claude/` (agents, orchestrator backlog, spikes), any `CLAUDE.md` / `HANDOFF.md`, any `memory/` or `outbox/` dir; every `.gitignore` secret/data name: `*.secret`, `*.token`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.env`, `.env.*`, `*.env`, `*.db`, `*.db-*`, `*.sqlite*`, `config.toml`, `id_rsa*`, `id_ed25519*`; `*.jsonl` except directly under `tests/fixtures/` (all case-insensitive) |
| Replaced | `README.md` ← `scripts/release_templates/README.release.md`, `CLAUDE.md` ← `scripts/release_templates/CLAUDE.release.md` (conventions only, no owner rules) |
| Refused | a non-empty, symlinked, in-repo, foreign-owned or group/other-writable `--out`; a tracked symlink or special file; a dirty work tree (unless `--allow-dirty`); a missing template; a missing `--config` (unless `--no-config`) |
| Secret scan | every exported byte through the admin's `RegexSecretScanner` (C15 rules) |
| Personal-data denylist | `owner_login`, `allowed_hosts`, `preview_origin` host and `notify_owner_chat_id` (≥ 5 digits) from `--config` (default `/etc/preview-dashboard/config.toml`; missing or unreadable = refused, `--no-config` skips it); the literal contents of every `*.token` / `*.secret` in `--secrets-dir` (default `/etc/preview-dashboard`; missing dir = none installed; an unlistable dir or unreadable, symlinked or non-regular file = refused; values ≥ 8 characters, never printed); git `user.email`/`user.name`; the `origin` remote's owner and `owner/repo`; the checkout paths; any real tailnet name (`*.tail<hex>.ts.net`); any pointer into the owner-only agent tree (`.claude/` + `orchestrator` or `agents`); every `--deny TEXT`. Case-insensitive (secret contents: exact); other terms shorter than 4 characters are ignored |
| Output dir | created with `mkdir` (never reused unless it already exists empty, owned by you, not group/other-writable); every subdir and file is created relative to an `O_NOFOLLOW` directory fd, so a planted symlink can't redirect a write |
| Output | hits are listed as `<path>: <rule or source label>`, never the matched text; on success files are written 0644 (0755 if executable) and the loaded denylist source labels are printed (`denylist sources: …`) |

## Steps

```bash
git -C /path/to/working-repo switch main
git -C /path/to/working-repo pull --ff-only
uv run python scripts/export_release.py --out /tmp/release-YYYYMMDD
```

1. Read the hit list if it refuses; fix the file in the working repo (neutral examples: `owner@example.com`, `dashboard.example.ts.net`, `example-org/example-repo`; build test secrets at runtime, e.g. `"AKIA" + "Q" * 16`), commit, export again.
2. In the export: `uv sync`, `make check` (the release must pass its own checks), and look over `git diff` against the previous release.
3. In the release repo checkout: replace its files with the export (keep its `.git/`), commit one release commit (`Release YYYY-MM-DD from <working-repo commit>`), push. Never push the working repo's history there.
4. A first push or a new invitee is an owner decision.

## Rules

- The working repo stays the source of truth; nothing is edited in the release repo.
- `scripts/export_release.py` uses only the stdlib plus this repo's own scanner (`preview_dashboard.adapters.secret_scan`); run it with `uv run` so that import resolves.
- Adding a new owner-only file type? Add it to `EXCLUDED_COMPONENTS` / `EXCLUDED_NAMES` and a case to `tests/unit/test_export_release.py`.
