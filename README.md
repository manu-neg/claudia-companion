<!-- scripts/release_templates/README.release.md: the README.md of the shareable release.
     Written by scripts/export_release.py in place of the working repo's README. -->
# Preview Dashboard + Claudia

**TL;DR:** A private dashboard where Claude Code publishes what it makes (pages, images, video, docs, progress trackers) and you view, download, trash and restore it from your phone or laptop, over Tailscale only. Optional: Telegram alerts and questions, and **Claudia**, a companion you text on Telegram who starts and dispatches work through your own Claude Code subscription, with risky actions gated by an authenticator code. Setup: [`docs/setup.md`](docs/setup.md).

## How it works

```
Claude Code ──stdio──▶ MCP server ──Unix socket + token──▶ admin API ──▶ core (SQLite + file blobs)
                                                                             │
Your phone/laptop ──Tailscale HTTPS──▶ viewer ◀─────────────────────────────┘
Telegram ◀──▶ notifier (optional) ◀──▶ admin API ◀──▶ Claudia host (optional)
```

- **One-way publishing:** only Claude (through MCP tools and a local admin API) can publish; the viewer can only view, download, trash and restore.
- **Owner only:** the viewer answers on your tailnet (`tailscale serve`) and checks your Tailscale login; nothing is on the public internet.
- **Isolated previews:** published bytes are served from a separate, sandboxed origin; no cookies anywhere.
- **Your own accounts:** your Tailscale tailnet, your own Telegram bot, your own Claude Code login. Nothing is shared with the people who sent you this.

## Install

Follow [`docs/setup.md`](docs/setup.md) (prerequisites, Tailscale, Telegram bot, install wizard, MCP registration, Claudia). Short version:

```bash
uv sync
make check                          # optional: run the full test suite first
sudo deploy/setup-wizard.sh         # asks for your login, tailnet host, uv path
```

## Develop

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

| Task | Command |
|---|---|
| Install deps | `uv sync` |
| Lint / format | `uv run ruff check . && uv run ruff format --check .` |
| Types | `uv run mypy` |
| Tests | `uv run pytest` |
| Security scan | `uv run bandit -c pyproject.toml -r src && uv run pip-audit` |
| All checks | `make check` |

## Docs

| Doc | Contents |
|---|---|
| `docs/setup.md` | Step-by-step install for a new host |
| `docs/architecture.md` | Layers, processes, module map, extension points |
| `docs/security.md` | Threat model and numbered controls (the source of truth) |
| `docs/api.md` | Admin API, viewer API, MCP tools |
| `docs/operations.md` | Services, paths, backups, updates, troubleshooting |
| `docs/notifier.md` | Telegram notifier |
| `docs/extending.md` | Adding a content kind or storage adapter |
| `docs/adr/` | Architecture decision records |
| `CLAUDE.md` | Conventions for Claude Code working in this repo |

## License

Apache License 2.0 (includes a patent grant): see `LICENSE` and `NOTICE`.
The optional `claudia-voice` extra installs Piper (`piper-tts`, GPL-3.0) on
the host at runtime; it is not part of this repository. Voice models are not
shipped either (each keeps its own licence, listed in `NOTICE`).
