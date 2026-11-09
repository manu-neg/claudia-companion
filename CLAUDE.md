<!-- scripts/release_templates/CLAUDE.release.md: the CLAUDE.md of the shareable release.
     Architecture and conventions only; written by scripts/export_release.py. -->
# CLAUDE.md — Preview Dashboard

**TL;DR:** Private, one-way preview dashboard. Claude publishes content via a local MCP server → admin API (Unix socket) → core. The owner views/downloads/trashes/restores via the viewer app over Tailscale. Optional Telegram notifier and Claudia companion. Hexagonal architecture, security first.

Read these before changing anything:
- `docs/architecture.md` — layers, patterns, extension points
- `docs/security.md` — threat model + controls (every change must keep these true)
- `docs/adr/` — why things are the way they are

## Commands
| Task | Command |
|---|---|
| Install deps | `uv sync` |
| Lint / format | `uv run ruff check . && uv run ruff format --check .` |
| Types | `uv run mypy` |
| Tests | `uv run pytest` |
| Security scan | `uv run bandit -c pyproject.toml -r src && uv run pip-audit` |
| All checks | `make check` |

A change is done only when **all checks pass**.

## Architecture rules
```
interfaces → application → domain ← ports ← adapters
```
- `domain/` and `application/` import **no frameworks** (no FastAPI, sqlite3, httpx, mcp). Only stdlib + other core modules.
- Application services depend on **ports** (`typing.Protocol`), never on adapters.
- Only `bootstrap.py` (composition root) wires adapters into services.
- New content kind = new file in `kinds/` + registry entry + frontend renderer. No edits to unrelated code.
- New storage backend = new adapter implementing the port + contract tests.
- Prefer small classes with one responsibility; inject collaborators via constructor.

## Code conventions
- **File header (required):** every source file (py, js, css, html, sh, unit files) begins with a 2–4 line comment/docstring: what the file contains and what it is responsible for.
- **Comments:** short, explain *why* (security reason, constraint, non-obvious choice). Never restate code.
- **Docstrings:** public classes/functions get a concise docstring — purpose, args/returns if non-obvious, raised errors.
- Full type hints; `mypy --strict` clean. No `Any` unless justified in a comment.
- Errors: raise domain errors from `domain/errors.py`; interfaces map them to HTTP/MCP responses.
- No secrets, tokens, or real data in code, tests, or git.
- Frontend: vanilla ES modules, no build step, no inline scripts/styles (CSP), never assign untrusted strings to `innerHTML` (use `textContent` or DOMPurify output). No remote fonts or CDNs — vendor assets locally.

## Testing
- `tests/unit/` — pure logic with in-memory fakes (`tests/fakes.py`).
- `tests/integration/` — real adapters (tmp dirs, SQLite files).
- `tests/security/` — one test per control in `docs/security.md`.
- Port contracts: one shared test suite run against both fake and real adapter.

## Docs conventions
- Every doc starts with a **TL;DR** line, then scannable sections (tables, lists, short code blocks).
- Update docs in the same change as the code they describe.
- Significant decisions → new ADR `docs/adr/NNNN-title.md` (Context → Decision → Consequences, ≤ 1 page).

## Safety
- Never run `deploy/install.sh` or `deploy/uninstall.sh` for real from an agent session; `--dry-run` only. Installing is the owner's step.
- Never weaken a control in `docs/security.md` without updating it and adding an ADR.
