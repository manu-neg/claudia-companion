# Setup (new host)

**TL;DR:** On a Linux host in your tailnet: `uv sync`, `sudo deploy/setup-wizard.sh`, `sudo deploy/tailscale/serve.sh`, merge the ACL snippet **and remove the default allow-all rule**, register the MCP server with your own Claude Code. Telegram (your own bot) and Claudia (your own subscription + authenticator app) are optional extra steps below. Everything runs on **your** accounts; nothing is shared with whoever gave you this repo.

**Never share** (not in chat, issues, screenshots, or with Claude/agents): the Telegram bot token, the tokens under `/etc/preview-dashboard/` (`*.token`), the TOTP secret (`totp.secret`, the `otpauth://` URI and its manual key), and your Claude login credentials. If one leaks, regenerate it.

Deeper reference for every step: `docs/operations.md`. Security model: `docs/security.md`.

## 1. Prerequisites

| Need | Why / how |
|---|---|
| Linux host with systemd and `nft` (nftables) | services + loopback firewall (`deploy/systemd/`, `deploy/nftables/`) |
| Python 3.12 and [uv](https://docs.astral.sh/uv/) | `uv sync`; the wizard detects `uv` on PATH or `/root/.local/bin/uv` |
| [Tailscale](https://tailscale.com/download) installed and `tailscale up` done | the dashboard is reachable only over your tailnet; MagicDNS + HTTPS certificates enabled in the admin console |
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed **as root**, logged in with **your own** subscription | Claude publishes through the MCP server (step 5); Claudia runs `claude -p` as root (step 7). Never an API key |
| `acl` package (`sudo apt install acl`) | only for Telegram/Claudia (`setfacl`); `install.sh` never installs packages |
| This repo checked out anywhere readable | `install.sh` copies it to `/opt/preview-dashboard` |

```bash
uv sync
make check              # optional: lint, types, tests, security scans
```

## 2. Install (wizard)

```bash
deploy/setup-wizard.sh --dry-run   # preview: no root, changes nothing
sudo deploy/setup-wizard.sh        # asks, prints the command, asks "Proceed? [y/N]", runs it
```

The wizard asks for three things (defaults detected from `tailscale status --json` and PATH) and validates them:

| Prompt | Example | Becomes |
|---|---|---|
| Tailscale login you will open the dashboard with | `you@example.com` | `owner_login` (only this identity may use the viewer); also `OWNER_LOGIN` in the ACL (step 3). The detected default is the login this host was enrolled with: change it if you browse with another one |
| Tailnet host name | `dashboard.your-tailnet.ts.net` | `allowed_hosts` + `preview_origin` |
| Path to uv | `/root/.local/bin/uv` | `--uv-bin` |

It then runs `deploy/install.sh --owner-login … --host … --uv-bin …`. It never asks for or writes a secret. Extra `install.sh` options go after `--` (used in steps 6–7). Without the wizard: `sudo deploy/install.sh --owner-login you@example.com --host dashboard.your-tailnet.ts.net --uv-bin /root/.local/bin/uv`.

## 3. Tailscale serve + ACL

```bash
sudo deploy/tailscale/serve.sh     # 443 -> dashboard, 8443 -> preview origin; verifies Funnel is off
```

The host name `serve.sh` prints must match `allowed_hosts` in `/etc/preview-dashboard/config.toml` (the `--host` you gave the wizard); if not, re-run the wizard with that name.

1. **Tag the host** `tag:pdash`: preferably in the admin console (Machines → the host → Edit ACL tags); `tailscale up --advertise-tags=tag:pdash` also works but re-applies every `tailscale up` flag.
2. **Merge** `deploy/tailscale/acl-snippet.json` into your tailnet policy (admin console → Access Controls), replacing `OWNER_LOGIN` with the login from step 2 of the wizard.
3. **Remove or narrow the default allow-all.** Tailscale grants are **additive**: the snippet's grant restricts nothing while the default rule still lets every device reach everything. Delete `{"src":["*"],"dst":["*"],"ip":["*"]}` from `grants` (or the legacy `acls` rule `{"action":"accept","src":["*"],"dst":["*:*"]}`), or narrow it so no source other than `OWNER_LOGIN` reaches `tag:pdash`.
4. **Funnel:** drop any `funnel` attribute in `nodeAttrs` that matches this host (`serve.sh` already verifies Funnel is off).
5. **Tests:** in the snippet's `tests` block, replace `OTHER_LOGIN` with any other user or tag in your tailnet (or delete that entry if you're its only user). The console then refuses to save a policy that lets a non-owner in.
6. **Verify:** open `https://<your host>/` from your own phone or laptop (works); from a non-owner device or user it must **fail** (connection refused or timeout). If it loads, the allow-all is still in force: fix step 3.

## 4. Verify

```bash
sudo deploy/check.sh               # live, read-only checks of the running install
```

## 5. Register the MCP server (your Claude Code)

```bash
claude mcp add --scope user preview-dashboard -- /opt/preview-dashboard/.venv/bin/preview-dashboard-mcp
claude mcp list                    # preview-dashboard: connected
```

No `--env`, no token, no arguments (the server refuses them; `docs/operations.md` "Registering the MCP server"). Files to publish go under `/root/outbox/`.

## 6. Telegram (optional): your own bot

1. In Telegram, message **@BotFather**: `/newbot`, save the token to a root-only file (e.g. `/root/telegram-bot.token`, mode 0600). Never commit or paste it anywhere else.
2. `/setjoingroups` → **Disable** (private 1:1 chat only). Don't message the bot yet.
3. Install the notifier (placeholder chat id `1`; pairing prints the real one):
   ```bash
   sudo apt install acl
   sudo deploy/setup-wizard.sh -- --telegram-chat-id 1 --telegram-token-file /root/telegram-bot.token
   ```
4. Pair, then put the printed chat id into `notify_owner_chat_id` in `/etc/preview-dashboard/config.toml`:
   ```bash
   sudo systemctl stop preview-dashboard-notifier
   sudo /opt/preview-dashboard/.venv/bin/preview-dashboard notify pair --token-group telegram=pdash-notify
   # send the printed /start <code> to your bot within 10 minutes
   sudo editor /etc/preview-dashboard/config.toml
   sudo systemctl restart preview-dashboard-admin preview-dashboard-notifier
   sudo /opt/preview-dashboard/.venv/bin/preview-dashboard notify test
   ```
5. Check that the test message **arrived in your own chat with the bot**, and that the chat id is really set (not the placeholder `1`):
   ```bash
   sudo grep notify_owner_chat_id /etc/preview-dashboard/config.toml
   ```
   Don't continue to Claudia (step 7) until both are right: Claudia accepts text only from that chat.
6. Delete the source token file: `install.sh` copied it to `/etc/preview-dashboard/telegram.token`, so the copy you made in step 1 is no longer needed:
   ```bash
   sudo shred -u /root/telegram-bot.token
   ```
Details and troubleshooting: `docs/operations.md` "Telegram notifications".

## 7. Claudia (optional): companion on Telegram

Needs step 6. Installed **off**; you turn it on.

```bash
sudo deploy/setup-wizard.sh -- --claudia          # groups, claudia.token, units (stays off)
sudo /root/.local/bin/claude                      # log in as root with YOUR subscription (never an API key)
sudo /opt/preview-dashboard/.venv/bin/preview-dashboard claudia totp setup --group pdash-totp
sudo editor /etc/preview-dashboard/config.toml    # claudia_enabled = true
                                                  # kb_root = "/var/lib/claudia-kb"
sudo deploy/setup-wizard.sh                       # re-run: enables + starts the host and the gardener timer
sudo deploy/check.sh
```

- `claude` not at `/root/.local/bin/claude`? Pass its absolute path: `sudo deploy/setup-wizard.sh -- --claudia --claude-bin /path/to/claude` (and the same `--claude-bin` on every later re-run).
- `claudia totp setup` (interactive terminal, root) prints an `otpauth://` URI and a manual key: add it to **your** authenticator app and type one current code. Risky actions Claudia wants to take need your Approve tap **and** a fresh code.
- **Run the TOTP setup only yourself, in your own terminal:** never through Claude Code, Claudia or any agent session (their transcripts would keep the secret), never in a screenshot or screen share. Afterwards clear the terminal and its scrollback (`clear`, then your terminal's "clear scrollback", or close the window).
- Text the bot to talk to Claudia; `/stop` stops every run. Off again: `claudia_enabled = false`, re-run the wizard.
- Voice replies (`install.sh --voice-models DIR`) need the four Piper files in DIR; each must match its SHA-256 pinned in `deploy/claudia/voices.sha256` (`install.sh` refuses otherwise and never downloads).

Reference: `docs/operations.md` "Claudia", ADR 0031 and 0036.

## 8. Updating

```bash
git pull
sudo deploy/setup-wizard.sh        # or the same install.sh command; idempotent, keeps data and config
```

Back up the database first when a release notes a schema migration (`docs/operations.md` "Updating", "Backups").

## 9. Uninstalling

```bash
sudo deploy/uninstall.sh                              # units + firewall rule; keeps data
sudo deploy/uninstall.sh --purge-data                 # also DB, blobs, config, tokens
sudo deploy/uninstall.sh --purge-data --purge-users   # also every service account and group
```

Also remove the MCP registration (`claude mcp remove preview-dashboard`), the Tailscale serve config (`tailscale serve reset`) and your bot (BotFather `/deletebot`). If you skipped step 6.6, delete the source bot-token file too (`sudo shred -u /root/telegram-bot.token`); `--purge-data` only removes the installed copies under `/etc/preview-dashboard/`.
